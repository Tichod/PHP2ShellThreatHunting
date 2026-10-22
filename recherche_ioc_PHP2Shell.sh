#!/bin/bash
# recherche_ioc_PHP2Shell.sh
# by Olivier DEBRE / Microsoft Copilot
# Creation le :       <22/10/2026 11:14:51 Olivier DEBRE>
# Derniere modif le : <22/10/2026 11:56:52 Olivier DEBRE>
# Description : recherche locale d'IOC dans les journaux, fichiers, processus
#               et connexions reseau d'un serveur Linux.
# Utilisation : ./recherche_ioc_PHP2Shell.sh [fichier_configuration]
#set -x


# ================== Definition des variables  DEBUT ==================
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin
ServeurSource=$(hostname --fqdn 2>/dev/null || hostname)
RepScript=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FichierConfig=${1:-${RepScript}/recherche_ioc_PHP2Shell.conf}
Horodatage=$(date '+%Y%m%d_%H%M%S')
FichierRapport=${RepScript}/recherche_ioc_PHP2Shell_${ServeurSource}_${Horodatage}.log
NbTrouves=0
NbErreurs=0

# Repertoires volontairement limites aux emplacements habituels des journaux.
# Ajouter des chemins si l'application ecrit ailleurs.
RepertoiresLogs="/var/log"

# ================== Definition des variables   FIN  ==================
# ================== Definition des fonctions  DEBUT ==================
function Signature()
{
    echo "Rapport genere par le script $0 sur le serveur $ServeurSource"
}

function Trouve()
{
    NbTrouves=$((NbTrouves + 1))
    echo "[TROUVE] Categorie=$1 Type=$2 IOC=$3"
    if [[ -n "$4" ]]; then
        echo "$4" | sed 's/^/         /'
    fi
    echo
}

function Information()
{
    echo "[INFO] $1"
}

function Erreur()
{
    NbErreurs=$((NbErreurs + 1))
    echo "[ERREUR] $1" >&2
}

function RechercheLogs()
{
    local Type="$1" IOC="$2"
    local Sortie
    # -I ignore les binaires ; -n donne le numero de ligne ; -E utilise les expressions regulieres etendues.
    Sortie=$(grep -RInIE --exclude='*.gz' --exclude='*.zip' --exclude='*.xz' -- "$IOC" $RepertoiresLogs 2>/dev/null | head -n 100)
    if [[ -n "$Sortie" ]]; then
        Trouve "LOG" "$Type" "$IOC" "$Sortie"
    fi

    # Les journaux compresses gzip sont recherches separement si zgrep est disponible.
    if command -v zgrep >/dev/null 2>&1; then
        local FichierGz SortieGz
        while IFS= read -r FichierGz; do
            SortieGz=$(zgrep -nEi -- "$IOC" "$FichierGz" 2>/dev/null | head -n 20)
            if [[ -n "$SortieGz" ]]; then
                Trouve "LOG_GZ" "$Type" "$IOC" "$FichierGz :
$SortieGz"
            fi
        done < <(find $RepertoiresLogs -type f -name '*.gz' -print 2>/dev/null)
    fi
}

function RechercheIPouDomaine()
{
    local Categorie="$1" Type="$2" IOC="$3"
    local Sortie

    # Traces textuelles dans les journaux.
    Sortie=$(grep -RInIF --exclude='*.gz' --exclude='*.zip' --exclude='*.xz' -- "$IOC" $RepertoiresLogs 2>/dev/null | head -n 100)
    if [[ -n "$Sortie" ]]; then
        Trouve "$Categorie" "$Type" "$IOC" "$Sortie"
    fi

    # Connexions actuelles. La recherche utilise la valeur litterale pour eviter l'effet des points en regexp.
    if command -v ss >/dev/null 2>&1; then
        Sortie=$(ss -tunap 2>/dev/null | grep -F -- "$IOC" | head -n 50)
        if [[ -n "$Sortie" ]]; then
            Trouve "${Categorie}_CONNEXION" "$Type" "$IOC" "$Sortie"
        fi
    elif command -v netstat >/dev/null 2>&1; then
        Sortie=$(netstat -tunap 2>/dev/null | grep -F -- "$IOC" | head -n 50)
        if [[ -n "$Sortie" ]]; then
            Trouve "${Categorie}_CONNEXION" "$Type" "$IOC" "$Sortie"
        fi
    fi
}

function RechercheFichier()
{
    local Type="$1" IOC="$2"
    # Les IOC FILE sont des chemins et sont donc testes directement.
    if [[ -e "$IOC" || -L "$IOC" ]]; then
        local Detail
        Detail=$(ls -la -- "$IOC" 2>/dev/null)
        Trouve "FILE" "$Type" "$IOC" "$Detail"
    fi
}

function RechercheHash()
{
    local Type="$1" IOC="$2"
    local CmdHash
    case "$Type" in
        SHA256) CmdHash=sha256sum ;;
        MD5)    CmdHash=md5sum ;;
        *) Erreur "Type de hash non gere : $Type"; return ;;
    esac
    command -v "$CmdHash" >/dev/null 2>&1 || { Erreur "Commande absente : $CmdHash"; return; }

    # Recherche ciblee dans les zones d'ecriture/execution courantes afin d'eviter un parcours integral du serveur.
    local Fichier Empreinte
    while IFS= read -r -d '' Fichier; do
        Empreinte=$($CmdHash "$Fichier" 2>/dev/null | awk '{print $1}')
        if [[ "$Empreinte" == "$IOC" ]]; then
            Trouve "HASH" "$Type" "$IOC" "$Fichier"
        fi
    done < <(find /tmp /var/tmp /dev/shm /var/www -xdev -type f -print0 2>/dev/null)
}

function RechercheProcessus()
{
    local Type="$1" IOC="$2"
    local Sortie
    Sortie=$(ps -eo pid,ppid,user,lstart,comm,args 2>/dev/null | awk -v ioc="$IOC" 'NR==1 || $5==ioc')
    if [[ $(echo "$Sortie" | wc -l) -gt 1 ]]; then
        Trouve "PROCESS" "$Type" "$IOC" "$Sortie"
    fi
}
# ================== Definition des fonctions   FIN  ==================

exec > >(tee "$FichierRapport") 2>&1

echo "============================================================"
echo "IOC search - serveur : $ServeurSource"
echo "Date : $(date '+%d/%m/%Y %H:%M:%S %z')"
echo "Configuration : $FichierConfig"
echo "============================================================"
echo

if [[ ! -f "$FichierConfig" ]]; then
    Erreur "Fichier de configuration introuvable : $FichierConfig"
    exit 1
fi

# Parsing du fichier de configuration : ignore commentaires et lignes vides.
while IFS=';' read -r Actif Categorie Type IOC Commentaire
do
    [[ -z "$Actif" ]] && continue
    [[ "$Actif" =~ ^[[:space:]]*# ]] && continue
    [[ "$Actif" != "1" ]] && continue
    [[ -z "$Categorie" || -z "$Type" || -z "$IOC" ]] && { Erreur "Ligne de configuration incomplete"; continue; }

    Information "Recherche $Categorie/$Type : $IOC${Commentaire:+ - $Commentaire}"

    case "$Categorie" in
        LOG)     RechercheLogs "$Type" "$IOC" ;;
        IP)      RechercheIPouDomaine "$Categorie" "$Type" "$IOC" ;;
        DOMAIN)  RechercheIPouDomaine "$Categorie" "$Type" "$IOC" ;;
        FILE)    RechercheFichier "$Type" "$IOC" ;;
        HASH)    RechercheHash "$Type" "$IOC" ;;
        PROCESS) RechercheProcessus "$Type" "$IOC" ;;
        *)       Erreur "Categorie inconnue : $Categorie" ;;
    esac
done < "$FichierConfig"

echo "============================================================"
echo "Resultat : $NbTrouves detection(s), $NbErreurs erreur(s)"
echo "Rapport : $FichierRapport"
Signature
echo "============================================================"

# 0 = aucun IOC trouve ; 2 = au moins un IOC trouve ; 1 = erreur technique sans detection.
if [[ "$NbTrouves" -gt 0 ]]; then
    exit 2
elif [[ "$NbErreurs" -gt 0 ]]; then
    exit 1
else
    exit 0
fi

# Variables locales au fichier recherche_ioc_PHP2Shell.sh pour edition avec emacs
#### Local Variables: ####
#### time-stamp-start:"# Derniere modif le : <" ####
#### time-stamp-end:">" ####
#### time-stamp-format:"%02d/%02m/%Y %02H:%02M:%02S Olivier DEBRE" ####
#### End: ####
