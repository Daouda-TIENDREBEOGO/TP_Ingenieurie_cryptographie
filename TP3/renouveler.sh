#!/usr/bin/env bash
set -eEuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PKI_DIR="${PKI_DIR:-"$PROJECT_DIR/TP2/pki/work"}"
DEPLOY_DIR="${DEPLOY_DIR:-/etc/nginx/tls}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
NGINX_BIN="${NGINX_BIN:-nginx}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
RENEW_BEFORE_DAYS="${RENEW_BEFORE_DAYS:-30}"

if [[ ! "$RENEW_BEFORE_DAYS" =~ ^[1-9][0-9]*$ ]]; then
    printf 'RENEW_BEFORE_DAYS doit être un entier strictement positif.\n' >&2
    exit 2
fi
for file in "$PKI_DIR/racine.cnf" "$PKI_DIR/inter.cnf" \
    "$PKI_DIR/root/racine.crt" "$PKI_DIR/inter/inter.crt" \
    "$DEPLOY_DIR/serveur.key" "$DEPLOY_DIR/serveur_chaine.crt"; do
    if [[ ! -r "$file" ]]; then
        printf 'Fichier requis absent ou illisible : %s\n' "$file" >&2
        exit 1
    fi
done

if ! "$OPENSSL_BIN" x509 -in "$DEPLOY_DIR/serveur_chaine.crt" -noout \
    >/dev/null 2>&1; then
    printf 'Le certificat actuellement déployé est illisible; arrêt sans modification.\n' >&2
    exit 1
fi
if "$OPENSSL_BIN" x509 -in "$DEPLOY_DIR/serveur_chaine.crt" \
    -checkend "$((RENEW_BEFORE_DAYS * 86400))" -noout >/dev/null; then
    printf 'Aucun renouvellement : le certificat expire dans plus de %s jours.\n' \
        "$RENEW_BEFORE_DAYS"
    exit 0
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="$DEPLOY_DIR/archive/$timestamp"
mkdir -m 700 -p "$DEPLOY_DIR/archive"
workdir="$(mktemp -d "$PKI_DIR/.renouvellement.XXXXXX")"
stagedir="$(mktemp -d "$DEPLOY_DIR/.renouvellement.XXXXXX")"
deploiement_commence=0
renouvellement_termine=0

nettoyer() {
    rm -f "$workdir/serveur.key" "$workdir/serveur.csr" \
        "$workdir/serveur.crt" "$workdir/serveur_chaine.crt" \
        "$stagedir/serveur.key" "$stagedir/serveur_chaine.crt"
    if ! rmdir "$workdir" "$stagedir" 2>/dev/null; then
        printf 'Avertissement : répertoire temporaire non vide, à examiner : %s %s\n' \
            "$workdir" "$stagedir" >&2
    fi
}

retour_arriere() {
    code=$?
    trap - ERR
    if [[ "$deploiement_commence" == 1 && "$renouvellement_termine" != 1 ]]; then
        printf 'Échec du déploiement; restauration du certificat précédent.\n' >&2
        cp -p "$backup_dir/serveur.key" "$DEPLOY_DIR/serveur.key"
        cp -p "$backup_dir/serveur_chaine.crt" "$DEPLOY_DIR/serveur_chaine.crt"
        if ! "$NGINX_BIN" -t || ! "$SYSTEMCTL_BIN" reload nginx; then
            printf 'ERREUR : le retour arrière doit être contrôlé manuellement.\n' >&2
        fi
    fi
    exit "$code"
}
trap retour_arriere ERR
trap nettoyer EXIT

mkdir -m 700 "$backup_dir"
cp -p "$DEPLOY_DIR/serveur.key" "$backup_dir/serveur.key"
cp -p "$DEPLOY_DIR/serveur_chaine.crt" "$backup_dir/serveur_chaine.crt"

"$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$workdir/serveur.key"
(
    cd "$workdir"
    MSYS_NO_PATHCONV=1 "$OPENSSL_BIN" req -new -key serveur.key \
        -subj '/CN=www.tp.local' \
        -addext 'subjectAltName=DNS:www.tp.local,DNS:tp.local' \
        -out serveur.csr
)
(
    cd "$PKI_DIR"
    "$OPENSSL_BIN" ca -batch -notext -config inter.cnf -extensions ext_serveur \
        -days 90 -in "$workdir/serveur.csr" -out "$workdir/serveur.crt"
)
"$OPENSSL_BIN" verify -purpose sslserver -CAfile "$PKI_DIR/root/racine.crt" \
    -untrusted "$PKI_DIR/inter/inter.crt" \
    -verify_hostname www.tp.local "$workdir/serveur.crt"
cat "$workdir/serveur.crt" "$PKI_DIR/inter/inter.crt" \
    > "$workdir/serveur_chaine.crt"
install -m 600 "$workdir/serveur.key" "$stagedir/serveur.key"
install -m 644 "$workdir/serveur_chaine.crt" "$stagedir/serveur_chaine.crt"

deploiement_commence=1
mv -f "$stagedir/serveur.key" "$DEPLOY_DIR/serveur.key"
mv -f "$stagedir/serveur_chaine.crt" "$DEPLOY_DIR/serveur_chaine.crt"
"$NGINX_BIN" -t
"$SYSTEMCTL_BIN" reload nginx
renouvellement_termine=1

printf 'Certificat renouvelé et nginx rechargé; sauvegarde : %s\n' "$backup_dir"
