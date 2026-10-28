#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${PKI_DIR:-"$SCRIPT_DIR/work"}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

if ! command -v "$OPENSSL_BIN" >/dev/null 2>&1; then
    printf 'Erreur : OpenSSL est introuvable (%s).\n' "$OPENSSL_BIN" >&2
    exit 1
fi
openssl_version="$("$OPENSSL_BIN" version)"
if [[ ! "$openssl_version" =~ ^OpenSSL[[:space:]]3\. ]]; then
    printf 'Erreur : OpenSSL 3 est requis; version détectée : %s\n' "$openssl_version" >&2
    exit 1
fi

if [[ -e "$PKI_DIR/root/racine.key" || -e "$PKI_DIR/inter/inter.key" ]]; then
    printf 'Erreur : une PKI existe déjà dans %s; choisir un nouveau PKI_DIR.\n' "$PKI_DIR" >&2
    exit 1
fi

mkdir -p "$PKI_DIR/root/certs" "$PKI_DIR/root/crl" "$PKI_DIR/root/newcerts" \
    "$PKI_DIR/inter/certs" "$PKI_DIR/inter/crl" "$PKI_DIR/inter/newcerts" \
    "$PKI_DIR/leaf"
install -m 600 "$SCRIPT_DIR/racine.cnf" "$PKI_DIR/racine.cnf"
install -m 600 "$SCRIPT_DIR/inter.cnf" "$PKI_DIR/inter.cnf"
: > "$PKI_DIR/root/index.txt"
: > "$PKI_DIR/inter/index.txt"
printf '1000\n' > "$PKI_DIR/root/serial"
printf '1000\n' > "$PKI_DIR/root/crlnumber"
printf '1000\n' > "$PKI_DIR/inter/serial"
printf '1000\n' > "$PKI_DIR/inter/crlnumber"

cd "$PKI_DIR"

printf '[1/6] Génération de l’AC racine P-384...\n'
"$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -out root/racine.key
"$OPENSSL_BIN" req -x509 -new -key root/racine.key -sha384 -days 3650 \
    -config racine.cnf -extensions ext_racine -out root/racine.crt
root_constraints="$("$OPENSSL_BIN" x509 -in root/racine.crt -noout \
    -ext basicConstraints)"
if [[ "$root_constraints" != *'CA:TRUE, pathlen:1'* ]]; then
    printf 'Erreur : CA:TRUE,pathlen:1 absent du certificat racine.\n' >&2
    exit 1
fi

printf '[2/6] Création et signature de l’AC intermédiaire P-256...\n'
"$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out inter/inter.key
MSYS_NO_PATHCONV=1 "$OPENSSL_BIN" req -new -key inter/inter.key \
    -subj '/C=BF/O=Universite TP/CN=AC intermediaire TP' \
    -out inter/inter.csr
"$OPENSSL_BIN" ca -batch -notext -config racine.cnf -extensions ext_inter \
    -days 1825 -in inter/inter.csr -out inter/inter.crt

intermediate_constraints="$("$OPENSSL_BIN" x509 -in inter/inter.crt -noout \
    -ext basicConstraints)"
intermediate_names="$("$OPENSSL_BIN" x509 -in inter/inter.crt -noout \
    -ext nameConstraints)"
if [[ "$intermediate_constraints" != *'CA:TRUE, pathlen:0'* ]]; then
    printf 'Erreur : pathlen:0 absent du certificat intermédiaire.\n' >&2
    exit 1
fi
if [[ "$intermediate_names" != *'DNS:tp.local'* || \
    "$intermediate_names" != *'DNS:.tp.local'* ]]; then
    printf 'Erreur : contraintes DNS tp.local incomplètes.\n' >&2
    exit 1
fi

printf '[3/6] Émission des certificats serveur, Alice et Bob...\n'
"$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out leaf/serveur.key
MSYS_NO_PATHCONV=1 "$OPENSSL_BIN" req -new -key leaf/serveur.key -subj '/CN=www.tp.local' \
    -addext 'subjectAltName=DNS:www.tp.local,DNS:tp.local' \
    -out leaf/serveur.csr
"$OPENSSL_BIN" ca -batch -notext -config inter.cnf -extensions ext_serveur \
    -days 90 -in leaf/serveur.csr -out leaf/serveur.crt

for client in alice bob; do
    "$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "leaf/$client.key"
    MSYS_NO_PATHCONV=1 "$OPENSSL_BIN" req -new -key "leaf/$client.key" \
        -subj "/CN=$client@tp.local" \
        -addext "subjectAltName=email:$client@tp.local" \
        -out "leaf/$client.csr"
    "$OPENSSL_BIN" ca -batch -notext -config inter.cnf -extensions ext_client \
        -days 90 -in "leaf/$client.csr" -out "leaf/$client.crt"
done

printf '[4/6] Vérification de la chaîne et des contraintes de noms...\n'
"$OPENSSL_BIN" verify -purpose sslserver -CAfile root/racine.crt -untrusted inter/inter.crt \
    -verify_hostname www.tp.local leaf/serveur.crt
"$OPENSSL_BIN" verify -purpose sslclient -CAfile root/racine.crt \
    -untrusted inter/inter.crt leaf/bob.crt
"$OPENSSL_BIN" verify -purpose sslclient -CAfile root/racine.crt \
    -untrusted inter/inter.crt leaf/alice.crt

"$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out leaf/hors-domaine.key
MSYS_NO_PATHCONV=1 "$OPENSSL_BIN" req -new -key leaf/hors-domaine.key -subj '/CN=www.example.com' \
    -addext 'subjectAltName=DNS:www.example.com' -out leaf/hors-domaine.csr
"$OPENSSL_BIN" ca -batch -notext -config inter.cnf -extensions ext_serveur \
    -days 90 -in leaf/hors-domaine.csr -out leaf/hors-domaine.crt
if error_output=$("$OPENSSL_BIN" verify -CAfile root/racine.crt \
    -untrusted inter/inter.crt -verify_hostname www.example.com \
    leaf/hors-domaine.crt 2>&1); then
    printf 'Erreur : le certificat hors domaine a été accepté.\n' >&2
    exit 1
elif [[ "$error_output" == *'permitted subtree violation'* ]]; then
    printf 'OK : le certificat hors domaine est rejeté par nameConstraints.\n'
else
    printf 'Erreur de validation inattendue pour le certificat hors domaine :\n%s\n' \
        "$error_output" >&2
    exit 1
fi

printf '[5/6] Révocation d’Alice et publication des CRL...\n'
"$OPENSSL_BIN" ca -batch -config inter.cnf -revoke leaf/alice.crt \
    -crl_reason keyCompromise
"$OPENSSL_BIN" ca -batch -config inter.cnf -gencrl -out inter/crl/inter.crl
"$OPENSSL_BIN" ca -batch -config racine.cnf -gencrl -out root/crl/racine.crl
cat inter/crl/inter.crl root/crl/racine.crl > crls.pem

printf '[6/6] Contrôle de la révocation...\n'
if error_output=$("$OPENSSL_BIN" verify -crl_check_all -CRLfile crls.pem \
    -CAfile root/racine.crt -untrusted inter/inter.crt leaf/alice.crt 2>&1); then
    printf 'Erreur : le certificat révoqué d’Alice a été accepté.\n' >&2
    exit 1
elif [[ "$error_output" == *'certificate revoked'* ]]; then
    printf 'OK : le certificat révoqué d’Alice est rejeté.\n'
else
    printf 'Erreur de validation inattendue pour le certificat d’Alice :\n%s\n' \
        "$error_output" >&2
    exit 1
fi

PUBLIC_DIR="$SCRIPT_DIR/public"
mkdir -p "$PUBLIC_DIR"
install -m 644 root/racine.crt "$PUBLIC_DIR/racine.crt"
install -m 644 inter/inter.crt "$PUBLIC_DIR/inter.crt"
install -m 644 leaf/serveur.crt leaf/alice.crt leaf/bob.crt \
    leaf/hors-domaine.crt "$PUBLIC_DIR/"
install -m 644 inter/crl/inter.crl root/crl/racine.crl crls.pem "$PUBLIC_DIR/"
cat leaf/serveur.crt inter/inter.crt > "$PUBLIC_DIR/serveur_chaine.crt"

printf '\nPKI prête dans %s\n' "$PKI_DIR"
printf 'Seuls des certificats et des CRL publics ont été copiés dans TP2/pki/public/.\n'
printf 'Les clés privées restent dans le répertoire de travail non versionné.\n'
