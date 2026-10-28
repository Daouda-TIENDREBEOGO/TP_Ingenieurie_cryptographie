#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${PKI_DIR:-"$SCRIPT_DIR/work"}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
cd "$PKI_DIR"

for file in root/racine.crt inter/inter.crt leaf/serveur.crt leaf/alice.crt \
    leaf/bob.crt crls.pem; do
    if [[ ! -s "$file" ]]; then
        printf 'Fichier requis absent ou vide : %s/%s\n' "$PKI_DIR" "$file" >&2
        exit 1
    fi
done

printf '[1/5] Nom DNS du serveur...\n'
"$OPENSSL_BIN" verify -purpose sslserver -CAfile root/racine.crt -untrusted inter/inter.crt \
    -verify_hostname www.tp.local leaf/serveur.crt

printf '[2/5] Refus du mauvais nom DNS...\n'
if error_output=$("$OPENSSL_BIN" verify -CAfile root/racine.crt \
    -untrusted inter/inter.crt -verify_hostname autre.example \
    leaf/serveur.crt 2>&1); then
    printf 'Échec : le nom DNS incorrect a été accepté.\n' >&2
    exit 1
elif [[ "$error_output" == *'hostname mismatch'* ]]; then
    printf '%s\n' "$error_output"
else
    printf 'Échec inattendu du contrôle de nom DNS :\n%s\n' "$error_output" >&2
    exit 1
fi

printf '[3/5] Usage client de Bob...\n'
"$OPENSSL_BIN" verify -purpose sslclient -CAfile root/racine.crt \
    -untrusted inter/inter.crt leaf/bob.crt

printf '[4/5] Refus du certificat révoqué d’Alice...\n'
if error_output=$("$OPENSSL_BIN" verify -crl_check_all -CRLfile crls.pem \
    -CAfile root/racine.crt -untrusted inter/inter.crt \
    leaf/alice.crt 2>&1); then
    printf 'Échec : le certificat révoqué a été accepté.\n' >&2
    exit 1
elif [[ "$error_output" == *'certificate revoked'* ]]; then
    printf '%s\n' "$error_output"
else
    printf 'Échec inattendu du contrôle de révocation :\n%s\n' "$error_output" >&2
    exit 1
fi

printf '[5/5] Extensions de l’AC intermédiaire...\n'
"$OPENSSL_BIN" x509 -in inter/inter.crt -noout -ext basicConstraints
"$OPENSSL_BIN" x509 -in inter/inter.crt -noout -ext nameConstraints
printf 'Vérifications terminées : les refus ci-dessus sont les résultats attendus.\n'
