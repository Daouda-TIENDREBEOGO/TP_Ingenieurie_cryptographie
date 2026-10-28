# Artefacts publics de la PKI

`pki/pki.sh` y copie les certificats publics et les CRL à la fin de chaque génération
complète. Ces fichiers servent à l'inspection et à la remise. Aucun fichier de clé privée,
de CSR ou de base de l'autorité ne doit y être copié.

Les fichiers sont générés localement avec OpenSSL 3; ils peuvent être recréés. Pour exploiter
l'AC ou renouveler un certificat, conserver le répertoire privé `pki/work/` hors de Git et
protéger ses clés selon la politique du laboratoire.
