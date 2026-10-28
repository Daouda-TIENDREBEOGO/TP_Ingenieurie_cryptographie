# Artefacts publics de la PKI

`TP2/pki/pki.sh` y copie les certificats publics et les CRL à la fin de chaque génération
complète. Ces fichiers servent à l'inspection et à la remise. Aucun fichier de clé privée,
de CSR ou de base de l'autorité ne doit y être copié.

Les fichiers sont générés localement avec OpenSSL 3; ils peuvent être recréés. Pour exploiter
l'AC, conserver le répertoire privé `TP2/pki/work/` hors de Git et protéger ses clés selon la
politique du laboratoire. Le TP 3 réutilise cet état local sans le copier dans son propre dossier.
