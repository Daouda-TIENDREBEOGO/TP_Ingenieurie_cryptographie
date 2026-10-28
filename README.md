# EC1 — Ingénierie de la cryptographie

Ce dépôt contient les livrables des trois TP du module EC1. **Commencez par le dossier du TP
que vous souhaitez évaluer : son code, ses tests et son compte rendu sont regroupés ensemble.**

## Plan du dépôt

```text
TP1/
  COMPTE-RENDU.md      Explications et réponses aux questions du TP 1
  coffre.py            Coffre de fichiers chiffrés
  tests/test_coffre.py Tests du format, du chiffrement et du rechiffrement
TP2/
  COMPTE-RENDU.md           Architecture, validations et réponses aux questions
  pki/
    racine.cnf, inter.cnf   Profils et paramètres OpenSSL
    pki.sh                  Création des AC, certificats et CRL
    verifications.sh        Vérifications positives et négatives
    public/                 Certificats et CRL publics reproductibles
TP3/
  COMPTE-RENDU.md       Mise en œuvre TLS, essais et réponses aux questions
  nginx/ec1.conf        Configuration du serveur TLS avec mTLS
  surveiller.py         Surveillance des dates d'expiration
  renouveler.sh         Renouvellement et retour arrière
  tests/test_surveiller.py
requirements.txt        Dépendances Python communes aux TP
```

Le **TP 3 réutilise la PKI du TP 2**. Les clés privées et l'état de l'autorité sont générés
localement dans `TP2/pki/work/`, dossier ignoré par Git. Ils ne font pas partie du dépôt et ne
doivent pas être publiés. Les certificats et listes de révocation dans `TP2/pki/public/` sont
des fichiers publics d'exemple.

## Prérequis

- Python 3.10 ou plus récent.
- OpenSSL 3 pour le TP 2 et les essais TLS.
- Linux, une VM Linux ou WSL2 Ubuntu pour les scripts PKI et le TP nginx.
- nginx pour exécuter le serveur du TP 3; `curl`, `nmap` et Wireshark pour les essais facultatifs.

## Installation et tests

Depuis la racine du dépôt, sous Windows/PowerShell :

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
```

Sous Linux/WSL, exécuter plutôt :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

Les tests sont rangés avec les TP qu'ils couvrent : `TP1/tests/` et `TP3/tests/`.

## TP 1 — Coffre de fichiers

Lire d'abord le [compte rendu du TP 1](TP1/COMPTE-RENDU.md), puis consulter
[`TP1/coffre.py`](TP1/coffre.py) et ses
[`tests`](TP1/tests/test_coffre.py).

Exécuter depuis la racine avec `python TP1/coffre.py`. Le programme demande le mot de passe de
manière interactive, sans l'afficher :

```text
python TP1/coffre.py chiffrer chemin/rapport.txt
python TP1/coffre.py dechiffrer chemin/rapport.txt.cfr --nom-original rapport.txt --sortie rapport-restaure.txt
```

Le fichier CFR1 commence par un en-tête de 44 octets et authentifie le nom d'origine avec
AES-GCM. La commande de déchiffrement doit donc recevoir exactement le même nom UTF-8.

## TP 2 — Infrastructure à clés publiques

Lire le [compte rendu du TP 2](TP2/COMPTE-RENDU.md), puis ouvrir le dossier
[`TP2/pki/`](TP2/pki/). Depuis la racine, dans Linux/WSL avec OpenSSL 3 :

```bash
openssl version
bash TP2/pki/pki.sh
bash TP2/pki/verifications.sh
```

Le script crée une AC racine P-384, une AC intermédiaire P-256 restreinte à `tp.local`, les
certificats de laboratoire et les listes de révocation. Il vérifie également le rejet d'un nom
hors domaine et du certificat révoqué d'Alice. La première exécution crée `TP2/pki/work/` et
ne remplace pas une autorité existante. Pour créer un autre laboratoire isolé, définir
`PKI_DIR` pour les **deux** commandes :

```bash
PKI_DIR="$PWD/TP2/pki/work-neuf" bash TP2/pki/pki.sh
PKI_DIR="$PWD/TP2/pki/work-neuf" bash TP2/pki/verifications.sh
```

Les scripts contrôlent OpenSSL 3 et les paramètres critiques. La génération complète est
automatisée pour le laboratoire; elle ne rend pas la clé racine « hors ligne ». Le compte rendu
explique cette limite et la séparation à prévoir en production.

## TP 3 — TLS, authentification client et supervision

Lire le [compte rendu du TP 3](TP3/COMPTE-RENDU.md), puis consulter
[`TP3/nginx/ec1.conf`](TP3/nginx/ec1.conf),
[`TP3/surveiller.py`](TP3/surveiller.py) et
[`TP3/renouveler.sh`](TP3/renouveler.sh). Ce TP dépend des certificats créés au TP 2.

Exemple de supervision des certificats publics :

```bash
python TP3/surveiller.py TP2/pki/public
echo $?
```

Codes de retour : `0` (tous les certificats expirent dans au moins 30 jours), `1` (au moins un
expire dans moins de 30 jours), `2` (au moins un expire dans moins de 7 jours ou une erreur
d'entrée). L'installation nginx et les commandes de démonstration sont décrites dans le compte
rendu du TP 3; exécutez-les uniquement sur votre machine de laboratoire.

Le renouvellement nécessite une PKI privée accessible et les droits d'administration sur le
serveur de laboratoire :

```bash
sudo env PKI_DIR="$PWD/TP2/pki/work" DEPLOY_DIR=/etc/nginx/tls \
  bash TP3/renouveler.sh
```

Le script vérifie la chaîne avant le déploiement, n'agit que lorsque le certificat expire dans
moins de 30 jours, conserve une sauvegarde et teste nginx avant son rechargement. Ne copiez pas
la clé racine ni l'état privé de l'AC sur un serveur web public. N'ajoutez un minuteur quotidien
qu'après avoir vérifié manuellement les droits, la rotation de l'AC, les alertes et le retour
arrière. Le compte rendu indique quelles vérifications doivent encore être faites sur la VM
(notamment la capture Wireshark et l'essai réel de nginx).

## Sécurité du dépôt

Avant de publier, vérifier les fichiers indexés :

```bash
git status --short
git check-ignore TP2/pki/work/root/racine.key
git ls-files '*.key' '*.csr' '*.p12' '*.pfx'
```

La dernière commande ne doit afficher aucun fichier. Ne versionnez aucune clé privée, CSR,
phrase secrète, sauvegarde de clé ou capture pouvant contenir des informations personnelles.
Les fichiers `TP2/pki/public/` ne contiennent que des certificats et CRL publics.
