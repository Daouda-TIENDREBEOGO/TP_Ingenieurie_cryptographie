# EC1 — Ingénierie de la cryptographie

Solution documentée des trois travaux pratiques du module EC1 : chiffrement authentifié,
infrastructure de clés et déploiement d'un canal TLS avec authentification mutuelle.
Les comptes rendus expliquent les choix, les limites et les commandes de reproduction; les
sorties attendues sont distinguées des mesures et captures qui doivent être réalisées sur la
machine de laboratoire.

## Contenu

| Fichier ou dossier | Rôle |
|---|---|
| [`coffre.py`](./coffre.py) | Format CFR1, Argon2id, HKDF-SHA256, AES-256-GCM et commandes interactives. |
| [`tests/test_coffre.py`](./tests/test_coffre.py) | Tests des propriétés de confidentialité, intégrité et séparation des clés. |
| [`pki/`](./pki/) | Configurations OpenSSL et scripts de création, validation, révocation et renouvellement. |
| [`pki/public/`](./pki/public/) | Certificats et listes de révocation publics, sans clé privée. |
| [`nginx/ec1.conf`](./nginx/ec1.conf) | Hôte TLS 1.2/1.3 avec authentification mutuelle et contrôle de révocation. |
| [`surveiller.py`](./surveiller.py) | Supervision des dates d'expiration PEM (codes de sortie 0, 1, 2). |
| [`tests/test_surveiller.py`](./tests/test_surveiller.py) | Tests des seuils de supervision et des bundles PEM. |
| [`docs/compte-rendu-tp1.md`](./docs/compte-rendu-tp1.md) | Compte rendu et réponses aux questions du TP 1. |
| [`docs/compte-rendu-tp2.md`](./docs/compte-rendu-tp2.md) | Compte rendu et réponses aux questions du TP 2. |
| [`docs/compte-rendu-tp3.md`](./docs/compte-rendu-tp3.md) | Compte rendu et réponses aux questions du TP 3. |

## Prérequis

- Python 3.10 ou plus récent.
- OpenSSL 3 pour la PKI et les commandes TLS.
- Linux (machine, VM ou WSL2 Ubuntu) pour nginx et les scripts d'administration.
- nginx pour le TP 3; `curl` et Wireshark sont facultatifs pour les observations réseau.

Les scripts PKI vérifient explicitement qu'OpenSSL 3 est utilisé. Les clés privées, demandes
de signature et bases de l'autorité sont générées dans `pki/work/`, dossier ignoré par Git.
Ne copiez jamais de clé privée, de mot de passe ou de sauvegarde de clé dans le dépôt.

## 1. Installer et tester le coffre

Depuis la racine du dépôt :

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
```

Sous Linux/WSL, remplacez l'activation par `source .venv/bin/activate`.

Les mots de passe sont lus sans écho au clavier; ne les passez ni en argument, ni dans une
variable d'environnement, ni dans un fichier versionné :

```text
python coffre.py chiffrer chemin/rapport.txt
python coffre.py dechiffrer chemin/rapport.txt.cfr --nom-original rapport.txt --sortie rapport-restaure.txt
```

Le second appel doit recevoir exactement le nom UTF-8 employé au chiffrement. Le programme
refuse d'écraser un fichier existant. Le fichier CFR1 commence par un en-tête de 44 octets :
identifiant (4), paramètres Argon2id (12), sel (16) et nonce (12). L'en-tête et le nom du fichier
sont authentifiés comme données associées.

## 2. Construire et valider la PKI

Dans une distribution Linux/WSL avec OpenSSL 3 :

```bash
openssl version
bash pki/pki.sh
bash pki/verifications.sh
```

Le script crée une racine P-384 (10 ans), un intermédiaire P-256 (5 ans, `pathlen:0` et
contraintes DNS `tp.local`), un serveur et deux clients P-256 (90 jours), puis un certificat
hors domaine pour démontrer son rejet à la validation. Il révoque Alice et publie les CRL.
Les certificats/CRL publics reproductibles sont copiés dans `pki/public/`; les clés et bases
privées restent dans `pki/work/`. Pour rendre la création automatique et reproductible,
l'exercice génère toutefois la racine sur la même machine que l'intermédiaire : cela ne
constitue pas une séparation hors ligne. En production, créer et conserver la racine hors
ligne, puis ne transférer que son certificat public et les éléments requis pour signer
l'intermédiaire.

La première exécution crée une base d'autorité nouvelle et n'écrase pas les clés existantes.
Pour reconstruire un laboratoire vierge, choisir un autre emplacement, par exemple :

```bash
PKI_DIR="$PWD/pki/work-neuf" bash pki/pki.sh
PKI_DIR="$PWD/pki/work-neuf" bash pki/verifications.sh
```

Ne supprimez pas un répertoire de PKI contenant des clés utiles sans avoir prévu leur
sauvegarde hors ligne.

## 3. Configurer le serveur TLS et superviser

Sur une VM de laboratoire dédiée :

1. Installer nginx, puis copier la chaîne du serveur (certificat serveur suivi de
   l'intermédiaire), la clé du serveur, la racine publique et `crls.pem` vers
   `/etc/nginx/tls/`. La clé doit être lisible uniquement par le compte d'administration ou
   le compte nginx selon le modèle de permissions choisi.
2. Ajouter `127.0.0.1 www.tp.local` au fichier `/etc/hosts`.
3. Installer [`nginx/ec1.conf`](./nginx/ec1.conf) comme site nginx, puis exécuter
   `nginx -t` avant `systemctl reload nginx`.
4. Émettre ou importer le certificat de Bob dans l'environnement de laboratoire et tester avec
   `openssl s_client` et `curl` (exemples détaillés dans le compte rendu du TP 3).

Pour surveiller un dossier contenant des certificats PEM :

```bash
python surveiller.py pki/public
echo $?
```

Codes de retour : `0` (tous les certificats ont au moins 30 jours), `1` (au moins un certificat
expire dans moins de 30 jours), `2` (au moins un certificat expire dans moins de 7 jours,
dossier invalide ou erreur de lecture). Un bundle PEM contenant plusieurs certificats est
analysé certificat par certificat.

Le renouvellement automatique est volontairement séparé du script de création. Le script
ci-dessous est un scénario de laboratoire sur une machine isolée contenant nginx et l'état
privé de l'AC; ne copiez pas `pki/work/` sur un serveur web public :

```bash
sudo env PKI_DIR=/chemin/prive/vers/pki/work DEPLOY_DIR=/etc/nginx/tls \
  bash pki/renouveler.sh
```

Le script ne renouvelle qu'à moins de 30 jours de l'expiration, vérifie le nom DNS et la chaîne,
archive les anciens fichiers dans `/etc/nginx/tls/archive/`, teste nginx puis le recharge. En
cas d'échec après le début du déploiement, il tente de restaurer les anciens fichiers.
Planifiez-le quotidiennement avec un minuteur `systemd` ou cron seulement après un essai
manuel, une revue des droits et la vérification de la procédure de retour arrière.
Dans une architecture réelle, la racine reste hors ligne et l'émission se fait sur une machine
de CA protégée; seuls le certificat feuille et la clé serveur nécessaire sont ensuite transférés
à nginx par un canal authentifié.

Exemple de planification quotidienne dans la crontab administrateur de la VM de laboratoire
(adapter les chemins après vérification) :

```cron
0 3 * * * PKI_DIR=/opt/ec1/pki/work DEPLOY_DIR=/etc/nginx/tls /bin/bash /opt/ec1/pki/renouveler.sh >> /var/log/ec1-renouvellement.log 2>&1
```

## Résultats et reproductibilité

Lancer les tests Python avec `python -m pytest -q`. Les validations OpenSSL se rejouent avec
`pki/verifications.sh`. Les certificats d'exemple prouvent la chaîne, le nom de serveur, l'usage
client, la contrainte de nom et la révocation; ils ne remplacent pas une capture de poignée de
main faite sur le serveur de laboratoire. Le TP 3 précise les observations à consigner et les
limites de ce qui peut être affirmé sans cette capture.

## Sécurité et dépôt GitHub

Avant chaque commit, vérifier :

```bash
git status --short
git check-ignore pki/work/root/racine.key
git ls-files '*.key' '*.csr'
```

La dernière commande ne doit afficher aucun fichier. Les certificats et CRL sont des données
publiques; les clés privées, sauvegardes, mots de passe, bases de CA et captures pouvant
contenir des données personnelles ne le sont pas. Ajouter les fichiers du projet au dépôt
après revue, puis configurer le dépôt distant GitHub choisi. Aucun dépôt distant ni accès
GitHub n'étant fourni ici, ces fichiers ne sont pas publiés automatiquement.
