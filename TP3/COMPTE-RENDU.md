# Compte rendu — TP 3 : canal sécurisé et gestion des certificats

## Configuration et objectif

Le bloc [`nginx/ec1.conf`](./nginx/ec1.conf) active TLS 1.2 et 1.3, exige un certificat client,
vérifie la chaîne jusqu'à la racine de laboratoire, contrôle la CRL et envoie un en-tête HSTS.
Le serveur doit présenter le certificat de `www.tp.local` suivi de l'intermédiaire, jamais la
racine. Le client de test est Bob, émis par l'intermédiaire; Alice a été révoquée au TP 2.

Les directives principales :

- `ssl_certificate` fournit la chaîne serveur/AC intermédiaire; `ssl_certificate_key` désigne
  la clé correspondante.
- `ssl_protocols TLSv1.2 TLSv1.3` exclut TLS 1.1 et les versions plus anciennes.
- `ssl_ciphers` limite TLS 1.2 à des suites ECDHE avec authentification ECDSA et chiffrement
  AEAD (AES-GCM ou ChaCha20-Poly1305), donc sans suites CBC ni échange statique. La sélection
  des suites TLS 1.3 reste celle des valeurs sûres par défaut d'OpenSSL.
- `ssl_session_tickets off` évite des tickets dont les clés de protection n'auraient pas été
  renouvelées.
- `ssl_client_certificate`, `ssl_verify_client on` et `ssl_verify_depth 2` imposent et valident
  l'identité client.
- `ssl_crl` fournit les listes de révocation; leur mise à jour régulière est indispensable.
- `Strict-Transport-Security` demande au navigateur de revenir en HTTPS pour cet hôte pendant
  un an. Il est envoyé uniquement depuis le serveur HTTPS.
- `$ssl_client_s_dn` rend visible le sujet client validé pour le TP; une application réelle ne
  doit pas utiliser une chaîne de sujet brute comme unique autorisation métier.

## Mise en place et essais

Après création de la PKI, sur une machine Linux de laboratoire :

```bash
sudo install -d -m 700 /etc/nginx/tls
sudo install -m 600 TP2/pki/work/leaf/serveur.key /etc/nginx/tls/serveur.key
cat TP2/pki/work/leaf/serveur.crt TP2/pki/work/inter/inter.crt > /tmp/serveur_chaine.crt
sudo install -m 644 /tmp/serveur_chaine.crt TP2/pki/work/root/racine.crt \
  TP2/pki/work/crls.pem /etc/nginx/tls/
sudo install -m 644 TP3/nginx/ec1.conf /etc/nginx/sites-available/ec1
sudo ln -s /etc/nginx/sites-available/ec1 /etc/nginx/sites-enabled/ec1
echo '127.0.0.1 www.tp.local' | sudo tee -a /etc/hosts
sudo nginx -t
sudo systemctl reload nginx
```

La création du lien symbolique et l'ajout dans `hosts` ne doivent se faire qu'une fois; inspecter
le fichier avant de le modifier. Émettre un nouveau certificat pour Bob si sa clé/certificat
n'est pas disponible dans la PKI réutilisée :

```bash
cd TP2/pki/work
openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -verify_hostname www.tp.local -CAfile root/racine.crt \
  -cert leaf/bob.crt -key leaf/bob.key -cert_chain inter/inter.crt -brief
cat leaf/bob.crt inter/inter.crt > /tmp/bob_chaine.crt
curl --cacert root/racine.crt --cert /tmp/bob_chaine.crt --key leaf/bob.key \
  https://www.tp.local/
```

Sans certificat client, la négociation doit échouer à l'étape d'authentification client.
Avec Alice et la CRL chargée, la connexion doit être refusée pour certificat révoqué. Pour
tester TLS 1.1, utiliser `openssl s_client -connect www.tp.local:443 -tls1_1 -brief` : la
connexion doit échouer. La capture Wireshark doit être faite pendant ces essais sur la
machine de laboratoire; consigner la version, la suite, le groupe d'échange et le résultat de
validation réellement observés. Ne pas inventer de capture ou de suite négociée.
Pour `curl`, présenter le certificat client et son intermédiaire concaténés dans un fichier PEM;
avec le seul certificat feuille, certains clients n'envoient pas l'intermédiaire requis par
nginx.

Pour tester le refus de la cliente révoquée avec `curl`, lui fournir aussi la chaîne :

```bash
cat leaf/alice.crt inter/inter.crt > /tmp/alice_chaine.crt
curl --cacert root/racine.crt --cert /tmp/alice_chaine.crt --key leaf/alice.key \
  https://www.tp.local/
```

Cette connexion doit échouer. Autres contrôles négatifs :

```bash
openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -CAfile root/racine.crt -brief
openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -CAfile root/racine.crt -cert leaf/alice.crt -key leaf/alice.key \
  -cert_chain inter/inter.crt -brief
nmap --script ssl-enum-ciphers -p 443 www.tp.local
```

Le premier essai ne présente aucun certificat client; le second présente le certificat révoqué
d'Alice. Nmap doit seulement sonder le serveur de laboratoire : les suites TLS 1.2 affichées
doivent utiliser échange ECDHE et chiffrement AEAD; TLS 1.1 doit rester indisponible.

En TLS 1.3, les messages postérieurs à `ServerHello`, dont le certificat serveur, sont chiffrés
dans la poignée de main. Une capture passive sans secrets de session montre donc le
`ClientHello` et le `ServerHello`, mais ne permet pas de lire le certificat. En TLS 1.2, le
certificat du serveur est visible dans une poignée de main complète avant le passage aux clés
de trafic.

### Résultats du test sous WSL

Avec Ubuntu 26.04, nginx 1.28.3 et OpenSSL 3.5.5, la configuration de ce fichier a été testée
dans une instance nginx temporaire sur le port `18443`; seules les adresses des certificats et
le port d'écoute ont été adaptés. La configuration passe `nginx -t`. Bob est accepté en TLS
1.2 (`ECDHE-ECDSA-AES256-GCM-SHA384`) et en TLS 1.3 (`TLS_AES_256_GCM_SHA384`), avec
vérification de la chaîne réussie; la réponse HSTS est présente. Un client sans certificat et
Alice après révocation sont refusés, et TLS 1.1 n'est pas négociable. Le test utilisait les
certificats et clés générés dans un répertoire temporaire, puis supprimé. L'instance nginx
temporaire a été arrêtée sans modifier le service nginx ni ses sites existants.

## Supervision des certificats

[`surveiller.py`](./surveiller.py) parcourt un dossier récursivement et lit un ou plusieurs
certificats dans chaque fichier PEM :

- `OK` si tous expirent dans au moins 30 jours : code `0`;
- `ALERTE` si l'un expire dans moins de 30 jours : code `1`;
- `CRITIQUE` si l'un expire dans moins de 7 jours, ou en cas d'erreur d'entrée : code `2`.

Exemple depuis la racine : `python TP3/surveiller.py TP2/pki/public`. L'ordre des contrôles donne priorité au niveau
critique. Un certificat déjà expiré a un nombre de jours négatif et est donc critique. Les tests
automatiques créent des certificats éphémères pour vérifier les trois codes sans attendre une
expiration réelle.

## Renouvellement automatisé

[`renouveler.sh`](./renouveler.sh) sort sans changement si le certificat serveur a
encore au moins 30 jours. Sinon il génère une nouvelle clé P-256 et une CSR, fait signer la CSR
par l'AC intermédiaire, vérifie chaîne et nom DNS, puis installe la chaîne et la clé. Il conserve
les anciens fichiers dans `archive/`, exécute `nginx -t`, recharge le service et tente un
retour arrière si le déploiement échoue.

Le cycle de génération, signature, validation de chaîne, archivage et remplacement a été testé
avec OpenSSL réel et des commandes factices à la place de nginx/systemd; le serveur nginx n'a
pas été exécuté dans cet environnement. Le planificateur peut lancer le script quotidiennement
sous un compte d'administration, mais
il ne faut activer le minuteur qu'après avoir testé les permissions, le retour arrière, l'accès à
la base de l'AC et l'envoi d'alertes. La clé de l'intermédiaire est un secret de CA et doit être
protégée plus fortement que le compte de service nginx; la confier au serveur web pour que le
renouvellement fonctionne automatiquement serait un choix d'architecture risqué. En
production, séparer l'émetteur du serveur et authentifier le canal de renouvellement.
Un essai de panne simulant un rechargement refusé a confirmé par empreinte que la clé et la
chaîne précédentes sont restaurées. Le faux service refusant aussi le rechargement de retour
arrière, le script a correctement demandé un contrôle manuel; la reprise nginx réelle reste à
valider sur la VM.

## Questions de réflexion

1. **Pourquoi ne pas envoyer le certificat racine?**

   La racine doit déjà être installée comme ancre de confiance par le client. L'envoyer ne la
   rend pas digne de confiance; cela ajoute un certificat redondant et masque parfois une
   mauvaise configuration de chaîne.

2. **Pourquoi désactiver les tickets de session si les clés de tickets ne tournent pas?**

   Des clés de tickets durables augmentent la durée d'exposition si elles fuient et compliquent
   leur rotation. Désactiver les tickets évite de prétendre offrir une gestion de reprise de
   session sûre quand la rotation et la protection des clés ne sont pas opérationnelles.

3. **Que garantit HSTS?**

   Après réception de l'en-tête HTTPS, un navigateur compatible transforme les accès suivants
   en HTTPS pendant la durée annoncée. Il réduit les attaques de rétrogradation et le
   détournement HTTP (« SSL stripping ») pour cet hôte; il ne protège pas la première visite
   avant réception de la politique, sauf préchargement HSTS.

4. **Quel effet ont des certificats publics de durée plus courte?**

   Une organisation qui renouvelle à la main risque plus d'expirations, d'interruptions et
   d'erreurs de déploiement. Elle doit automatiser l'inventaire, les alertes, l'émission, le
   déploiement avec contrôle et le retour arrière. Les échéances citées dans le sujet sont à
   vérifier auprès de la politique de l'autorité compétente au moment de leur mise en œuvre.

5. **Pourquoi des clients réagissent-ils différemment à une chaîne incomplète?**

   Certains possèdent déjà l'intermédiaire en cache ou tentent de le récupérer par un mécanisme
   AIA; d'autres ne le font pas, n'ont pas accès au réseau ou appliquent des règles plus strictes.
   Le serveur doit envoyer le certificat feuille et les intermédiaires nécessaires.

6. **Procédure si la clé privée du serveur fuit.**

   Isoler le serveur et ouvrir un incident; révoquer immédiatement le certificat et publier les
   CRL; générer une nouvelle clé sur un système maîtrisé; émettre un nouveau certificat après
   vérification du SAN et de la chaîne; déployer de façon atomique et tester; invalider les
   sessions/tickets concernés; analyser journaux et sauvegardes, déterminer l'étendue de la
   fuite et informer les responsables; surveiller la nouvelle empreinte et documenter les
   mesures correctives. Si une clé d'AC a aussi été exposée, appliquer le plan de réponse PKI
   correspondant plutôt que de simplement renouveler la feuille.

## Éléments à compléter après l'essai sur la VM

Inscrire dans la version remise la version TLS et la suite réellement observées pour Bob, le
résultat pour Alice, le rejet TLS 1.1, ainsi qu'une capture Wireshark annotée. Les certificats
et la configuration présents dans le dépôt permettent de reproduire ces observations, mais
aucune donnée de capture n'est fabriquée à la place de l'exécution.
