# Compte rendu — TP 2 : infrastructure de gestion de clés

## Architecture réalisée

Le script [`pki/pki.sh`](./pki/pki.sh) crée une autorité de certification racine P-384 valide
10 ans, conservée dans l'espace de travail privé, puis une autorité intermédiaire P-256 valide
5 ans avec `CA:TRUE,pathlen:0` et des contraintes DNS limitées à `tp.local`. L'intermédiaire
émet des certificats P-256 de 90 jours pour `www.tp.local`, Alice et Bob. Les certificats et
listes de révocation publiés dans [`pki/public/`](./pki/public/) ne contiennent aucune clé
privée. Tous les états privés de l'AC sont créés dans `TP2/pki/work/`, exclu du dépôt.

**Limite de la maquette :** pour rendre le script autonome, la clé racine est générée sur la
même machine que l'intermédiaire et n'est pas réellement hors ligne. Ce n'est pas le modèle
de déploiement recommandé. En exploitation, créer la racine sur un support/système hors ligne,
la protéger séparément, et ne transférer à l'émetteur que le certificat racine public et les
éléments contrôlés nécessaires à l'émission. Protéger également la clé intermédiaire; le
script de TP ne constitue pas un HSM ni une politique de séparation des rôles. Pour simplifier
les tests automatisés, les clés générées ne sont pas chiffrées par phrase secrète; `umask 077`
les protège contre les autres comptes locaux, mais ne protège pas un disque ou une sauvegarde
volés. Ne réutiliser cette configuration qu'en laboratoire.

## Extensions essentielles

- **AC racine (`ext_racine`)** : `basicConstraints=critical,CA:TRUE,pathlen:1` autorise une
  seule AC subordonnée; `keyUsage=critical,keyCertSign,cRLSign` limite la clé à la signature
  de certificats et de CRL; `subjectKeyIdentifier=hash` fournit un identifiant stable.
- **AC intermédiaire (`ext_inter`)** : `CA:TRUE,pathlen:0` autorise des certificats feuilles,
  mais aucune nouvelle AC subordonnée; `keyUsage` conserve les usages de CA; les identifiants
  SKI/AKI relient les certificats; `nameConstraints` limite la validation des noms DNS à
  `tp.local` et à ses sous-domaines.
- **Certificat serveur (`ext_serveur`)** : `CA:FALSE` interdit l'usage comme CA;
  `digitalSignature` autorise la signature de la poignée de main TLS; `extendedKeyUsage` vaut
  `serverAuth`; SAN est copié de la CSR, et le client vérifie `www.tp.local` contre ce SAN.
- **Certificat client (`ext_client`)** : les mêmes contraintes de feuille, mais EKU vaut
  `clientAuth`; les SAN e-mail distinguent les identités de laboratoire.
- **CRL** : `authorityKeyIdentifier` identifie l'émetteur de la liste; la base de l'AC conserve
  les numéros de série et motifs révoqués.

Le script de vérification [`pki/verifications.sh`](./pki/verifications.sh) rejoue les contrôles
de chaîne, nom d'hôte, usage client et révocation. Le script de génération émet aussi un
certificat pour `www.example.com` : la signature prouve que la CA a signé la demande, mais la
validation du chemin doit le rejeter en raison de la contrainte de nom. OpenSSL `ca` copie les
extensions demandées par la CSR; une contrainte X.509 s'applique lors de la validation de la
chaîne et ne constitue pas, à elle seule, une politique d'émission au moment de la signature.
Une CA de production doit valider les identités et les noms avant de signer.

## Reproduction

```bash
openssl version
bash TP2/pki/pki.sh
bash TP2/pki/verifications.sh
```

OpenSSL doit afficher une version majeure 3. Les commandes de génération créent des clés
privées uniquement dans `TP2/pki/work/`. Les sorties de vérification attendues comprennent
`OK` pour le serveur, Bob et Alice avant vérification de CRL; un échec de nom pour un hôte
incorrect; un échec de sous-arbre autorisé pour le certificat hors domaine; et `certificate
revoked` pour Alice avec la CRL. Les refus contrôlés sont des résultats positifs du test.

Exécution de cette remise avec OpenSSL 3.5.6 : la chaîne serveur et l'usage client de Bob sont
valides; l'hôte incorrect échoue avec `hostname mismatch`; l'AC signe bien le certificat hors
domaine, mais sa validation échoue avec `permitted subtree violation`; après publication des
CRL, Alice échoue avec `certificate revoked`. L'intermédiaire affiche `CA:TRUE, pathlen:0` et
les deux sous-arbres DNS attendus. Alice est également valide avant sa révocation.

Pour le certificat racine, le sujet et l'émetteur sont identiques parce que la racine est
auto-signée : elle signe son propre certificat et constitue l'ancre de confiance installée par
les clients. Les certificats feuilles ne deviennent pas fiables par le seul fait qu'ils sont
auto-signés; la confiance provient de la racine configurée chez le vérificateur.

## Questions de réflexion

1. **Pourquoi garder la clé racine hors ligne? Que faire en cas de compromission?**

   La racine peut certifier toute la hiérarchie. La garder hors ligne réduit son exposition et
   limite son utilisation aux opérations rares, notamment signer une AC intermédiaire ou sa
   révocation. Si l'intermédiaire est compromis, la racine révoque son certificat, publie une
   CRL, puis signe une nouvelle AC et les feuilles sont réémises. Si la racine est compromise,
   il faut créer et distribuer un nouvel ancrage de confiance; la révocation par la racine
   compromise ne rétablit pas la confiance.

2. **À quoi sert `pathlen:0`?**

   Il interdit à l'intermédiaire de signer une autre AC subordonnée. Sans cette limite, une
   chaîne non prévue pourrait introduire une nouvelle autorité, étendre les délégations et
   rendre la gouvernance de la hiérarchie moins contrôlable.

3. **Pourquoi le serveur génère-t-il sa propre clé privée?**

   La clé ne quitte pas le serveur : la CSR ne transmet que la clé publique, l'identité demandée
   et une preuve de possession. Si l'AC générait les clés, elle devrait transporter et protéger
   des secrets clients, ce qui élargirait fortement le risque de compromission.

4. **CN ou SAN pour le nom d'hôte?**

   Les clients modernes vérifient les noms DNS dans `subjectAltName`; le CN n'est pas une
   solution de repli fiable. Le certificat serveur du laboratoire contient donc explicitement
   `DNS:www.tp.local` (et `DNS:tp.local`).

5. **Limites des CRL, OCSP et certificats courts.**

   Une CRL est périodiquement publiée, potentiellement volumineuse et périmée entre deux
   mises à jour; sa disponibilité et le comportement de repli du client comptent. OCSP interroge
   l'état en ligne mais expose des requêtes aux serveurs et dépend du répondeur; l'agrafage OCSP
   réduit ces appels côté client. Les certificats de courte durée réduisent la fenêtre de
   révocation, mais imposent une émission et un renouvellement automatisés fiables.

6. **Politique minimale de certification.**
   1. Seuls les responsables autorisés demandent un certificat pour un service ou une personne.
   2. L'identité et le droit d'utiliser le nom sont contrôlés hors bande par un responsable.
   3. La clé privée est générée et conservée par le demandeur; la CSR est signée.
   4. Les certificats feuilles sont limités à `tp.local`, à un rôle et à un usage EKU.
   5. Les certificats feuilles durent 90 jours; les renouvellements sont authentifiés.
   6. Les clés d'AC sont sous contrôle renforcé et l'AC racine reste hors ligne.
   7. Le numéro de série, le demandeur, l'approbateur et les dates sont journalisés.
   8. Toute clé suspectée compromise est révoquée sans délai et la CRL est republiée.
   9. Les clients vérifient la chaîne, le SAN, l'usage et l'état de révocation.
   10. Les clés, sauvegardes et journaux sensibles sont protégés et leur accès est audité.

## Résultats et limites

Le script automatise les opérations et les vérifications reproductibles, mais ne remplace pas
la revue humaine de l'identité et de l'autorisation d'émission. Les refus attendus doivent être
consignés avec leur raison OpenSSL lors de l'exécution sur Linux; un code d'échec seul ne
permet pas de distinguer un test négatif correct d'une erreur de configuration.
