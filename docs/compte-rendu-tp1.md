# Compte rendu — TP 1 : chiffrement authentifié et dérivation de clés

## Objectif et livrables

Le module [`coffre.py`](../coffre.py) protège des octets avec Argon2id, HKDF-SHA256 et
AES-256-GCM. Il stocke les paramètres nécessaires au déchiffrement dans un format versionné,
lie le nom du fichier au chiffré et expose une interface de fichier interactive. Les tests sont
dans [`tests/test_coffre.py`](../tests/test_coffre.py).

## Conception du format

| Position | Taille | Champ | Rôle |
|---:|---:|---|---|
| 0 | 4 | `CFR1` | Identifiant et version du format. |
| 4 | 12 | temps, mémoire, parallélisme | Trois entiers non signés big-endian pour Argon2id. |
| 16 | 16 | sel aléatoire | Une dérivation indépendante pour chaque fichier. |
| 32 | 12 | nonce aléatoire | Nonce AES-GCM de 96 bits. |
| 44 | variable | chiffré et étiquette | Résultat d'AES-GCM, incluant l'étiquette de 16 octets. |

Les paramètres de départ proposés dans le sujet sont `t=3`, `m=65536 Kio` et `p=4`. La mesure
sur cette machine étant inférieure à la cible, le coût temps a été ajusté à `t=10`, en conservant
`m=65536 Kio` et `p=4`. Les valeurs finales sont écrites dans chaque en-tête. Le code impose
des bornes à la lecture pour qu'un en-tête modifié ne puisse pas demander une allocation
mémoire ou un temps de calcul arbitraire. Argon2id produit une clé maîtresse de 32 octets;
HKDF-SHA256, avec `info = b"coffre-v1|fichier"`, produit la clé AES. Une nouvelle clé
maîtresse est calculée à partir du sel aléatoire de chaque fichier.

AES-GCM authentifie `en-tête complet || nom UTF-8`. Tout changement du nonce, des paramètres,
du texte chiffré, de l'étiquette ou du nom provoque le rejet du déchiffrement. Le mot de passe
n'est pas stocké. Les fonctions de bas niveau laissent remonter `InvalidTag`, tandis que la CLI
affiche un seul message d'échec pour ne pas révéler si le mot de passe, le nom ou le contenu est
en cause.

### Mesure du coût

La commande suivante permet de mesurer le coût avec les paramètres définitifs sur la machine
de remise; consigner plusieurs essais et leur médiane, car le résultat dépend du matériel et de
la charge :

```bash
python -c "from time import perf_counter; from coffre import cle_maitresse; s=b'x'*16; t=perf_counter(); cle_maitresse('mesure locale',s); print(f'{perf_counter()-t:.3f} s')"
```

Mesure de cette remise : avec `t=10`, `m=65536 Kio`, `p=4`, cinq dérivations ont pris entre
0,393 et 0,467 seconde; la médiane mesurée est 0,415 seconde. La cible de 0,5 seconde est donc
approchée sur cette machine. Les résultats varient avec le processeur et la charge; refaire
plusieurs essais sur la machine de remise et ajuster `t` si nécessaire. Le format versionné
permet de relever ultérieurement les paramètres de dérivation; les lecteurs doivent conserver
les bornes et les algorithmes pris en charge avant de modifier leur politique.

## Tests de sécurité

`python -m pytest -q` exécute des tests pour :

- le retour exact des données, y compris les données vides et UTF-8;
- la différence de deux chiffrés du même contenu (sel et nonce nouveaux);
- le refus du mauvais mot de passe (`InvalidTag`);
- le refus d'une modification du nonce authentifié;
- le refus d'un nom de fichier différent;
- le refus d'un identifiant de format inconnu et d'un fichier tronqué;
- le rechiffrement sous un nouveau mot de passe et le refus de l'ancien;
- le rejet des paramètres Argon2id hors des bornes définies.

## Questions de réflexion

1. **Pourquoi le sel est-il stocké en clair?**

   Le sel n'est pas un secret : il empêche les tables précalculées d'être réutilisées et fait
   dériver une clé différente pour chaque fichier. Le mot de passe reste le secret; publier le
   sel ne le révèle pas, mais un mot de passe faible reste attaquable hors ligne.

2. **Pourquoi la probabilité de réutiliser un nonce est-elle négligeable ici?**

   Le sel aléatoire fait dériver une clé différente par fichier; une collision de nonce entre
   fichiers distincts ne réutilise donc normalement pas la même paire clé/nonce. Les deux
   tirages aléatoires de 128 bits (sel) et de 96 bits (nonce) ont néanmoins une probabilité de
   collision non nulle : ce n'est pas une garantie mathématique d'unicité. Le sel de 128 bits
   rend une collision de clé entre des fichiers chiffrés avec le même mot de passe
   extrêmement improbable à l'échelle de millions de fichiers. Le nonce ne doit jamais être
   réutilisé avec une même clé AES-GCM.

3. **Que se passerait-il si le nom n'était pas dans les données associées?**

   Un attaquant pourrait renommer ou substituer des fichiers chiffrés sans que l'authentification
   lie le contenu à son nom attendu. Un programme qui associe les fichiers à leurs noms pourrait
   alors interpréter un contenu valide sous un contexte incorrect. L'AAD lie le nom, sans le
   chiffrer.

4. **Pourquoi authentifier l'en-tête?**

   Sans authentification, un tiers pourrait modifier les paramètres Argon2id, les faire baisser
   ou provoquer un coût excessif avant l'échec. Ici ils sont bornés pour limiter le déni de
   service, puis l'en-tête entier est authentifié par GCM. Le sel et les paramètres sont
   publics, mais leur intégrité reste nécessaire pour retrouver la bonne clé et protéger la
   politique de dérivation.

5. **Pourquoi ne pas afficher la cause précise d'un échec?**

   Différencier un mauvais mot de passe d'un fichier altéré crée un oracle qui aide à tester des
   mots de passe ou à cartographier des erreurs d'authentification. La CLI renvoie un message
   uniforme; les détails de diagnostic ne doivent pas être exposés à un utilisateur distant.

## Évolution du format

Le marqueur `CFR1` permet de distinguer explicitement les versions et les paramètres par
fichier. Pour faire évoluer la politique, une version future pourra définir de nouveaux champs
et limites, tout en gardant un lecteur compatible pour les anciennes versions. La fonction
`rechiffrer(ancien_mdp, nouveau_mdp, nom, blob)` déchiffre, puis chiffre à nouveau avec un
sel, un nonce et les paramètres par défaut neufs; elle ne modifie jamais le blob en place.

## Limites et consignes de remise

Le fichier CFR1 ne contient pas son nom d'origine : il faut fournir le même nom UTF-8 au
déchiffrement. La CLI le demande explicitement. Les paramètres de production doivent être
mesurés sur la machine cible, et un mot de passe fort reste indispensable. Ne déposer dans Git
ni mot de passe, ni fichier en clair confidentiel, ni exemple contenant des données privées.
