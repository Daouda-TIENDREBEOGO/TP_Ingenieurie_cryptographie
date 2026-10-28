#!/usr/bin/env python3
"""Coffre de fichiers : Argon2id, HKDF-SHA256 et AES-256-GCM."""

from __future__ import annotations

import argparse
import getpass
import os
import struct
import sys
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"CFR1"
HEADER_FORMAT = ">4sIII"
HEADER_SIZE = 44
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

DEFAULT_TIME_COST = 10
DEFAULT_MEMORY_COST = 64 * 1024
DEFAULT_PARALLELISM = 4
MAX_TIME_COST = 10
MAX_MEMORY_COST = 256 * 1024
MAX_PARALLELISM = 8
MIN_MEMORY_COST = 64 * 1024


class FormatError(ValueError):
    """Le fichier ne respecte pas un format CFR1 reconnu."""


def _validate_filename(nom: str) -> bytes:
    if not isinstance(nom, str) or not nom:
        raise ValueError("Le nom du fichier doit être une chaîne non vide.")
    encoded = nom.encode("utf-8")
    if len(encoded) > 4096:
        raise ValueError("Le nom du fichier est trop long.")
    return encoded


def _validate_parameters(temps: int, memoire: int, parallelisme: int) -> None:
    if not 3 <= temps <= MAX_TIME_COST:
        raise FormatError("Paramètre Argon2id temps hors limites.")
    if not MIN_MEMORY_COST <= memoire <= MAX_MEMORY_COST:
        raise FormatError("Paramètre Argon2id mémoire hors limites.")
    if not 1 <= parallelisme <= MAX_PARALLELISM or memoire < 8 * parallelisme:
        raise FormatError("Paramètre Argon2id parallélisme hors limites.")


def cle_maitresse(
    mot_de_passe: str,
    sel: bytes,
    *,
    temps: int = DEFAULT_TIME_COST,
    memoire: int = DEFAULT_MEMORY_COST,
    parallelisme: int = DEFAULT_PARALLELISM,
) -> bytes:
    """Dérive une clé maîtresse de 32 octets avec Argon2id."""
    if not isinstance(mot_de_passe, str) or not mot_de_passe:
        raise ValueError("Le mot de passe doit être une chaîne non vide.")
    if not isinstance(sel, bytes) or len(sel) != SALT_SIZE:
        raise ValueError("Le sel Argon2id doit contenir exactement 16 octets.")
    _validate_parameters(temps, memoire, parallelisme)
    return hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"),
        salt=sel,
        time_cost=temps,
        memory_cost=memoire,
        parallelism=parallelisme,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """Dérive une sous-clé distincte pour un usage donné."""
    if not isinstance(maitresse, bytes) or len(maitresse) != KEY_SIZE:
        raise ValueError("La clé maîtresse doit contenir exactement 32 octets.")
    if not isinstance(usage, bytes) or not usage:
        raise ValueError("L'étiquette d'usage doit être une chaîne d'octets non vide.")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=b"coffre-v1|" + usage,
    ).derive(maitresse)


def _parametres_defaut() -> tuple[int, int, int]:
    return DEFAULT_TIME_COST, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM


def chiffrer(
    mot_de_passe: str,
    nom: str,
    donnees: bytes,
    *,
    parametres: tuple[int, ...] | None = None,
) -> bytes:
    """Chiffre des octets et lie le nom du fichier à l'authentification."""
    nom_bytes = _validate_filename(nom)
    if not isinstance(donnees, bytes):
        raise TypeError("Les données à chiffrer doivent être des octets.")
    if parametres is None:
        parametres = _parametres_defaut()
    if len(parametres) != 3:
        raise ValueError("Les paramètres Argon2id doivent être (temps, mémoire, parallélisme).")
    temps, memoire, parallelisme = parametres
    _validate_parameters(temps, memoire, parallelisme)

    sel = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    entete = struct.pack(HEADER_FORMAT, MAGIC, temps, memoire, parallelisme) + sel + nonce
    maitresse = cle_maitresse(
        mot_de_passe,
        sel,
        temps=temps,
        memoire=memoire,
        parallelisme=parallelisme,
    )
    cle = sous_cle(maitresse, b"fichier")
    chiffre = AESGCM(cle).encrypt(nonce, donnees, entete + nom_bytes)
    return entete + chiffre


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    """Déchiffre un fichier CFR1; AESGCM rejette tout écart authentifié."""
    nom_bytes = _validate_filename(nom)
    if not isinstance(blob, bytes) or len(blob) < HEADER_SIZE + 16:
        raise FormatError("Fichier chiffré tronqué ou invalide.")

    entete = blob[:HEADER_SIZE]
    magic, temps, memoire, parallelisme = struct.unpack(HEADER_FORMAT, entete[:16])
    if magic != MAGIC:
        raise FormatError("Identifiant de format inconnu.")
    _validate_parameters(temps, memoire, parallelisme)
    sel = entete[16:32]
    nonce = entete[32:44]
    maitresse = cle_maitresse(
        mot_de_passe,
        sel,
        temps=temps,
        memoire=memoire,
        parallelisme=parallelisme,
    )
    cle = sous_cle(maitresse, b"fichier")
    return AESGCM(cle).decrypt(nonce, blob[HEADER_SIZE:], entete + nom_bytes)


def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    """Déchiffre puis chiffre à nouveau avec un sel et un nonce neufs."""
    donnees = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(nouveau_mdp, nom, donnees)


def _creer_fichier_exclusif(chemin: Path, donnees: bytes) -> None:
    cree = False
    try:
        with chemin.open("xb") as fichier:
            cree = True
            fichier.write(donnees)
    except OSError:
        if cree:
            chemin.unlink(missing_ok=True)
        raise


def _main() -> int:
    parser = argparse.ArgumentParser(description="Chiffrer ou déchiffrer un fichier avec CFR1.")
    commandes = parser.add_subparsers(dest="commande", required=True)
    chiffrement = commandes.add_parser("chiffrer", help="Chiffrer un fichier.")
    chiffrement.add_argument("source", type=Path)
    chiffrement.add_argument("-o", "--sortie", type=Path)
    dechiffrement = commandes.add_parser("dechiffrer", help="Déchiffrer un fichier CFR1.")
    dechiffrement.add_argument("source", type=Path)
    dechiffrement.add_argument("--nom-original", required=True, help="Nom utilisé lors du chiffrement.")
    dechiffrement.add_argument("-o", "--sortie", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.commande == "chiffrer":
            mot_de_passe = getpass.getpass("Mot de passe : ")
            confirmation = getpass.getpass("Confirmer le mot de passe : ")
            if mot_de_passe != confirmation:
                parser.error("Les mots de passe ne correspondent pas.")
            sortie = args.sortie or args.source.with_name(args.source.name + ".cfr")
            blob = chiffrer(mot_de_passe, args.source.name, args.source.read_bytes())
            _creer_fichier_exclusif(sortie, blob)
        else:
            mot_de_passe = getpass.getpass("Mot de passe : ")
            donnees = dechiffrer(
                mot_de_passe,
                args.nom_original,
                args.source.read_bytes(),
            )
            _creer_fichier_exclusif(args.sortie, donnees)
    except (InvalidTag, FormatError):
        print("Échec du déchiffrement : fichier, nom ou mot de passe incorrect.", file=sys.stderr)
        return 2
    except FileExistsError as exc:
        print(f"Le fichier de sortie existe déjà : {exc.filename}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Erreur de fichier : {exc}", file=sys.stderr)
        return 2

    print(f"Fichier écrit : {sortie if args.commande == 'chiffrer' else args.sortie}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
