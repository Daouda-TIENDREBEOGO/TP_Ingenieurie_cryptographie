#!/usr/bin/env python3
"""Surveille les dates d'expiration des certificats PEM d'un dossier."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

CERTIFICATE_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
EXTENSIONS = {".crt", ".cer", ".pem"}


@dataclass(frozen=True)
class EtatCertificat:
    chemin: Path
    sujet: str
    jours_restants: int
    niveau: str


def _certificats_pem(chemin: Path) -> list[x509.Certificate]:
    contenu = chemin.read_bytes()
    blocs = CERTIFICATE_BLOCK.findall(contenu)
    if not blocs and chemin.suffix.lower() != ".pem":
        raise ValueError(f"Aucun certificat PEM dans {chemin}.")
    return [x509.load_pem_x509_certificate(bloc) for bloc in blocs]


def analyser_certificats(
    chemins: list[Path], maintenant: datetime
) -> list[EtatCertificat]:
    if maintenant.tzinfo is None:
        raise ValueError("L'horodatage de référence doit inclure un fuseau horaire.")
    etats: list[EtatCertificat] = []
    for chemin in chemins:
        for certificat in _certificats_pem(chemin):
            expiration = certificat.not_valid_after_utc
            jours = (expiration - maintenant).days
            niveau = "CRITIQUE" if jours < 7 else "ALERTE" if jours < 30 else "OK"
            etats.append(
                EtatCertificat(
                    chemin=chemin,
                    sujet=certificat.subject.rfc4514_string(),
                    jours_restants=jours,
                    niveau=niveau,
                )
            )
    return etats


def main(argv: list[str] | None = None, *, maintenant: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Affiche l'état de validité des certificats PEM d'un dossier."
    )
    parser.add_argument("dossier", type=Path, help="Dossier à analyser récursivement.")
    args = parser.parse_args(argv)
    if not args.dossier.is_dir():
        parser.error(f"Le dossier n'existe pas : {args.dossier}")

    chemins = sorted(
        chemin
        for chemin in args.dossier.rglob("*")
        if chemin.is_file() and chemin.suffix.lower() in EXTENSIONS
    )
    if not chemins:
        print(f"Aucun fichier de certificat trouvé dans {args.dossier}.", file=sys.stderr)
        return 2

    try:
        etats = analyser_certificats(
            chemins,
            maintenant or datetime.now(timezone.utc),
        )
    except (OSError, ValueError) as exc:
        print(f"Erreur de lecture des certificats : {exc}", file=sys.stderr)
        return 2
    if not etats:
        print(f"Aucun certificat PEM trouvé dans {args.dossier}.", file=sys.stderr)
        return 2

    for etat in etats:
        print(
            f"{etat.niveau:8} {etat.jours_restants:5} jour(s) "
            f"{etat.chemin} — {etat.sujet}"
        )
    if any(etat.niveau == "CRITIQUE" for etat in etats):
        return 2
    if any(etat.niveau == "ALERTE" for etat in etats):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
