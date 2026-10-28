from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from TP3.surveiller import main


def _creer_certificat(expiration: datetime) -> bytes:
    maintenant = datetime.now(timezone.utc)
    cle = ec.generate_private_key(ec.SECP256R1())
    sujet = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.tp.local")])
    certificat = (
        x509.CertificateBuilder()
        .subject_name(sujet)
        .issuer_name(sujet)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - timedelta(days=1))
        .not_valid_after(expiration)
        .sign(cle, hashes.SHA256())
    )
    return certificat.public_bytes(Encoding.PEM)


def test_codes_de_sortie_selon_les_seuils(tmp_path):
    maintenant = datetime.now(timezone.utc)
    dossier = tmp_path / "certificats"
    dossier.mkdir()

    (dossier / "ok.crt").write_bytes(
        _creer_certificat(maintenant + timedelta(days=40))
    )
    assert main([str(dossier)], maintenant=maintenant) == 0

    (dossier / "alerte.crt").write_bytes(
        _creer_certificat(maintenant + timedelta(days=20))
    )
    assert main([str(dossier)], maintenant=maintenant) == 1

    (dossier / "critique.crt").write_bytes(
        _creer_certificat(maintenant + timedelta(days=5))
    )
    assert main([str(dossier)], maintenant=maintenant) == 2


def test_un_bundle_pem_est_parcouru_certificat_par_certificat(tmp_path):
    maintenant = datetime.now(timezone.utc)
    dossier = tmp_path / "certificats"
    dossier.mkdir()
    bloc_ok = _creer_certificat(maintenant + timedelta(days=40))
    bloc_alerte = _creer_certificat(maintenant + timedelta(days=20))
    (dossier / "chaine.pem").write_bytes(bloc_ok + bloc_alerte)
    assert main([str(dossier)], maintenant=maintenant) == 1


def test_un_dossier_sans_certificat_est_signale(tmp_path):
    assert main([str(tmp_path)]) == 2
