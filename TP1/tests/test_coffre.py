import pytest
from cryptography.exceptions import InvalidTag

from TP1.coffre import (
    HEADER_SIZE,
    FormatError,
    chiffrer,
    cle_maitresse,
    dechiffrer,
    rechiffrer,
    sous_cle,
)


def test_derivation_argon2id_retourne_32_octets():
    assert len(cle_maitresse("mot de passe fort", b"s" * 16)) == 32


def test_hkdf_separe_les_usages():
    maitresse = b"k" * 32
    assert sous_cle(maitresse, b"fichier") != sous_cle(maitresse, b"autre")


@pytest.mark.parametrize("donnees", [b"", b"contenu confidentiel", "été ☀".encode()])
def test_aller_retour(donnees):
    blob = chiffrer("mot de passe fort", "rapport.txt", donnees)
    assert len(blob) >= HEADER_SIZE + 16
    assert dechiffrer("mot de passe fort", "rapport.txt", blob) == donnees


def test_deux_chiffrements_du_meme_fichier_sont_differents():
    premier = chiffrer("mot de passe fort", "rapport.txt", b"meme contenu")
    second = chiffrer("mot de passe fort", "rapport.txt", b"meme contenu")
    assert premier != second


def test_mauvais_mot_de_passe_est_refuse():
    blob = chiffrer("mot de passe fort", "rapport.txt", b"secret")
    with pytest.raises(InvalidTag):
        dechiffrer("mauvais mot de passe", "rapport.txt", blob)


def test_modification_du_nonce_authentifie_est_refusee():
    blob = bytearray(chiffrer("mot de passe fort", "rapport.txt", b"secret"))
    blob[32] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer("mot de passe fort", "rapport.txt", bytes(blob))


def test_modification_d_un_octet_du_chiffre_est_refusee():
    blob = bytearray(chiffrer("mot de passe fort", "rapport.txt", b"secret"))
    blob[HEADER_SIZE] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer("mot de passe fort", "rapport.txt", bytes(blob))


def test_renommage_est_refuse():
    blob = chiffrer("mot de passe fort", "rapport.txt", b"secret")
    with pytest.raises(InvalidTag):
        dechiffrer("mot de passe fort", "autre.txt", blob)


def test_identifiant_inconnu_et_troncature_sont_refuses():
    blob = chiffrer("mot de passe fort", "rapport.txt", b"secret")
    with pytest.raises(FormatError):
        dechiffrer("mot de passe fort", "rapport.txt", b"BAD!" + blob[4:])
    with pytest.raises(FormatError):
        dechiffrer("mot de passe fort", "rapport.txt", blob[:20])


def test_rechiffrement_change_le_mot_de_passe_et_regenere_le_fichier():
    ancien = chiffrer("ancien mot de passe", "rapport.txt", b"donnees")
    nouveau = rechiffrer("ancien mot de passe", "nouveau mot de passe", "rapport.txt", ancien)
    assert nouveau != ancien
    assert dechiffrer("nouveau mot de passe", "rapport.txt", nouveau) == b"donnees"
    with pytest.raises(InvalidTag):
        dechiffrer("ancien mot de passe", "rapport.txt", nouveau)


def test_parametres_d_argon2id_hors_limites_refuses():
    with pytest.raises(FormatError):
        chiffrer(
            "mot de passe fort",
            "rapport.txt",
            b"secret",
            parametres=(3, 32 * 1024, 4),
        )
    with pytest.raises(ValueError):
        chiffrer("mot de passe fort", "rapport.txt", b"secret", parametres=())
