"""Tests for TRO signing and verification."""

import json
import os
from unittest.mock import patch

import pytest

from tro_utils.tro_utils import TRO

from tests.helpers import create_tro_with_gpg

PUBLIC_KEY_ARMOR = "-----BEGIN PGP PUBLIC KEY BLOCK-----"


def _trs(declaration):
    """Return the ``trov:wasAssembledBy`` block of a saved declaration."""
    with open(declaration) as fp:
        return json.load(fp)["@graph"][0]["trov:wasAssembledBy"]


class TestTROSigning:
    """Test TRO signing and verification."""

    def test_sign_tro(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test signing a TRO with GPG."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add some content
        tro.add_arrangement(str(temp_workspace), comment="Test")
        tro.save()

        # Sign the TRO
        signature = tro.trs_signature()

        assert signature is not None
        assert len(str(signature)) > 0

        # Verify signature file was created
        assert os.path.exists(tro.sig_filename)

        # Verify signature content
        with open(tro.sig_filename, "r") as f:
            sig_content = f.read()
            assert "BEGIN PGP SIGNATURE" in sig_content

    def test_sign_without_gpg_key(self, tmp_path):
        """Test that signing without GPG key raises error."""
        tro = TRO(filepath=str(tmp_path / "test_tro.jsonld"))

        with pytest.raises(RuntimeError, match="GPG fingerprint was not provided"):
            tro.trs_signature()

    def test_sign_without_passphrase(self, tmp_path, gpg_setup):
        """Test that signing without passphrase raises error."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            gpg_fingerprint=gpg_setup["fingerprint"],
        )

        with pytest.raises(RuntimeError, match="GPG passphrase was not provided"):
            tro.trs_signature()


class TestPublicKeyAttachment:
    """Test that trov:publicKey is only injected at signing time."""

    def test_public_key_absent_until_attached(
        self, temp_workspace, tmp_path, gpg_setup, trs_profile
    ):
        """Saving before signing must not record a public key."""
        declaration = str(tmp_path / "test_tro.jsonld")
        tro = create_tro_with_gpg(
            filepath=declaration,
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )
        tro.add_arrangement(str(temp_workspace), comment="Test")
        tro.save()

        assert "trov:publicKey" not in _trs(declaration)

        tro.attach_public_key()
        tro.save()

        public_key = _trs(declaration)["trov:publicKey"]
        assert public_key.startswith(PUBLIC_KEY_ARMOR)
        assert public_key == gpg_setup["gpg"].export_keys(gpg_setup["keyid"])
        assert tro.gpg_key_id == gpg_setup["keyid"]

    def test_attach_public_key_without_fingerprint(self, tmp_path):
        """Attaching a key without a configured fingerprint raises."""
        tro = TRO(filepath=str(tmp_path / "test_tro.jsonld"))

        with pytest.raises(RuntimeError, match="GPG fingerprint was not provided"):
            tro.attach_public_key()

    def test_attach_public_key_without_keyring(self, tmp_path, monkeypatch):
        """A fingerprint missing from the keyring is reported as such."""
        gpg_home = tmp_path / "empty_keyring"
        gpg_home.mkdir(mode=0o700)
        monkeypatch.setattr("tro_utils.tro_utils.GPG_HOME", str(gpg_home))

        tro = TRO(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_fingerprint="0" * 40,
        )

        with pytest.raises(RuntimeError, match="was not found in the keyring"):
            tro.attach_public_key()

    def test_save_with_fingerprint_but_no_keyring(
        self, temp_workspace, tmp_path, monkeypatch
    ):
        """Building and saving a TRO must not require the configured key."""
        gpg_home = tmp_path / "empty_keyring"
        gpg_home.mkdir(mode=0o700)
        monkeypatch.setattr("tro_utils.tro_utils.GPG_HOME", str(gpg_home))
        declaration = str(tmp_path / "test_tro.jsonld")

        tro = TRO(filepath=declaration, gpg_fingerprint="0" * 40)
        tro.add_arrangement(str(temp_workspace), comment="Test")
        tro.save()

        assert "trov:publicKey" not in _trs(declaration)

    def test_read_write_never_touches_gpg(self, temp_workspace, tmp_path):
        """No GPG binary is needed to create, mutate, save or reload a TRO."""
        declaration = str(tmp_path / "test_tro.jsonld")

        def no_gpg(*args, **kwargs):
            raise AssertionError("GPG must not be used outside of signing")

        with patch.object(TRO, "_gpg", no_gpg):
            tro = TRO(filepath=declaration, gpg_fingerprint="0" * 40)
            tro.add_arrangement(str(temp_workspace), comment="Test")
            tro.save()
            reloaded = TRO(filepath=declaration, gpg_fingerprint="0" * 40)

        assert reloaded.list_arrangements()
