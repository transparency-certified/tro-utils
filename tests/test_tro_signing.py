"""Tests for TRO signing and verification."""

import os

import pytest

from tro_utils.tro_utils import TRO

from tests.helpers import create_tro_with_gpg


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
