"""Tests for TRO object creation and initialization."""

import json

import pytest

from tro_utils.tro_utils import TRO

from tests.helpers import create_tro_with_gpg


class TestTROCreation:
    """Test TRO object creation and initialization."""

    def test_create_tro_raises_on_old_vocabulary_version(self, tmp_path):
        """Loading a TRO with a vocabulary version older than TROV_VOCABULARY_VERSION raises RuntimeError."""
        old_tro_path = tmp_path / "old_tro.jsonld"
        old_tro_data = {
            "@context": [{}],
            "@graph": [
                {
                    "@id": "tro",
                    "trov:wasAssembledBy": {"trov:hasCapability": []},
                    "trov:hasArrangement": [],
                    "trov:hasComposition": {"trov:hasArtifact": []},
                    "trov:hasPerformance": [],
                    "trov:hasAttribute": [],
                }
            ],
        }
        old_tro_path.write_text(json.dumps(old_tro_data))

        with pytest.raises(RuntimeError, match="older version of the TRO vocabulary"):
            TRO(filepath=str(old_tro_path))

    def test_create_tro_without_file(self, tmp_path, gpg_setup):
        """Test creating a new TRO without existing file."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "new_tro.jsonld"),
            gpg_setup=gpg_setup,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
            tro_creator="Test Creator",
            tro_name="Test TRO",
            tro_description="A test TRO object",
        )

        assert tro.basename == "new_tro"
        assert tro.gpg_key_id == gpg_setup["keyid"]
        assert "TransparentResearchObject" in str(tro.data)
        assert tro.data["@graph"][0]["schema:creator"] == "Test Creator"
        assert tro.data["@graph"][0]["schema:name"] == "Test TRO"
        assert not (tmp_path / "new_tro.jsonld").exists()
        tro.save()
        assert (tmp_path / "new_tro.jsonld").exists()

    def test_create_tro_with_profile(self, tmp_path, gpg_setup, trs_profile):
        """Test creating a TRO with a TRS profile."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "new_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Check that profile was loaded
        trs_data = tro.data["@graph"][0]["trov:wasAssembledBy"]
        assert trs_data["trov:name"] == "test-trs"
        assert len(trs_data["trov:hasCapability"]) == 2

    def test_tro_filenames(self, tmp_path, gpg_setup):
        """Test that TRO generates correct filenames."""
        filepath = str(tmp_path / "my_tro.jsonld")
        tro = create_tro_with_gpg(filepath=filepath, gpg_setup=gpg_setup)

        assert tro.tro_filename == filepath
        assert tro.sig_filename == str(tmp_path / "my_tro.sig")
        assert tro.tsr_filename == str(tmp_path / "my_tro.tsr")
