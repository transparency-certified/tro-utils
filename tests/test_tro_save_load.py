"""Tests for TRO save and load operations."""

import json
import os

from tests.helpers import create_tro_with_gpg


class TestTROSaveLoad:
    """Test TRO save and load operations."""

    def test_save_tro(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test saving a TRO to disk."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        tro.add_arrangement(str(temp_workspace), comment="Test arrangement")
        tro.save()

        # Verify file was created
        assert os.path.exists(tro.tro_filename)

        # Verify file content is valid JSON
        with open(tro.tro_filename, "r") as f:
            data = json.load(f)
            assert "@graph" in data
            assert data["@graph"][0]["@type"] == [
                "trov:TransparentResearchObject",
                "schema:CreativeWork",
            ]

    def test_load_existing_tro(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test loading an existing TRO from disk."""
        # Create and save a TRO
        tro1 = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )
        tro1.add_arrangement(str(temp_workspace), comment="First arrangement")
        tro1.save()

        # Load the same TRO
        tro2 = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Verify the loaded TRO has the same data
        assert len(tro2.list_arrangements()) == 1
        assert tro2.list_arrangements()[0]["rdfs:comment"] == "First arrangement"

        # Add another arrangement to the loaded TRO
        (temp_workspace / "new_file.txt").write_text("new content")
        tro2.add_arrangement(str(temp_workspace), comment="Second arrangement")

        # Verify it now has two arrangements
        assert len(tro2.list_arrangements()) == 2
