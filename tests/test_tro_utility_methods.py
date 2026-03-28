"""Tests for TRO utility methods."""

from tests.helpers import create_tro_with_gpg


class TestTROUtilityMethods:
    """Test utility methods of TRO class."""

    def test_get_composition_seq(self, tmp_path, gpg_setup):
        """Test getting composition sequence number."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Initially should be 0
        assert tro.get_composition_seq() == 0

    def test_get_arrangement_seq(self, tmp_path, gpg_setup):
        """Test getting arrangement sequence number."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Initially should be 0
        assert tro.get_arrangement_seq() == 0

    def test_get_composition_info(self, temp_workspace, tmp_path, gpg_setup):
        """Test getting composition information."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )
        tro.add_arrangement(str(temp_workspace), comment="Test")

        composition_info = tro.get_composition_info()

        assert "@id" in composition_info
        assert composition_info["@id"] == "composition/1"
        assert "@type" in composition_info
        assert "trov:hasArtifact" in composition_info
        assert len(composition_info["trov:hasArtifact"]) > 0
