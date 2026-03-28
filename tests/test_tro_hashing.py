"""Tests for hashing and composition management."""

from tro_utils.tro_utils import TRO

from tests.helpers import create_tro_with_gpg


class TestTROHashingAndComposition:
    """Test hashing and composition management."""

    def test_sha256_for_file(self, tmp_path):
        """Test computing SHA256 hash for a file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        hash_value = TRO.sha256_for_file(str(test_file))

        # Verify hash is correct (pre-computed for "Hello, World!")
        expected_hash = (
            "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        )
        assert hash_value == expected_hash

    def test_composition_fingerprint(self, temp_workspace, tmp_path, gpg_setup):
        """Test that composition fingerprint is computed correctly."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )
        tro.add_arrangement(str(temp_workspace), comment="Test")

        composition = tro.data["@graph"][0]["trov:hasComposition"]

        # Verify fingerprint exists
        assert "trov:hasFingerprint" in composition
        assert (
            composition["trov:hasFingerprint"]["@type"] == "trov:CompositionFingerprint"
        )
        assert (
            composition["trov:hasFingerprint"]["trov:hash"]["trov:hashAlgorithm"]
            == "sha256"
        )
        assert (
            len(composition["trov:hasFingerprint"]["trov:hash"]["trov:hashValue"]) == 64
        )
