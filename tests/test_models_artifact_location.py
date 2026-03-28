"""Unit tests for ArtifactLocation."""

from tro_utils.models import ArtifactLocation


class TestArtifactLocation:
    """Unit tests for ArtifactLocation."""

    def test_to_from_jsonld(self):
        loc = ArtifactLocation("arr/0/loc/0", "comp/1/artifact/0", "data/input.csv")
        jld = loc.to_jsonld()
        assert jld["@id"] == "arr/0/loc/0"
        assert jld["trov:artifact"]["@id"] == "comp/1/artifact/0"
        assert jld["trov:path"] == "data/input.csv"
        restored = ArtifactLocation.from_jsonld(jld)
        assert restored.location_id == loc.location_id
        assert restored.artifact_id == loc.artifact_id
        assert restored.path == loc.path
