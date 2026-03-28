"""Unit tests for ArtifactComposition."""

from tro_utils.models import ArtifactComposition, HashValue, ResearchArtifact


class TestArtifactComposition:
    """Unit tests for ArtifactComposition."""

    def test_add_artifact_updates_fingerprint(self):
        comp = ArtifactComposition()
        assert comp.fingerprint is None
        a = ResearchArtifact(
            "comp/1/artifact/0", HashValue("sha256", "aaa"), "text/plain"
        )
        comp.add_artifact(a)
        assert comp.fingerprint is not None

    def test_get_by_hash(self):
        comp = ArtifactComposition()
        a = ResearchArtifact("x/0", HashValue("sha256", "abc"), "text/plain")
        comp.add_artifact(a)
        assert comp.get_by_hash("sha256:abc") is a
        assert comp.get_by_hash("sha256:xyz") is None

    def test_get_by_id(self):
        comp = ArtifactComposition()
        a = ResearchArtifact("x/0", HashValue("sha256", "abc"), "text/plain")
        comp.add_artifact(a)
        assert comp.get_by_id("x/0") is a
        assert comp.get_by_id("x/9") is None

    def test_next_artifact_id(self):
        comp = ArtifactComposition(composition_id="composition/1")
        assert comp.next_artifact_id() == "composition/1/artifact/0"
        comp.add_artifact(
            ResearchArtifact(
                "composition/1/artifact/0", HashValue("sha256", "a"), "text/plain"
            )
        )
        assert comp.next_artifact_id() == "composition/1/artifact/1"

    def test_to_from_jsonld_roundtrip(self):
        comp = ArtifactComposition()
        comp.add_artifact(
            ResearchArtifact(
                "comp/1/artifact/0", HashValue("sha256", "aaa"), "text/plain"
            )
        )
        comp.add_artifact(
            ResearchArtifact(
                "comp/1/artifact/1", HashValue("sha256", "bbb"), "text/csv"
            )
        )
        jld = comp.to_jsonld()
        restored = ArtifactComposition.from_jsonld(jld)
        assert len(restored.artifacts) == 2
        assert restored.fingerprint is not None
