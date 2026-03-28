"""Unit tests for ResearchArtifact model."""

import pytest

from tro_utils.models import HashValue, ResearchArtifact


class TestResearchArtifact:
    """Unit tests for ResearchArtifact model."""

    def _make_artifact(self):
        return ResearchArtifact(
            artifact_id="composition/1/artifact/0",
            hash=HashValue("sha256", "deadbeef"),
            mime_type="text/csv",
        )

    def test_to_jsonld(self):
        a = self._make_artifact()
        jld = a.to_jsonld()
        assert jld["@id"] == "composition/1/artifact/0"
        assert jld["@type"] == "trov:ResearchArtifact"
        assert jld["trov:hash"]["trov:hashAlgorithm"] == "sha256"
        assert jld["trov:mimeType"] == "text/csv"

    def test_from_jsonld_roundtrip(self):
        a = self._make_artifact()
        restored = ResearchArtifact.from_jsonld(a.to_jsonld())
        assert restored.artifact_id == a.artifact_id
        assert restored.hash == a.hash
        assert restored.mime_type == a.mime_type

    def test_from_jsonld_legacy_sha256(self):
        data = {
            "@id": "composition/1/artifact/0",
            "@type": "trov:ResearchArtifact",
            "trov:sha256": "aabbcc",
            "trov:mimeType": "text/plain",
        }
        a = ResearchArtifact.from_jsonld(data)
        assert a.hash.algorithm == "sha256"
        assert a.hash.value == "aabbcc"

    def test_from_jsonld_missing_hash_raises(self):
        with pytest.raises(ValueError):
            ResearchArtifact.from_jsonld({"@id": "x", "@type": "trov:ResearchArtifact"})

    def test_from_file(self, tmp_path):
        f = tmp_path / "sample.txt"
        f.write_text("hello world")
        artifact = ResearchArtifact.from_file(f, "composition/1/artifact/0")
        assert artifact.artifact_id == "composition/1/artifact/0"
        assert artifact.hash.algorithm == "sha256"
        assert len(artifact.hash.value) == 64
        assert artifact.mime_type  # non-empty mime type

    def test_from_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ResearchArtifact.from_file(tmp_path / "nonexistent.txt", "x")
