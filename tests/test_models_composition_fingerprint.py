"""Unit tests for CompositionFingerprint."""

from tro_utils.models import CompositionFingerprint, HashValue, ResearchArtifact


class TestCompositionFingerprint:
    """Unit tests for CompositionFingerprint."""

    def test_compute_deterministic(self):
        artifacts = [
            ResearchArtifact("a/0", HashValue("sha256", "aaa"), "text/plain"),
            ResearchArtifact("a/1", HashValue("sha256", "bbb"), "text/csv"),
        ]
        fp1 = CompositionFingerprint.compute(artifacts)
        fp2 = CompositionFingerprint.compute(list(reversed(artifacts)))
        assert fp1.hash.value == fp2.hash.value  # order-independent

    def test_to_from_jsonld(self):
        artifacts = [ResearchArtifact("a/0", HashValue("sha256", "abc"), "text/plain")]
        fp = CompositionFingerprint.compute(artifacts)
        jld = fp.to_jsonld()
        restored = CompositionFingerprint.from_jsonld(jld)
        assert restored.hash.value == fp.hash.value
