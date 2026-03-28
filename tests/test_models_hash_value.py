"""Unit tests for HashValue value object."""

import pytest

from tro_utils.models import HashValue


class TestHashValue:
    """Unit tests for HashValue value object."""

    def test_from_string_roundtrip(self):
        h = HashValue.from_string("sha256:abc123")
        assert h.algorithm == "sha256"
        assert h.value == "abc123"
        assert h.to_string() == "sha256:abc123"
        assert str(h) == "sha256:abc123"

    def test_from_string_invalid_raises(self):
        with pytest.raises(ValueError, match="Expected"):
            HashValue.from_string("invalidsyntax")

    def test_to_jsonld(self):
        h = HashValue(algorithm="sha256", value="deadbeef")
        jld = h.to_jsonld()
        assert jld == {"trov:hashAlgorithm": "sha256", "trov:hashValue": "deadbeef"}

    def test_from_jsonld_dict(self):
        h = HashValue.from_jsonld(
            {"trov:hashAlgorithm": "sha256", "trov:hashValue": "deadbeef"}
        )
        assert h.algorithm == "sha256"
        assert h.value == "deadbeef"

    def test_from_jsonld_list_prefers_sha256(self):
        data = [
            {"trov:hashAlgorithm": "md5", "trov:hashValue": "aaa"},
            {"trov:hashAlgorithm": "sha256", "trov:hashValue": "bbb"},
        ]
        h = HashValue.from_jsonld(data)
        assert h.algorithm == "sha256"
        assert h.value == "bbb"

    def test_from_jsonld_list_falls_back_to_first(self):
        data = [{"trov:hashAlgorithm": "md5", "trov:hashValue": "aaa"}]
        h = HashValue.from_jsonld(data)
        assert h.algorithm == "md5"

    def test_from_jsonld_legacy_sha256(self):
        h = HashValue.from_jsonld({"trov:sha256": "cafebabe"})
        assert h.algorithm == "sha256"
        assert h.value == "cafebabe"

    def test_from_jsonld_string(self):
        h = HashValue.from_jsonld("sha512:1234")
        assert h.algorithm == "sha512"
        assert h.value == "1234"

    def test_from_jsonld_invalid_raises(self):
        with pytest.raises(ValueError):
            HashValue.from_jsonld({"no": "hash_fields"})

    def test_equality(self):
        assert HashValue("sha256", "abc") == HashValue("sha256", "abc")
        assert HashValue("sha256", "abc") != HashValue("sha256", "xyz")
