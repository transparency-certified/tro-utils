"""Tests for extra vocabulary support in @context."""

import json

import pytest

from tro_utils.models import TransparentResearchObject
from tro_utils.tro_utils import TRO


class TestExtraContext:
    """Tests for extra vocabulary support in @context."""

    def test_extra_context_default_empty(self):
        """TransparentResearchObject.extra_context defaults to an empty dict."""
        tro = TransparentResearchObject()
        assert tro.extra_context == {}

    def test_extra_context_dict_in_jsonld(self):
        """A dict extra_context entry appears in the serialised @context."""
        tro = TransparentResearchObject()
        tro.extra_context = {"ex": "http://example.org/"}
        data = tro.to_jsonld()
        assert data["@context"]["ex"] == "http://example.org/"

    def test_extra_context_multiple_entries(self):
        """Multiple extra_context entries all appear in @context."""
        tro = TransparentResearchObject()
        tro.extra_context = {
            "ex": "http://example.org/",
            "foaf": "http://xmlns.com/foaf/0.1/",
        }
        data = tro.to_jsonld()
        assert data["@context"]["ex"] == "http://example.org/"
        assert data["@context"]["foaf"] == "http://xmlns.com/foaf/0.1/"

    def test_extra_context_base_context_still_present(self):
        """The standard base context keys are always present in @context."""
        tro = TransparentResearchObject()
        tro.extra_context = {"ex": "http://example.org/"}
        data = tro.to_jsonld()
        base = data["@context"]
        assert "trov" in base
        assert "rdf" in base

    def test_extra_context_roundtrip(self, tmp_path):
        """Extra context entries survive a save/load roundtrip."""
        tro = TransparentResearchObject()
        tro.extra_context = {
            "ex": "http://example.org/",
            "foaf": "http://xmlns.com/foaf/0.1/",
        }
        filepath = tmp_path / "tro_with_extra_ctx.jsonld"
        tro.save(str(filepath))

        loaded = TransparentResearchObject.load(str(filepath))
        assert loaded.extra_context["ex"] == "http://example.org/"
        assert loaded.extra_context["foaf"] == "http://xmlns.com/foaf/0.1/"

    def test_extra_context_via_tro_facade(self, tmp_path):
        """TRO facade propagates extra_context to the underlying model."""
        tro_file = tmp_path / "tro.jsonld"
        tro = TRO(
            filepath=str(tro_file),
            extra_context={"ex": "http://example.org/"},
        )
        tro.save()

        with open(tro_file) as f:
            data = json.load(f)
        assert data["@context"]["ex"] == "http://example.org/"

    def test_extra_context_via_tro_facade_extends_existing(self, tmp_path):
        """TRO facade merges extra_context into any context already in the file."""
        tro_file = tmp_path / "tro.jsonld"
        # First save with one extra context entry
        tro = TRO(
            filepath=str(tro_file),
            extra_context={"ex": "http://example.org/"},
        )
        tro.save()

        # Re-open and add a second entry
        tro2 = TRO(
            filepath=str(tro_file),
            extra_context={"foaf": "http://xmlns.com/foaf/0.1/"},
        )
        tro2.save()

        with open(tro_file) as f:
            data = json.load(f)
        assert data["@context"]["ex"] == "http://example.org/"
        assert data["@context"]["foaf"] == "http://xmlns.com/foaf/0.1/"
