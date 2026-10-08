"""Tests for the TRS identifier rule.

The ``@id`` of the TRS a declaration defines must be an absolute IRI, or a
compact IRI whose prefix is not ``trov``, so the same TRS carries the same
identifier in every document that mentions it.  A bare ``"trs"`` resolves
against whatever document contains it, so it does not qualify.
"""

import json

import pytest

from tro_utils.models import TransparentResearchObject, TrustedResearchSystem
from tro_utils.models.trs import (
    UNIDENTIFIED_TRS_ID,
    is_conforming_trs_id,
    validate_trs_id,
)


class TestConformance:
    """Which identifiers qualify."""

    @pytest.mark.parametrize(
        "value",
        [
            "https://example.org/trs",
            "http://localhost/",
            "urn:uuid:6fa459ea-ee8a-3ca4-894e-db77e160355e",
            "ex:trs",  # compact IRI, non-trov prefix
            "wt:systems/1",
            UNIDENTIFIED_TRS_ID,
        ],
    )
    def test_conforming(self, value):
        assert is_conforming_trs_id(value)
        assert validate_trs_id(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "trs",  # bare relative reference, the old default
            "trs/capability/1",
            "",
            "trov:trs",  # compact IRI under the reserved prefix
            "trov:systems/1",
            "_:b0",  # blank node, not stable across documents
            "//example.org/trs",  # no scheme
            "https:",  # empty remainder
            None,
            42,
        ],
    )
    def test_non_conforming(self, value):
        assert not is_conforming_trs_id(value)
        with pytest.raises(ValueError, match="absolute IRI"):
            validate_trs_id(value)

    def test_error_names_the_offending_value(self):
        with pytest.raises(ValueError, match="got 'trs'"):
            validate_trs_id("trs")


class TestProfileResolution:
    """from_profile picks the identifier and validates it."""

    def test_profile_id_is_honoured(self):
        """A profile's own @id used to be dropped on the floor."""
        trs = TrustedResearchSystem.from_profile({"@id": "https://example.org/trs"})
        assert trs.trs_id == "https://example.org/trs"

    def test_profile_id_not_swallowed_into_extra_fields(self):
        trs = TrustedResearchSystem.from_profile({"@id": "ex:trs"})
        assert "@id" not in trs.extra_fields
        assert trs.to_jsonld()["@id"] == "ex:trs"

    def test_url_used_when_no_id(self):
        trs = TrustedResearchSystem.from_profile(
            {"schema:url": "https://wholetale.org/"}
        )
        assert trs.trs_id == "https://wholetale.org/"

    def test_legacy_trov_url_still_used(self):
        """Profiles predating the schema.org description of the TRS.

        trov:url was never a TROV term, but profiles in the wild use it, and
        dropping it would silently demote those systems to the unidentified
        placeholder.
        """
        trs = TrustedResearchSystem.from_profile({"trov:url": "http://localhost/"})
        assert trs.trs_id == "http://localhost/"

    def test_schema_url_wins_over_trov_url(self):
        trs = TrustedResearchSystem.from_profile(
            {"schema:url": "https://wholetale.org/", "trov:url": "http://localhost/"}
        )
        assert trs.trs_id == "https://wholetale.org/"

    def test_profile_id_wins_over_url(self):
        trs = TrustedResearchSystem.from_profile(
            {"@id": "ex:trs", "schema:url": "https://wholetale.org/"}
        )
        assert trs.trs_id == "ex:trs"

    def test_argument_wins_over_profile(self):
        trs = TrustedResearchSystem.from_profile(
            {"@id": "ex:trs"}, trs_id="https://example.org/other"
        )
        assert trs.trs_id == "https://example.org/other"

    def test_placeholder_when_unidentified(self):
        trs = TrustedResearchSystem.from_profile({"schema:name": "nameless"})
        assert trs.trs_id == UNIDENTIFIED_TRS_ID
        assert is_conforming_trs_id(trs.trs_id)

    def test_non_conforming_url_falls_back(self):
        """A schema:url that is not a usable IRI is skipped, not an error."""
        trs = TrustedResearchSystem.from_profile({"schema:url": "localhost"})
        assert trs.trs_id == UNIDENTIFIED_TRS_ID

    def test_non_conforming_profile_id_raises(self):
        """An explicitly stated @id is reported, never quietly replaced."""
        with pytest.raises(ValueError, match="TRS profile @id"):
            TrustedResearchSystem.from_profile({"@id": "trs"})

    def test_non_conforming_argument_raises(self):
        with pytest.raises(ValueError, match="TRS @id"):
            TrustedResearchSystem.from_profile({}, trs_id="trov:trs")

    def test_schema_properties_describe_the_trs(self):
        """A profile describes the organization with schema.org properties.

        schema:name and schema:description are typed fields; the rest ride
        along in extra_fields and reach the declaration unchanged.
        """
        trs = TrustedResearchSystem.from_profile(
            {
                "@id": "https://example.org/trs",
                "schema:name": "shakuras",
                "schema:description": "My local system",
                "schema:email": "root@dev.null",
                "schema:url": "https://example.org/trs",
                "schema:owner": {
                    "@id": "https://orcid.org/0000-0002-1825-0097",
                    "@type": "schema:Person",
                    "schema:name": "Some Operator",
                },
            }
        )
        jld = trs.to_jsonld()
        assert jld["schema:name"] == "shakuras"
        assert jld["schema:description"] == "My local system"
        assert jld["schema:email"] == "root@dev.null"
        assert jld["schema:url"] == "https://example.org/trs"
        assert jld["schema:owner"]["@type"] == "schema:Person"
        # Nothing invented a trov: term for any of it.
        assert not [
            k for k in jld if k.startswith("trov:") and k != "trov:hasCapability"
        ]

    def test_default_instance_conforms(self):
        """Even the bare default carries a usable identifier."""
        assert is_conforming_trs_id(TrustedResearchSystem().trs_id)


class TestEnforcementBoundary:
    """Legacy declarations stay readable; new ones cannot be written."""

    def _legacy_declaration(self):
        tro = TransparentResearchObject(
            trs=TrustedResearchSystem(trs_id="https://example.org/trs")
        )
        jld = tro.to_jsonld()
        jld["@graph"][0]["trov:wasAssembledBy"]["@id"] = "trs"
        return jld

    def test_legacy_declaration_loads(self):
        restored = TransparentResearchObject.from_jsonld(self._legacy_declaration())
        assert restored.trs.trs_id == "trs"

    def test_legacy_declaration_cannot_be_saved(self, tmp_path):
        restored = TransparentResearchObject.from_jsonld(self._legacy_declaration())
        out = tmp_path / "t.jsonld"
        with pytest.raises(ValueError, match="absolute IRI"):
            restored.save(out)
        assert not out.exists()

    def test_save_succeeds_once_id_is_fixed(self, tmp_path):
        restored = TransparentResearchObject.from_jsonld(self._legacy_declaration())
        restored.trs.trs_id = "https://example.org/trs"
        out = tmp_path / "t.jsonld"
        restored.save(out)
        with open(out) as f:
            assert (
                json.load(f)["@graph"][0]["trov:wasAssembledBy"]["@id"]
                == "https://example.org/trs"
            )

    def test_missing_id_reads_as_placeholder(self):
        jld = self._legacy_declaration()
        del jld["@graph"][0]["trov:wasAssembledBy"]["@id"]
        restored = TransparentResearchObject.from_jsonld(jld)
        assert restored.trs.trs_id == UNIDENTIFIED_TRS_ID


class TestReferencesUseTheSameId:
    """Everything that points at the TRS must use its identifier."""

    def test_performance_and_creator_reference_trs_id(self, tmp_path):
        import datetime

        d = tmp_path / "w"
        d.mkdir()
        (d / "main.py").write_text("print(1)")

        tro = TransparentResearchObject(
            trs=TrustedResearchSystem(trs_id="https://example.org/trs", name="Ex")
        )
        tro.add_arrangement(str(d), comment="before")
        tro.add_performance(
            start_time=datetime.datetime(2024, 6, 1, 10, 0),
            end_time=datetime.datetime(2024, 6, 1, 11, 0),
            accessed_arrangement="arrangement/0",
        )
        graph = tro.to_jsonld()["@graph"][0]

        assert graph["trov:wasAssembledBy"]["@id"] == "https://example.org/trs"
        assert graph["schema:creator"]["@id"] == "https://example.org/trs"
        performance = graph["trov:hasPerformance"][0]
        assert performance["trov:wasConductedBy"]["@id"] == "https://example.org/trs"
