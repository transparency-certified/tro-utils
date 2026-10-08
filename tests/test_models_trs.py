"""Unit tests for TRSCapability and TrustedResearchSystem."""

from tro_utils.models import TRSCapability, TrustedResearchSystem


class TestTRSCapability:
    """Unit tests for TRSCapability."""

    def test_to_from_jsonld(self):
        cap = TRSCapability("trs/capability/0", "trov:CanProvideInternetIsolation")
        jld = cap.to_jsonld()
        restored = TRSCapability.from_jsonld(jld)
        assert restored.capability_id == cap.capability_id
        assert restored.capability_type == cap.capability_type


class TestTrustedResearchSystem:
    """Unit tests for TrustedResearchSystem."""

    def test_from_profile_typed_schema_fields(self):
        """schema:name and schema:description become typed fields."""
        trs = TrustedResearchSystem.from_profile(
            {
                "@id": "https://example.org/trs",
                "schema:name": "My TRS",
                "schema:description": "A system",
            }
        )
        assert trs.name == "My TRS"
        assert trs.description == "A system"
        # Typed, so not duplicated into extra_fields.
        assert "schema:name" not in trs.extra_fields

    def test_from_profile_preserves_extra_fields(self):
        """Everything not typed is carried through verbatim.

        That covers the rest of the schema.org description of the
        organization as well as vendor-specific keys.
        """
        profile = {
            "schema:name": "My TRS",
            "schema:url": "https://example.org/trs",
            "schema:email": "admin@example.org",
            "schema:owner": {
                "@type": "schema:Person",
                "schema:name": "Some Operator",
            },
            "trov:hasCapability": [
                {"@id": "trs/cap/0", "@type": "trov:CanProvideInternetIsolation"}
            ],
            "trov:publicKey": None,
            "ex:custom": "value",
        }
        trs = TrustedResearchSystem.from_profile(profile)
        assert trs.extra_fields.get("schema:url") == "https://example.org/trs"
        assert trs.extra_fields.get("schema:email") == "admin@example.org"
        assert trs.extra_fields["schema:owner"]["schema:name"] == "Some Operator"
        assert trs.extra_fields.get("ex:custom") == "value"
        assert len(trs.capabilities) == 1

    def test_to_jsonld_includes_extra_fields(self):
        trs = TrustedResearchSystem(
            trs_id="https://example.org/trs",
            extra_fields={"schema:url": "https://example.org/", "ex:custom": "bar"},
        )
        jld = trs.to_jsonld()
        assert jld["schema:url"] == "https://example.org/"
        assert jld["ex:custom"] == "bar"

    def test_to_jsonld_describes_an_organization(self):
        """The TRS node is typed as an organization, which is what makes the
        schema.org properties above the right way to describe it."""
        jld = TrustedResearchSystem(
            trs_id="https://example.org/trs", name="My TRS"
        ).to_jsonld()
        assert "schema:Organization" in jld["@type"]
        assert jld["schema:name"] == "My TRS"

    def test_from_to_jsonld_roundtrip(self):
        trs = TrustedResearchSystem(
            trs_id="https://example.org/trs",
            name="Test TRS",
            description="desc",
            capabilities=[
                TRSCapability("trs/cap/0", "trov:CanProvideInternetIsolation")
            ],
            extra_fields={"schema:url": "https://example.org/"},
        )
        jld = trs.to_jsonld()
        restored = TrustedResearchSystem.from_jsonld(jld)
        assert restored.trs_id == trs.trs_id
        assert restored.name == trs.name
        assert len(restored.capabilities) == 1
        assert restored.extra_fields.get("schema:url") == "https://example.org/"
