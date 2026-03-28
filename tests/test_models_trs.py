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

    def test_from_profile_preserves_extra_fields(self):
        profile = {
            "trov:name": "My TRS",
            "trov:hasCapability": [
                {"@id": "trs/cap/0", "@type": "trov:CanProvideInternetIsolation"}
            ],
            "trov:publicKey": None,
            "trov:custom": "value",
        }
        trs = TrustedResearchSystem.from_profile(profile, trs_id="trs")
        assert trs.extra_fields.get("trov:name") == "My TRS"
        assert trs.extra_fields.get("trov:custom") == "value"
        assert len(trs.capabilities) == 1

    def test_to_jsonld_includes_extra_fields(self):
        trs = TrustedResearchSystem(
            trs_id="trs",
            extra_fields={"trov:name": "foo", "trov:owner": "bar"},
        )
        jld = trs.to_jsonld()
        assert jld["trov:name"] == "foo"
        assert jld["trov:owner"] == "bar"

    def test_from_to_jsonld_roundtrip(self):
        trs = TrustedResearchSystem(
            trs_id="trs",
            name="Test TRS",
            description="desc",
            capabilities=[
                TRSCapability("trs/cap/0", "trov:CanProvideInternetIsolation")
            ],
            extra_fields={"trov:name": "custom-name"},
        )
        jld = trs.to_jsonld()
        restored = TrustedResearchSystem.from_jsonld(jld)
        assert restored.trs_id == trs.trs_id
        assert len(restored.capabilities) == 1
        assert restored.extra_fields.get("trov:name") == "custom-name"
