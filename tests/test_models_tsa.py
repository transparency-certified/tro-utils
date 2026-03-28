"""Unit tests for TimeStampingAuthority."""

from tro_utils.models import TimeStampingAuthority


class TestTimeStampingAuthority:
    """Unit tests for TimeStampingAuthority."""

    def test_to_from_jsonld(self):
        tsa = TimeStampingAuthority(tsa_id="tsa", public_key="-----BEGIN...")
        jld = tsa.to_jsonld()
        assert jld["@id"] == "tsa"
        assert jld["@type"] == "trov:TimeStampingAuthority"
        assert jld["trov:publicKey"] == "-----BEGIN..."
        restored = TimeStampingAuthority.from_jsonld(jld)
        assert restored.tsa_id == tsa.tsa_id
        assert restored.public_key == tsa.public_key

    def test_without_public_key(self):
        tsa = TimeStampingAuthority()
        jld = tsa.to_jsonld()
        assert "trov:publicKey" not in jld
