"""Unit tests for the Agent model (schema:creator as a typed agent node)."""

import pytest

from tro_utils.models import (
    Agent,
    ORGANIZATION,
    PERSON,
    TransparentResearchObject,
    TrustedResearchSystem,
)
from tro_utils.models.agent import normalise_agent_type


class TestAgent:
    """Unit tests for Agent."""

    def test_person_serialises_as_person(self):
        agent = Agent.person("Alice")
        assert agent.to_jsonld() == {
            "@type": "schema:Person",
            "schema:name": "Alice",
        }

    def test_organization_serialises_as_organization(self):
        agent = Agent.organization("NCSA")
        assert agent.to_jsonld() == {
            "@type": "schema:Organization",
            "schema:name": "NCSA",
        }

    def test_agent_id_emitted_when_set(self):
        agent = Agent.person("Alice", agent_id="https://orcid.org/0000-0002-1825-0097")
        assert agent.to_jsonld()["@id"] == "https://orcid.org/0000-0002-1825-0097"

    def test_extra_fields_round_trip(self):
        agent = Agent.person("Alice", **{"schema:email": "alice@example.org"})
        jld = agent.to_jsonld()
        assert jld["schema:email"] == "alice@example.org"
        assert Agent.from_jsonld(jld) == agent

    def test_roundtrip(self):
        for agent in (Agent.person("Alice"), Agent.organization("NCSA", "ror:x")):
            assert Agent.from_jsonld(agent.to_jsonld()) == agent

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("person", PERSON),
            ("Person", PERSON),
            ("schema:Person", PERSON),
            ("https://schema.org/Person", PERSON),
            ("organization", ORGANIZATION),
            ("schema:Organization", ORGANIZATION),
        ],
    )
    def test_type_aliases_normalised(self, value, expected):
        assert normalise_agent_type(value) == expected
        assert Agent(name="x", agent_type=value).to_jsonld()["@type"] == expected

    @pytest.mark.parametrize("bad", ["schema:Thing", "SoftwareApplication", ""])
    def test_invalid_type_rejected(self, bad):
        with pytest.raises(ValueError, match="schema:Person or schema:Organization"):
            Agent(name="x", agent_type=bad)

    def test_type_list_accepted(self):
        """A declaration may give @type as a list."""
        agent = Agent.from_jsonld(
            {"@type": ["schema:Thing", "schema:Person"], "schema:name": "Alice"}
        )
        assert agent.agent_type == PERSON

    def test_type_list_without_agent_rejected(self):
        with pytest.raises(ValueError, match="names no"):
            Agent.from_jsonld({"@type": ["schema:Thing"], "schema:name": "x"})


class TestAgentCoercion:
    """A bare name has no type, so it becomes an organization."""

    def test_bare_string_becomes_organization(self):
        assert Agent.coerce("Alice") == Agent.organization("Alice")

    def test_legacy_string_creator_parsed(self):
        """Older declarations stored schema:creator as a plain string."""
        assert Agent.from_jsonld("TRO utils") == Agent.organization("TRO utils")

    def test_agent_passed_through(self):
        agent = Agent.person("Alice")
        assert Agent.coerce(agent) is agent

    def test_dict_parsed(self):
        assert Agent.coerce(
            {"@type": "schema:Person", "schema:name": "Alice"}
        ) == Agent.person("Alice")

    def test_default_type_override(self):
        assert Agent.coerce("Alice", default_type=PERSON) == Agent.person("Alice")

    def test_unsupported_value_rejected(self):
        with pytest.raises(ValueError, match="Cannot interpret"):
            Agent.coerce(42)


class TestTROCreator:
    """TransparentResearchObject always serialises creator as an agent node."""

    def test_default_creator_mirrors_trs(self):
        trs = TrustedResearchSystem(trs_id="trs", name="Whole Tale")
        tro = TransparentResearchObject(trs=trs)
        assert tro.to_jsonld()["@graph"][0]["schema:creator"] == {
            "@id": "trs",
            "@type": "schema:Organization",
            "schema:name": "Whole Tale",
        }

    def test_default_creator_falls_back_when_trs_unnamed(self):
        tro = TransparentResearchObject()
        creator = tro.to_jsonld()["@graph"][0]["schema:creator"]
        assert creator["@type"] == ORGANIZATION
        assert creator["schema:name"] == "TRO utils"

    def test_string_creator_coerced(self):
        tro = TransparentResearchObject(creator="Alice")
        assert tro.creator == Agent.organization("Alice")

    def test_agent_creator_preserved(self):
        agent = Agent.person("Alice", agent_id="https://orcid.org/0000")
        tro = TransparentResearchObject(creator=agent)
        assert tro.to_jsonld()["@graph"][0]["schema:creator"] == {
            "@id": "https://orcid.org/0000",
            "@type": "schema:Person",
            "schema:name": "Alice",
        }

    def test_never_serialises_a_bare_string(self):
        """Even a mock/default creator is a node, never a plain name."""
        for creator in (None, "Alice", Agent.person("Bob")):
            tro = TransparentResearchObject(creator=creator)
            serialised = tro.to_jsonld()["@graph"][0]["schema:creator"]
            assert isinstance(serialised, dict)
            assert serialised["@type"] in (PERSON, ORGANIZATION)

    def test_legacy_declaration_loads(self):
        """A declaration with a string creator still loads."""
        tro = TransparentResearchObject(creator=Agent.person("Alice"))
        jld = tro.to_jsonld()
        jld["@graph"][0]["schema:creator"] = "Legacy Name"
        restored = TransparentResearchObject.from_jsonld(jld)
        assert restored.creator == Agent.organization("Legacy Name")

    def test_missing_creator_falls_back_to_trs(self):
        trs = TrustedResearchSystem(trs_id="trs", name="Whole Tale")
        tro = TransparentResearchObject(trs=trs)
        jld = tro.to_jsonld()
        del jld["@graph"][0]["schema:creator"]
        restored = TransparentResearchObject.from_jsonld(jld)
        assert restored.creator == Agent.organization("Whole Tale", "trs")

    def test_creator_list_takes_first(self):
        """schema.org allows several creators; only the first is modelled."""
        tro = TransparentResearchObject()
        jld = tro.to_jsonld()
        jld["@graph"][0]["schema:creator"] = [
            {"@type": "schema:Person", "schema:name": "Alice"},
            {"@type": "schema:Person", "schema:name": "Bob"},
        ]
        restored = TransparentResearchObject.from_jsonld(jld)
        assert restored.creator == Agent.person("Alice")

    def test_creator_survives_roundtrip(self):
        tro = TransparentResearchObject(creator=Agent.person("Alice"))
        restored = TransparentResearchObject.from_jsonld(tro.to_jsonld())
        assert restored.creator == tro.creator
