"""Agent model — a typed ``schema:Person`` or ``schema:Organization``.

``schema:creator`` expects an agent, not a bare name, so every creator is
represented by an :class:`Agent` that serialises to a proper node.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ._base import TROVModel

PERSON = "schema:Person"
ORGANIZATION = "schema:Organization"

#: The only two types ``schema:creator`` may carry here.
AGENT_TYPES = (PERSON, ORGANIZATION)

# Accept unprefixed terms and the full IRI on input; everything is written
# back out in the prefixed form used throughout a declaration.
_TYPE_ALIASES = {
    "person": PERSON,
    "schema:person": PERSON,
    "https://schema.org/person": PERSON,
    "http://schema.org/person": PERSON,
    "organization": ORGANIZATION,
    "schema:organization": ORGANIZATION,
    "https://schema.org/organization": ORGANIZATION,
    "http://schema.org/organization": ORGANIZATION,
}

_KNOWN_AGENT_KEYS = {"@id", "@type", "schema:name"}


def normalise_agent_type(value: str) -> str:
    """Return *value* as either ``schema:Person`` or ``schema:Organization``.

    Args:
        value: A type name, optionally unprefixed (``"person"``) or given as a
            full schema.org IRI.

    Returns:
        The canonical prefixed type string.

    Raises:
        ValueError: If *value* is neither a person nor an organization.
    """
    try:
        return _TYPE_ALIASES[str(value).strip().lower()]
    except KeyError:
        raise ValueError(
            f"schema:creator must be {PERSON} or {ORGANIZATION}, got {value!r}"
        ) from None


@dataclass
class Agent(TROVModel):
    """A ``schema:Person`` or ``schema:Organization``.

    Unknown fields (``schema:email``, ``schema:affiliation``, ...) are kept in
    :attr:`extra_fields` and round-tripped verbatim.
    """

    name: str = ""
    agent_type: str = ORGANIZATION
    agent_id: str | None = None
    extra_fields: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.agent_type = normalise_agent_type(self.agent_type)

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def person(cls, name: str, agent_id: str | None = None, **extra: Any) -> "Agent":
        """Return a ``schema:Person`` named *name*."""
        return cls(
            name=name, agent_type=PERSON, agent_id=agent_id, extra_fields=dict(extra)
        )

    @classmethod
    def organization(
        cls, name: str, agent_id: str | None = None, **extra: Any
    ) -> "Agent":
        """Return a ``schema:Organization`` named *name*."""
        return cls(
            name=name,
            agent_type=ORGANIZATION,
            agent_id=agent_id,
            extra_fields=dict(extra),
        )

    @classmethod
    def coerce(cls, value: Any, default_type: str = ORGANIZATION) -> "Agent":
        """Return *value* as an :class:`Agent`.

        Accepts an :class:`Agent` (returned unchanged), a JSON-LD dict, or a
        bare name.  A bare name carries no type information, so it becomes
        *default_type*.

        Args:
            value: An ``Agent``, a JSON-LD agent dict, or a name string.
            default_type: Type to assume for a bare name.

        Returns:
            An :class:`Agent`.

        Raises:
            ValueError: If *value* is not one of the accepted forms.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            return cls.from_jsonld(value)
        if isinstance(value, str):
            return cls(name=value, agent_type=default_type)
        raise ValueError(f"Cannot interpret {value!r} as a schema:creator")

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.agent_id is not None:
            result["@id"] = self.agent_id
        result["@type"] = normalise_agent_type(self.agent_type)
        # Extra fields first so the typed name wins on conflict.
        result.update(self.extra_fields)
        result["schema:name"] = self.name
        return result

    @classmethod
    def from_jsonld(cls, data: dict[str, Any] | str) -> "Agent":
        """Deserialise an agent from JSON-LD.

        Args:
            data: An agent dict, or a bare name as written by versions that
                stored ``schema:creator`` as a plain string.

        Returns:
            An :class:`Agent`.

        Raises:
            ValueError: If ``@type`` names neither a person nor an organization.
        """
        if isinstance(data, str):
            return cls.coerce(data)

        raw_type = data.get("@type", ORGANIZATION)
        # @type may be a list; use the first entry that names an agent.
        if isinstance(raw_type, list):
            for candidate in raw_type:
                try:
                    agent_type = normalise_agent_type(candidate)
                    break
                except ValueError:
                    continue
            else:
                raise ValueError(
                    f"schema:creator @type names no {PERSON} or {ORGANIZATION}: "
                    f"{raw_type!r}"
                )
        else:
            agent_type = normalise_agent_type(raw_type)

        extra = {k: v for k, v in data.items() if k not in _KNOWN_AGENT_KEYS}
        return cls(
            name=data.get("schema:name", ""),
            agent_type=agent_type,
            agent_id=data.get("@id"),
            extra_fields=extra,
        )
