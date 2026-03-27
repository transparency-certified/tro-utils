"""TrustedResearchSystem and TRSCapability models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ._base import TROVModel

# Profile keys that are handled as typed fields on TrustedResearchSystem;
# all other keys are stored verbatim in ``extra_fields``.
_KNOWN_TRS_KEYS = {
    "@id",
    "@type",
    "schema:name",
    "schema:description",
    "trov:publicKey",
    "trov:hasCapability",
}


@dataclass
class TRSCapability(TROVModel):
    """A single capability declared by a :class:`TrustedResearchSystem`."""

    capability_id: str
    capability_type: str

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        return {
            "@id": self.capability_id,
            "@type": self.capability_type,
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "TRSCapability":
        return cls(
            capability_id=data["@id"],
            capability_type=data["@type"],
        )


@dataclass
class TrustedResearchSystem(TROVModel):
    """A Trusted Research System (TRS) that assembled and/or ran a TRO.

    Unknown profile fields (e.g. ``trov:name``, ``trov:owner``, etc.) are
    stored in :attr:`extra_fields` and round-tripped verbatim through
    ``to_jsonld()`` / ``from_jsonld()``.
    """

    trs_id: str = "trs"
    name: str = ""
    description: str = ""
    public_key: str | None = None
    capabilities: list[TRSCapability] = field(default_factory=list)
    extra_fields: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_profile(
        cls, profile: dict[str, Any], trs_id: str = "trs"
    ) -> "TrustedResearchSystem":
        """Load a TRS from the profile dict used by the existing CLI.

        The profile format mirrors what is stored under ``trov:wasAssembledBy``
        in a JSON-LD document (minus the ``@id`` / ``@type`` keys).
        All unrecognised keys are preserved in :attr:`extra_fields`.

        Args:
            profile: Dict with optional keys ``schema:name``,
                ``schema:description``, ``trov:publicKey``,
                ``trov:hasCapability``, plus any vendor-specific fields.
            trs_id: The ``@id`` to use for this TRS.

        Returns:
            :class:`TrustedResearchSystem` instance.
        """
        capabilities = [
            TRSCapability.from_jsonld(cap)
            for cap in profile.get("trov:hasCapability", [])
        ]
        extra = {k: v for k, v in profile.items() if k not in _KNOWN_TRS_KEYS}
        return cls(
            trs_id=trs_id,
            name=profile.get("schema:name", ""),
            description=profile.get("schema:description", ""),
            public_key=profile.get("trov:publicKey"),
            capabilities=capabilities,
            extra_fields=extra,
        )

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "@id": self.trs_id,
            "@type": ["trov:TrustedResearchSystem", "schema:Organization"],
            "trov:hasCapability": [cap.to_jsonld() for cap in self.capabilities],
        }
        # Merge extra (vendor) fields first so typed fields can override
        result.update(self.extra_fields)
        if self.name:
            result["schema:name"] = self.name
        if self.description:
            result["schema:description"] = self.description
        if self.public_key is not None:
            result["trov:publicKey"] = self.public_key
        return result

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "TrustedResearchSystem":
        """Deserialise from a JSON-LD TRS dict (``trov:wasAssembledBy`` value).

        Args:
            data: Dict with ``@id``, optional ``schema:name``, etc.

        Returns:
            :class:`TrustedResearchSystem` instance.
        """
        capabilities = [
            TRSCapability.from_jsonld(cap) for cap in data.get("trov:hasCapability", [])
        ]
        extra = {k: v for k, v in data.items() if k not in _KNOWN_TRS_KEYS}
        return cls(
            trs_id=data.get("@id", "trs"),
            name=data.get("schema:name", ""),
            description=data.get("schema:description", ""),
            public_key=data.get("trov:publicKey"),
            capabilities=capabilities,
            extra_fields=extra,
        )
