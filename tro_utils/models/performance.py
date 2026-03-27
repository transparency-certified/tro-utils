"""TrustedResearchPerformance and PerformanceAttribute models."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

from ._base import TROVModel


@dataclass
class PerformanceAttribute(TROVModel):
    """A single attribute of a :class:`TrustedResearchPerformance`.

    Warranted by a :class:`~tro_utils.models.trs.TRSCapability`.
    """

    attribute_id: str
    attribute_type: str
    warranted_by_id: str

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        return {
            "@id": self.attribute_id,
            "@type": self.attribute_type,
            "trov:warrantedBy": {"@id": self.warranted_by_id},
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "PerformanceAttribute":
        return cls(
            attribute_id=data["@id"],
            attribute_type=data["@type"],
            warranted_by_id=data["trov:warrantedBy"]["@id"],
        )


@dataclass
class TrustedResearchPerformance(TROVModel):
    """A record of a single execution run within a TRO."""

    performance_id: str
    comment: str = ""
    conducted_by_id: str = "trs"
    started_at: datetime.datetime | None = None
    ended_at: datetime.datetime | None = None
    accessed_arrangement_id: str | None = None
    contributed_to_arrangement_id: str | None = None
    attributes: list[PerformanceAttribute] = field(default_factory=list)

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "@id": self.performance_id,
            "@type": "trov:TrustedResearchPerformance",
            "rdfs:comment": self.comment,
            "trov:wasConductedBy": {"@id": self.conducted_by_id},
            "trov:hasPerformanceAttribute": [
                attr.to_jsonld() for attr in self.attributes
            ],
        }
        if self.started_at is not None:
            result["trov:startedAtTime"] = self.started_at.isoformat()
        if self.ended_at is not None:
            result["trov:endedAtTime"] = self.ended_at.isoformat()
        if self.accessed_arrangement_id is not None:
            result["trov:accessedArrangement"] = {"@id": self.accessed_arrangement_id}
        if self.contributed_to_arrangement_id is not None:
            result["trov:contributedToArrangement"] = {
                "@id": self.contributed_to_arrangement_id
            }
        return result

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "TrustedResearchPerformance":
        """Deserialise from a JSON-LD performance dict.

        Args:
            data: Dict with ``@id``, optional timing keys, arrangement refs, etc.

        Returns:
            :class:`TrustedResearchPerformance` instance.
        """

        def _parse_dt(value: str | None) -> datetime.datetime | None:
            if value is None:
                return None
            return datetime.datetime.fromisoformat(value)

        attributes = [
            PerformanceAttribute.from_jsonld(attr)
            for attr in data.get("trov:hasPerformanceAttribute", [])
        ]

        accessed = data.get("trov:accessedArrangement")
        contributed = data.get("trov:contributedToArrangement")

        return cls(
            performance_id=data["@id"],
            comment=data.get("rdfs:comment", ""),
            conducted_by_id=data.get("trov:wasConductedBy", {}).get("@id", "trs"),
            started_at=_parse_dt(data.get("trov:startedAtTime")),
            ended_at=_parse_dt(data.get("trov:endedAtTime")),
            accessed_arrangement_id=accessed["@id"] if accessed else None,
            contributed_to_arrangement_id=contributed["@id"] if contributed else None,
            attributes=attributes,
        )
