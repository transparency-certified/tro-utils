"""TrustedResearchPerformance and PerformanceAttribute models."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

from ._base import TROVModel


@dataclass
class ArrangementRef(TROVModel):
    """A reference to an :class:`~tro_utils.models.arrangement.ArtifactArrangement`.

    Used by :class:`TrustedResearchPerformance` to record which arrangements
    were accessed or contributed to.  ``path`` indicates the mount / working
    directory that arrangement paths are relative to.
    """

    arrangement_id: str
    path: str | None = None

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        result: dict[str, Any] = {"@id": self.arrangement_id}
        if self.path is not None:
            result["trov:mountPath"] = self.path
        return result

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "ArrangementRef":
        return cls(
            arrangement_id=data["@id"],
            path=data.get("trov:mountPath"),
        )


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
    accessed_arrangements: list[ArrangementRef] = field(default_factory=list)
    contributed_to_arrangements: list[ArrangementRef] = field(default_factory=list)
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
        if len(self.accessed_arrangements) == 1:
            result["trov:accessedArrangement"] = self.accessed_arrangements[
                0
            ].to_jsonld()
        elif len(self.accessed_arrangements) > 1:
            result["trov:accessedArrangement"] = [
                ref.to_jsonld() for ref in self.accessed_arrangements
            ]
        if len(self.contributed_to_arrangements) == 1:
            result["trov:contributedToArrangement"] = self.contributed_to_arrangements[
                0
            ].to_jsonld()
        elif len(self.contributed_to_arrangements) > 1:
            result["trov:contributedToArrangement"] = [
                ref.to_jsonld() for ref in self.contributed_to_arrangements
            ]
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

        def _parse_refs(value: Any) -> list[ArrangementRef]:
            if value is None:
                return []
            if isinstance(value, list):
                return [ArrangementRef.from_jsonld(item) for item in value]
            return [ArrangementRef.from_jsonld(value)]

        return cls(
            performance_id=data["@id"],
            comment=data.get("rdfs:comment", ""),
            conducted_by_id=data.get("trov:wasConductedBy", {}).get("@id", "trs"),
            started_at=_parse_dt(data.get("trov:startedAtTime")),
            ended_at=_parse_dt(data.get("trov:endedAtTime")),
            accessed_arrangements=_parse_refs(data.get("trov:accessedArrangement")),
            contributed_to_arrangements=_parse_refs(
                data.get("trov:contributedToArrangement")
            ),
            attributes=attributes,
        )
