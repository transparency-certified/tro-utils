"""TROAttribute model.

Represents a TRO-level attribute warranted by a performance attribute.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._base import TROVModel


@dataclass
class TROAttribute(TROVModel):
    """A TRO-level attribute (e.g. ``trov:IncludesAllInputData``).

    TRO attributes are warranted by one or more
    :class:`~tro_utils.models.performance.PerformanceAttribute` instances.
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
    def from_jsonld(cls, data: dict[str, Any]) -> "TROAttribute":
        """Deserialise from a JSON-LD TRO attribute dict.

        Args:
            data: Dict with ``@id``, ``@type``, ``trov:warrantedBy``.

        Returns:
            :class:`TROAttribute` instance.
        """
        return cls(
            attribute_id=data["@id"],
            attribute_type=data["@type"],
            warranted_by_id=data["trov:warrantedBy"]["@id"],
        )
