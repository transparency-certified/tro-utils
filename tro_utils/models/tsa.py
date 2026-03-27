"""TimeStampingAuthority model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._base import TROVModel


@dataclass
class TimeStampingAuthority(TROVModel):
    """A Time Stamping Authority (TSA) that signed a TRO timestamp."""

    tsa_id: str = "tsa"
    public_key: str | None = None

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "@id": self.tsa_id,
            "@type": "trov:TimeStampingAuthority",
        }
        if self.public_key is not None:
            result["trov:publicKey"] = self.public_key
        return result

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "TimeStampingAuthority":
        """Deserialise from a JSON-LD TSA dict (``trov:wasTimestampedBy`` value).

        Args:
            data: Dict with ``@id`` and optional ``trov:publicKey``.

        Returns:
            :class:`TimeStampingAuthority` instance.
        """
        return cls(
            tsa_id=data.get("@id", "tsa"),
            public_key=data.get("trov:publicKey"),
        )
