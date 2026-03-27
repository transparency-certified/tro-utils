"""Abstract base class for all TRO data model objects."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class TROVModel(ABC):
    """Abstract base for all TROV model objects.

    Every concrete subclass must implement ``to_jsonld()`` and ``from_jsonld()``
    to support full JSON-LD round-trip serialisation.
    """

    @abstractmethod
    def to_jsonld(self) -> dict[str, Any]:
        """Serialise this object to a JSON-LD compatible dict."""

    @classmethod
    @abstractmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "TROVModel":
        """Deserialise an instance from a JSON-LD compatible dict."""
