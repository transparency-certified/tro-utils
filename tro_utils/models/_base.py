"""Abstract base class for all TRO data model objects."""

from __future__ import annotations

import datetime
from abc import ABC, abstractmethod
from typing import Any


def ensure_aware(value: datetime.datetime | None) -> datetime.datetime | None:
    """Return *value* as a timezone-aware datetime.

    Every timestamp recorded in a TRO must be unambiguous, so naive datetimes
    are assumed to denote local wall-clock time and get the system's current
    UTC offset attached.  Values that already carry a ``tzinfo`` (and ``None``)
    pass through untouched.

    Args:
        value: A datetime to normalise, or ``None``.

    Returns:
        A timezone-aware datetime for the same instant, or ``None``.
    """
    if value is None or value.tzinfo is not None:
        return value
    return value.astimezone()


def aware_now() -> datetime.datetime:
    """Return the current local time as a timezone-aware datetime."""
    return datetime.datetime.now().astimezone()


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
