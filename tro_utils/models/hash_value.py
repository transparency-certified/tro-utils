"""HashValue value object.

Wraps an (algorithm, value) pair and handles the ``"sha256:abc..."``
string format used throughout the JSON-LD documents.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._base import TROVModel


@dataclass(frozen=True)
class HashValue(TROVModel):
    """Immutable (algorithm, hex-value) pair."""

    algorithm: str
    value: str

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_string(cls, s: str) -> "HashValue":
        """Parse ``"<algorithm>:<hex>"`` string (e.g. ``"sha256:abc..."``).

        Args:
            s: Colon-separated algorithm + hex value string.

        Returns:
            HashValue instance.

        Raises:
            ValueError: If the string is not in the expected format.
        """
        if ":" not in s:
            raise ValueError(f"Expected '<algorithm>:<value>' format, got: {s!r}")
        algorithm, value = s.split(":", 1)
        return cls(algorithm=algorithm, value=value)

    # ------------------------------------------------------------------
    # String representation
    # ------------------------------------------------------------------

    def to_string(self) -> str:
        """Return ``"<algorithm>:<hex>"`` form."""
        return f"{self.algorithm}:{self.value}"

    def __str__(self) -> str:  # noqa: D105
        return self.to_string()

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        """Serialise to ``{"trov:hashAlgorithm": ..., "trov:hashValue": ...}``."""
        return {
            "trov:hashAlgorithm": self.algorithm,
            "trov:hashValue": self.value,
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any] | list | str) -> "HashValue":
        """Deserialise from several supported JSON-LD hash shapes.

        Handles:
        * ``{"trov:hashAlgorithm": str, "trov:hashValue": str}``
        * ``[{"trov:hashAlgorithm": ..., "trov:hashValue": ...}, ...]``  — first sha256 wins
        * ``{"trov:sha256": str}``  — legacy format
        * ``"sha256:abc..."``  — plain string

        Args:
            data: JSON-LD hash representation.

        Returns:
            HashValue instance.
        """
        if isinstance(data, str):
            return cls.from_string(data)

        if isinstance(data, list):
            # Prefer sha256 if present in the list
            for entry in data:
                if entry.get("trov:hashAlgorithm") == "sha256":
                    return cls.from_jsonld(entry)
            return cls.from_jsonld(data[0])

        if "trov:hashAlgorithm" in data and "trov:hashValue" in data:
            return cls(
                algorithm=data["trov:hashAlgorithm"],
                value=data["trov:hashValue"],
            )

        if "trov:sha256" in data:
            return cls(algorithm="sha256", value=data["trov:sha256"])

        raise ValueError(f"Unrecognised hash JSON-LD shape: {data!r}")
