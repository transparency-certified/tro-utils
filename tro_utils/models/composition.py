"""ArtifactComposition and CompositionFingerprint models."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from ._base import TROVModel
from .artifact import ResearchArtifact
from .hash_value import HashValue


@dataclass(frozen=True)
class CompositionFingerprint(TROVModel):
    """SHA-256 fingerprint over the sorted artifact hashes in a composition."""

    hash: HashValue

    @classmethod
    def compute(cls, artifacts: list[ResearchArtifact]) -> "CompositionFingerprint":
        """Compute the fingerprint for a list of artifacts.

        The fingerprint is sha256 of the sorted, concatenated artifact hash values,
        matching the existing ``TRO.calculate_fingerprint`` logic.

        Args:
            artifacts: List of :class:`ResearchArtifact` to fingerprint.

        Returns:
            A new :class:`CompositionFingerprint`.
        """
        hash_values = sorted(a.hash.value for a in artifacts)
        digest = hashlib.sha256("".join(hash_values).encode("utf-8")).hexdigest()
        return cls(hash=HashValue(algorithm="sha256", value=digest))

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        return {
            "@id": "fingerprint",
            "@type": "trov:CompositionFingerprint",
            "trov:hash": self.hash.to_jsonld(),
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "CompositionFingerprint":
        return cls(hash=HashValue.from_jsonld(data["trov:hash"]))


@dataclass
class ArtifactComposition(TROVModel):
    """Registry of all unique :class:`ResearchArtifact` objects in a TRO."""

    composition_id: str = "composition/1"
    artifacts: list[ResearchArtifact] = field(default_factory=list)
    fingerprint: CompositionFingerprint | None = None

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_artifact(self, artifact: ResearchArtifact) -> None:
        """Append *artifact* and recompute the fingerprint.

        Args:
            artifact: The artifact to add.
        """
        self.artifacts.append(artifact)
        self._recompute_fingerprint()

    def _recompute_fingerprint(self) -> None:
        self.fingerprint = CompositionFingerprint.compute(self.artifacts)

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def get_by_hash(self, hash_str: str) -> ResearchArtifact | None:
        """Return the artifact whose hash string matches *hash_str*, or ``None``.

        Args:
            hash_str: Hash string in ``"<algorithm>:<value>"`` form.
        """
        for artifact in self.artifacts:
            if artifact.hash.to_string() == hash_str:
                return artifact
        return None

    def get_by_id(self, artifact_id: str) -> ResearchArtifact | None:
        """Return the artifact with the given ``@id``, or ``None``."""
        for artifact in self.artifacts:
            if artifact.artifact_id == artifact_id:
                return artifact
        return None

    def next_artifact_id(self) -> str:
        """Return the next sequential artifact ``@id``."""
        return f"{self.composition_id}/artifact/{len(self.artifacts)}"

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "@id": self.composition_id,
            "@type": "trov:ArtifactComposition",
            "trov:hasArtifact": sorted(
                [a.to_jsonld() for a in self.artifacts],
                key=lambda x: x["@id"],
            ),
        }
        if self.fingerprint:
            result["trov:hasFingerprint"] = self.fingerprint.to_jsonld()
        return result

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "ArtifactComposition":
        """Deserialise from a JSON-LD composition dict.

        Args:
            data: Dict with ``@id``, ``trov:hasArtifact`` list, and optional fingerprint.

        Returns:
            :class:`ArtifactComposition` instance.
        """
        artifacts = [
            ResearchArtifact.from_jsonld(a) for a in data.get("trov:hasArtifact", [])
        ]
        fingerprint = None
        if "trov:hasFingerprint" in data:
            fingerprint = CompositionFingerprint.from_jsonld(
                data["trov:hasFingerprint"]
            )

        obj = cls(
            composition_id=data.get("@id", "composition/1"),
            artifacts=artifacts,
            fingerprint=fingerprint,
        )
        return obj
