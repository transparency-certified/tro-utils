"""ResearchArtifact model.

Represents a single research artifact (file) tracked within a TRO
composition, including its content hash and MIME type.
"""

from __future__ import annotations

import hashlib
import pathlib
from dataclasses import dataclass
from typing import Any

from ._base import TROVModel
from .hash_value import HashValue


@dataclass
class ResearchArtifact(TROVModel):
    """A single research artifact stored in an :class:`ArtifactComposition`."""

    artifact_id: str
    hash: HashValue
    mime_type: str

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_file(
        cls, path: str | pathlib.Path, artifact_id: str
    ) -> "ResearchArtifact":
        """Create a ``ResearchArtifact`` by hashing a file on disk.

        Args:
            path: Absolute or relative path to the file.
            artifact_id: The ``@id`` to assign (e.g. ``"composition/1/artifact/3"``).

        Returns:
            A new :class:`ResearchArtifact`.

        Raises:
            FileNotFoundError: If *path* does not point to an existing regular file.
        """
        import magic  # local import — optional dep

        p = pathlib.Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Not a regular file: {p}")

        sha256 = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)

        hash_value = HashValue(algorithm="sha256", value=sha256.hexdigest())

        if p.is_symlink():
            mime_type = "inode/symlink"
        else:
            magic_wrapper = magic.Magic(mime=True, uncompress=True)
            mime_type = magic_wrapper.from_file(str(p)) or "application/octet-stream"

        return cls(artifact_id=artifact_id, hash=hash_value, mime_type=mime_type)

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        return {
            "@id": self.artifact_id,
            "@type": "trov:ResearchArtifact",
            "trov:hash": self.hash.to_jsonld(),
            "trov:mimeType": self.mime_type,
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "ResearchArtifact":
        """Deserialise from a JSON-LD artifact dict.

        Args:
            data: Dict with ``@id``, ``trov:hash``/``trov:sha256``, ``trov:mimeType``.

        Returns:
            :class:`ResearchArtifact` instance.
        """
        # Support both new trov:hash and legacy trov:sha256
        if "trov:hash" in data:
            h = HashValue.from_jsonld(data["trov:hash"])
        elif "trov:sha256" in data:
            h = HashValue(algorithm="sha256", value=data["trov:sha256"])
        else:
            raise ValueError(f"Artifact has no recognisable hash field: {data!r}")

        return cls(
            artifact_id=data["@id"],
            hash=h,
            mime_type=data.get("trov:mimeType", "application/octet-stream"),
        )
