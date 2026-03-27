"""ArtifactArrangement and ArtifactLocation models.

An arrangement is a snapshot of file locations at a particular point in time,
linking each file path to a :class:`~tro_utils.models.artifact.ResearchArtifact`
stored in the :class:`~tro_utils.models.composition.ArtifactComposition`.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any

from ._base import TROVModel
from .artifact import ResearchArtifact
from .composition import ArtifactComposition


@dataclass
class ArtifactLocation(TROVModel):
    """A single (path, artifact) mapping within an arrangement."""

    location_id: str
    artifact_id: str
    path: str

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        return {
            "@id": self.location_id,
            "@type": "trov:ArtifactLocation",
            "trov:artifact": {"@id": self.artifact_id},
            "trov:path": self.path,
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "ArtifactLocation":
        return cls(
            location_id=data["@id"],
            artifact_id=data["trov:artifact"]["@id"],
            path=data["trov:path"],
        )


@dataclass
class ArtifactArrangement(TROVModel):
    """A snapshot of all artifact locations at a given point in time."""

    arrangement_id: str
    comment: str = ""
    locations: list[ArtifactLocation] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_directory(
        cls,
        directory: str | pathlib.Path,
        composition: ArtifactComposition,
        arrangement_id: str,
        comment: str | None = None,
        ignore_dirs: list[str] | None = None,
        resolve_symlinks: bool = True,
    ) -> "ArtifactArrangement":
        """Scan *directory* and create an arrangement, updating *composition* in place.

        New files are added to *composition*; existing files (by hash) are reused.
        This mirrors the logic in ``TRO.add_arrangement``.

        Args:
            directory: Root directory to scan.
            composition: The :class:`ArtifactComposition` to add new artifacts to.
            arrangement_id: The ``@id`` for this arrangement (e.g. ``"arrangement/1"``).
            comment: Human-readable description of this arrangement snapshot.
            ignore_dirs: Directory names to skip (default: ``[".git"]``).
            resolve_symlinks: Whether to follow symlinks when walking the tree.

        Returns:
            A new :class:`ArtifactArrangement`.
        """
        import magic  # local import

        if ignore_dirs is None:
            ignore_dirs = [".git"]
        if comment is None:
            comment = f"Scanned {directory}"

        directory = pathlib.Path(directory)
        magic_wrapper = magic.Magic(mime=True, uncompress=True)

        # Collect sha256 for all files in the directory
        file_hashes: dict[pathlib.Path, str] = {}
        for root, dirs, files in os.walk(str(directory)):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for filename in files:
                filepath = pathlib.Path(root) / filename
                hash_str = cls._sha256_for_file(str(filepath), resolve_symlinks)
                file_hashes[filepath] = hash_str

        # Add any new artifacts to the composition
        for filepath, hash_str in file_hashes.items():
            if composition.get_by_hash(hash_str) is None:
                artifact_id = composition.next_artifact_id()
                if filepath.is_symlink():
                    mime_type = "inode/symlink"
                else:
                    mime_type = (
                        magic_wrapper.from_file(str(filepath))
                        or "application/octet-stream"
                    )
                from .hash_value import HashValue

                algorithm, value = hash_str.split(":", 1)
                artifact = ResearchArtifact(
                    artifact_id=artifact_id,
                    hash=HashValue(algorithm=algorithm, value=value),
                    mime_type=mime_type,
                )
                composition.add_artifact(artifact)

        # Build locations
        locations: list[ArtifactLocation] = []
        for i, (filepath, hash_str) in enumerate(file_hashes.items()):
            artifact = composition.get_by_hash(hash_str)
            assert artifact is not None  # guaranteed by the loop above
            rel_path = filepath.relative_to(directory).as_posix()
            locations.append(
                ArtifactLocation(
                    location_id=f"{arrangement_id}/location/{i}",
                    artifact_id=artifact.artifact_id,
                    path=rel_path,
                )
            )

        return cls(
            arrangement_id=arrangement_id,
            comment=comment,
            locations=locations,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sha256_for_file(filepath: str, resolve_symlinks: bool = True) -> str:
        """Return ``"sha256:<hex>"`` for *filepath*, or ``"none:"`` for symlinks/non-files."""
        p = pathlib.Path(filepath)
        if not p.is_file() or p.is_symlink():
            return "none:"
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return f"sha256:{sha256.hexdigest()}"

    def to_path_hash_map(self, composition: ArtifactComposition) -> dict[str, str]:
        """Return a ``{relative_path: "sha256:<hex>"}`` mapping.

        Requires the corresponding :class:`ArtifactComposition` to resolve
        artifact IDs to hash strings.

        Args:
            composition: The composition that owns the artifacts referenced here.

        Returns:
            Dict mapping relative file path → hash string.
        """
        result: dict[str, str] = {}
        for location in self.locations:
            artifact = composition.get_by_id(location.artifact_id)
            if artifact is not None:
                result[location.path] = artifact.hash.to_string()
        return result

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        return {
            "@id": self.arrangement_id,
            "@type": "trov:ArtifactArrangement",
            "rdfs:comment": self.comment,
            "trov:hasArtifactLocation": [loc.to_jsonld() for loc in self.locations],
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "ArtifactArrangement":
        """Deserialise from a JSON-LD arrangement dict.

        Args:
            data: Dict with ``@id``, ``rdfs:comment``, ``trov:hasArtifactLocation``.

        Returns:
            :class:`ArtifactArrangement` instance.
        """
        locations = [
            ArtifactLocation.from_jsonld(loc)
            for loc in data.get("trov:hasArtifactLocation", [])
        ]
        return cls(
            arrangement_id=data["@id"],
            comment=data.get("rdfs:comment", ""),
            locations=locations,
        )
