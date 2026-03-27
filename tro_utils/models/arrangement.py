"""ArtifactArrangement and ArtifactLocation models.

An arrangement is a snapshot of file locations at a particular point in time,
linking each file path to a :class:`~tro_utils.models.artifact.ResearchArtifact`
stored in the :class:`~tro_utils.models.composition.ArtifactComposition`.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any

from ._base import TROVModel
from .artifact import ResearchArtifact
from .composition import ArtifactComposition


@dataclass
class ArtifactLocation(TROVModel):
    """A single (path, artifact) binding within an arrangement."""

    location_id: str
    artifact_id: str
    path: str

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
        """Return a ``{relative_path: "sha256:<hex>"}`` binding.

        Requires the corresponding :class:`ArtifactComposition` to resolve
        artifact IDs to hash strings.

        Args:
            composition: The composition that owns the artifacts referenced here.

        Returns:
            Dict mapping relative file path to hash string.
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

    # ------------------------------------------------------------------
    # Snapshot serialisation / deserialisation
    # ------------------------------------------------------------------

    def to_snapshot(self, composition: ArtifactComposition) -> dict[str, Any]:
        """Serialise this arrangement and its referenced artifacts as a standalone dict.

        The returned structure is self-contained: it embeds the subset of
        *composition* artifacts that are referenced by this arrangement so the
        snapshot can be loaded into a different TRO without the original
        composition.

        Args:
            composition: The composition that owns the artifacts referenced by
                this arrangement.

        Returns:
            A JSON-serialisable dict.
        """
        artifact_ids = {loc.artifact_id for loc in self.locations}
        artifacts = [
            a.to_jsonld()
            for a in composition.artifacts
            if a.artifact_id in artifact_ids
        ]
        return {
            "@type": "trov:ArrangementSnapshot",
            "rdfs:comment": self.comment,
            "trov:hasArtifactLocation": [loc.to_jsonld() for loc in self.locations],
            "trov:hasArtifact": artifacts,
        }

    def save_snapshot(
        self, filepath: str | pathlib.Path, composition: ArtifactComposition
    ) -> None:
        """Write this arrangement as a standalone snapshot JSON-LD file.

        Args:
            filepath: Destination path (will be created/overwritten).
            composition: The composition that owns the referenced artifacts.
        """
        with open(filepath, "w") as f:
            json.dump(self.to_snapshot(composition), f, indent=2, sort_keys=True)

    @classmethod
    def from_snapshot(
        cls,
        data: dict[str, Any],
        target_composition: ArtifactComposition,
        arrangement_id: str,
        comment: str | None = None,
    ) -> "ArtifactArrangement":
        """Merge snapshot data into *target_composition* and return a new arrangement.

        Artifacts are matched by content hash so duplicates are never inserted.
        Location IDs are rewritten to fit the new *arrangement_id*.

        Args:
            data: Dict previously produced by :meth:`to_snapshot`.
            target_composition: The composition to merge artifacts into.
            arrangement_id: The ``@id`` to assign to the new arrangement.
            comment: Override the comment stored in *data* when provided.

        Returns:
            A new :class:`ArtifactArrangement` whose locations point to
            artifacts in *target_composition*.
        """
        from .artifact import ResearchArtifact

        # Build a local lookup: snapshot-local artifact @id to ResearchArtifact
        snap_artifacts: dict[str, ResearchArtifact] = {
            art_data["@id"]: ResearchArtifact.from_jsonld(art_data)
            for art_data in data.get("trov:hasArtifact", [])
        }

        # Merge each snapshot artifact into the target composition, tracking IDs
        id_remap: dict[str, str] = {}  # snapshot_id to target composition id
        for snap_id, artifact in snap_artifacts.items():
            hash_str = artifact.hash.to_string()
            existing = target_composition.get_by_hash(hash_str)
            if existing is not None:
                id_remap[snap_id] = existing.artifact_id
            else:
                new_id = target_composition.next_artifact_id()
                target_composition.add_artifact(
                    ResearchArtifact(
                        artifact_id=new_id,
                        hash=artifact.hash,
                        mime_type=artifact.mime_type,
                    )
                )
                id_remap[snap_id] = new_id

        # Rebuild locations with remapped artifact IDs
        locations: list[ArtifactLocation] = []
        for i, loc_data in enumerate(data.get("trov:hasArtifactLocation", [])):
            snap_art_id = loc_data["trov:artifact"]["@id"]
            locations.append(
                ArtifactLocation(
                    location_id=f"{arrangement_id}/location/{i}",
                    artifact_id=id_remap[snap_art_id],
                    path=loc_data["trov:path"],
                )
            )

        return cls(
            arrangement_id=arrangement_id,
            comment=comment if comment is not None else data.get("rdfs:comment", ""),
            locations=locations,
        )

    @classmethod
    def load_snapshot(
        cls,
        filepath: str | pathlib.Path,
        target_composition: ArtifactComposition,
        arrangement_id: str,
        comment: str | None = None,
    ) -> "ArtifactArrangement":
        """Load a snapshot file and merge it into *target_composition*.

        Args:
            filepath: Path to a JSON-LD snapshot file previously saved with
                :meth:`save_snapshot`.
            target_composition: The composition to merge artifacts into.
            arrangement_id: The ``@id`` to assign to the new arrangement.
            comment: Override the comment stored in the file when provided.

        Returns:
            A new :class:`ArtifactArrangement`.
        """
        with open(filepath) as f:
            data = json.load(f)
        return cls.from_snapshot(data, target_composition, arrangement_id, comment)
