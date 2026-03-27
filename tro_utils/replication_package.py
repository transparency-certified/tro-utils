"""ReplicationPackage — verifies a research package against a TRO arrangement.

Provides a standalone :class:`ReplicationPackage` class for verifying that a
directory or zip archive matches the file-hash mapping recorded in an
:class:`~tro_utils.models.arrangement.ArtifactArrangement`.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import zipfile
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class VerificationResult:
    """Result of a :meth:`ReplicationPackage.verify` call."""

    files_missing_in_arrangement: list[str] = field(default_factory=list)
    mismatched_hashes: list[tuple[str, str | None, str]] = field(default_factory=list)
    files_missing_in_package: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """``True`` when all checks pass."""
        return not (
            self.files_missing_in_arrangement
            or self.mismatched_hashes
            or self.files_missing_in_package
        )


class ReplicationPackage:
    """Verify a research package (directory or zip) against an arrangement.

    Example::

        from tro_utils.models import TransparentResearchObject
        from tro_utils.replication_package import ReplicationPackage

        tro = TransparentResearchObject.load("my_tro.jsonld")
        arrangement = tro.arrangements[1]           # "after execution" snapshot
        result = ReplicationPackage.verify(
            arrangement, tro.composition, "path/to/package"
        )
        if result.is_valid:
            print("Package matches arrangement.")
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def verify(
        cls,
        arrangement,
        composition,
        package: str | pathlib.Path,
        subpath: str | None = None,
    ) -> VerificationResult:
        """Verify *package* against *arrangement*.

        Args:
            arrangement: :class:`~tro_utils.models.arrangement.ArtifactArrangement`
                to compare against.
            composition: :class:`~tro_utils.models.composition.ArtifactComposition`
                that owns the artifact hashes.
            package: Path to a directory or ``.zip`` file to inspect.
            subpath: If set, only package entries whose path starts with
                *subpath* are considered (relative to *subpath* after stripping).

        Returns:
            A :class:`VerificationResult` describing any discrepancies.
        """
        arrangement_map: dict[str, str] = arrangement.to_path_hash_map(composition)
        result = VerificationResult()

        for rel_filename, file_hash in cls._iterate_package_files(package, subpath):
            if rel_filename not in arrangement_map:
                result.files_missing_in_arrangement.append(rel_filename)

            expected_hash = arrangement_map.pop(rel_filename, None)
            if file_hash != expected_hash:
                result.mismatched_hashes.append(
                    (rel_filename, expected_hash, file_hash)
                )

        # Files present in the arrangement but absent from the package
        result.files_missing_in_package = list(arrangement_map.keys())
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iterate_package_files(
        package: str | pathlib.Path,
        subpath: str | None,
    ) -> Iterator[tuple[str, str]]:
        """Yield ``(relative_path, "sha256:<hex>")`` pairs from *package*.

        Args:
            package: Directory or zip archive path.
            subpath: Optional path prefix to strip (directories inside zip).

        Yields:
            Tuples of ``(relative_filename, hash_string)``.
        """
        package = pathlib.Path(package)
        if package.is_dir():
            yield from ReplicationPackage._iter_directory(package, subpath)
        else:
            yield from ReplicationPackage._iter_zip(package, subpath)

    @staticmethod
    def _iter_directory(
        root: pathlib.Path,
        subpath: str | None,
    ) -> Iterator[tuple[str, str]]:
        for dirpath, _dirs, files in os.walk(root):
            for filename in files:
                filepath = pathlib.Path(dirpath) / filename
                original = filepath.relative_to(root).as_posix()
                rel = ReplicationPackage._apply_subpath(original, subpath)
                if rel is None:
                    continue
                hash_str = ReplicationPackage._sha256_file(filepath)
                yield rel, hash_str

    @staticmethod
    def _iter_zip(
        zip_path: pathlib.Path,
        subpath: str | None,
    ) -> Iterator[tuple[str, str]]:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for fileinfo in zf.infolist():
                rel = ReplicationPackage._apply_subpath(fileinfo.filename, subpath)
                if rel is None:
                    continue
                sha256 = hashlib.sha256()
                with zf.open(fileinfo.filename) as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256.update(chunk)
                yield rel, f"sha256:{sha256.hexdigest()}"

    @staticmethod
    def _apply_subpath(original: str, subpath: str | None) -> str | None:
        """Strip *subpath* prefix from *original*, or return ``None`` to skip."""
        if subpath is None:
            return original
        import pathlib as _pl

        orig = _pl.PurePosixPath(original)
        sub = _pl.PurePosixPath(subpath)
        try:
            return orig.relative_to(sub).as_posix()
        except ValueError:
            return None

    @staticmethod
    def _sha256_file(filepath: pathlib.Path) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return f"sha256:{sha256.hexdigest()}"
