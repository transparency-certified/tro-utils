"""Tests for the ReplicationPackage class using the model API."""

import zipfile

import pytest

from tro_utils.models import ArtifactArrangement, ArtifactComposition
from tro_utils.replication_package import ReplicationPackage, VerificationResult


class TestReplicationPackageModel:
    """Tests for the ReplicationPackage class using the model API."""

    def test_verify_directory_matches(self, tmp_path):
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "file.txt").write_text("hello")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        result = ReplicationPackage.verify(arr, comp, workdir)
        assert result.is_valid
        assert not result.files_missing_in_arrangement
        assert not result.mismatched_hashes
        assert not result.files_missing_in_package

    def test_verify_missing_file_in_package(self, tmp_path):
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "file.txt").write_text("hello")
        (workdir / "extra.txt").write_text("world")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        # Remove one file from package before verifying
        (workdir / "extra.txt").unlink()

        result = ReplicationPackage.verify(arr, comp, workdir)
        assert not result.is_valid
        assert "extra.txt" in result.files_missing_in_package

    def test_verify_extra_file_in_package(self, tmp_path):
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "file.txt").write_text("hello")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        # Add a new file not in the arrangement
        (workdir / "unexpected.txt").write_text("surprise")

        result = ReplicationPackage.verify(arr, comp, workdir)
        assert not result.is_valid
        assert "unexpected.txt" in result.files_missing_in_arrangement

    def test_verify_zip_matches(self, tmp_path):
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "data.csv").write_text("a,b\n1,2\n")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        # Package into a zip
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(workdir / "data.csv", "data.csv")

        result = ReplicationPackage.verify(arr, comp, zip_path)
        assert result.is_valid

    def test_verify_zip_with_subpath(self, tmp_path):
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "data.csv").write_text("a,b\n1,2\n")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        # Package into zip with a prefix subpath
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(workdir / "data.csv", "subdir/data.csv")

        result = ReplicationPackage.verify(arr, comp, zip_path, subpath="subdir")
        assert result.is_valid

    def test_verification_result_is_valid_property(self):
        ok = VerificationResult()
        assert ok.is_valid

        bad = VerificationResult(files_missing_in_arrangement=["x"])
        assert not bad.is_valid
