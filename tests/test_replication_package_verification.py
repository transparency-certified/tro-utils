"""Tests for verification of replication packages against TRO arrangements."""

import pytest

from tests.helpers import create_tro_with_gpg


class TestReplicationPackageVerification:
    """Test verification of replication packages against arrangements."""

    def test_verify_identical_directory(self, temp_workspace, tmp_path, gpg_setup):
        """Test verifying a directory that exactly matches the arrangement."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Verify the same directory
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should be identical
        assert is_valid is True
        assert len(missing) == 0
        assert len(mismatched) == 0
        assert len(extra) == 0

    def test_verify_directory_with_modified_file(
        self, temp_workspace, tmp_path, gpg_setup
    ):
        """Test verifying a directory where a file has been modified."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Modify a file in the workspace
        (temp_workspace / "notes.txt").write_text("Modified content\n")

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should detect mismatch
        assert is_valid is False
        assert len(missing) == 0
        assert len(mismatched) == 1
        assert mismatched[0][0] == "notes.txt"  # filename
        assert len(extra) == 0

    def test_verify_directory_with_extra_file(
        self, temp_workspace, tmp_path, gpg_setup
    ):
        """Test verifying a directory with an extra file not in arrangement."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Add a new file
        (temp_workspace / "extra_file.txt").write_text("Extra content\n")

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should detect the extra file as missing in arrangement
        # Also appears in mismatched because expected_hash is None
        assert is_valid is False
        assert len(missing) == 1
        assert "extra_file.txt" in missing
        assert len(mismatched) == 1
        assert mismatched[0][0] == "extra_file.txt"
        assert mismatched[0][1] is None  # No expected hash
        assert len(extra) == 0

    def test_verify_directory_with_missing_file(
        self, temp_workspace, tmp_path, gpg_setup
    ):
        """Test verifying a directory missing a file from the arrangement."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Remove a file
        (temp_workspace / "notes.txt").unlink()

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should detect the file as extra in arrangement (not found in package)
        assert is_valid is False
        assert len(missing) == 0
        assert len(mismatched) == 0
        assert len(extra) == 1
        assert "notes.txt" in extra

    def test_verify_zipfile_identical(self, temp_workspace, tmp_path, gpg_setup):
        """Test verifying a zipfile that exactly matches the arrangement."""
        import zipfile

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Create a zipfile with the same content
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for file in temp_workspace.iterdir():
                if file.is_file():
                    zf.write(file, file.name)

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(zip_path))

        # Should be identical
        assert is_valid is True
        assert len(missing) == 0
        assert len(mismatched) == 0
        assert len(extra) == 0

    def test_verify_zipfile_with_modified_file(
        self, temp_workspace, tmp_path, gpg_setup
    ):
        """Test verifying a zipfile where a file has been modified."""
        import zipfile

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Create a zipfile with modified content
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for file in temp_workspace.iterdir():
                if file.is_file():
                    if file.name == "notes.txt":
                        zf.writestr("notes.txt", "Modified content\n")
                    else:
                        zf.write(file, file.name)

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(zip_path))

        # Should detect mismatch
        assert is_valid is False
        assert len(missing) == 0
        assert len(mismatched) == 1
        assert mismatched[0][0] == "notes.txt"
        assert len(extra) == 0

    def test_verify_with_subpath_directory(self, tmp_path, gpg_setup):
        """Test verifying a directory with subpath filtering."""
        # Create a more complex directory structure
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        subdir = workspace / "data"
        subdir.mkdir()
        (subdir / "file1.txt").write_text("Content 1\n")
        (subdir / "file2.txt").write_text("Content 2\n")

        other = workspace / "other"
        other.mkdir()
        (other / "file3.txt").write_text("Content 3\n")

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement for the entire workspace
        tro.add_arrangement(str(workspace), comment="Full workspace", ignore_dirs=[])

        # Verify only the data subpath
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package(
            "arrangement/0", str(workspace), subpath="data"
        )

        # Should verify only files in data/ subdirectory
        # When checking with subpath, only files starting with subpath are checked
        # The 'extra' list should contain files NOT checked (not in subpath) that are in arrangement
        assert is_valid is False
        assert (
            len(extra) == 3
        )  # All files are in extra because subpath filter leaves arrangement_map intact
        assert "other/file3.txt" in extra
        assert "data/file1.txt" in extra
        assert "data/file2.txt" in extra

    def test_verify_with_subpath_zipfile(self, tmp_path, gpg_setup):
        """Test verifying a zipfile with subpath filtering."""
        import zipfile

        # Create a more complex directory structure
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        subdir = workspace / "data"
        subdir.mkdir()
        (subdir / "file1.txt").write_text("Content 1\n")
        (subdir / "file2.txt").write_text("Content 2\n")

        other = workspace / "other"
        other.mkdir()
        (other / "file3.txt").write_text("Content 3\n")

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement for the entire workspace
        tro.add_arrangement(str(workspace), comment="Full workspace", ignore_dirs=[])

        # Create a zipfile
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(subdir / "file1.txt", "data/file1.txt")
            zf.write(subdir / "file2.txt", "data/file2.txt")
            zf.write(other / "file3.txt", "other/file3.txt")

        # Verify only the data subpath
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package(
            "arrangement/0", str(zip_path), subpath="data"
        )

        # Should verify only files in data/ subdirectory
        # When checking with subpath, only files starting with subpath are checked
        # The 'extra' list should contain files NOT checked that are in arrangement
        assert is_valid is False
        assert len(extra) == 3
        assert "other/file3.txt" in extra

    def test_verify_invalid_arrangement_id(self, temp_workspace, tmp_path, gpg_setup):
        """Test that verifying with invalid arrangement ID raises error."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Try to verify with non-existent arrangement
        with pytest.raises(ValueError, match="not found"):
            tro.verify_replication_package("arrangement/99", str(temp_workspace))

    def test_verify_multiple_issues(self, temp_workspace, tmp_path, gpg_setup):
        """Test verifying a package with multiple types of issues."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Make multiple changes
        (temp_workspace / "notes.txt").write_text("Modified\n")  # Modified
        (temp_workspace / "config.json").unlink()  # Removed (will be in extra)
        (temp_workspace / "new_file.txt").write_text(
            "New\n"
        )  # Added (will be in missing)

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should detect all issues
        assert is_valid is False
        assert len(missing) == 1  # new_file.txt
        assert "new_file.txt" in missing
        assert (
            len(mismatched) == 2
        )  # notes.txt (modified) + new_file.txt (not in arrangement)
        # Find which is which
        mismatched_files = {m[0]: m for m in mismatched}
        assert "notes.txt" in mismatched_files
        assert "new_file.txt" in mismatched_files
        assert mismatched_files["new_file.txt"][1] is None  # No expected hash
        assert len(extra) == 1  # config.json
        assert "config.json" in extra

    def test_verify_nested_directory_structure(self, tmp_path, gpg_setup):
        """Test verifying a package with nested directory structure."""
        # Create nested structure
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        (workspace / "root.txt").write_text("Root file\n")

        level1 = workspace / "level1"
        level1.mkdir()
        (level1 / "file1.txt").write_text("Level 1\n")

        level2 = level1 / "level2"
        level2.mkdir()
        (level2 / "file2.txt").write_text("Level 2\n")

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(workspace), comment="Nested structure", ignore_dirs=[])

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(workspace))

        # Should be valid
        assert is_valid is True
        assert len(missing) == 0
        assert len(mismatched) == 0
        assert len(extra) == 0

    def test_get_arrangement_path_hash_map(self, temp_workspace, tmp_path, gpg_setup):
        """Test getting the path-to-hash binding for an arrangement."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Test", ignore_dirs=[])

        # Get the binding
        path_hash_map = tro.get_arrangement_path_hash_map("arrangement/0")

        # Verify binding contains all files
        assert len(path_hash_map) == 3
        assert "input_data.csv" in path_hash_map
        assert "notes.txt" in path_hash_map
        assert "config.json" in path_hash_map

        # Verify all values are valid SHA256 hashes
        for path, hash_value in path_hash_map.items():
            assert hash_value.startswith("sha256:")
            assert len(hash_value) == 64 + len(
                "sha256:"
            )  # "sha256:" prefix + 64 hex chars
            assert all(c in "0123456789abcdef" for c in hash_value[len("sha256:") :])

    def test_get_arrangement_path_hash_map_invalid_id(self, tmp_path, gpg_setup):
        """Test that getting map for invalid arrangement ID raises error."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Try to get binding for non-existent arrangement
        with pytest.raises(ValueError, match="not found"):
            tro.get_arrangement_path_hash_map("arrangement/99")
