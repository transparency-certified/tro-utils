"""Tests for TRO arrangement operations."""

import pytest

from tro_utils.models import ArtifactArrangement, ArtifactComposition

from tests.helpers import create_tro_with_gpg


class TestTROArrangements:
    """Test TRO arrangement operations."""

    def test_add_arrangement_from_snapshot(self, tmp_path, gpg_setup):
        """add_arrangement_from_snapshot loads a pre-computed snapshot into the TRO."""
        # Create a snapshot independently
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "data.csv").write_text("a,b\n1,2")
        (workdir / "readme.txt").write_text("desc")

        snap_comp = ArtifactComposition()
        snap_arr = ArtifactArrangement.from_directory(
            workdir, snap_comp, "arrangement/0", comment="static mount"
        )
        snap_path = tmp_path / "mount.jsonld"
        snap_arr.save_snapshot(snap_path, snap_comp)

        # Load into a TRO
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )
        tro.add_arrangement_from_snapshot(str(snap_path))
        tro.save()

        arrangements = tro.list_arrangements()
        assert len(arrangements) == 1
        assert arrangements[0]["rdfs:comment"] == "static mount"
        paths = [
            loc["trov:path"] for loc in arrangements[0]["trov:hasArtifactLocation"]
        ]
        assert "data.csv" in paths
        assert "readme.txt" in paths

    def test_add_arrangement_from_snapshot_comment_override(self, tmp_path, gpg_setup):
        """comment kwarg overrides the comment stored in the snapshot file."""
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "f.txt").write_text("x")

        snap_comp = ArtifactComposition()
        snap_arr = ArtifactArrangement.from_directory(
            workdir, snap_comp, "arrangement/0", comment="original comment"
        )
        snap_path = tmp_path / "snap.jsonld"
        snap_arr.save_snapshot(snap_path, snap_comp)

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )
        tro.add_arrangement_from_snapshot(str(snap_path), comment="overridden")

        arrangements = tro.list_arrangements()
        assert arrangements[0]["rdfs:comment"] == "overridden"

    def test_add_arrangement_from_snapshot_deduplicates_artifacts(
        self, tmp_path, gpg_setup
    ):
        """Files already in the TRO composition are not duplicated when a snapshot is loaded."""
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "common.txt").write_text("shared content")

        # First add the directory normally so the artifact is in the TRO composition
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )
        tro.add_arrangement(str(workdir), comment="live")
        artifact_count_after_first = len(tro._model.composition.artifacts)

        # Create a snapshot with the same file
        snap_comp = ArtifactComposition()
        snap_arr = ArtifactArrangement.from_directory(
            workdir, snap_comp, "arrangement/0", comment="snap"
        )
        snap_path = tmp_path / "snap.jsonld"
        snap_arr.save_snapshot(snap_path, snap_comp)

        tro.add_arrangement_from_snapshot(str(snap_path))

        # Composition artifact count must not have grown
        assert len(tro._model.composition.artifacts) == artifact_count_after_first

    def test_add_arrangement(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test adding an arrangement to a TRO."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add first arrangement
        tro.add_arrangement(
            str(temp_workspace), comment="Initial arrangement", ignore_dirs=[]
        )

        # Verify arrangement was added
        arrangements = tro.list_arrangements()
        assert len(arrangements) == 1
        assert arrangements[0]["rdfs:comment"] == "Initial arrangement"
        assert (
            len(arrangements[0]["trov:hasArtifactLocation"]) == 3
        )  # 3 files in workspace

        # Verify composition was updated
        composition = tro.data["@graph"][0]["trov:hasComposition"]
        assert len(composition["trov:hasArtifact"]) == 3
        assert "trov:hasFingerprint" in composition

    def test_add_multiple_arrangements(
        self, temp_workspace, tmp_path, gpg_setup, trs_profile
    ):
        """Test adding multiple arrangements tracks changes."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add first arrangement
        tro.add_arrangement(str(temp_workspace), comment="Before processing")

        # Modify workspace - process CSV and create output
        csv_data = (temp_workspace / "input_data.csv").read_text()
        lines = csv_data.strip().split("\n")
        filtered_lines = [lines[0]]  # header
        for line in lines[1:]:
            parts = line.split(",")
            if int(parts[1]) > 150:
                filtered_lines.append(line)

        output_file = temp_workspace / "output.csv"
        output_file.write_text("\n".join(filtered_lines) + "\n")

        # Update notes
        notes_file = temp_workspace / "notes.txt"
        notes_file.write_text(
            notes_file.read_text() + "Processed data with threshold 150\n"
        )

        # Add second arrangement
        tro.add_arrangement(str(temp_workspace), comment="After processing")

        # Verify two arrangements exist
        arrangements = tro.list_arrangements()
        assert len(arrangements) == 2
        assert arrangements[0]["rdfs:comment"] == "Before processing"
        assert arrangements[1]["rdfs:comment"] == "After processing"

        # Second arrangement should have more files
        assert len(arrangements[1]["trov:hasArtifactLocation"]) == 4  # added output.csv

        # Composition should have all unique files
        composition = tro.data["@graph"][0]["trov:hasComposition"]
        # Modified notes.txt gets a new hash, so we have: 3 originals + 1 new output + 1 modified notes = 5
        assert len(composition["trov:hasArtifact"]) >= 4

    def test_arrangement_with_ignore_dirs(self, temp_workspace, tmp_path, gpg_setup):
        """Test that ignore_dirs properly excludes directories."""
        # Create a directory to ignore
        git_dir = temp_workspace / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("git config")

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement with default ignore (.git)
        tro.add_arrangement(str(temp_workspace), comment="Test ignore")

        # Verify .git files were not included
        arrangements = tro.list_arrangements()
        loci = arrangements[0]["trov:hasArtifactLocation"]
        locations = [loc["trov:path"] for loc in loci]

        assert not any(".git" in loc for loc in locations)
