"""Unit tests for ArtifactArrangement."""

from tro_utils.models import (
    ArtifactArrangement,
    ArtifactComposition,
    ArtifactLocation,
    HashValue,
    ResearchArtifact,
    TransparentResearchObject,
)


class TestArtifactArrangement:
    """Unit tests for ArtifactArrangement."""

    def test_from_directory(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "a.txt").write_text("alpha")
        (d / "b.txt").write_text("beta")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(
            d, comp, "arrangement/0", comment="test"
        )

        assert arr.arrangement_id == "arrangement/0"
        assert arr.comment == "test"
        assert len(arr.locations) == 2
        assert len(comp.artifacts) == 2

    def test_from_directory_no_duplicate_artifacts(self, tmp_path):
        """Identical files across two arrangements share artifacts in composition."""
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "same.txt").write_text("identical content")

        comp = ArtifactComposition()
        ArtifactArrangement.from_directory(d, comp, "arrangement/0")
        ArtifactArrangement.from_directory(d, comp, "arrangement/1")

        assert len(comp.artifacts) == 1  # same artifact reused

    def test_to_path_hash_map(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "file.txt").write_text("content")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(d, comp, "arrangement/0")
        binding = arr.to_path_hash_map(comp)

        assert "file.txt" in binding
        assert binding["file.txt"].startswith("sha256:")

    def test_to_from_jsonld_roundtrip(self):
        arr = ArtifactArrangement(
            arrangement_id="arrangement/0",
            comment="snapshot",
            locations=[
                ArtifactLocation(
                    "arrangement/0/location/0", "comp/1/artifact/0", "data/in.csv"
                )
            ],
        )
        jld = arr.to_jsonld()
        restored = ArtifactArrangement.from_jsonld(jld)
        assert restored.arrangement_id == arr.arrangement_id
        assert restored.comment == arr.comment
        assert len(restored.locations) == 1

    # ------------------------------------------------------------------
    # Snapshot tests
    # ------------------------------------------------------------------

    def test_to_snapshot_contains_artifacts_and_locations(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "a.txt").write_text("alpha")
        (d / "b.txt").write_text("beta")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(
            d, comp, "arrangement/0", comment="snap"
        )
        snap = arr.to_snapshot(comp)

        assert snap["@type"] == "trov:ArrangementSnapshot"
        assert snap["rdfs:comment"] == "snap"
        assert len(snap["trov:hasArtifactLocation"]) == 2
        assert len(snap["trov:hasArtifact"]) == 2

    def test_to_snapshot_only_includes_referenced_artifacts(self, tmp_path):
        """Artifacts in the composition but not referenced by this arrangement are excluded."""
        d1 = tmp_path / "dir1"
        d1.mkdir()
        (d1 / "a.txt").write_text("alpha")

        d2 = tmp_path / "dir2"
        d2.mkdir()
        (d2 / "b.txt").write_text("beta")

        comp = ArtifactComposition()
        arr1 = ArtifactArrangement.from_directory(d1, comp, "arrangement/0")
        ArtifactArrangement.from_directory(d2, comp, "arrangement/1")

        # composition has 2 artifacts; arr1 only references 1
        assert len(comp.artifacts) == 2
        snap = arr1.to_snapshot(comp)
        assert len(snap["trov:hasArtifact"]) == 1

    def test_save_and_load_snapshot_roundtrip(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "file.txt").write_text("content")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(
            d, comp, "arrangement/0", comment="original"
        )

        snap_path = tmp_path / "snap.jsonld"
        arr.save_snapshot(snap_path, comp)

        # Load into a fresh composition
        new_comp = ArtifactComposition()
        restored = ArtifactArrangement.load_snapshot(
            snap_path, new_comp, "arrangement/99", comment=None
        )

        assert restored.arrangement_id == "arrangement/99"
        assert restored.comment == "original"  # taken from snapshot
        assert len(restored.locations) == 1
        assert restored.locations[0].path == "file.txt"
        assert len(new_comp.artifacts) == 1

    def test_load_snapshot_comment_override(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "file.txt").write_text("x")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(
            d, comp, "arrangement/0", comment="original"
        )
        snap_path = tmp_path / "snap.jsonld"
        arr.save_snapshot(snap_path, comp)

        new_comp = ArtifactComposition()
        restored = ArtifactArrangement.load_snapshot(
            snap_path, new_comp, "arrangement/0", comment="overridden"
        )
        assert restored.comment == "overridden"

    def test_load_snapshot_deduplicates_artifacts(self, tmp_path):
        """Loading a snapshot whose artifacts already exist in the target composition does not create duplicates."""
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "file.txt").write_text("same content")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(
            d, comp, "arrangement/0", comment="snap"
        )
        snap_path = tmp_path / "snap.jsonld"
        arr.save_snapshot(snap_path, comp)

        # target_comp already contains the same artifact (scanned independently)
        target_comp = ArtifactComposition()
        ArtifactArrangement.from_directory(d, target_comp, "arrangement/0")
        assert len(target_comp.artifacts) == 1

        restored = ArtifactArrangement.load_snapshot(
            snap_path, target_comp, "arrangement/1"
        )
        # Still only one artifact - no duplicate
        assert len(target_comp.artifacts) == 1
        assert restored.locations[0].artifact_id == target_comp.artifacts[0].artifact_id

    def test_from_snapshot_remaps_location_ids(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "f.txt").write_text("data")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(d, comp, "arrangement/0")
        snap = arr.to_snapshot(comp)

        new_comp = ArtifactComposition()
        restored = ArtifactArrangement.from_snapshot(snap, new_comp, "arrangement/7")
        assert restored.locations[0].location_id == "arrangement/7/location/0"

    def test_add_arrangement_from_snapshot_on_tro_model(self, tmp_path):
        """TransparentResearchObject.add_arrangement_from_snapshot wires up correctly."""
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "data.txt").write_text("hello")

        # Create a snapshot independently
        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(
            d, comp, "arrangement/0", comment="pre-computed"
        )
        snap_path = tmp_path / "snap.jsonld"
        arr.save_snapshot(snap_path, comp)

        # Load into a fresh TRO model
        tro_model = TransparentResearchObject()
        added = tro_model.add_arrangement_from_snapshot(snap_path)

        assert added.arrangement_id == "arrangement/0"
        assert added.comment == "pre-computed"
        assert len(tro_model.arrangements) == 1
        assert len(tro_model.composition.artifacts) == 1
        assert (
            tro_model.arrangements[0].locations[0].artifact_id
            == tro_model.composition.artifacts[0].artifact_id
        )
