"""Tests that a declaration does not depend on filesystem iteration order.

``os.walk`` yields directory entries in whatever order the filesystem reports,
which differs between machines and filesystems.  That order used to decide both
the artifact ``@id`` assigned to each file and the order of
``trov:hasArtifactLocation``, so scanning the same tree on two machines
produced two different declarations.
"""

import json
import os

import pytest

from tro_utils.models import (
    ArtifactArrangement,
    ArtifactComposition,
)


@pytest.fixture
def tree(tmp_path):
    """A tree whose sorted order differs from any plausible creation order."""
    d = tmp_path / "workdir"
    d.mkdir()
    (d / "zebra.txt").write_text("z")
    (d / "apple.txt").write_text("a")
    (d / "middle.txt").write_text("m")
    sub = d / "nested"
    sub.mkdir()
    (sub / "deep.txt").write_text("d")
    (sub / "alpha.txt").write_text("al")
    deeper = sub / "further"
    deeper.mkdir()
    (deeper / "leaf.txt").write_text("l")
    return d


@pytest.fixture
def reversed_walk(monkeypatch):
    """Make os.walk report every directory's entries in reverse order."""
    real_walk = os.walk

    def fake_walk(top, *args, **kwargs):
        for root, dirs, files in real_walk(top, *args, **kwargs):
            dirs.sort(reverse=True)
            files.sort(reverse=True)
            yield root, dirs, files

    monkeypatch.setattr(os, "walk", fake_walk)


def _scan(directory):
    comp = ArtifactComposition()
    arr = ArtifactArrangement.from_directory(directory, comp, "arrangement/0")
    return arr, comp


class TestScanOrderIndependence:
    """The same tree must yield the same declaration whatever the walk order."""

    def test_locations_sorted_by_path(self, tree):
        arr, _ = _scan(tree)
        paths = [loc.path for loc in arr.locations]
        assert paths == sorted(paths)
        assert paths == [
            "apple.txt",
            "middle.txt",
            "nested/alpha.txt",
            "nested/deep.txt",
            "nested/further/leaf.txt",
            "zebra.txt",
        ]

    def test_declaration_identical_under_reversed_walk(
        self, tree, reversed_walk, request
    ):
        """Byte-for-byte identical output despite the opposite walk order."""
        reversed_arr, reversed_comp = _scan(tree)

        # Undo the monkeypatch to scan the same tree in the normal order.
        request.getfixturevalue("monkeypatch").undo()
        normal_arr, normal_comp = _scan(tree)

        assert json.dumps(reversed_arr.to_jsonld(), sort_keys=True) == json.dumps(
            normal_arr.to_jsonld(), sort_keys=True
        )
        assert json.dumps(reversed_comp.to_jsonld(), sort_keys=True) == json.dumps(
            normal_comp.to_jsonld(), sort_keys=True
        )

    def test_artifact_ids_assigned_in_path_order(self, tree):
        """Each file's artifact @id is derived from its path rank, not walk order."""
        arr, comp = _scan(tree)
        by_path = {loc.path: loc.artifact_id for loc in arr.locations}
        assert [by_path[p] for p in sorted(by_path)] == [
            f"composition/1/artifact/{i}" for i in range(len(by_path))
        ]

    def test_location_ids_follow_path_order(self, tree):
        arr, _ = _scan(tree)
        assert [loc.location_id for loc in arr.locations] == [
            f"arrangement/0/location/{i}" for i in range(len(arr.locations))
        ]

    def test_fingerprint_unaffected_by_order(self, tree, reversed_walk, request):
        """The fingerprint was already order-independent; keep it that way."""
        _, reversed_comp = _scan(tree)
        request.getfixturevalue("monkeypatch").undo()
        _, normal_comp = _scan(tree)
        assert reversed_comp.fingerprint == normal_comp.fingerprint


class TestCompositionOrdering:
    """trov:hasArtifact must be ordered numerically, not lexicographically."""

    def test_artifact_order_is_numeric(self, tmp_path):
        d = tmp_path / "many"
        d.mkdir()
        for i in range(12):
            (d / f"file{i:02d}.txt").write_text(f"content {i}")

        comp = ArtifactComposition()
        ArtifactArrangement.from_directory(d, comp, "arrangement/0")

        ids = [a["@id"] for a in comp.to_jsonld()["trov:hasArtifact"]]
        assert ids == [f"composition/1/artifact/{i}" for i in range(12)]
        # A plain string sort would have put artifact/10 directly after /1.
        assert ids[1] == "composition/1/artifact/1"


class TestSnapshotOrdering:
    """Snapshot round-trips must not depend on the snapshot's internal order."""

    def test_snapshot_merge_is_order_independent(self, tree, tmp_path):
        arr, comp = _scan(tree)
        snapshot = arr.to_snapshot(comp)

        # A snapshot written by an older version may list things in any order.
        shuffled = json.loads(json.dumps(snapshot))
        shuffled["trov:hasArtifactLocation"].reverse()
        shuffled["trov:hasArtifact"].reverse()

        target_a = ArtifactComposition()
        from_sorted = ArtifactArrangement.from_snapshot(
            snapshot, target_a, "arrangement/9"
        )
        target_b = ArtifactComposition()
        from_shuffled = ArtifactArrangement.from_snapshot(
            shuffled, target_b, "arrangement/9"
        )

        assert from_sorted.to_jsonld() == from_shuffled.to_jsonld()
        assert target_a.to_jsonld() == target_b.to_jsonld()

    def test_snapshot_file_is_path_ordered(self, tree, tmp_path):
        arr, comp = _scan(tree)
        out = tmp_path / "snap.jsonld"
        arr.save_snapshot(out, comp)
        data = json.loads(out.read_text())
        paths = [loc["trov:path"] for loc in data["trov:hasArtifactLocation"]]
        assert paths == sorted(paths)


class TestLegacyOrderNormalised:
    """A declaration loaded with scrambled locations serialises in path order."""

    def test_to_jsonld_sorts_loaded_locations(self, tree):
        arr, _ = _scan(tree)
        arr.locations.reverse()
        paths = [
            loc["trov:path"] for loc in arr.to_jsonld()["trov:hasArtifactLocation"]
        ]
        assert paths == sorted(paths)
