"""Tests for TRO performance operations."""

import datetime

import pytest

from tro_utils import TRPAttribute

from tests.helpers import create_tro_with_gpg


class TestTROPerformances:
    """Test TRO performance operations."""

    def test_add_performance(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test adding a performance to a TRO."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add two arrangements
        tro.add_arrangement(str(temp_workspace), comment="Before")

        # Simulate some work
        (temp_workspace / "output.txt").write_text("processed")

        tro.add_arrangement(str(temp_workspace), comment="After")

        # Add performance
        start_time = datetime.datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime.datetime(2024, 1, 1, 11, 0, 0)

        tro.add_performance(
            start_time=start_time,
            end_time=end_time,
            comment="Data processing workflow",
            accessed_arrangement="arrangement/0",
            modified_arrangement="arrangement/1",
            attrs=["trov:InternetIsolation", TRPAttribute.RECORD_NETWORK],
        )

        # Verify performance was added
        performances = tro.data["@graph"][0]["trov:hasPerformance"]
        assert len(performances) == 1

        perf = performances[0]
        assert perf["rdfs:comment"] == "Data processing workflow"
        assert perf["trov:startedAtTime"] == "2024-01-01T10:00:00"
        assert perf["trov:endedAtTime"] == "2024-01-01T11:00:00"
        accessed = perf["trov:accessedArrangement"]
        assert accessed["@type"] == "trov:ArrangementBinding"
        assert accessed["trov:arrangement"]["@id"] == "arrangement/0"
        contributed = perf["trov:contributedToArrangement"]
        assert contributed["trov:arrangement"]["@id"] == "arrangement/1"
        assert len(perf["trov:hasPerformanceAttribute"]) == 2

    def test_add_performance_invalid_arrangement(
        self, tmp_path, gpg_setup, trs_profile
    ):
        """Test that adding performance with invalid arrangement raises error."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
        )

        start_time = datetime.datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime.datetime(2024, 1, 1, 11, 0, 0)

        # Try to add performance with non-existent arrangement
        with pytest.raises(ValueError, match="does not exist"):
            tro.add_performance(
                start_time=start_time,
                end_time=end_time,
                accessed_arrangement="arrangement/99",
                modified_arrangement="arrangement/0",
                attrs=[],
            )

    def test_add_performance_multiple_arrangements(
        self, temp_workspace, tmp_path, gpg_setup, trs_profile
    ):
        """add_performance accepts a list of arrangement IDs for accessed/modified."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
        )
        tro.add_arrangement(str(temp_workspace), comment="A")
        (temp_workspace / "out.txt").write_text("x")
        tro.add_arrangement(str(temp_workspace), comment="B")
        (temp_workspace / "out2.txt").write_text("y")
        tro.add_arrangement(str(temp_workspace), comment="C")

        start_time = datetime.datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime.datetime(2024, 1, 1, 11, 0, 0)

        tro.add_performance(
            start_time=start_time,
            end_time=end_time,
            comment="multi",
            accessed_arrangement=["arrangement/0", "arrangement/1"],
            modified_arrangement=["arrangement/2"],
            attrs=[],
        )

        perf = tro.data["@graph"][0]["trov:hasPerformance"][0]
        # Two accessed → serialised as a list
        accessed = perf["trov:accessedArrangement"]
        assert isinstance(accessed, list)
        assert len(accessed) == 2
        assert {r["trov:arrangement"]["@id"] for r in accessed} == {
            "arrangement/0",
            "arrangement/1",
        }
        # One contributed → serialised as a plain dict
        contributed = perf["trov:contributedToArrangement"]
        assert isinstance(contributed, dict)
        assert contributed["trov:arrangement"]["@id"] == "arrangement/2"

    def test_add_performance_multiple_arrangements_invalid(
        self, tmp_path, gpg_setup, trs_profile
    ):
        """Providing any invalid ID in a list raises ValueError."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
        )
        start_time = datetime.datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime.datetime(2024, 1, 1, 11, 0, 0)
        with pytest.raises(ValueError, match="does not exist"):
            tro.add_performance(
                start_time=start_time,
                end_time=end_time,
                accessed_arrangement=["arrangement/0", "arrangement/999"],
                modified_arrangement=None,
                attrs=[],
            )

    def test_add_performance_arrangement_ref_with_path(
        self, temp_workspace, tmp_path, gpg_setup, trs_profile
    ):
        """A (arrangement_id, path) tuple is accepted and serialises trov:boundTo."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
        )
        tro.add_arrangement(str(temp_workspace), comment="A")
        (temp_workspace / "out.txt").write_text("x")
        tro.add_arrangement(str(temp_workspace), comment="B")

        tro.add_performance(
            start_time=datetime.datetime(2024, 1, 1, 10, 0, 0),
            end_time=datetime.datetime(2024, 1, 1, 11, 0, 0),
            comment="with path",
            accessed_arrangement=("arrangement/0", "/mnt/data"),
            modified_arrangement="arrangement/1",
            attrs=[],
        )

        perf = tro.data["@graph"][0]["trov:hasPerformance"][0]
        accessed = perf["trov:accessedArrangement"]
        assert accessed["trov:arrangement"]["@id"] == "arrangement/0"
        assert accessed["trov:boundTo"] == "/mnt/data"
        # contributed has no path
        contributed = perf["trov:contributedToArrangement"]
        assert contributed["trov:arrangement"]["@id"] == "arrangement/1"
        assert "trov:boundTo" not in contributed

    def test_add_performance_mixed_strings_and_refs(
        self, temp_workspace, tmp_path, gpg_setup, trs_profile
    ):
        """A mixed list of str and (id, path) tuples is accepted; boundTo serialised where set."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
        )
        tro.add_arrangement(str(temp_workspace), comment="A")
        (temp_workspace / "out.txt").write_text("x")
        tro.add_arrangement(str(temp_workspace), comment="B")
        (temp_workspace / "out2.txt").write_text("y")
        tro.add_arrangement(str(temp_workspace), comment="C")

        tro.add_performance(
            start_time=datetime.datetime(2024, 1, 1, 10, 0, 0),
            end_time=datetime.datetime(2024, 1, 1, 11, 0, 0),
            comment="mixed",
            accessed_arrangement=[
                ("arrangement/0", "/mnt/input"),
                "arrangement/1",
            ],
            modified_arrangement=("arrangement/2", "/mnt/output"),
            attrs=[],
        )

        perf = tro.data["@graph"][0]["trov:hasPerformance"][0]
        accessed = perf["trov:accessedArrangement"]
        assert isinstance(accessed, list)
        assert len(accessed) == 2
        by_id = {r["trov:arrangement"]["@id"]: r for r in accessed}
        assert by_id["arrangement/0"]["trov:boundTo"] == "/mnt/input"
        assert "trov:boundTo" not in by_id["arrangement/1"]
        contributed = perf["trov:contributedToArrangement"]
        assert contributed["trov:arrangement"]["@id"] == "arrangement/2"
        assert contributed["trov:boundTo"] == "/mnt/output"

    def test_add_performance_extra_attrs(
        self, temp_workspace, tmp_path, gpg_setup, trs_profile
    ):
        """Test that extra attributes passed to add_performance are included in the performance."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
        )
        (temp_workspace / "input.txt").write_text("x")
        tro.add_arrangement(str(temp_workspace), comment="A")
        (temp_workspace / "output.txt").write_text("y")
        tro.add_arrangement(str(temp_workspace), comment="B")

        tro.add_performance(
            start_time=datetime.datetime(2024, 1, 1, 10, 0, 0),
            end_time=datetime.datetime(2024, 1, 1, 11, 0, 0),
            comment="with attrs",
            accessed_arrangement="arrangement/0",
            modified_arrangement="arrangement/1",
            extra_attributes={"trov:customAttr": "customValue"},
        )
        perf = tro.data["@graph"][0]["trov:hasPerformance"][0]
        assert perf["trov:customAttr"] == "customValue"

        tro.save()
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
        )
        perf = tro.data["@graph"][0]["trov:hasPerformance"][0]
        assert perf["trov:customAttr"] == "customValue"
