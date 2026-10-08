"""Unit tests for the root TransparentResearchObject model."""

import datetime

import pytest

from tro_utils.models import (
    TimeStampingAuthority,
    TransparentResearchObject,
    TRSCapability,
    TrustedResearchSystem,
)


class TestTransparentResearchObject:
    """Unit tests for the root TransparentResearchObject model."""

    def _make_tro(self):
        return TransparentResearchObject(
            name="Test TRO",
            description="A test",
            creator="Tester",
        )

    def test_to_jsonld_structure(self):
        tro = self._make_tro()
        jld = tro.to_jsonld()
        assert "@context" in jld
        assert "@graph" in jld
        graph = jld["@graph"][0]
        assert graph["schema:name"] == "Test TRO"
        assert "trov:TransparentResearchObject" in graph["@type"]
        assert "trov:hasComposition" in graph
        assert "trov:hasArrangement" in graph
        assert "trov:hasPerformance" in graph

    def test_from_jsonld_roundtrip(self):
        tro = self._make_tro()
        jld = tro.to_jsonld()
        restored = TransparentResearchObject.from_jsonld(jld)
        assert restored.name == tro.name
        assert restored.description == tro.description
        assert restored.creator == tro.creator

    def test_date_created_default_is_aware(self):
        tro = self._make_tro()
        assert tro.date_created.tzinfo is not None
        assert (
            datetime.datetime.fromisoformat(
                tro.to_jsonld()["@graph"][0]["schema:dateCreated"]
            ).tzinfo
            is not None
        )

    def test_naive_date_created_becomes_aware(self):
        naive = datetime.datetime(2024, 6, 1, 10, 0)
        tro = TransparentResearchObject(date_created=naive)
        assert tro.date_created == naive.astimezone()
        assert tro.date_created.tzinfo is not None

    def test_offsetless_date_created_parsed_as_aware(self):
        """Legacy declarations written without an offset load as local time."""
        tro = self._make_tro()
        jld = tro.to_jsonld()
        jld["@graph"][0]["schema:dateCreated"] = "2026-03-27T13:37:05.646960"
        restored = TransparentResearchObject.from_jsonld(jld)
        assert (
            restored.date_created
            == datetime.datetime(2026, 3, 27, 13, 37, 5, 646960).astimezone()
        )

    def test_date_created_offset_preserved(self):
        tz = datetime.timezone(datetime.timedelta(hours=9))
        tro = TransparentResearchObject(
            date_created=datetime.datetime(2024, 6, 1, 10, 0, tzinfo=tz)
        )
        graph = tro.to_jsonld()["@graph"][0]
        assert graph["schema:dateCreated"] == "2024-06-01T10:00:00+09:00"
        restored = TransparentResearchObject.from_jsonld(tro.to_jsonld())
        assert restored.date_created.utcoffset() == datetime.timedelta(hours=9)

    def test_from_jsonld_old_vocab_raises(self):
        jld = {
            "@context": [{}],
            "@graph": [
                {
                    "@id": "tro",
                    "trov:vocabularyVersion": "0.0.1",
                    "trov:wasAssembledBy": {"trov:hasCapability": []},
                    "trov:hasArrangement": [],
                    "trov:hasComposition": {
                        "@id": "composition/1",
                        "trov:hasArtifact": [],
                    },
                    "trov:hasPerformance": [],
                    "trov:hasAttribute": [],
                }
            ],
        }
        with pytest.raises(RuntimeError, match="older version"):
            TransparentResearchObject.from_jsonld(jld)

    def test_add_arrangement_updates_composition(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "a.txt").write_text("alpha")
        (d / "b.txt").write_text("beta")

        tro = self._make_tro()
        arr = tro.add_arrangement(str(d), comment="snap1")

        assert len(tro.arrangements) == 1
        assert len(tro.composition.artifacts) == 2
        assert arr.arrangement_id == "arrangement/0"

    def test_add_performance_validates_arrangements(self):
        tro = self._make_tro()
        with pytest.raises(ValueError, match="does not exist"):
            tro.add_performance(
                start_time=datetime.datetime.now(),
                end_time=datetime.datetime.now(),
                accessed_arrangement="arrangement/99",
                modified_arrangement="arrangement/0",
            )

    def test_save_load_roundtrip(self, tmp_path):
        tro = self._make_tro()
        filepath = tmp_path / "test.jsonld"
        tro.save(str(filepath))
        assert filepath.exists()
        restored = TransparentResearchObject.load(str(filepath))
        assert restored.name == tro.name
        assert restored.creator == tro.creator

    def test_tsa_roundtrip(self):
        tro = self._make_tro()
        tro.tsa = TimeStampingAuthority(
            tsa_id="tsa", public_key="-----BEGIN PUBLIC KEY-----"
        )
        jld = tro.to_jsonld()
        restored = TransparentResearchObject.from_jsonld(jld)
        assert restored.tsa is not None
        assert restored.tsa.public_key == "-----BEGIN PUBLIC KEY-----"

    def test_full_workflow_roundtrip(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "input.csv").write_text("a,b\n1,2\n")
        (d / "script.py").write_text("print('hello')\n")

        tro = TransparentResearchObject(
            name="Full Workflow Test",
            trs=TrustedResearchSystem(
                trs_id="trs",
                capabilities=[
                    TRSCapability("trs/cap/0", "trov:CanProvideInternetIsolation")
                ],
            ),
        )

        tro.add_arrangement(str(d), comment="before")
        (d / "output.txt").write_text("result\n")
        tro.add_arrangement(str(d), comment="after")

        tro.add_performance(
            start_time=datetime.datetime(2024, 6, 1, 10, 0),
            end_time=datetime.datetime(2024, 6, 1, 11, 0),
            comment="run script",
            accessed_arrangement="arrangement/0",
            modified_arrangement="arrangement/1",
            attrs=["trov:InternetIsolation"],
        )

        filepath = tmp_path / "workflow.jsonld"
        tro.save(str(filepath))
        restored = TransparentResearchObject.load(str(filepath))

        assert len(restored.arrangements) == 2
        assert len(restored.performances) == 1
        assert restored.performances[0].comment == "run script"
        assert len(restored.performances[0].attributes) == 1
