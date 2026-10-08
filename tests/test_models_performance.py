"""Unit tests for PerformanceAttribute, TrustedResearchPerformance, and TROAttribute."""

import datetime

from tro_utils.models import (
    ArrangementBinding,
    PerformanceAttribute,
    TROAttribute,
    TrustedResearchPerformance,
)


class TestPerformanceAttribute:
    """Unit tests for PerformanceAttribute."""

    def test_to_from_jsonld(self):
        attr = PerformanceAttribute(
            "trp/0/attribute/0",
            "trov:InternetIsolation",
            "trov:CanProvideInternetIsolation",
        )
        jld = attr.to_jsonld()
        restored = PerformanceAttribute.from_jsonld(jld)
        assert restored.attribute_id == attr.attribute_id
        assert restored.attribute_type == attr.attribute_type
        assert restored.warranted_by_id == attr.warranted_by_id


class TestTrustedResearchPerformance:
    """Unit tests for TrustedResearchPerformance."""

    def test_to_from_jsonld_roundtrip(self):
        trp = TrustedResearchPerformance(
            performance_id="trp/0",
            comment="test run",
            conducted_by_id="trs",
            started_at=datetime.datetime(2024, 1, 1, 10, 0, 0),
            ended_at=datetime.datetime(2024, 1, 1, 11, 0, 0),
            accessed_arrangements=[
                ArrangementBinding("trp/0/binding/0", "arrangement/0", path="/workdir")
            ],
            contributed_to_arrangements=[
                ArrangementBinding("trp/0/binding/1", "arrangement/1")
            ],
            attributes=[
                PerformanceAttribute(
                    "trp/0/attribute/0",
                    "trov:InternetIsolation",
                    "trov:CanProvideInternetIsolation",
                )
            ],
        )
        jld = trp.to_jsonld()
        restored = TrustedResearchPerformance.from_jsonld(jld)
        assert restored.performance_id == trp.performance_id
        assert restored.comment == trp.comment
        assert restored.started_at == trp.started_at
        assert restored.ended_at == trp.ended_at
        assert restored.accessed_arrangements == trp.accessed_arrangements
        assert restored.contributed_to_arrangements == trp.contributed_to_arrangements
        assert len(restored.attributes) == 1

    def test_optional_fields_absent_when_none(self):
        trp = TrustedResearchPerformance(performance_id="trp/0")
        jld = trp.to_jsonld()
        assert "trov:startedAtTime" not in jld
        assert "trov:endedAtTime" not in jld
        assert "trov:accessedArrangement" not in jld
        assert "trov:contributedToArrangement" not in jld

    def test_naive_timestamps_become_aware(self):
        """Naive input is read as local time and gets the local offset attached."""
        naive_start = datetime.datetime(2024, 1, 1, 10, 0, 0)
        naive_end = datetime.datetime(2024, 1, 1, 11, 0, 0)
        trp = TrustedResearchPerformance(
            performance_id="trp/0", started_at=naive_start, ended_at=naive_end
        )
        assert trp.started_at.tzinfo is not None
        assert trp.ended_at.tzinfo is not None
        # Same instant, not a relabelled wall clock.
        assert trp.started_at == naive_start.astimezone()
        assert trp.ended_at == naive_end.astimezone()

    def test_aware_timestamps_preserved(self):
        """An explicit offset is kept verbatim rather than shifted."""
        tz = datetime.timezone(datetime.timedelta(hours=9))
        started = datetime.datetime(2024, 1, 1, 10, 0, 0, tzinfo=tz)
        trp = TrustedResearchPerformance(performance_id="trp/0", started_at=started)
        assert trp.started_at == started
        assert trp.started_at.utcoffset() == datetime.timedelta(hours=9)
        assert trp.to_jsonld()["trov:startedAtTime"] == "2024-01-01T10:00:00+09:00"

    def test_naive_timestamps_never_serialised(self):
        """Assigning a naive value after construction still serialises as aware."""
        trp = TrustedResearchPerformance(performance_id="trp/0")
        trp.started_at = datetime.datetime(2024, 1, 1, 10, 0, 0)
        trp.ended_at = datetime.datetime(2024, 1, 1, 11, 0, 0)
        jld = trp.to_jsonld()
        for key in ("trov:startedAtTime", "trov:endedAtTime"):
            assert datetime.datetime.fromisoformat(jld[key]).tzinfo is not None

    def test_offsetless_jsonld_parsed_as_aware(self):
        """Legacy declarations written without an offset load as local time."""
        trp = TrustedResearchPerformance.from_jsonld(
            {
                "@id": "trp/0",
                "@type": "trov:TrustedResearchPerformance",
                "trov:startedAtTime": "2026-03-27T13:37:05.646960",
                "trov:endedAtTime": "2026-03-27T13:37:33.817230",
            }
        )
        assert trp.started_at.tzinfo is not None
        assert trp.ended_at.tzinfo is not None
        assert (
            trp.started_at
            == datetime.datetime(2026, 3, 27, 13, 37, 5, 646960).astimezone()
        )

    def test_aware_jsonld_roundtrip_preserves_offset(self):
        trp = TrustedResearchPerformance.from_jsonld(
            {
                "@id": "trp/0",
                "@type": "trov:TrustedResearchPerformance",
                "trov:startedAtTime": "2024-01-01T10:00:00+09:00",
            }
        )
        assert trp.started_at.utcoffset() == datetime.timedelta(hours=9)
        assert trp.to_jsonld()["trov:startedAtTime"] == "2024-01-01T10:00:00+09:00"


class TestTROAttribute:
    """Unit tests for TROAttribute."""

    def test_to_from_jsonld(self):
        attr = TROAttribute(
            "tro/attribute/0", "trov:IncludesAllInputData", "trp/0/attribute/0"
        )
        jld = attr.to_jsonld()
        restored = TROAttribute.from_jsonld(jld)
        assert restored.attribute_id == attr.attribute_id
        assert restored.attribute_type == attr.attribute_type
        assert restored.warranted_by_id == attr.warranted_by_id
