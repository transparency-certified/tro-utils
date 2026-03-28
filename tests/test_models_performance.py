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
            "trp/0/attribute/0", "trov:InternetIsolation", "trs/cap/0"
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
                    "trp/0/attribute/0", "trov:InternetIsolation", "trs/cap/0"
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
