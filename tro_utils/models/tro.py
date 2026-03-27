"""TransparentResearchObject root model.

This is the top-level object that maps directly to the ``tro`` node in the
JSON-LD ``@graph`` and owns all other model objects.
"""

from __future__ import annotations

import datetime
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any

from packaging.version import Version

from ._base import TROVModel
from .arrangement import ArtifactArrangement
from .attribute import TROAttribute
from .composition import ArtifactComposition
from .performance import PerformanceAttribute, TrustedResearchPerformance
from .trs import TrustedResearchSystem
from .tsa import TimeStampingAuthority

TROV_VOCABULARY_VERSION = Version("0.1")

_JSONLD_CONTEXT = [
    {
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
        "trov": f"https://w3id.org/trace/trov/{TROV_VOCABULARY_VERSION}#",
        "schema": "https://schema.org",
    }
]


@dataclass
class TransparentResearchObject(TROVModel):
    """Root object representing a full Transparent Research Object (TRO)."""

    tro_id: str = "tro"
    name: str = "Some TRO"
    description: str = "Some description"
    creator: str = "TRO utils"
    date_created: datetime.datetime = field(default_factory=datetime.datetime.now)
    vocabulary_version: str = str(TROV_VOCABULARY_VERSION)
    trs: TrustedResearchSystem = field(default_factory=TrustedResearchSystem)
    tsa: TimeStampingAuthority | None = None
    created_with_name: str | None = None
    created_with_version: str | None = None
    composition: ArtifactComposition = field(default_factory=ArtifactComposition)
    arrangements: list[ArtifactArrangement] = field(default_factory=list)
    performances: list[TrustedResearchPerformance] = field(default_factory=list)
    attributes: list[TROAttribute] = field(default_factory=list)

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, filepath: str | pathlib.Path) -> "TransparentResearchObject":
        """Deserialise a TRO from a JSON-LD file on disk.

        Args:
            filepath: Path to the ``.jsonld`` file.

        Returns:
            :class:`TransparentResearchObject` instance.

        Raises:
            RuntimeError: If the file was created with an incompatible vocabulary version.
        """
        with open(filepath) as f:
            raw = json.load(f)
        return cls.from_jsonld(raw)

    def save(self, filepath: str | pathlib.Path) -> None:
        """Serialise this TRO to a JSON-LD file on disk.

        Args:
            filepath: Destination path (will be created/overwritten).
        """
        with open(filepath, "w") as f:
            json.dump(self.to_jsonld(), f, indent=2, sort_keys=True)

    # ------------------------------------------------------------------
    # High-level mutation helpers
    # ------------------------------------------------------------------

    def add_arrangement(
        self,
        directory: str | pathlib.Path,
        comment: str | None = None,
        ignore_dirs: list[str] | None = None,
        resolve_symlinks: bool = True,
    ) -> ArtifactArrangement:
        """Scan *directory* and add a new arrangement (updating the composition).

        Args:
            directory: Directory to scan.
            comment: Human-readable label for this arrangement snapshot.
            ignore_dirs: Directory names to exclude (default: ``[".git"]``).
            resolve_symlinks: Whether to follow symlinks.

        Returns:
            The newly created :class:`ArtifactArrangement`.
        """
        arrangement_id = f"arrangement/{len(self.arrangements)}"
        arrangement = ArtifactArrangement.from_directory(
            directory=directory,
            composition=self.composition,
            arrangement_id=arrangement_id,
            comment=comment,
            ignore_dirs=ignore_dirs,
            resolve_symlinks=resolve_symlinks,
        )
        self.arrangements.append(arrangement)
        return arrangement

    def add_performance(
        self,
        start_time: datetime.datetime,
        end_time: datetime.datetime,
        comment: str | None = None,
        accessed_arrangement: str | None = None,
        modified_arrangement: str | None = None,
        attrs: list | None = None,
        extra_attributes: dict[str, Any] | None = None,
    ) -> TrustedResearchPerformance:
        """Record a new performance (execution run).

        Mirrors the logic of ``TRO.add_performance`` in ``tro_utils.py``.

        Args:
            start_time: When execution started.
            end_time: When execution ended.
            comment: Human-readable description.
            accessed_arrangement: ``@id`` of the input arrangement.
            modified_arrangement: ``@id`` of the output arrangement.
            attrs: List of :class:`~tro_utils.TRPAttribute` members (or their
                string values) to record as performance attributes.
            extra_attributes: Additional raw key/value pairs to merge into the
                performance JSON-LD (for forward compatibility).

        Returns:
            The newly created :class:`TrustedResearchPerformance`.

        Raises:
            ValueError: If a referenced arrangement does not exist, or if a
                required TRS capability is missing.
        """
        from tro_utils import (
            TRPAttribute,
            TROVCapability,
        )  # avoid circular at module level

        if attrs is None:
            attrs = []
        if extra_attributes is None:
            extra_attributes = {}

        available_ids = {arr.arrangement_id for arr in self.arrangements}

        if accessed_arrangement and accessed_arrangement not in available_ids:
            raise ValueError(
                f"Arrangement {accessed_arrangement!r} does not exist. "
                f"Available: {sorted(available_ids)}"
            )
        if modified_arrangement and modified_arrangement not in available_ids:
            raise ValueError(
                f"Arrangement {modified_arrangement!r} does not exist. "
                f"Available: {sorted(available_ids)}"
            )

        trs_caps = {
            cap.capability_type: cap.capability_id for cap in self.trs.capabilities
        }

        performance_id = f"trp/{len(self.performances)}"
        performance_attributes: list[PerformanceAttribute] = []
        for i, attr in enumerate(attrs):
            if isinstance(attr, str):
                attr = TRPAttribute(attr)
            cap = TROVCapability.translate(attr)
            if cap.value not in trs_caps:
                raise ValueError(
                    f"Capability {cap.value!r} required for attribute {attr.value!r} "
                    f"but not present in TRS capabilities: {list(trs_caps.keys())}"
                )
            performance_attributes.append(
                PerformanceAttribute(
                    attribute_id=f"{performance_id}/attribute/{i}",
                    attribute_type=attr.value,
                    warranted_by_id=trs_caps[cap.value],
                )
            )

        trp = TrustedResearchPerformance(
            performance_id=performance_id,
            comment=comment or "Some performance",
            conducted_by_id=self.trs.trs_id,
            started_at=start_time,
            ended_at=end_time,
            accessed_arrangement_id=accessed_arrangement,
            contributed_to_arrangement_id=modified_arrangement,
            attributes=performance_attributes,
        )

        # Merge extra_attributes as raw fields — stored as a side-channel dict
        # via the JSON-LD round-trip (no typed model needed for forward compat)
        if extra_attributes:
            trp._extra_attributes = extra_attributes  # type: ignore[attr-defined]

        self.performances.append(trp)
        return trp

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        graph_node: dict[str, Any] = {
            "@id": self.tro_id,
            "@type": ["trov:TransparentResearchObject", "schema:CreativeWork"],
            "schema:creator": self.creator,
            "schema:dateCreated": self.date_created.isoformat(),
            "schema:description": self.description,
            "schema:name": self.name,
            "trov:vocabularyVersion": self.vocabulary_version,
            "trov:wasAssembledBy": self.trs.to_jsonld(),
            "trov:hasComposition": self.composition.to_jsonld(),
            "trov:hasArrangement": [arr.to_jsonld() for arr in self.arrangements],
            "trov:hasPerformance": [perf.to_jsonld() for perf in self.performances],
            "trov:hasAttribute": [attr.to_jsonld() for attr in self.attributes],
        }

        if self.tsa is not None:
            graph_node["trov:wasTimestampedBy"] = self.tsa.to_jsonld()

        if self.created_with_name or self.created_with_version:
            created_with: dict[str, Any] = {
                "@type": "schema:SoftwareApplication",
            }
            if self.created_with_name:
                created_with["schema:name"] = self.created_with_name
            if self.created_with_version:
                created_with["schema:softwareVersion"] = self.created_with_version
            graph_node["trov:createdWith"] = created_with

        # Merge any extra_attributes from performances (forward compat)
        for i, perf in enumerate(self.performances):
            extra = getattr(perf, "_extra_attributes", {})
            if extra:
                graph_node["trov:hasPerformance"][i].update(extra)

        return {
            "@context": _JSONLD_CONTEXT,
            "@graph": [graph_node],
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "TransparentResearchObject":
        """Deserialise a full TRO from its JSON-LD dict representation.

        Args:
            data: The top-level JSON-LD dict with ``@context`` and ``@graph``.

        Returns:
            :class:`TransparentResearchObject` instance.

        Raises:
            RuntimeError: If the vocabulary version is too old.
        """
        graph = data["@graph"][0]

        vocab_version = Version(graph.get("trov:vocabularyVersion", "0.0.1"))
        if vocab_version < TROV_VOCABULARY_VERSION:
            raise RuntimeError(
                "Your TRO was created with an older version of the TRO vocabulary. "
                "In order to properly parse it you need to use tro-utils < 0.3.0."
            )

        # TRS
        trs = TrustedResearchSystem.from_jsonld(graph.get("trov:wasAssembledBy", {}))

        # TSA (optional)
        tsa: TimeStampingAuthority | None = None
        if "trov:wasTimestampedBy" in graph:
            tsa = TimeStampingAuthority.from_jsonld(graph["trov:wasTimestampedBy"])

        # Composition
        composition = ArtifactComposition.from_jsonld(
            graph.get(
                "trov:hasComposition", {"@id": "composition/1", "trov:hasArtifact": []}
            )
        )

        # Arrangements
        raw_arrangements = graph.get("trov:hasArrangement", [])
        if isinstance(raw_arrangements, dict):
            raw_arrangements = [raw_arrangements]
        arrangements = [ArtifactArrangement.from_jsonld(a) for a in raw_arrangements]

        # Performances
        raw_performances = graph.get("trov:hasPerformance", [])
        if isinstance(raw_performances, dict):
            raw_performances = [raw_performances]
        performances = [
            TrustedResearchPerformance.from_jsonld(p) for p in raw_performances
        ]

        # TRO-level attributes
        raw_attributes = graph.get("trov:hasAttribute", [])
        if isinstance(raw_attributes, dict):
            raw_attributes = [raw_attributes]
        attributes = [TROAttribute.from_jsonld(a) for a in raw_attributes]

        # created_with (optional)
        created_with = graph.get("trov:createdWith", {})

        # date_created
        date_created_raw = graph.get("schema:dateCreated")
        if date_created_raw:
            try:
                date_created = datetime.datetime.fromisoformat(date_created_raw)
            except ValueError:
                date_created = datetime.datetime.now()
        else:
            date_created = datetime.datetime.now()

        return cls(
            tro_id=graph.get("@id", "tro"),
            name=graph.get("schema:name", ""),
            description=graph.get("schema:description", ""),
            creator=graph.get("schema:creator", ""),
            date_created=date_created,
            vocabulary_version=graph.get(
                "trov:vocabularyVersion", str(TROV_VOCABULARY_VERSION)
            ),
            trs=trs,
            tsa=tsa,
            created_with_name=created_with.get("schema:name"),
            created_with_version=created_with.get("schema:softwareVersion"),
            composition=composition,
            arrangements=arrangements,
            performances=performances,
            attributes=attributes,
        )
