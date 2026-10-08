"""TrustedResearchSystem and TRSCapability models."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ._base import TROVModel

# Profile keys that are handled as typed fields on TrustedResearchSystem;
# all other keys are stored verbatim in ``extra_fields``.
_KNOWN_TRS_KEYS = {
    "@id",
    "@type",
    "schema:name",
    "schema:description",
    "trov:publicKey",
    "trov:hasCapability",
}

#: Used when a profile identifies the TRS neither by ``@id`` nor by a URL.
UNIDENTIFIED_TRS_ID = "https://w3id.org/trace/tro-utils#unidentified-trs"

# An absolute IRI and a compact IRI share this shape: a scheme/prefix per
# RFC 3986, a colon, then a non-empty remainder.  What this rules out is a
# bare relative reference such as "trs" or "trs/capability/1", which resolves
# against whatever document happens to contain it.
_IRI_RE = re.compile(r"^(?P<prefix>[A-Za-z][A-Za-z0-9+.\-]*):(?P<rest>.+)$")

# The trov prefix names the vocabulary itself, so a TRS minted under it would
# not be the same TRS wherever it is defined.
_RESERVED_PREFIX = "trov"


def iri_prefix(value: Any) -> str | None:
    """Return the scheme/prefix of *value*, or ``None`` if it is not an IRI.

    Args:
        value: A candidate ``@id``.

    Returns:
        The part before the first colon, or ``None`` when *value* is a
        relative reference, a blank node, or not a string at all.
    """
    if not isinstance(value, str):
        return None
    match = _IRI_RE.match(value)
    return match.group("prefix") if match else None


def is_conforming_trs_id(value: Any) -> bool:
    """Return whether *value* may identify a TRS.

    A TRS ``@id`` must be an absolute IRI, or a compact IRI whose prefix is
    not ``trov``, so that the same TRS carries the same identifier in every
    document that mentions it.

    Args:
        value: A candidate ``@id``.

    Returns:
        ``True`` when *value* conforms.
    """
    prefix = iri_prefix(value)
    return prefix is not None and prefix != _RESERVED_PREFIX


def is_conforming_capability_id(value: Any) -> bool:
    """Return whether *value* may identify a TRS capability.

    A capability belongs to the TRS rather than to any one declaration, so it
    has to be named the same way everywhere: an absolute IRI or a compact IRI.
    Unlike a TRS ``@id``, the ``trov`` prefix is allowed here -- the usual
    identifier for a capability *is* its vocabulary term, e.g.
    ``trov:CanRecordInternetAccess``.

    Args:
        value: A candidate ``@id``.

    Returns:
        ``True`` when *value* conforms.
    """
    return iri_prefix(value) is not None


def validate_capability_id(value: Any, source: str = "capability @id") -> str:
    """Return *value* unchanged, or raise if it cannot identify a capability.

    Args:
        value: The candidate ``@id``.
        source: Label for the error message.

    Returns:
        *value*.

    Raises:
        ValueError: If *value* does not conform.  See
            :func:`is_conforming_capability_id`.
    """
    if is_conforming_capability_id(value):
        return value
    raise ValueError(
        f"{source} must be an absolute IRI or a compact IRI -- usually the "
        f"capability's own term, e.g. 'trov:CanRecordInternetAccess' -- so "
        f"that trov:warrantedBy refers to the same capability wherever it is "
        f"mentioned; got {value!r}. A relative id such as 'trs/capability/1' "
        f"resolves against whichever document contains it. Omit @id to use "
        f"the capability's @type."
    )


def validate_trs_id(value: Any, source: str = "TRS @id") -> str:
    """Return *value* unchanged, or raise if it cannot identify a TRS.

    Args:
        value: The candidate ``@id``.
        source: Label for the error message.

    Returns:
        *value*.

    Raises:
        ValueError: If *value* does not conform.  See :func:`is_conforming_trs_id`.
    """
    if is_conforming_trs_id(value):
        return value
    raise ValueError(
        f"{source} must be an absolute IRI (e.g. "
        f"'https://example.org/trs') or a compact IRI whose prefix is not "
        f"'{_RESERVED_PREFIX}' (e.g. 'ex:trs'), so that the TRS is the same "
        f"wherever it is defined; got {value!r}"
    )


@dataclass
class TRSCapability(TROVModel):
    """A single capability declared by a :class:`TrustedResearchSystem`.

    The ``@id`` is what ``trov:warrantedBy`` points at from a performance
    attribute, so it has to name the same capability in every declaration --
    see :func:`is_conforming_capability_id`.  A profile that states no ``@id``
    gets the capability's own term, which is the usual identifier for it.
    """

    capability_id: str
    capability_type: str

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_profile_entry(cls, data: dict[str, Any]) -> "TRSCapability":
        """Build a capability from one ``trov:hasCapability`` profile entry.

        Args:
            data: Dict with ``@type`` and an optional ``@id``.

        Returns:
            :class:`TRSCapability` identified by its stated ``@id``, or by its
            ``@type`` when none is stated.

        Raises:
            ValueError: If a stated ``@id`` cannot identify a capability, or if
                the entry has no usable ``@type``.
        """
        capability_type = data["@type"]
        if "@id" in data:
            capability_id = validate_capability_id(
                data["@id"], "TRS profile capability @id"
            )
        else:
            capability_id = validate_capability_id(
                capability_type, "TRS profile capability @type"
            )
        return cls(capability_id=capability_id, capability_type=capability_type)

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        return {
            "@id": self.capability_id,
            "@type": self.capability_type,
        }

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "TRSCapability":
        """Deserialise from a declaration, permissively.

        Declarations written before capabilities were named by a conforming
        IRI carry a relative ``@id``; they have to stay loadable, so nothing
        is validated here.  :meth:`from_profile_entry` is the checked path.
        """
        return cls(
            capability_id=data["@id"],
            capability_type=data["@type"],
        )


@dataclass
class TrustedResearchSystem(TROVModel):
    """A Trusted Research System (TRS) that assembled and/or ran a TRO.

    The TRS is a ``schema:Organization``, so it is described with schema.org
    properties: ``schema:name`` and ``schema:description`` are typed fields,
    and the rest (``schema:url``, ``schema:email``, ``schema:owner``, plus any
    vendor-specific keys) are stored in :attr:`extra_fields` and round-tripped
    verbatim through ``to_jsonld()`` / ``from_jsonld()``.
    """

    trs_id: str = UNIDENTIFIED_TRS_ID
    name: str = ""
    description: str = ""
    public_key: str | None = None
    capabilities: list[TRSCapability] = field(default_factory=list)
    extra_fields: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_profile(
        cls, profile: dict[str, Any], trs_id: str | None = None
    ) -> "TrustedResearchSystem":
        """Load a TRS from the profile dict used by the existing CLI.

        The profile format mirrors what is stored under ``trov:wasAssembledBy``
        in a JSON-LD document.  All unrecognised keys are preserved in
        :attr:`extra_fields`.

        The identifier is taken from *trs_id*, else the profile's ``@id``, else
        its ``schema:url``, else :data:`UNIDENTIFIED_TRS_ID`.  Whichever is
        used must conform -- see :func:`validate_trs_id`.

        Args:
            profile: Dict with optional keys ``@id``, ``schema:name``,
                ``schema:description``, ``trov:publicKey``,
                ``trov:hasCapability``, plus any vendor-specific fields.
            trs_id: Overrides the ``@id`` carried by *profile*.

        Returns:
            :class:`TrustedResearchSystem` instance.

        Raises:
            ValueError: If the resolved identifier does not conform.
        """
        capabilities = [
            TRSCapability.from_profile_entry(cap)
            for cap in profile.get("trov:hasCapability", [])
        ]
        extra = {k: v for k, v in profile.items() if k not in _KNOWN_TRS_KEYS}
        return cls(
            trs_id=cls._resolve_profile_id(profile, trs_id),
            name=profile.get("schema:name", ""),
            description=profile.get("schema:description", ""),
            public_key=profile.get("trov:publicKey"),
            capabilities=capabilities,
            extra_fields=extra,
        )

    @staticmethod
    def _resolve_profile_id(profile: dict[str, Any], trs_id: str | None) -> str:
        """Pick the TRS ``@id`` for *profile* and check that it conforms.

        An identifier the caller or profile states explicitly is validated
        rather than quietly replaced, so a non-conforming one is reported
        instead of being papered over by the fallback.
        """
        if trs_id is not None:
            return validate_trs_id(trs_id, "TRS @id")
        if "@id" in profile:
            return validate_trs_id(profile["@id"], "TRS profile @id")
        # A TRS's URL already identifies it globally.  trov:url is read only
        # for profiles written before the TRS was described with schema.org
        # properties; the TROV vocabulary never defined that term.
        for key in ("schema:url", "trov:url"):
            url = profile.get(key)
            if url is not None and is_conforming_trs_id(url):
                return url
        return UNIDENTIFIED_TRS_ID

    # ------------------------------------------------------------------
    # JSON-LD serialisation
    # ------------------------------------------------------------------

    def to_jsonld(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "@id": self.trs_id,
            "@type": ["trov:TrustedResearchSystem", "schema:Organization"],
            "trov:hasCapability": [cap.to_jsonld() for cap in self.capabilities],
        }
        # Merge extra (vendor) fields first so typed fields can override
        result.update(self.extra_fields)
        if self.name:
            result["schema:name"] = self.name
        if self.description:
            result["schema:description"] = self.description
        if self.public_key is not None:
            result["trov:publicKey"] = self.public_key
        return result

    @classmethod
    def from_jsonld(cls, data: dict[str, Any]) -> "TrustedResearchSystem":
        """Deserialise from a JSON-LD TRS dict (``trov:wasAssembledBy`` value).

        Args:
            data: Dict with ``@id``, optional ``schema:name``, etc.

        Returns:
            :class:`TrustedResearchSystem` instance.
        """
        capabilities = [
            TRSCapability.from_jsonld(cap) for cap in data.get("trov:hasCapability", [])
        ]
        extra = {k: v for k, v in data.items() if k not in _KNOWN_TRS_KEYS}
        return cls(
            # Read as-is: declarations predating this rule carry a bare
            # "trs", and they must stay loadable.
            trs_id=data.get("@id", UNIDENTIFIED_TRS_ID),
            name=data.get("schema:name", ""),
            description=data.get("schema:description", ""),
            public_key=data.get("trov:publicKey"),
            capabilities=capabilities,
            extra_fields=extra,
        )
