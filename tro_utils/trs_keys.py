"""TRS key lists: which keys a TRS signed with, and when.

A key list is a JSON or YAML file the verifier supplies, e.g.::

    format: https://w3id.org/trace/trs-keys/v1
    updated: 2026-11-16T00:00:00Z
    systems:
      - ids: [https://sivacor.org/]
        name: SIVACOR
        keys:
          - fingerprint: F7DB 4853 9F20 7AD4 612D C408 D8BB 2071 862A FF4A
            valid_from: 2025-11-13T00:00:00Z
            status: current

A key is judged against the time of the TRO's trusted timestamp, not against
its current OpenPGP state, so that TROs signed with a since-retired key stay
verifiable. See https://github.com/transparency-certified/tro-utils/issues/36.
"""

from __future__ import annotations

import datetime
import json
import pathlib
from dataclasses import dataclass, field

import yaml

FORMAT = "https://w3id.org/trace/trs-keys/v1"

CURRENT = "current"
RETIRED = "retired"
COMPROMISED = "compromised"
STATUSES = (CURRENT, RETIRED, COMPROMISED)


def normalize_fingerprint(value):
    """Return *value* as an upper-case hex fingerprint without spaces.

    Raises:
        ValueError: If *value* is not a full v4 (40 hex digits) or v5/v6 (64)
            fingerprint. A key ID is the tail of a fingerprint and is too
            short to identify a key safely, so it is refused.
    """
    fingerprint = "".join(value.split()).upper()
    if fingerprint.startswith("0X"):
        fingerprint = fingerprint[2:]
    if len(fingerprint) not in (40, 64) or any(
        c not in "0123456789ABCDEF" for c in fingerprint
    ):
        raise ValueError(f"{value!r} is not a full OpenPGP key fingerprint")
    return fingerprint


def _timestamp(value, where):
    """Parse an ISO 8601 date or date-time; a bare date is midnight UTC."""
    if isinstance(value, str):
        try:
            value = datetime.date.fromisoformat(value)
        except ValueError:
            try:
                value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(
                    f"{where}: {value!r} is not an ISO 8601 date"
                ) from None
    # YAML turns unquoted dates and times into objects of its own accord
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            raise ValueError(f"{where}: {value.isoformat()!r} has no time zone")
        return value
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, datetime.time(), datetime.timezone.utc)
    raise ValueError(f"{where}: expected an ISO 8601 date, got {value!r}")


def _optional_timestamp(entry, name, where):
    value = entry.get(name)
    return None if value is None else _timestamp(value, f"{where}.{name}")


def _require(entry, name, where):
    if entry.get(name) is None:
        raise ValueError(f"{where}: {name} is required")
    return entry[name]


@dataclass
class TRSKey:
    """One key a TRS signed with, and when."""

    fingerprint: str
    valid_from: datetime.datetime
    status: str = CURRENT
    valid_until: datetime.datetime | None = None
    compromised_since: datetime.datetime | None = None
    note: str | None = None

    @classmethod
    def from_dict(cls, entry, where):
        if not isinstance(entry, dict):
            raise ValueError(f"{where}: expected a mapping")
        fingerprint = _require(entry, "fingerprint", where)
        if not isinstance(fingerprint, str):
            # YAML reads an unquoted, all-digit fingerprint as a number
            raise ValueError(f"{where}.fingerprint: quote it, so it reads as text")
        status = entry.get("status", CURRENT)
        if status not in STATUSES:
            raise ValueError(
                f"{where}.status: expected one of {', '.join(STATUSES)}, "
                f"got {status!r}"
            )
        key = cls(
            fingerprint=normalize_fingerprint(fingerprint),
            valid_from=_timestamp(
                _require(entry, "valid_from", where), f"{where}.valid_from"
            ),
            status=status,
            valid_until=_optional_timestamp(entry, "valid_until", where),
            compromised_since=_optional_timestamp(entry, "compromised_since", where),
            note=entry.get("note"),
        )
        if status == RETIRED and key.valid_until is None:
            raise ValueError(f"{where}: a retired key needs valid_until")
        if status == COMPROMISED and key.compromised_since is None:
            raise ValueError(f"{where}: a compromised key needs compromised_since")
        if key.valid_until is not None and key.valid_until < key.valid_from:
            raise ValueError(f"{where}: valid_until is before valid_from")
        return key

    def check(self, signed_at):
        """Judge a signature by this key made at *signed_at*.

        Args:
            signed_at: Time of the trusted timestamp, or ``None`` if the TRO
                has none.

        Returns:
            ``(ok, message)``: *message* is the reason when *ok* is false, and
            a warning (or ``None``) when it is true.
        """
        if signed_at is None:
            if self.status != CURRENT:
                return False, (
                    f"the key is {self.status} and the TRO has no trusted "
                    "timestamp to show when it was signed"
                )
            return True, (
                "the TRO has no trusted timestamp, so when it was signed "
                "could not be checked"
            )
        when = signed_at.isoformat()
        if signed_at < self.valid_from:
            return False, (
                f"timestamped {when}, before the key came into use "
                f"({self.valid_from.isoformat()})"
            )
        if self.valid_until is not None and signed_at > self.valid_until:
            return False, (
                f"timestamped {when}, after the key went out of use "
                f"({self.valid_until.isoformat()})"
            )
        if self.status == COMPROMISED:
            since = self.compromised_since.isoformat()
            if signed_at >= self.compromised_since:
                return False, (
                    f"timestamped {when}, after the key was compromised ({since})"
                )
            return True, (
                f"the key was compromised from {since}; the trusted timestamp "
                f"({when}) shows the TRO was signed before that"
            )
        return True, None


@dataclass
class TRSEntry:
    """A TRS in a key list: every @id it has used, and its keys."""

    ids: list[str]
    keys: list[TRSKey]
    name: str | None = None


@dataclass
class TRSKeyList:
    """The keys of one or more TRSs, as read from a key list file."""

    systems: list[TRSEntry] = field(default_factory=list)
    updated: datetime.datetime | None = None

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("expected a mapping at the top level")
        if data.get("format") != FORMAT:
            raise ValueError(f"format must be {FORMAT!r}, got {data.get('format')!r}")
        systems = data.get("systems")
        if not isinstance(systems, list):
            raise ValueError("systems: expected a list")
        parsed = []
        for i, system in enumerate(systems):
            where = f"systems[{i}]"
            if not isinstance(system, dict):
                raise ValueError(f"{where}: expected a mapping")
            ids = _require(system, "ids", where)
            if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
                raise ValueError(f"{where}.ids: expected a list of IRIs")
            keys = _require(system, "keys", where)
            if not isinstance(keys, list):
                raise ValueError(f"{where}.keys: expected a list")
            parsed.append(
                TRSEntry(
                    ids=ids,
                    name=system.get("name"),
                    keys=[
                        TRSKey.from_dict(key, f"{where}.keys[{j}]")
                        for j, key in enumerate(keys)
                    ],
                )
            )
        return cls(systems=parsed, updated=_optional_timestamp(data, "updated", "list"))

    @classmethod
    def load(cls, path):
        """Read a key list from a JSON file, or YAML if it ends in .yaml/.yml.

        Raises:
            ValueError: If the file cannot be parsed or is not a key list.
        """
        path = pathlib.Path(path)
        text = path.read_text()
        try:
            if path.suffix.lower() in (".yaml", ".yml"):
                data = yaml.safe_load(text)
            else:
                data = json.loads(text)
            return cls.from_dict(data)
        except (ValueError, yaml.YAMLError) as err:
            raise ValueError(f"{path}: {err}") from err

    def keys_for(self, trs_id):
        """Return the keys listed for the TRS identified by *trs_id*.

        Returns:
            ``None`` if no system in the list has *trs_id* among its ids.
        """
        found = [s for s in self.systems if trs_id in s.ids]
        if not found:
            return None
        return [key for s in found for key in s.keys]
