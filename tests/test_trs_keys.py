"""Tests for reading TRS key lists and judging keys by them."""

import datetime
import json

import pytest

from tro_utils.trs_keys import COMPROMISED, CURRENT, RETIRED, TRSKey, TRSKeyList

FPR = "F7DB48539F207AD4612DC408D8BB2071862AFF4A"
UTC = datetime.timezone.utc


def _at(*args):
    return datetime.datetime(*args, tzinfo=UTC)


def _list(**key):
    return {
        "format": "https://w3id.org/trace/trs-keys/v1",
        "systems": [
            {
                "ids": ["https://sivacor.org/"],
                "name": "SIVACOR",
                "keys": [
                    {"fingerprint": FPR, "valid_from": "2025-11-13T00:00:00Z", **key}
                ],
            }
        ],
    }


YAML = """\
format: https://w3id.org/trace/trs-keys/v1
updated: 2026-11-16T00:00:00Z
systems:
  - ids: [https://sivacor.org/]
    name: SIVACOR
    keys:
      - fingerprint: F7DB 4853 9F20 7AD4 612D C408 D8BB 2071 862A FF4A
        valid_from: 2025-11-13
        status: retired
        valid_until: 2026-06-01T12:00:00+02:00
"""


class TestLoad:
    def test_json(self, tmp_path):
        path = tmp_path / "keys.json"
        path.write_text(json.dumps(_list(valid_until=None)))

        keys = TRSKeyList.load(path).keys_for("https://sivacor.org/")

        assert keys == [TRSKey(fingerprint=FPR, valid_from=_at(2025, 11, 13))]

    @pytest.mark.parametrize("suffix", [".yaml", ".yml"])
    def test_yaml(self, tmp_path, suffix):
        """Unquoted dates, a spaced fingerprint and an offset all read right."""
        path = tmp_path / f"keys{suffix}"
        path.write_text(YAML)

        key_list = TRSKeyList.load(path)
        (key,) = key_list.keys_for("https://sivacor.org/")

        assert key_list.updated == _at(2026, 11, 16)
        assert key.fingerprint == FPR
        assert key.valid_from == _at(2025, 11, 13)
        assert key.status == RETIRED
        assert key.valid_until == _at(2026, 6, 1, 10)

    def test_yaml_and_json_agree(self, tmp_path):
        yaml_path = tmp_path / "keys.yaml"
        yaml_path.write_text(YAML)
        json_path = tmp_path / "keys.json"
        json_path.write_text(
            json.dumps(
                _list(
                    status="retired",
                    valid_from="2025-11-13",
                    valid_until="2026-06-01T10:00:00Z",
                )
                | {"updated": "2026-11-16T00:00:00Z"}
            )
        )

        assert TRSKeyList.load(yaml_path) == TRSKeyList.load(json_path)

    def test_unknown_trs(self):
        assert TRSKeyList.from_dict(_list()).keys_for("https://example.org/") is None

    def test_keys_of_every_matching_system(self):
        data = _list()
        data["systems"].append(
            {
                "ids": ["https://sivacor.org/"],
                "keys": [{"fingerprint": "A" * 40, "valid_from": "2027-01-01"}],
            }
        )

        keys = TRSKeyList.from_dict(data).keys_for("https://sivacor.org/")

        assert [k.fingerprint for k in keys] == [FPR, "A" * 40]

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "keys.json"
        path.write_text("{")

        with pytest.raises(ValueError, match="keys.json"):
            TRSKeyList.load(path)

    def test_invalid_yaml(self, tmp_path):
        path = tmp_path / "keys.yaml"
        path.write_text("systems: [\n")

        with pytest.raises(ValueError, match="keys.yaml"):
            TRSKeyList.load(path)

    @pytest.mark.parametrize(
        "data, message",
        [
            ([], "mapping at the top level"),
            ({"systems": []}, "format must be"),
            (_list() | {"systems": {}}, "systems: expected a list"),
            (_list(fingerprint="D8BB2071862AFF4A"), "not a full OpenPGP"),
            (_list(fingerprint=1234), "quote it"),
            (_list(status="lost"), "expected one of current, retired, compromised"),
            (_list(status="retired"), "a retired key needs valid_until"),
            (_list(status="compromised"), "needs compromised_since"),
            (_list(valid_from=None), "valid_from is required"),
            (_list(valid_from="yesterday"), "not an ISO 8601 date"),
            (_list(valid_from="2025-11-13T00:00:00"), "has no time zone"),
            (_list(valid_until="2025-01-01"), "valid_until is before valid_from"),
        ],
    )
    def test_rejects(self, data, message):
        with pytest.raises(ValueError, match=message):
            TRSKeyList.from_dict(data)

    def test_rejects_unquoted_numeric_fingerprint(self, tmp_path):
        path = tmp_path / "keys.yaml"
        path.write_text(
            YAML.replace("F7DB 4853 9F20 7AD4 612D C408 D8BB 2071 862A FF4A", "1" * 40)
        )

        with pytest.raises(ValueError, match="quote it"):
            TRSKeyList.load(path)


class TestCheck:
    key = TRSKey(fingerprint=FPR, valid_from=_at(2025, 11, 13))

    def test_current(self):
        assert self.key.check(_at(2026, 1, 1)) == (True, None)

    def test_before_valid_from(self):
        ok, reason = self.key.check(_at(2025, 1, 1))

        assert not ok
        assert "before the key came into use" in reason

    def test_retired(self):
        key = TRSKey(FPR, _at(2025, 11, 13), RETIRED, valid_until=_at(2026, 6, 1))

        assert key.check(_at(2026, 5, 31)) == (True, None)
        ok, reason = key.check(_at(2026, 6, 2))
        assert not ok
        assert "after the key went out of use" in reason

    def test_compromised(self):
        key = TRSKey(
            FPR, _at(2025, 11, 13), COMPROMISED, compromised_since=_at(2026, 6, 1)
        )

        ok, warning = key.check(_at(2026, 5, 31))
        assert ok
        assert "signed before that" in warning
        ok, reason = key.check(_at(2026, 6, 1))
        assert not ok
        assert "after the key was compromised" in reason

    def test_no_timestamp(self):
        ok, warning = self.key.check(None)
        assert ok
        assert "no trusted timestamp" in warning

        retired = TRSKey(FPR, _at(2025, 11, 13), RETIRED, valid_until=_at(2026, 6, 1))
        ok, reason = retired.check(None)
        assert not ok
        assert "the key is retired" in reason

    def test_status_defaults_to_current(self):
        assert self.key.status == CURRENT
