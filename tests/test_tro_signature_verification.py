"""Tests for verifying the TRS signature of a TRO."""

import datetime
import json
import pathlib
import subprocess
from unittest.mock import MagicMock, patch

import gnupg
import pytest
import yaml
from click.testing import CliRunner

from tro_utils.cli import cli
from tro_utils.tro_utils import TRO, _kill_gpg_agent, normalize_fingerprint

from tests.helpers import create_tro_with_gpg


@pytest.fixture
def signed_tro(tmp_path, temp_workspace, gpg_setup, trs_profile):
    """Return the path of a signed TRO whose key is in the test keyring."""
    declaration = str(tmp_path / "test_tro.jsonld")
    tro = create_tro_with_gpg(
        filepath=declaration,
        gpg_setup=gpg_setup,
        profile=trs_profile,
        gpg_fingerprint=gpg_setup["fingerprint"],
        gpg_passphrase=gpg_setup["passphrase"],
    )
    tro.add_arrangement(str(temp_workspace), comment="Test")
    # Sign exactly as request_timestamp() does, without contacting a TSA
    tro.attach_public_key()
    tro.save()
    tro.trs_signature()
    return declaration


@pytest.fixture
def mislabeled_tro(tmp_path, temp_workspace, gpg_setup, trs_profile, other_key):
    """Return a TRO signed by the test key that embeds a different public key."""
    declaration = str(tmp_path / "test_tro.jsonld")
    tro = create_tro_with_gpg(
        filepath=declaration,
        gpg_setup=gpg_setup,
        profile=trs_profile,
        gpg_fingerprint=gpg_setup["fingerprint"],
        gpg_passphrase=gpg_setup["passphrase"],
    )
    tro.add_arrangement(str(temp_workspace), comment="Test")
    tro._model.trs.public_key = other_key
    tro.save()
    tro.trs_signature()
    return declaration


@pytest.fixture
def empty_keyring(tmp_path):
    home = tmp_path / "empty_gnupg"
    home.mkdir(mode=0o700)
    yield str(home)
    _kill_gpg_agent(str(home))


@pytest.fixture
def other_key(tmp_path_factory):
    """Public key of a second, unrelated signer."""
    home = tmp_path_factory.mktemp("other_gnupg")
    home.chmod(0o700)
    gpg = gnupg.GPG(gnupghome=str(home))
    key = gpg.gen_key(
        gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real="Other",
            name_email="other@example.com",
            no_protection=True,
        )
    )
    yield gpg.export_keys(str(key))
    _kill_gpg_agent(str(home))


@pytest.fixture
def expired_key_tro(tmp_path, trs_profile):
    """Return ``(declaration, gnupghome)`` for a TRO signed by a now-expired key."""
    home = tmp_path / "expired_gnupg"
    home.mkdir(mode=0o700)
    # Create the key and sign in 2020, so the key has long expired by now
    gpg = gnupg.GPG(
        gnupghome=str(home), options=["--faked-system-time", "20200101T000000"]
    )
    key = gpg.gen_key(
        gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real="Expired",
            name_email="expired@example.com",
            no_protection=True,
            expire_date="1d",
        )
    )
    declaration = tmp_path / "test_tro.jsonld"
    TRO(filepath=str(declaration), profile=trs_profile).save()
    signature = gpg.sign(declaration.read_bytes(), keyid=str(key), detach=True)
    (tmp_path / "test_tro.sig").write_text(str(signature))
    yield str(declaration), str(home)
    _kill_gpg_agent(str(home))


@pytest.fixture
def never_trusted_keyring(tmp_path, gpg_setup):
    """A keyring holding the signing key, marked as never trusted.

    Owner trust only decides a key's validity under the direct trust model.
    """
    home = tmp_path / "never_gnupg"
    home.mkdir(mode=0o700)
    (home / "gpg.conf").write_text("trust-model direct\n")
    gpg = gnupg.GPG(gnupghome=str(home))
    gpg.import_keys(gpg_setup["gpg"].export_keys(gpg_setup["fingerprint"]))
    gpg.trust_keys(gpg_setup["fingerprint"], "TRUST_NEVER")
    yield str(home)
    _kill_gpg_agent(str(home))


@pytest.fixture
def uncertified_keyring(tmp_path, gpg_setup):
    """A keyring holding the signing key, imported but never certified."""
    home = tmp_path / "uncertified_gnupg"
    home.mkdir(mode=0o700)
    gpg = gnupg.GPG(gnupghome=str(home))
    gpg.import_keys(gpg_setup["gpg"].export_keys(gpg_setup["fingerprint"]))
    yield str(home)
    _kill_gpg_agent(str(home))


@pytest.fixture
def key_file(tmp_path, gpg_setup):
    """The signing key exported to an armored file, as a TRS would publish it."""
    path = tmp_path / "trs.asc"
    path.write_text(gpg_setup["gpg"].export_keys(gpg_setup["fingerprint"]))
    return str(path)


@pytest.fixture
def binary_key_file(tmp_path, gpg_setup):
    path = tmp_path / "trs.gpg"
    path.write_bytes(
        gpg_setup["gpg"].export_keys(gpg_setup["fingerprint"], armor=False)
    )
    return str(path)


@pytest.fixture
def other_key_file(tmp_path, other_key):
    path = tmp_path / "other.asc"
    path.write_text(other_key)
    return str(path)


def _spaced(fingerprint):
    """Format a fingerprint in groups of four, as key pages print it."""
    return " ".join(fingerprint[i : i + 4] for i in range(0, len(fingerprint), 4))


def _write_key_list(path, declaration, fingerprint, trs_id=None, **key):
    """Write a key list for the TRS of *declaration*, as JSON or YAML."""
    data = {
        "format": "https://w3id.org/trace/trs-keys/v1",
        "systems": [
            {
                "ids": [trs_id or TRO(filepath=declaration)._model.trs.trs_id],
                "keys": [
                    {"fingerprint": fingerprint, "valid_from": "2019-01-01", **key}
                ],
            }
        ],
    }
    path = pathlib.Path(path)
    if path.suffix == ".yaml":
        path.write_text(yaml.safe_dump(data))
    else:
        path.write_text(json.dumps(data))
    return str(path)


@pytest.fixture
def timestamped(tmp_path):
    """Give the signed TRO a .tsr whose verified time is 2026-01-01."""
    (tmp_path / "test_tro.tsr").write_bytes(b"tsr")
    when = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    with (
        patch.object(TRO, "verify_timestamp") as verify,
        patch.object(TRO, "timestamp_time", return_value=when),
    ):
        yield verify


def _replace_embedded_key(declaration, public_key):
    with open(declaration) as fp:
        data = json.load(fp)
    data["@graph"][0]["trov:wasAssembledBy"]["trov:publicKey"] = public_key
    with open(declaration, "w") as fp:
        json.dump(data, fp, indent=2, sort_keys=True)


class TestVerifySignature:
    def test_valid_with_keyring(self, signed_tro, gpg_setup):
        result = TRO(filepath=signed_tro).verify_signature()

        assert result.valid
        assert result.trusted
        assert result.fingerprint == gpg_setup["fingerprint"]
        assert "Test User" in result.username
        assert not result.used_embedded_key
        assert result.embedded_key_matches is True

    def test_key_missing_from_keyring(self, signed_tro, gpg_setup, empty_keyring):
        result = TRO(filepath=signed_tro).verify_signature(gnupghome=empty_keyring)

        assert not result.valid
        assert result.key_missing
        assert result.fingerprint == gpg_setup["fingerprint"]

    def test_embedded_key(self, signed_tro, gpg_setup, empty_keyring):
        with patch("tro_utils.tro_utils.GPG_HOME", empty_keyring):
            result = TRO(filepath=signed_tro).verify_signature(use_embedded_key=True)

        assert result.valid
        assert not result.trusted
        assert result.used_embedded_key
        assert result.fingerprint == gpg_setup["fingerprint"]

    def test_embedded_key_stops_agent(self, signed_tro):
        """The throwaway keyring's gpg-agent is stopped before it is removed."""
        with patch("tro_utils.tro_utils._kill_gpg_agent") as kill:
            TRO(filepath=signed_tro).verify_signature(use_embedded_key=True)

        kill.assert_called_once()

    def test_kill_gpg_agent_without_gpgconf(self, tmp_path):
        with patch("subprocess.run", side_effect=FileNotFoundError) as run:
            _kill_gpg_agent(str(tmp_path))

        run.assert_called_once()

    def test_uncertified_key(self, signed_tro, uncertified_keyring):
        """A key that is only present in the keyring is not trusted."""
        result = TRO(filepath=signed_tro).verify_signature(
            gnupghome=uncertified_keyring
        )

        assert result.valid
        assert not result.trusted

    def test_no_auto_key_retrieve(self, signed_tro):
        """gpg must not fetch the signing key by the fingerprint in the .sig."""
        options = []
        verify_data = gnupg.GPG.verify_data

        def spy(gpg, *args, **kwargs):
            options.extend(gpg.options)
            return verify_data(gpg, *args, **kwargs)

        with patch.object(gnupg.GPG, "verify_data", spy):
            TRO(filepath=signed_tro).verify_signature()

        assert "--no-auto-key-retrieve" in options

    def test_tampered_declaration(self, signed_tro):
        with open(signed_tro, "a") as fp:
            fp.write("\n")

        result = TRO(filepath=signed_tro).verify_signature()

        assert not result.valid
        assert not result.key_missing

    def test_expired_key(self, expired_key_tro):
        declaration, home = expired_key_tro

        result = TRO(filepath=declaration).verify_signature(gnupghome=home)

        assert not result.valid
        assert result.status == "signing key has expired"

    def test_never_trusted_key(self, signed_tro, never_trusted_keyring):
        result = TRO(filepath=signed_tro).verify_signature(
            gnupghome=never_trusted_keyring
        )

        assert not result.valid
        assert result.status == "signing key is marked as never trusted"

    def test_embedded_key_matched_by_key_id(self, signed_tro, gpg_setup):
        """GnuPG < 2.2.7 reports a missing key by its key ID only."""
        fake = MagicMock(
            valid=False,
            status="no public key",
            key_status=None,
            fingerprint=None,
            pubkey_fingerprint=None,
            key_id=gpg_setup["fingerprint"][-16:],
            trust_level=None,
            TRUST_NEVER=2,
        )
        with patch.object(gnupg.GPG, "verify_data", return_value=fake):
            result = TRO(filepath=signed_tro).verify_signature()

        assert result.key_missing
        assert result.embedded_key_matches is True

    def test_embedded_key_mismatch(self, signed_tro, other_key):
        """A wrong trov:publicKey is reported; the TRO no longer verifies anyway."""
        _replace_embedded_key(signed_tro, other_key)

        result = TRO(filepath=signed_tro).verify_signature(use_embedded_key=True)

        assert not result.valid
        assert result.key_missing
        assert result.embedded_key_matches is False

    def test_missing_signature(self, signed_tro, tmp_path):
        (tmp_path / "test_tro.sig").unlink()

        with pytest.raises(RuntimeError, match="Signature file does not exist"):
            TRO(filepath=signed_tro).verify_signature()

    def test_no_embedded_key(self, signed_tro):
        _replace_embedded_key(signed_tro, None)

        with pytest.raises(RuntimeError, match="does not embed a public key"):
            TRO(filepath=signed_tro).verify_signature(use_embedded_key=True)

    def test_valid_signature_with_wrong_embedded_key(self, mislabeled_tro):
        result = TRO(filepath=mislabeled_tro).verify_signature()

        assert result.valid
        assert result.embedded_key_matches is False


class TestVerifySignatureKeyringFile:
    @pytest.mark.parametrize("fixture", ["key_file", "binary_key_file"])
    def test_valid(self, signed_tro, gpg_setup, fixture, request):
        path = request.getfixturevalue(fixture)

        result = TRO(filepath=signed_tro).verify_signature(keyring=path)

        assert result.valid
        assert result.trusted
        assert result.keyring == path
        assert result.fingerprint == gpg_setup["fingerprint"]

    def test_only_keys_in_file_are_used(self, signed_tro, gpg_setup, other_key_file):
        """The signing key in the default keyring is not consulted."""
        result = TRO(filepath=signed_tro).verify_signature(keyring=other_key_file)

        assert not result.valid
        assert result.key_missing
        assert result.fingerprint == gpg_setup["fingerprint"]

    def test_no_keys_in_file(self, signed_tro, tmp_path):
        path = tmp_path / "empty.asc"
        path.write_text("nothing here\n")

        with pytest.raises(RuntimeError, match="No public keys found"):
            TRO(filepath=signed_tro).verify_signature(keyring=str(path))

    def test_stops_agent(self, signed_tro, key_file):
        with patch("tro_utils.tro_utils._kill_gpg_agent") as kill:
            TRO(filepath=signed_tro).verify_signature(keyring=key_file)

        kill.assert_called_once()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"use_embedded_key": True, "keyring": "k.asc"},
            {"gnupghome": "home", "keyring": "k.asc"},
            {"use_embedded_key": True, "gnupghome": "home"},
        ],
    )
    def test_key_sources_are_exclusive(self, signed_tro, kwargs):
        with pytest.raises(ValueError, match="mutually exclusive"):
            TRO(filepath=signed_tro).verify_signature(**kwargs)


class TestVerifySignatureFingerprint:
    def test_match_confirms_uncertified_key(
        self, signed_tro, gpg_setup, uncertified_keyring
    ):
        result = TRO(filepath=signed_tro).verify_signature(
            gnupghome=uncertified_keyring,
            fingerprints=[_spaced(gpg_setup["fingerprint"])],
        )

        assert result.valid
        assert result.fingerprint_matches is True
        assert result.trusted

    def test_match_confirms_embedded_key(self, signed_tro, gpg_setup):
        result = TRO(filepath=signed_tro).verify_signature(
            use_embedded_key=True,
            fingerprints=[gpg_setup["fingerprint"].lower()],
        )

        assert result.valid
        assert result.trusted

    def test_any_of_several_matches(self, signed_tro, gpg_setup):
        result = TRO(filepath=signed_tro).verify_signature(
            fingerprints=["A" * 40, gpg_setup["fingerprint"]]
        )

        assert result.valid
        assert result.fingerprint_matches is True

    def test_mismatch(self, signed_tro):
        result = TRO(filepath=signed_tro).verify_signature(
            use_embedded_key=True, fingerprints=["A" * 40]
        )

        assert not result.valid
        assert not result.trusted
        assert result.fingerprint_matches is False
        assert result.status == "signing key does not have the expected fingerprint"

    def test_not_given(self, signed_tro):
        result = TRO(filepath=signed_tro).verify_signature()

        assert result.fingerprint_matches is None

    @pytest.mark.parametrize(
        "value, expected",
        [
            (
                "f7db 4853 9f20 7ad4 612d  c408 d8bb 2071 862a ff4a",
                "F7DB48539F207AD4612DC408D8BB2071862AFF4A",
            ),
            (
                "0xF7DB48539F207AD4612DC408D8BB2071862AFF4A",
                "F7DB48539F207AD4612DC408D8BB2071862AFF4A",
            ),
            ("B" * 64, "B" * 64),
        ],
    )
    def test_normalize(self, value, expected):
        assert normalize_fingerprint(value) == expected

    @pytest.mark.parametrize("value", ["D8BB2071862AFF4A", "G" * 40, ""])
    def test_normalize_rejects(self, value):
        with pytest.raises(ValueError, match="not a full OpenPGP key fingerprint"):
            normalize_fingerprint(value)


class TestVerifySignatureTRSKeys:
    @pytest.mark.parametrize("name", ["keys.json", "keys.yaml"])
    def test_current_key(self, signed_tro, gpg_setup, tmp_path, timestamped, name):
        keys = _write_key_list(tmp_path / name, signed_tro, gpg_setup["fingerprint"])

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert result.valid
        assert result.trusted
        assert result.used_embedded_key
        assert result.listed_status == "current"
        assert result.timestamp.year == 2026
        assert result.warnings == []
        timestamped.assert_called_once_with(quiet=True)

    def test_uses_keyring_when_given(
        self, signed_tro, gpg_setup, tmp_path, timestamped, key_file
    ):
        keys = _write_key_list(
            tmp_path / "k.json", signed_tro, gpg_setup["fingerprint"]
        )

        result = TRO(filepath=signed_tro).verify_signature(
            trs_keys=keys, keyring=key_file
        )

        assert result.valid
        assert not result.used_embedded_key

    def test_retired_key_in_window(self, signed_tro, gpg_setup, tmp_path, timestamped):
        keys = _write_key_list(
            tmp_path / "k.json",
            signed_tro,
            gpg_setup["fingerprint"],
            status="retired",
            valid_until="2026-06-01",
        )

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert result.valid
        assert result.listed_status == "retired"

    def test_retired_key_after_window(
        self, signed_tro, gpg_setup, tmp_path, timestamped
    ):
        keys = _write_key_list(
            tmp_path / "k.json",
            signed_tro,
            gpg_setup["fingerprint"],
            status="retired",
            valid_until="2025-06-01",
        )

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert not result.valid
        assert not result.trusted
        assert "after the key went out of use" in result.status

    def test_compromised_later(self, signed_tro, gpg_setup, tmp_path, timestamped):
        keys = _write_key_list(
            tmp_path / "k.json",
            signed_tro,
            gpg_setup["fingerprint"],
            status="compromised",
            compromised_since="2026-06-01",
        )

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert result.valid
        assert "signed before that" in result.warnings[0]

    def test_compromised_earlier(self, signed_tro, gpg_setup, tmp_path, timestamped):
        keys = _write_key_list(
            tmp_path / "k.json",
            signed_tro,
            gpg_setup["fingerprint"],
            status="compromised",
            compromised_since="2025-06-01",
        )

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert not result.valid
        assert "after the key was compromised" in result.status

    def test_no_timestamp_current_key(self, signed_tro, gpg_setup, tmp_path):
        keys = _write_key_list(
            tmp_path / "k.json", signed_tro, gpg_setup["fingerprint"]
        )

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert result.valid
        assert result.timestamp is None
        assert "no trusted timestamp" in result.warnings[0]

    def test_no_timestamp_retired_key(self, signed_tro, gpg_setup, tmp_path):
        keys = _write_key_list(
            tmp_path / "k.json",
            signed_tro,
            gpg_setup["fingerprint"],
            status="retired",
            valid_until="2030-01-01",
        )

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert not result.valid
        assert "the key is retired" in result.status

    def test_bad_timestamp(self, signed_tro, gpg_setup, tmp_path):
        keys = _write_key_list(
            tmp_path / "k.json", signed_tro, gpg_setup["fingerprint"]
        )
        (tmp_path / "test_tro.tsr").write_bytes(b"tsr")

        with (
            patch.object(
                TRO,
                "verify_timestamp",
                side_effect=subprocess.CalledProcessError(1, "openssl"),
            ),
            pytest.raises(RuntimeError, match="Timestamp verification failed"),
        ):
            TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

    def test_key_not_listed(self, signed_tro, tmp_path, timestamped):
        keys = _write_key_list(tmp_path / "k.json", signed_tro, "A" * 40)

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert not result.valid
        assert result.status.startswith("the signing key is not listed for")

    def test_trs_not_listed(self, signed_tro, gpg_setup, tmp_path, timestamped):
        keys = _write_key_list(
            tmp_path / "k.json",
            signed_tro,
            gpg_setup["fingerprint"],
            trs_id="https://example.org/",
        )

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert not result.valid
        assert result.status.startswith("the key list has no TRS with @id")

    def test_expired_key_judged_by_list(self, expired_key_tro, tmp_path):
        """A key that has since expired passes if the list covers the signature."""
        declaration, home = expired_key_tro
        fingerprint = gnupg.GPG(gnupghome=home).list_keys()[0]["fingerprint"]
        keys = _write_key_list(
            tmp_path / "k.json",
            declaration,
            fingerprint,
            status="retired",
            valid_until="2020-01-02",
        )
        (tmp_path / "test_tro.tsr").write_bytes(b"tsr")
        when = datetime.datetime(2020, 1, 1, 12, tzinfo=datetime.timezone.utc)

        with (
            patch.object(TRO, "verify_timestamp"),
            patch.object(TRO, "timestamp_time", return_value=when),
        ):
            result = TRO(filepath=declaration).verify_signature(
                gnupghome=home, trs_keys=keys
            )

        assert result.valid
        assert "signing key has expired" in result.warnings[0]

    def test_tampered(self, signed_tro, gpg_setup, tmp_path, timestamped):
        keys = _write_key_list(
            tmp_path / "k.json", signed_tro, gpg_setup["fingerprint"]
        )
        with open(signed_tro, "a") as fp:
            fp.write("\n")

        result = TRO(filepath=signed_tro).verify_signature(trs_keys=keys)

        assert not result.valid
        timestamped.assert_not_called()

    def test_never_trusted_still_fails(
        self, signed_tro, gpg_setup, tmp_path, timestamped, never_trusted_keyring
    ):
        keys = _write_key_list(
            tmp_path / "k.json", signed_tro, gpg_setup["fingerprint"]
        )

        result = TRO(filepath=signed_tro).verify_signature(
            trs_keys=keys, gnupghome=never_trusted_keyring
        )

        assert not result.valid
        assert result.status == "signing key is marked as never trusted"


class TestVerifySignatureCLI:
    def _run(self, *args):
        return CliRunner().invoke(cli, ["verify-signature", *args])

    def test_ok(self, signed_tro, gpg_setup):
        result = self._run(signed_tro)

        assert result.exit_code == 0, result.output
        assert "Signature: OK" in result.output
        assert gpg_setup["fingerprint"] in result.output
        assert "Key trust:" in result.output
        assert "Warning" not in result.output

    def test_uncertified_key_warns(self, signed_tro, gpg_setup, uncertified_keyring):
        result = self._run(signed_tro, "--gnupghome", uncertified_keyring)

        assert result.exit_code == 0, result.output
        assert "Signature: OK" in result.output
        assert "you have not certified it" in result.output
        assert f"gpg --lsign-key {gpg_setup['fingerprint']}" in result.output

    def test_not_a_jsonld_file(self, signed_tro, tmp_path):
        other = tmp_path / "test_tro.json"
        other.write_text(pathlib.Path(signed_tro).read_text())

        result = self._run(str(other))

        assert result.exit_code == 2
        assert "expected a .jsonld declaration" in result.output

    def test_unreadable_declaration(self, signed_tro):
        data = json.loads(pathlib.Path(signed_tro).read_text())
        data["@graph"][0]["trov:vocabularyVersion"] = "0.0.1"
        pathlib.Path(signed_tro).write_text(json.dumps(data))

        result = self._run(signed_tro)

        assert result.exit_code == 1
        assert "older version of the TRO vocabulary" in result.output
        assert isinstance(result.exception, SystemExit)  # no traceback

    def test_corrupt_signature(self, signed_tro, tmp_path):
        (tmp_path / "test_tro.sig").write_text("not a signature\n")

        result = self._run(signed_tro)

        assert result.exit_code == 1
        assert "Signature verification failed" in result.output
        assert "(key None)" not in result.output

    def test_key_missing(self, signed_tro, gpg_setup, empty_keyring):
        result = self._run(signed_tro, "--gnupghome", empty_keyring)

        assert result.exit_code == 1
        assert f"Signing key {gpg_setup['fingerprint']} is not in your keyring" in (
            result.output
        )

    def test_embedded_key_warns(self, signed_tro):
        result = self._run(signed_tro, "--use-embedded-key")

        assert result.exit_code == 0, result.output
        assert "attested only by the TRO itself" in result.output

    def test_embedded_key_did_not_sign(self, signed_tro, gpg_setup, other_key):
        _replace_embedded_key(signed_tro, other_key)

        result = self._run(signed_tro, "--use-embedded-key")

        assert result.exit_code == 1
        assert "did not sign it" in result.output
        assert gpg_setup["fingerprint"] in result.output
        assert "or use --use-embedded-key" not in result.output

    def test_wrong_embedded_key_warns(self, mislabeled_tro):
        result = self._run(mislabeled_tro)

        assert result.exit_code == 0, result.output
        assert "Signature: OK" in result.output
        assert "(trov:publicKey) is not the key that signed it" in result.output

    def test_never_trusted_key(self, signed_tro, never_trusted_keyring):
        result = self._run(signed_tro, "--gnupghome", never_trusted_keyring)

        assert result.exit_code == 1
        assert "failed: signing key is marked as never trusted" in result.output

    def test_tampered(self, signed_tro):
        with open(signed_tro, "a") as fp:
            fp.write("\n")

        result = self._run(signed_tro)

        assert result.exit_code == 1
        assert "Signature verification failed" in result.output

    def test_expired_key(self, expired_key_tro):
        declaration, home = expired_key_tro

        result = self._run(declaration, "--gnupghome", home)

        assert result.exit_code == 1
        assert "Signature verification failed: signing key has expired" in (
            result.output
        )

    def test_missing_signature(self, signed_tro, tmp_path):
        (tmp_path / "test_tro.sig").unlink()

        result = self._run(signed_tro)

        assert result.exit_code == 1
        assert "Signature file does not exist" in result.output

    def test_keyring_file(self, signed_tro, key_file):
        result = self._run(signed_tro, "--keyring", key_file)

        assert result.exit_code == 0, result.output
        assert f"Key found in: {key_file}" in result.output
        assert "Warning" not in result.output

    def test_keyring_file_without_signing_key(
        self, signed_tro, gpg_setup, other_key_file
    ):
        result = self._run(signed_tro, "--keyring", other_key_file)

        assert result.exit_code == 1
        assert f"Signing key {gpg_setup['fingerprint']} is not in {other_key_file}" in (
            result.output
        )

    def test_key_sources_are_exclusive(self, signed_tro, key_file):
        result = self._run(signed_tro, "--keyring", key_file, "--use-embedded-key")

        assert result.exit_code == 2
        assert "mutually exclusive" in result.output

    def test_fingerprint_confirms_embedded_key(self, signed_tro, gpg_setup):
        result = self._run(
            signed_tro,
            "--use-embedded-key",
            "--fingerprint",
            _spaced(gpg_setup["fingerprint"]),
        )

        assert result.exit_code == 0, result.output
        assert "Key confirmed by: the fingerprint you gave" in result.output
        assert "Warning" not in result.output

    def test_fingerprint_confirms_uncertified_key(
        self, signed_tro, gpg_setup, uncertified_keyring
    ):
        result = self._run(
            signed_tro,
            "--gnupghome",
            uncertified_keyring,
            "--fingerprint",
            gpg_setup["fingerprint"],
        )

        assert result.exit_code == 0, result.output
        assert "Warning" not in result.output

    def test_fingerprint_mismatch(self, signed_tro):
        result = self._run(signed_tro, "--fingerprint", "A" * 40)

        assert result.exit_code == 1
        assert "does not have the expected fingerprint" in result.output

    def test_fingerprint_must_be_full(self, signed_tro, gpg_setup):
        result = self._run(signed_tro, "--fingerprint", gpg_setup["keyid"])

        assert result.exit_code == 2
        assert "not a full OpenPGP key fingerprint" in result.output

    def test_trs_keys(self, signed_tro, gpg_setup, tmp_path, timestamped):
        keys = _write_key_list(
            tmp_path / "k.yaml", signed_tro, gpg_setup["fingerprint"]
        )

        result = self._run(signed_tro, "--trs-keys", keys)

        assert result.exit_code == 0, result.output
        assert f"Key listed in: {keys} (current)" in result.output
        assert "Timestamp: 2026-01-01T00:00:00+00:00" in result.output
        assert "Warning" not in result.output

    def test_trs_keys_warning(self, signed_tro, gpg_setup, tmp_path):
        keys = _write_key_list(
            tmp_path / "k.json", signed_tro, gpg_setup["fingerprint"]
        )

        result = self._run(signed_tro, "--trs-keys", keys)

        assert result.exit_code == 0, result.output
        assert "Warning: the TRO has no trusted timestamp" in result.output

    def test_trs_keys_rejects(self, signed_tro, tmp_path, timestamped):
        keys = _write_key_list(tmp_path / "k.json", signed_tro, "A" * 40)

        result = self._run(signed_tro, "--trs-keys", keys)

        assert result.exit_code == 1
        assert "the signing key is not listed for" in result.output

    def test_invalid_trs_keys(self, signed_tro, tmp_path):
        keys = tmp_path / "k.yaml"
        keys.write_text("format: nope\n")

        result = self._run(signed_tro, "--trs-keys", str(keys))

        assert result.exit_code == 1
        assert "format must be" in result.output
