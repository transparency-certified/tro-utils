"""Tests for verifying the TRS signature of a TRO."""

import json
from unittest.mock import MagicMock, patch

import gnupg
import pytest
from click.testing import CliRunner

from tro_utils.cli import cli
from tro_utils.tro_utils import TRO

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
def empty_keyring(tmp_path):
    home = tmp_path / "empty_gnupg"
    home.mkdir(mode=0o700)
    return str(home)


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
    return gpg.export_keys(str(key))


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
    return str(declaration), str(home)


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
    return str(home)


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
        assert result.used_embedded_key
        assert result.fingerprint == gpg_setup["fingerprint"]

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
