"""Tests for TRO timestamping operations."""

import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from tro_utils import __version__
from tro_utils.cli import cli
from tro_utils.tro_utils import TRO

from tests.helpers import create_tro_with_gpg

TSA_DATA = pathlib.Path(__file__).parent / "data" / "tsa"


def _write_tsr(path):
    """Put a real FreeTSA response at *path*; it need not match the TRO."""
    shutil.copyfile(TSA_DATA / "freetsa-2026.tsr", path)


class TestTROTimestamping:
    """Test TRO timestamping operations."""

    @patch("tro_utils.tsa.verify_token")
    @patch("tro_utils.tsa.rfc3161ng.RemoteTimestamper")
    @patch("tro_utils.tsa.encoder.encode")
    def test_request_timestamp(
        self,
        mock_encode,
        mock_timestamper,
        mock_verify_token,
        temp_workspace,
        tmp_path,
        gpg_setup,
        trs_profile,
    ):
        """Test requesting a timestamp from TSA (mocked)."""
        # Mock the encoder to return bytes
        mock_encode.return_value = b"encoded_tsr_data"

        # Mock the timestamper
        mock_tsr = MagicMock()
        mock_ts_instance = MagicMock()
        mock_ts_instance.return_value = mock_tsr
        mock_timestamper.return_value = mock_ts_instance

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add some content
        tro.add_arrangement(str(temp_workspace), comment="Test")
        tro.save()

        # Request timestamp
        tro.request_timestamp()

        # Verify timestamper was called
        mock_timestamper.assert_called_once_with(
            "https://freetsa.org/tsr", hashname="sha512", include_tsa_certificate=True
        )
        mock_ts_instance.assert_called_once()
        # The response is checked before it is saved
        mock_verify_token.assert_called_once_with(
            mock_ts_instance.call_args.kwargs["data"], b"encoded_tsr_data", quiet=True
        )

        # Verify TSR file was created
        assert os.path.exists(tro.tsr_filename)

    @patch("subprocess.check_call")
    def test_verify_timestamp(
        self,
        mock_check_call,
        temp_workspace,
        tmp_path,
        gpg_setup,
        trs_profile,
    ):
        """Test verifying a timestamp (with mocked external calls)."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add content and save
        tro.add_arrangement(str(temp_workspace), comment="Test")
        tro.save()

        _write_tsr(tro.tsr_filename)
        # Create a fake SIG file
        with open(tro.sig_filename, "wb") as f:
            f.write(b"fake sig data")

        # Verify timestamp
        tro.verify_timestamp()

        mock_check_call.assert_called_once()
        call_args = mock_check_call.call_args[0][0]
        assert call_args[:3] == ["openssl", "ts", "-verify"]
        # Checked as of the token's time, with the bundled certificates
        signed_at = datetime.datetime(
            2026, 11, 17, 16, 7, 41, tzinfo=datetime.timezone.utc
        )
        assert call_args[call_args.index("-attime") + 1] == str(
            int(signed_at.timestamp())
        )
        assert call_args[call_args.index("-CAfile") + 1].endswith("freetsa-root.pem")
        assert call_args[call_args.index("-untrusted") + 1].endswith("freetsa-tsa.pem")

    @patch("subprocess.check_call")
    @patch("tro_utils.tsa.encoder.encode")
    @patch("tro_utils.tsa.rfc3161ng.RemoteTimestamper")
    def test_timestamped_payload_matches_saved_declaration(
        self,
        mock_timestamper,
        mock_encode,
        mock_check_call,
        temp_workspace,
        tmp_path,
        gpg_setup,
        trs_profile,
    ):
        """The timestamped payload must match what a verifier recomputes.

        Regression test for the ordering of ``attach_public_key()``: the public
        key has to land in the declaration before it is hashed *and* be written
        to disk, otherwise a signed TRO fails its own ``verify_timestamp()``.
        """
        mock_encode.return_value = (TSA_DATA / "freetsa-2026.tsr").read_bytes()
        mock_tsr = MagicMock()
        mock_ts_instance = MagicMock(return_value=mock_tsr)
        mock_timestamper.return_value = mock_ts_instance

        declaration = str(tmp_path / "test_tro.jsonld")
        tro = create_tro_with_gpg(
            filepath=declaration,
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )
        tro.add_arrangement(str(temp_workspace), comment="Test")
        tro.save()

        tro.request_timestamp()
        signed_payload = mock_ts_instance.call_args.kwargs["data"]

        # Signing must persist the declaration it attested to
        with open(declaration) as fp:
            saved = json.load(fp)
        public_key = saved["@graph"][0]["trov:wasAssembledBy"]["trov:publicKey"]
        assert public_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")

        # A third party verifies from the files alone: no fingerprint, no
        # passphrase, no keyring.
        verified_payload = {}

        def capture_payload(args):
            with open(args[args.index("-data") + 1], "rb") as fp:
                verified_payload["data"] = fp.read()

        mock_check_call.side_effect = capture_payload
        TRO(filepath=declaration).verify_timestamp()

        assert verified_payload["data"] == signed_payload

    @patch("subprocess.check_call")
    def test_verify_timestamp_hashes_declaration_on_disk(
        self, mock_check_call, tmp_path, trs_profile
    ):
        """The declaration is hashed as stored, not as re-serialized.

        Reformatting leaves the model unchanged, so hashing the model would
        accept bytes that were never timestamped.
        """
        declaration = tmp_path / "test_tro.jsonld"
        TRO(filepath=str(declaration), profile=trs_profile).save()
        data = json.loads(declaration.read_text())
        declaration.write_text(json.dumps(data, indent=4, sort_keys=True))
        (tmp_path / "test_tro.sig").write_bytes(b"fake sig data")
        _write_tsr(tmp_path / "test_tro.tsr")

        verified_payload = {}

        def capture_payload(args):
            with open(args[args.index("-data") + 1], "rb") as fp:
                verified_payload["data"] = fp.read()

        mock_check_call.side_effect = capture_payload
        TRO(filepath=str(declaration)).verify_timestamp()

        hashed = json.loads(verified_payload["data"])["tro_declaration"]
        assert hashed == hashlib.sha512(declaration.read_bytes()).hexdigest()

    @patch("subprocess.check_call")
    def test_verify_timestamp_quiet(self, mock_check_call, tmp_path, trs_profile):
        """quiet=True hides what openssl prints."""
        declaration = tmp_path / "test_tro.jsonld"
        TRO(filepath=str(declaration), profile=trs_profile).save()
        (tmp_path / "test_tro.sig").write_bytes(b"fake sig data")
        _write_tsr(tmp_path / "test_tro.tsr")

        TRO(filepath=str(declaration)).verify_timestamp(quiet=True)

        assert mock_check_call.call_args.kwargs == {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }

    def test_verify_timestamp_missing_signature(self, tmp_path, trs_profile):
        declaration = tmp_path / "test_tro.jsonld"
        TRO(filepath=str(declaration), profile=trs_profile).save()

        with pytest.raises(RuntimeError, match="Signature file does not exist"):
            TRO(filepath=str(declaration)).verify_timestamp()

    def test_timestamp_time(self, tmp_path):
        """The time is read from the stored response, as an aware datetime."""
        declaration = tmp_path / "test_tro.jsonld"
        _write_tsr(tmp_path / "test_tro.tsr")

        assert TRO(filepath=str(declaration)).timestamp_time() == datetime.datetime(
            2026, 11, 17, 16, 7, 41, tzinfo=datetime.timezone.utc
        )

    def test_verify_timestamp_missing_response(self, tmp_path, trs_profile):
        declaration = tmp_path / "test_tro.jsonld"
        TRO(filepath=str(declaration), profile=trs_profile).save()
        (tmp_path / "test_tro.sig").write_bytes(b"fake sig data")

        with pytest.raises(RuntimeError, match="Timestamp file does not exist"):
            TRO(filepath=str(declaration)).verify_timestamp()


def _saved_tro(tmp_path, trs_profile, created_with):
    """Save a TRO whose ``trov:createdWith`` is replaced by *created_with*."""
    declaration = tmp_path / "test_tro.jsonld"
    TRO(filepath=str(declaration), profile=trs_profile).save()
    data = json.loads(declaration.read_text())
    if created_with is None:
        data["@graph"][0].pop("trov:createdWith", None)
    else:
        data["@graph"][0]["trov:createdWith"] = created_with
    declaration.write_text(json.dumps(data, indent=2, sort_keys=True))
    (tmp_path / "test_tro.sig").write_bytes(b"fake sig data")
    _write_tsr(tmp_path / "test_tro.tsr")
    return TRO(filepath=str(declaration))


def _created_with(version):
    return {
        "@type": "schema:SoftwareApplication",
        "schema:name": "tro-utils",
        "schema:softwareVersion": version,
    }


class TestCreatedWithMismatch:
    """verify_timestamp should explain failures caused by a version mismatch."""

    def test_no_mismatch_for_current_version(self, tmp_path, trs_profile):
        tro = TRO(filepath=str(tmp_path / "test_tro.jsonld"), profile=trs_profile)
        assert tro.created_with_mismatch() is None

    def test_mismatch_for_other_version(self, tmp_path, trs_profile):
        tro = _saved_tro(tmp_path, trs_profile, _created_with("0.4.5"))
        mismatch = tro.created_with_mismatch()
        assert "tro-utils 0.4.5" in mismatch
        assert "pip install tro-utils==0.4.5" in mismatch

    def test_mismatch_for_other_software(self, tmp_path, trs_profile):
        created_with = {"schema:name": "other-tool", "schema:softwareVersion": "1.0"}
        tro = _saved_tro(tmp_path, trs_profile, created_with)
        mismatch = tro.created_with_mismatch()
        assert "other-tool 1.0" in mismatch
        assert "pip install" not in mismatch

    def test_mismatch_when_created_with_missing(self, tmp_path, trs_profile):
        tro = _saved_tro(tmp_path, trs_profile, None)
        assert "no trov:createdWith" in tro.created_with_mismatch()

    @patch("subprocess.check_call")
    def test_failure_names_creating_version(
        self, mock_check_call, tmp_path, trs_profile
    ):
        mock_check_call.side_effect = subprocess.CalledProcessError(1, "openssl")
        tro = _saved_tro(tmp_path, trs_profile, _created_with("0.4.5"))

        with pytest.raises(RuntimeError, match="tro-utils==0.4.5"):
            tro.verify_timestamp()

    @patch("subprocess.check_call")
    def test_failure_without_mismatch_is_unchanged(
        self, mock_check_call, tmp_path, trs_profile
    ):
        mock_check_call.side_effect = subprocess.CalledProcessError(1, "openssl")
        tro = _saved_tro(tmp_path, trs_profile, _created_with(__version__))

        with pytest.raises(subprocess.CalledProcessError):
            tro.verify_timestamp()

    @patch("subprocess.check_call")
    def test_cli_warns_on_mismatch(self, mock_check_call, tmp_path, trs_profile):
        tro = _saved_tro(tmp_path, trs_profile, _created_with("0.4.5"))

        result = CliRunner().invoke(cli, ["verify-timestamp", tro.tro_filename])

        assert result.exit_code == 0
        assert "Warning: The TRO was created with tro-utils 0.4.5" in result.output

    @patch("subprocess.check_call")
    def test_cli_reports_failure_with_version(
        self, mock_check_call, tmp_path, trs_profile
    ):
        mock_check_call.side_effect = subprocess.CalledProcessError(1, "openssl")
        tro = _saved_tro(tmp_path, trs_profile, _created_with("0.4.5"))

        result = CliRunner().invoke(cli, ["verify-timestamp", tro.tro_filename])

        assert result.exit_code == 1
        assert "pip install tro-utils==0.4.5" in result.output

    @pytest.mark.parametrize(
        "response",
        [b"not a timestamp", (TSA_DATA / "freetsa-2026.tsr").read_bytes() + b"\0"],
        ids=["other data", "trailing data"],
    )
    def test_cli_reports_unreadable_response(self, tmp_path, trs_profile, response):
        """A .tsr that is not a timestamp gives an error, not a traceback."""
        tro = _saved_tro(tmp_path, trs_profile, _created_with(__version__))
        (tmp_path / "test_tro.tsr").write_bytes(response)

        result = CliRunner().invoke(cli, ["verify-timestamp", tro.tro_filename])

        assert result.exit_code == 1
        assert "not an RFC 3161 response" in result.output
        assert isinstance(result.exception, SystemExit)
