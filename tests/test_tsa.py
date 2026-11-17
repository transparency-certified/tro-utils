"""Tests for verifying FreeTSA timestamps with the bundled certificates.

These run openssl on real FreeTSA responses:

- ``freetsa-2025``: the timestamp of ``tro-6939493694a55af77d16a130`` in
  https://doi.org/10.3886/E240721V1 (2025-12-10), signed with the certificate
  FreeTSA replaced on 2026-02-15 and that expired on 2026-03-11. Its payload is
  built from that TRO's declaration and signature.
- ``freetsa-2026``: a response requested for these tests (2026-11-17), signed
  with the current certificate, which it carries.
"""

import datetime
import pathlib
import subprocess

import pytest

from tro_utils import tsa

TSA_DATA = pathlib.Path(__file__).parent / "data" / "tsa"
UTC = datetime.timezone.utc


def _payload(name):
    return (TSA_DATA / f"{name}.payload").read_bytes()


def _tsr(name):
    return str(TSA_DATA / f"{name}.tsr")


@pytest.mark.parametrize(
    "name, signed_at",
    [
        ("freetsa-2025", datetime.datetime(2025, 12, 10, 10, 19, 42, tzinfo=UTC)),
        ("freetsa-2026", datetime.datetime(2026, 11, 17, 16, 7, 41, tzinfo=UTC)),
    ],
)
def test_token_time(name, signed_at):
    with open(_tsr(name), "rb") as fp:
        assert tsa.token_time(fp.read()) == signed_at


def test_token_time_rejects_other_data():
    with pytest.raises(RuntimeError, match="not an RFC 3161 response"):
        tsa.token_time(b"not a timestamp")


@pytest.mark.parametrize("name", ["freetsa-2025", "freetsa-2026"])
def test_verify(name):
    tsa.verify_token(_payload(name), _tsr(name), quiet=True)


def test_verify_after_certificate_expired():
    """A token stays valid after its signing certificate has expired.

    The certificate that signed freetsa-2025 is no longer served by FreeTSA
    and expired on 2026-03-11; it is found among the bundled certificates and
    checked as of the token's time.
    """
    with pytest.raises(subprocess.CalledProcessError):
        _verify_now("freetsa-2025")
    tsa.verify_token(_payload("freetsa-2025"), _tsr("freetsa-2025"), quiet=True)


def test_verify_without_bundled_signing_certificates(monkeypatch):
    """A token that carries its certificate needs only the root."""
    # openssl refuses an -untrusted file without certificates
    monkeypatch.setattr(tsa, "TSA_CERTIFICATES", tsa.ROOT_CERTIFICATE)

    tsa.verify_token(_payload("freetsa-2026"), _tsr("freetsa-2026"), quiet=True)
    with pytest.raises(subprocess.CalledProcessError):
        tsa.verify_token(_payload("freetsa-2025"), _tsr("freetsa-2025"), quiet=True)


@pytest.mark.parametrize("name", ["freetsa-2025", "freetsa-2026"])
def test_verify_rejects_other_payload(name):
    with pytest.raises(subprocess.CalledProcessError):
        tsa.verify_token(_payload(name) + b" ", _tsr(name), quiet=True)


def test_verify_rejects_untrusted_root(tmp_path, monkeypatch):
    """The signing certificates alone are not trusted."""
    monkeypatch.setattr(tsa, "ROOT_CERTIFICATE", tsa.TSA_CERTIFICATES)

    with pytest.raises(subprocess.CalledProcessError):
        tsa.verify_token(_payload("freetsa-2026"), _tsr("freetsa-2026"), quiet=True)


def test_verify_rejects_other_data(tmp_path):
    tsr = tmp_path / "bad.tsr"
    tsr.write_bytes(b"not a timestamp")

    with pytest.raises(RuntimeError, match="not an RFC 3161 response"):
        tsa.verify_token(_payload("freetsa-2026"), str(tsr), quiet=True)


def test_certificates_are_installed():
    for resource in (tsa.ROOT_CERTIFICATE, tsa.TSA_CERTIFICATES):
        assert "-----BEGIN CERTIFICATE-----" in resource.read_text()


def _verify_now(name):
    """Verify as tro-utils did before: as of the current time."""
    with (
        tsa.importlib.resources.as_file(tsa.ROOT_CERTIFICATE) as root,
        tsa.importlib.resources.as_file(tsa.TSA_CERTIFICATES) as untrusted,
    ):
        args = ["openssl", "ts", "-verify", "-data", str(TSA_DATA / f"{name}.payload")]
        args += ["-in", _tsr(name), "-CAfile", str(root), "-untrusted", str(untrusted)]
        subprocess.run(args, check=True, capture_output=True)
