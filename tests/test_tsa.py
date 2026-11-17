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
from unittest.mock import MagicMock, patch

import pytest
import rfc3161ng
from pyasn1.codec.der import encoder

from tro_utils import tsa

TSA_DATA = pathlib.Path(__file__).parent / "data" / "tsa"
UTC = datetime.timezone.utc


def _payload(name):
    return (TSA_DATA / f"{name}.payload").read_bytes()


def _response(name):
    return (TSA_DATA / f"{name}.tsr").read_bytes()


def _rejection():
    """A response in which the TSA refuses the request: no token."""
    status = rfc3161ng.PKIStatusInfo()
    status["status"] = 2  # rejection
    response = rfc3161ng.TimeStampResp()
    response["status"] = status
    return encoder.encode(response)


@pytest.fixture
def old_openssl():
    """Pretend openssl is one whose ts -verify has no -attime."""
    with patch.object(tsa, "_openssl_supports_attime", return_value=False):
        yield


@pytest.mark.parametrize(
    "name, signed_at",
    [
        ("freetsa-2025", datetime.datetime(2025, 12, 10, 10, 19, 42, tzinfo=UTC)),
        ("freetsa-2026", datetime.datetime(2026, 11, 17, 16, 7, 41, tzinfo=UTC)),
    ],
)
def test_token_time(name, signed_at):
    assert tsa.token_time(_response(name)) == signed_at


@pytest.mark.parametrize(
    "response",
    [
        b"not a timestamp",
        _response("freetsa-2026") + b"\0",  # trailing data
        _rejection(),
    ],
    ids=["other data", "trailing data", "rejection"],
)
def test_token_time_rejects(response):
    with pytest.raises(RuntimeError, match="not an RFC 3161 response"):
        tsa.token_time(response)


@pytest.mark.parametrize("name", ["freetsa-2025", "freetsa-2026"])
def test_verify(name):
    tsa.verify_token(_payload(name), _response(name), quiet=True)


def test_verify_after_certificate_expired(old_openssl):
    """A token stays valid after its signing certificate has expired.

    The certificate that signed freetsa-2025 is no longer served by FreeTSA
    and expired on 2026-03-11; it is found among the bundled certificates and
    checked as of the token's time. An openssl that can only check it as of
    now says why it may have failed.
    """
    with pytest.raises(RuntimeError, match="cannot check a timestamp as of the time"):
        tsa.verify_token(_payload("freetsa-2025"), _response("freetsa-2025"))


def test_old_openssl_still_verifies_current_certificate(old_openssl):
    tsa.verify_token(_payload("freetsa-2026"), _response("freetsa-2026"), quiet=True)


def test_this_openssl_supports_attime():
    """The rest of these tests assume an openssl that checks as of a time."""
    tsa._openssl_supports_attime.cache_clear()
    assert tsa._openssl_supports_attime()


def test_detects_openssl_without_attime():
    usage = MagicMock(stdout="", stderr="usage: ts -verify [-untrusted file]\n")
    tsa._openssl_supports_attime.cache_clear()
    try:
        with patch.object(tsa.subprocess, "run", return_value=usage):
            assert not tsa._openssl_supports_attime()
    finally:
        tsa._openssl_supports_attime.cache_clear()


def test_verify_without_bundled_signing_certificates(monkeypatch):
    """A token that carries its certificate needs only the root."""
    # openssl refuses an -untrusted file without certificates
    monkeypatch.setattr(tsa, "TSA_CERTIFICATES", tsa.ROOT_CERTIFICATE)

    tsa.verify_token(_payload("freetsa-2026"), _response("freetsa-2026"), quiet=True)
    with pytest.raises(subprocess.CalledProcessError):
        tsa.verify_token(
            _payload("freetsa-2025"), _response("freetsa-2025"), quiet=True
        )


@pytest.mark.parametrize("name", ["freetsa-2025", "freetsa-2026"])
def test_verify_rejects_other_payload(name):
    with pytest.raises(subprocess.CalledProcessError):
        tsa.verify_token(_payload(name) + b" ", _response(name), quiet=True)


def test_verify_rejects_untrusted_root(monkeypatch):
    """The signing certificates alone are not trusted."""
    monkeypatch.setattr(tsa, "ROOT_CERTIFICATE", tsa.TSA_CERTIFICATES)

    with pytest.raises(subprocess.CalledProcessError):
        tsa.verify_token(
            _payload("freetsa-2026"), _response("freetsa-2026"), quiet=True
        )


def test_verify_rejects_rejection():
    with pytest.raises(RuntimeError, match="not an RFC 3161 response"):
        tsa.verify_token(_payload("freetsa-2026"), _rejection(), quiet=True)


def _timestamper_returning(response):
    """Patch FreeTSA to answer every request with *response*."""
    decoded = rfc3161ng.decode_timestamp_response(response)
    return patch.object(
        tsa.rfc3161ng,
        "RemoteTimestamper",
        return_value=MagicMock(return_value=decoded),
    )


def test_request_token():
    with _timestamper_returning(_response("freetsa-2026")) as timestamper:
        response = tsa.request_token(_payload("freetsa-2026"))

    assert response == _response("freetsa-2026")
    timestamper.assert_called_once_with(
        "https://freetsa.org/tsr", hashname="sha512", include_tsa_certificate=True
    )


def test_request_token_rejects_token_for_other_data():
    with (
        _timestamper_returning(_response("freetsa-2026")),
        pytest.raises(RuntimeError, match="does not verify"),
    ):
        tsa.request_token(_payload("freetsa-2025"))


def test_certificates_are_installed():
    for resource in (tsa.ROOT_CERTIFICATE, tsa.TSA_CERTIFICATES):
        assert "-----BEGIN CERTIFICATE-----" in resource.read_text()
