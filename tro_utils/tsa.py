"""Requesting and verifying RFC 3161 timestamps from FreeTSA.

FreeTSA's certificates ship with tro-utils rather than being downloaded when a
token is verified. The server only offers its current signing certificate, so
a token signed by an earlier one could no longer be verified once FreeTSA
replaced it.
"""

from __future__ import annotations

import datetime
import functools
import importlib.resources
import subprocess
import tempfile

import rfc3161ng
from pyasn1.codec.der import encoder
from pyasn1.error import PyAsn1Error

TSA_URL = "https://freetsa.org/tsr"

_CERTS = importlib.resources.files(__package__) / "certs"
#: The one certificate trusted for timestamps.
ROOT_CERTIFICATE = _CERTS / "freetsa-root.pem"
#: Every signing certificate FreeTSA has used; untrusted unless they chain to
#: :data:`ROOT_CERTIFICATE`.
TSA_CERTIFICATES = _CERTS / "freetsa-tsa.pem"


def request_token(payload: bytes) -> bytes:
    """Timestamp *payload* and return the DER-encoded response.

    The response carries FreeTSA's signing certificate, so that it can be
    verified without FreeTSA, or tro-utils, having to provide it later. It is
    verified before it is returned, so that a rejection or a token for other
    data is caught now rather than when the TRO is checked.

    Raises:
        RuntimeError: If FreeTSA's response does not timestamp *payload*.
    """
    timestamper = rfc3161ng.RemoteTimestamper(
        TSA_URL, hashname="sha512", include_tsa_certificate=True
    )
    response = encoder.encode(timestamper(data=payload, return_tsr=True))
    try:
        verify_token(payload, response, quiet=True)
    except (subprocess.CalledProcessError, RuntimeError) as err:
        raise RuntimeError(
            f"The timestamp returned by {TSA_URL} does not verify: {err}"
        ) from err
    return response


def token_time(response: bytes) -> datetime.datetime:
    """Return the time in a timestamp *response*, without verifying it."""
    try:
        decoded = rfc3161ng.decode_timestamp_response(response)
        return rfc3161ng.get_timestamp(decoded.time_stamp_token, naive=False)
    except (PyAsn1Error, ValueError) as err:
        raise RuntimeError(
            "The timestamp file is not an RFC 3161 response with a token"
        ) from err


@functools.cache
def _openssl_supports_attime() -> bool:
    """Whether ``openssl ts -verify`` takes ``-attime``.

    LibreSSL, which macOS ships as openssl, and old OpenSSL releases do not.
    """
    result = subprocess.run(
        ["openssl", "ts", "-help"], capture_output=True, text=True, check=False
    )
    return "-attime" in result.stdout + result.stderr


def _openssl_version() -> str:
    result = subprocess.run(
        ["openssl", "version"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() or "this openssl"


def verify_token(payload: bytes, response: bytes, quiet: bool = False) -> None:
    """Check that the timestamp *response* timestamps *payload*.

    The certificates are checked as of the time in the token, not now: a
    signing certificate that was valid when the token was made keeps the token
    valid after the certificate expires. That time is part of what the TSA
    signed, so it cannot be changed without failing the check, but it is the
    TSA's word: anyone who obtained a key FreeTSA has retired could make tokens
    dated while its certificate was valid, and they would verify. Nothing
    checks revocation either.

    Args:
        payload: The timestamped data.
        response: The DER-encoded timestamp response.
        quiet: Don't pass on what openssl prints.

    Raises:
        subprocess.CalledProcessError: If the token does not verify.
        RuntimeError: If *response* holds no timestamp token, or if it fails
            to verify with an openssl that cannot check it as of its own time.
    """
    signed_at = token_time(response)
    attime = _openssl_supports_attime()
    with (
        tempfile.NamedTemporaryFile() as data_f,
        tempfile.NamedTemporaryFile() as tsr_f,
        importlib.resources.as_file(ROOT_CERTIFICATE) as root,
        importlib.resources.as_file(TSA_CERTIFICATES) as untrusted,
    ):
        data_f.write(payload)
        data_f.flush()
        tsr_f.write(response)
        tsr_f.flush()
        args = [
            "openssl",
            "ts",
            "-verify",
            "-data",
            data_f.name,
            "-in",
            tsr_f.name,
            "-CAfile",
            str(root),
            "-untrusted",
            str(untrusted),
        ]
        if attime:
            args += ["-attime", str(int(signed_at.timestamp()))]
        try:
            if quiet:
                subprocess.check_call(
                    args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            else:
                subprocess.check_call(args)
        except subprocess.CalledProcessError as err:
            if attime:
                raise
            # Checked as of now, a token whose certificate has since expired
            # fails as if it had been tampered with.
            raise RuntimeError(
                f"Timestamp verification failed, possibly only because "
                f"{_openssl_version()} cannot check a timestamp as of the time "
                "it was made. Verify with OpenSSL 1.1.1 or later."
            ) from err
