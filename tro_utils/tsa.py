"""Requesting and verifying RFC 3161 timestamps from FreeTSA.

FreeTSA's certificates ship with tro-utils rather than being downloaded when a
token is verified. The server only offers its current signing certificate, so
a token signed by an earlier one could no longer be verified once FreeTSA
replaced it.
"""

from __future__ import annotations

import datetime
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
    verified without FreeTSA, or tro-utils, having to provide it later.
    """
    timestamper = rfc3161ng.RemoteTimestamper(
        TSA_URL, hashname="sha512", include_tsa_certificate=True
    )
    return encoder.encode(timestamper(data=payload, return_tsr=True))


def token_time(response: bytes) -> datetime.datetime:
    """Return the time in a timestamp *response*, without verifying it."""
    try:
        decoded = rfc3161ng.decode_timestamp_response(response)
        return rfc3161ng.get_timestamp(decoded.time_stamp_token, naive=False)
    except PyAsn1Error as err:
        raise RuntimeError("The timestamp file is not an RFC 3161 response") from err


def verify_token(payload: bytes, tsr_filename: str, quiet: bool = False) -> None:
    """Check that the response in *tsr_filename* timestamps *payload*.

    The certificates are checked as of the time in the token, not now: a
    signing certificate that was valid when the token was made keeps the token
    valid after the certificate expires. Taking that time from the token before
    it is verified is safe, since it is part of what the TSA signed.

    Args:
        payload: The timestamped data.
        tsr_filename: The DER-encoded timestamp response.
        quiet: Don't pass on what openssl prints.

    Raises:
        subprocess.CalledProcessError: If the token does not verify.
        RuntimeError: If the file is not a timestamp response at all.
    """
    with open(tsr_filename, "rb") as fp:
        signed_at = token_time(fp.read())
    with (
        tempfile.NamedTemporaryFile() as data_f,
        importlib.resources.as_file(ROOT_CERTIFICATE) as root,
        importlib.resources.as_file(TSA_CERTIFICATES) as untrusted,
    ):
        data_f.write(payload)
        data_f.flush()
        args = [
            "openssl",
            "ts",
            "-verify",
            "-data",
            data_f.name,
            "-in",
            tsr_filename,
            "-CAfile",
            str(root),
            "-untrusted",
            str(untrusted),
            "-attime",
            str(int(signed_at.timestamp())),
        ]
        if quiet:
            subprocess.check_call(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            subprocess.check_call(args)
