"""Shared helper functions for tro_utils tests."""

import os

from tro_utils.tro_utils import TRO


def create_tro_with_gpg(filepath, gpg_setup, **kwargs):
    """Helper to create TRO with proper GPG configuration."""
    # Set GPG_HOME environment variable
    os.environ["GPG_HOME"] = gpg_setup["gpg_home"]

    # Temporarily remove gpg_fingerprint from kwargs to avoid key_map lookup error
    gpg_fingerprint = kwargs.pop("gpg_fingerprint", None)

    # Create TRO instance without fingerprint first
    tro = TRO(filepath=filepath, **kwargs)

    # Now manually set up the GPG key if fingerprint was provided
    # This works around the key_map issue in the gnupg library
    if gpg_fingerprint:
        tro.gpg = gpg_setup["gpg"]
        tro.gpg_key_id = gpg_setup["keyid"]
        tro.data["@graph"][0]["trov:wasAssembledBy"]["trov:publicKey"] = (
            tro.gpg.export_keys(tro.gpg_key_id)
        )
        tro.gpg_passphrase = kwargs.get("gpg_passphrase")

    return tro
