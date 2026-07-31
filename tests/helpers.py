"""Shared helper functions for tro_utils tests."""

import os

from tro_utils import tro_utils
from tro_utils.tro_utils import TRO


def create_tro_with_gpg(filepath, gpg_setup, **kwargs):
    """Create a TRO pointed at the test GPG keyring.

    ``tro_utils.tro_utils.GPG_HOME`` is read at import time, so it is redirected
    here to the keyring created by the ``gpg_setup`` fixture. GPG itself is only
    contacted when a key is needed, so a TRO created without a fingerprint never
    touches it.
    """
    os.environ["GPG_HOME"] = gpg_setup["gpg_home"]
    tro_utils.GPG_HOME = gpg_setup["gpg_home"]

    return TRO(filepath=filepath, **kwargs)
