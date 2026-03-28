"""Shared fixtures for tro_utils tests."""

import json

import gnupg
import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace with sample files."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Create sample CSV file with mock data
    csv_file = workspace / "input_data.csv"
    csv_file.write_text("name,value,category\nitem1,100,A\nitem2,200,B\nitem3,150,A\n")

    # Create a text file with some initial content
    txt_file = workspace / "notes.txt"
    txt_file.write_text("Initial notes\n")

    # Create a config file
    config_file = workspace / "config.json"
    config_file.write_text('{"threshold": 150, "mode": "filter"}')

    return workspace


@pytest.fixture(scope="session")
def gpg_setup(tmp_path_factory):
    """Set up a temporary GPG environment for testing (once per session)."""
    gpg_home = tmp_path_factory.mktemp("gnupg")
    gpg_home.chmod(0o700)

    # Create GPG instance
    gpg = gnupg.GPG(gnupghome=str(gpg_home))

    # Generate a test key (this is slow, so we only do it once)
    input_data = gpg.gen_key_input(
        key_type="RSA",
        key_length=2048,
        name_real="Test User",
        name_email="test@example.com",
        passphrase="test_passphrase",
    )
    key = gpg.gen_key(input_data)

    # Get the key fingerprint and keyid
    # Note: gnupg library doesn't populate key_map on initial generation
    # We need to use the key result directly
    keys = gpg.list_keys()
    fingerprint = str(key)  # The gen_key returns the fingerprint

    # Find the keyid from the keys list
    keyid = None
    for k in keys:
        if k["fingerprint"] == fingerprint:
            keyid = k["keyid"]
            break

    return {
        "gpg_home": str(gpg_home),
        "gpg": gpg,
        "fingerprint": fingerprint,
        "keyid": keyid,
        "passphrase": "test_passphrase",
    }


@pytest.fixture(scope="session")
def trs_profile(tmp_path_factory):
    """Create a TRS profile file (once per session)."""
    profile_dir = tmp_path_factory.mktemp("profiles")
    profile_file = profile_dir / "trs.jsonld"
    profile_data = {
        "rdfs:comment": "Test TRS for testing purposes",
        "trov:hasCapability": [
            {"@id": "trs/capability/1", "@type": "trov:CanRecordInternetAccess"},
            {"@id": "trs/capability/2", "@type": "trov:CanProvideInternetIsolation"},
        ],
        "trov:owner": "Test User",
        "trov:description": "Test TRS",
        "trov:contact": "test@example.com",
        "trov:url": "http://localhost/",
        "trov:name": "test-trs",
    }
    profile_file.write_text(json.dumps(profile_data, indent=2))
    return str(profile_file)


@pytest.fixture
def tro_declaration(tmp_path):
    """Return path for TRO declaration file."""
    return str(tmp_path / "test_tro.jsonld")
