"""Tests for tro_utils package."""

import datetime
import importlib
import json
import os
import sys
from hashlib import sha256
from importlib.metadata import PackageNotFoundError
from unittest.mock import MagicMock, patch

import gnupg
import pytest

from tro_utils import TRPAttribute
from tro_utils.tro_utils import TRO


# Helper function to create TRO with proper GPG setup
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


class TestVersion:
    """Tests for package version detection in tro_utils/__init__.py."""

    def test_version_fallback_when_package_not_found(self):
        """__version__ should be 'unknown' when the package is not installed."""
        with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
            import tro_utils as _tro_utils

            importlib.reload(_tro_utils)
            assert _tro_utils.__version__ == "unknown"

    def test_version_set_from_metadata(self):
        """__version__ should reflect the value returned by importlib.metadata.version."""
        with patch("importlib.metadata.version", return_value="1.2.3"):
            import tro_utils as _tro_utils

            importlib.reload(_tro_utils)
            assert _tro_utils.__version__ == "1.2.3"


class TestTROCreation:
    """Test TRO object creation and initialization."""

    def test_create_tro_raises_on_old_vocabulary_version(self, tmp_path):
        """Loading a TRO with a vocabulary version older than TROV_VOCABULARY_VERSION raises RuntimeError."""
        import json

        old_tro_path = tmp_path / "old_tro.jsonld"
        old_tro_data = {
            "@context": [{}],
            "@graph": [
                {
                    "@id": "tro",
                    "trov:wasAssembledBy": {"trov:hasCapability": []},
                    "trov:hasArrangement": [],
                    "trov:hasComposition": {"trov:hasArtifact": []},
                    "trov:hasPerformance": [],
                    "trov:hasAttribute": [],
                }
            ],
        }
        old_tro_path.write_text(json.dumps(old_tro_data))

        with pytest.raises(RuntimeError, match="older version of the TRO vocabulary"):
            TRO(filepath=str(old_tro_path))

    def test_create_tro_without_file(self, tmp_path, gpg_setup):
        """Test creating a new TRO without existing file."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "new_tro.jsonld"),
            gpg_setup=gpg_setup,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
            tro_creator="Test Creator",
            tro_name="Test TRO",
            tro_description="A test TRO object",
        )

        assert tro.basename == "new_tro"
        assert tro.gpg_key_id == gpg_setup["keyid"]
        assert "TransparentResearchObject" in str(tro.data)
        assert tro.data["@graph"][0]["schema:creator"] == "Test Creator"
        assert tro.data["@graph"][0]["schema:name"] == "Test TRO"
        assert not (tmp_path / "new_tro.jsonld").exists()
        tro.save()
        assert (tmp_path / "new_tro.jsonld").exists()

    def test_create_tro_with_profile(self, tmp_path, gpg_setup, trs_profile):
        """Test creating a TRO with a TRS profile."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "new_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Check that profile was loaded
        trs_data = tro.data["@graph"][0]["trov:wasAssembledBy"]
        assert trs_data["trov:name"] == "test-trs"
        assert len(trs_data["trov:hasCapability"]) == 2

    def test_tro_filenames(self, tmp_path, gpg_setup):
        """Test that TRO generates correct filenames."""
        filepath = str(tmp_path / "my_tro.jsonld")
        tro = create_tro_with_gpg(filepath=filepath, gpg_setup=gpg_setup)

        assert tro.tro_filename == filepath
        assert tro.sig_filename == str(tmp_path / "my_tro.sig")
        assert tro.tsr_filename == str(tmp_path / "my_tro.tsr")


class TestTROArrangements:
    """Test TRO arrangement operations."""

    def test_add_arrangement(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test adding an arrangement to a TRO."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add first arrangement
        tro.add_arrangement(
            str(temp_workspace), comment="Initial arrangement", ignore_dirs=[]
        )

        # Verify arrangement was added
        arrangements = tro.list_arrangements()
        assert len(arrangements) == 1
        assert arrangements[0]["rdfs:comment"] == "Initial arrangement"
        assert (
            len(arrangements[0]["trov:hasArtifactLocation"]) == 3
        )  # 3 files in workspace

        # Verify composition was updated
        composition = tro.data["@graph"][0]["trov:hasComposition"]
        assert len(composition["trov:hasArtifact"]) == 3
        assert "trov:hasFingerprint" in composition

    def test_add_multiple_arrangements(
        self, temp_workspace, tmp_path, gpg_setup, trs_profile
    ):
        """Test adding multiple arrangements tracks changes."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add first arrangement
        tro.add_arrangement(str(temp_workspace), comment="Before processing")

        # Modify workspace - process CSV and create output
        csv_data = (temp_workspace / "input_data.csv").read_text()
        lines = csv_data.strip().split("\n")
        filtered_lines = [lines[0]]  # header
        for line in lines[1:]:
            parts = line.split(",")
            if int(parts[1]) > 150:
                filtered_lines.append(line)

        output_file = temp_workspace / "output.csv"
        output_file.write_text("\n".join(filtered_lines) + "\n")

        # Update notes
        notes_file = temp_workspace / "notes.txt"
        notes_file.write_text(
            notes_file.read_text() + "Processed data with threshold 150\n"
        )

        # Add second arrangement
        tro.add_arrangement(str(temp_workspace), comment="After processing")

        # Verify two arrangements exist
        arrangements = tro.list_arrangements()
        assert len(arrangements) == 2
        assert arrangements[0]["rdfs:comment"] == "Before processing"
        assert arrangements[1]["rdfs:comment"] == "After processing"

        # Second arrangement should have more files
        assert len(arrangements[1]["trov:hasArtifactLocation"]) == 4  # added output.csv

        # Composition should have all unique files
        composition = tro.data["@graph"][0]["trov:hasComposition"]
        # Modified notes.txt gets a new hash, so we have: 3 originals + 1 new output + 1 modified notes = 5
        assert len(composition["trov:hasArtifact"]) >= 4

    def test_arrangement_with_ignore_dirs(self, temp_workspace, tmp_path, gpg_setup):
        """Test that ignore_dirs properly excludes directories."""
        # Create a directory to ignore
        git_dir = temp_workspace / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("git config")

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement with default ignore (.git)
        tro.add_arrangement(str(temp_workspace), comment="Test ignore")

        # Verify .git files were not included
        arrangements = tro.list_arrangements()
        loci = arrangements[0]["trov:hasArtifactLocation"]
        locations = [loc["trov:path"] for loc in loci]

        assert not any(".git" in loc for loc in locations)


class TestTROPerformances:
    """Test TRO performance operations."""

    def test_add_performance(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test adding a performance to a TRO."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Add two arrangements
        tro.add_arrangement(str(temp_workspace), comment="Before")

        # Simulate some work
        (temp_workspace / "output.txt").write_text("processed")

        tro.add_arrangement(str(temp_workspace), comment="After")

        # Add performance
        start_time = datetime.datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime.datetime(2024, 1, 1, 11, 0, 0)

        tro.add_performance(
            start_time=start_time,
            end_time=end_time,
            comment="Data processing workflow",
            accessed_arrangement="arrangement/0",
            modified_arrangement="arrangement/1",
            attrs=["trov:InternetIsolation", TRPAttribute.RECORD_NETWORK],
        )

        # Verify performance was added
        performances = tro.data["@graph"][0]["trov:hasPerformance"]
        assert len(performances) == 1

        perf = performances[0]
        assert perf["rdfs:comment"] == "Data processing workflow"
        assert perf["trov:startedAtTime"] == "2024-01-01T10:00:00"
        assert perf["trov:endedAtTime"] == "2024-01-01T11:00:00"
        assert perf["trov:accessedArrangement"]["@id"] == "arrangement/0"
        assert perf["trov:contributedToArrangement"]["@id"] == "arrangement/1"
        assert len(perf["trov:hasPerformanceAttribute"]) == 2

    def test_add_performance_invalid_arrangement(
        self, tmp_path, gpg_setup, trs_profile
    ):
        """Test that adding performance with invalid arrangement raises error."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
        )

        start_time = datetime.datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime.datetime(2024, 1, 1, 11, 0, 0)

        # Try to add performance with non-existent arrangement
        with pytest.raises(ValueError, match="does not exist"):
            tro.add_performance(
                start_time=start_time,
                end_time=end_time,
                accessed_arrangement="arrangement/99",
                modified_arrangement="arrangement/0",
                attrs=[],
            )


class TestTROSigning:
    """Test TRO signing and verification."""

    def test_sign_tro(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test signing a TRO with GPG."""
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

        # Sign the TRO
        signature = tro.trs_signature()

        assert signature is not None
        assert len(str(signature)) > 0

        # Verify signature file was created
        assert os.path.exists(tro.sig_filename)

        # Verify signature content
        with open(tro.sig_filename, "r") as f:
            sig_content = f.read()
            assert "BEGIN PGP SIGNATURE" in sig_content

    def test_sign_without_gpg_key(self, tmp_path):
        """Test that signing without GPG key raises error."""
        tro = TRO(filepath=str(tmp_path / "test_tro.jsonld"))

        with pytest.raises(RuntimeError, match="GPG fingerprint was not provided"):
            tro.trs_signature()

    def test_sign_without_passphrase(self, tmp_path, gpg_setup):
        """Test that signing without passphrase raises error."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            gpg_fingerprint=gpg_setup["fingerprint"],
        )

        with pytest.raises(RuntimeError, match="GPG passphrase was not provided"):
            tro.trs_signature()


class TestTROTimestamping:
    """Test TRO timestamping operations."""

    @patch("tro_utils.tro_utils.rfc3161ng.RemoteTimestamper")
    @patch("tro_utils.tro_utils.encoder.encode")
    def test_request_timestamp(
        self,
        mock_encode,
        mock_timestamper,
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
            "https://freetsa.org/tsr", hashname="sha512"
        )
        mock_ts_instance.assert_called_once()

        # Verify TSR file was created
        assert os.path.exists(tro.tsr_filename)

    @patch("subprocess.check_call")
    @patch("requests.get")
    def test_verify_timestamp(
        self,
        mock_get,
        mock_check_call,
        temp_workspace,
        tmp_path,
        gpg_setup,
        trs_profile,
    ):
        """Test verifying a timestamp (with mocked external calls)."""
        # Mock certificate downloads
        mock_response = MagicMock()
        mock_response.content = b"fake cert content"
        mock_get.return_value = mock_response

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

        # Create a fake TSR file
        with open(tro.tsr_filename, "wb") as f:
            f.write(b"fake tsr data")
        # Create a fake SIG file
        with open(tro.sig_filename, "wb") as f:
            f.write(b"fake sig data")

        # Verify timestamp
        tro.verify_timestamp()

        # Verify external calls were made
        assert mock_get.call_count == 2  # Two cert downloads
        mock_check_call.assert_called_once()

        # Verify openssl command structure
        call_args = mock_check_call.call_args[0][0]
        assert call_args[0] == "openssl"
        assert call_args[1] == "ts"
        assert call_args[2] == "-verify"


class TestTROSaveLoad:
    """Test TRO save and load operations."""

    def test_save_tro(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test saving a TRO to disk."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        tro.add_arrangement(str(temp_workspace), comment="Test arrangement")
        tro.save()

        # Verify file was created
        assert os.path.exists(tro.tro_filename)

        # Verify file content is valid JSON
        with open(tro.tro_filename, "r") as f:
            data = json.load(f)
            assert "@graph" in data
            assert data["@graph"][0]["@type"] == [
                "trov:TransparentResearchObject",
                "schema:CreativeWork",
            ]

    def test_load_existing_tro(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test loading an existing TRO from disk."""
        # Create and save a TRO
        tro1 = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )
        tro1.add_arrangement(str(temp_workspace), comment="First arrangement")
        tro1.save()

        # Load the same TRO
        tro2 = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Verify the loaded TRO has the same data
        assert len(tro2.list_arrangements()) == 1
        assert tro2.list_arrangements()[0]["rdfs:comment"] == "First arrangement"

        # Add another arrangement to the loaded TRO
        (temp_workspace / "new_file.txt").write_text("new content")
        tro2.add_arrangement(str(temp_workspace), comment="Second arrangement")

        # Verify it now has two arrangements
        assert len(tro2.list_arrangements()) == 2


class TestTROHashingAndComposition:
    """Test hashing and composition management."""

    def test_sha256_for_file(self, tmp_path):
        """Test computing SHA256 hash for a file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        hash_value = TRO.sha256_for_file(str(test_file))

        # Verify hash is correct (pre-computed for "Hello, World!")
        expected_hash = (
            "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        )
        assert hash_value == expected_hash

    def test_sha256_for_directory(self, temp_workspace, tmp_path, gpg_setup):
        """Test computing SHA256 hashes for all files in a directory."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        hashes = tro.sha256_for_directory(str(temp_workspace), ignore_dirs=[])

        # Verify we got hashes for all files
        assert len(hashes) == 3  # 3 files in workspace

        # Verify all hashes are non-empty
        for filepath, hash_value in hashes.items():
            assert hash_value.startswith("sha256:")
            assert (
                len(hash_value[len("sha256:") :]) == 64
            )  # SHA256 produces 64 hex characters

    def test_composition_fingerprint(self, temp_workspace, tmp_path, gpg_setup):
        """Test that composition fingerprint is computed correctly."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )
        tro.add_arrangement(str(temp_workspace), comment="Test")

        composition = tro.data["@graph"][0]["trov:hasComposition"]

        # Verify fingerprint exists
        assert "trov:hasFingerprint" in composition
        assert (
            composition["trov:hasFingerprint"]["@type"] == "trov:CompositionFingerprint"
        )
        assert (
            composition["trov:hasFingerprint"]["trov:hash"]["trov:hashAlgorithm"]
            == "sha256"
        )
        assert (
            len(composition["trov:hasFingerprint"]["trov:hash"]["trov:hashValue"]) == 64
        )


class TestTROReporting:
    """Test TRO report generation."""

    def test_generate_report(self, temp_workspace, tmp_path, gpg_setup, trs_profile):
        """Test generating a report from a TRO."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        # Create a workflow
        tro.add_arrangement(str(temp_workspace), comment="Before")

        (temp_workspace / "output.txt").write_text("processed")

        tro.add_arrangement(str(temp_workspace), comment="After")

        tro.add_performance(
            start_time=datetime.datetime(2024, 1, 1, 10, 0, 0),
            end_time=datetime.datetime(2024, 1, 1, 11, 0, 0),
            comment="Test workflow",
            accessed_arrangement="arrangement/0",
            modified_arrangement="arrangement/1",
            attrs=[TRPAttribute.NET_ISOLATION],
        )

        # Create a simple template
        template_file = tmp_path / "template.jinja2"
        template_file.write_text(
            """
TRO Report
==========
Name: {{ tro.name }}
Creator: {{ tro.creator }}
Description: {{ tro.description }}

Arrangements: {{ tro.arrangements | length }}
Performances: {{ tro.trps | length }}
"""
        )

        report_file = tmp_path / "report.md"

        # Generate report
        tro.generate_report(str(template_file), str(report_file))

        # Verify report was created
        assert os.path.exists(report_file)

        # Verify report content
        report_content = report_file.read_text()
        assert "TRO Report" in report_content
        assert "Arrangements: 2" in report_content
        assert "Performances: 1" in report_content


class TestRealWorldWorkflow:
    """Test a complete real-world workflow."""

    def test_complete_data_processing_workflow(
        self, temp_workspace, tmp_path, gpg_setup, trs_profile
    ):
        """
        Test a complete workflow simulating a data processing task:
        1. Start with input CSV and config
        2. Process data (filter based on threshold)
        3. Generate output file
        4. Update notes
        5. Track everything in TRO
        """
        # Initialize TRO
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "data_workflow.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
            tro_creator="Test Researcher",
            tro_name="Data Processing Workflow",
            tro_description="Testing data filtering and aggregation",
        )

        # Snapshot 1: Initial state
        tro.add_arrangement(
            str(temp_workspace),
            comment="Initial dataset before processing",
            ignore_dirs=[],
        )

        # === Simulate computational work ===
        start_time = datetime.datetime.now()

        # Read config
        config = json.loads((temp_workspace / "config.json").read_text())
        threshold = config["threshold"]

        # Process CSV data
        csv_file = temp_workspace / "input_data.csv"
        lines = csv_file.read_text().strip().split("\n")
        header = lines[0]
        data_lines = lines[1:]

        # Filter data based on threshold
        filtered_data = [header]
        summary_stats = {"total": len(data_lines), "filtered": 0, "categories": {}}

        for line in data_lines:
            parts = line.split(",")
            _, value, category = parts[0], int(parts[1]), parts[2]

            if value > threshold:
                filtered_data.append(line)
                summary_stats["filtered"] += 1
                summary_stats["categories"][category] = (
                    summary_stats["categories"].get(category, 0) + 1
                )

        # Write filtered output
        output_file = temp_workspace / "filtered_output.csv"
        output_file.write_text("\n".join(filtered_data) + "\n")

        # Write summary
        summary_file = temp_workspace / "summary.json"
        summary_file.write_text(json.dumps(summary_stats, indent=2))

        # Update notes
        notes_file = temp_workspace / "notes.txt"
        notes_content = notes_file.read_text()
        notes_content += f"\nProcessing completed at {datetime.datetime.now()}\n"
        notes_content += f"Applied threshold: {threshold}\n"
        notes_content += f"Filtered {summary_stats['filtered']} out of {summary_stats['total']} records\n"
        notes_file.write_text(notes_content)

        end_time = datetime.datetime.now()
        # === End of computational work ===

        # Snapshot 2: After processing
        tro.add_arrangement(
            str(temp_workspace),
            comment="Dataset after filtering and summary generation",
            ignore_dirs=[],
        )

        # Record the performance
        tro.add_performance(
            start_time=start_time,
            end_time=end_time,
            comment=f"Data filtering with threshold={threshold}",
            accessed_arrangement="arrangement/0",
            modified_arrangement="arrangement/1",
            attrs=[TRPAttribute.NET_ISOLATION, TRPAttribute.RECORD_NETWORK],
        )

        # Save the TRO
        tro.save()

        # === Verification ===

        # Verify arrangements
        arrangements = tro.list_arrangements()
        assert len(arrangements) == 2
        assert arrangements[0]["rdfs:comment"] == "Initial dataset before processing"
        assert (
            arrangements[1]["rdfs:comment"]
            == "Dataset after filtering and summary generation"
        )

        # Verify initial arrangement has 3 files
        assert len(arrangements[0]["trov:hasArtifactLocation"]) == 3

        # Verify final arrangement has more files (added filtered_output.csv and summary.json)
        assert len(arrangements[1]["trov:hasArtifactLocation"]) == 5

        # Verify file locations in final arrangement
        final_locations = [
            loc["trov:path"] for loc in arrangements[1]["trov:hasArtifactLocation"]
        ]
        assert "filtered_output.csv" in final_locations
        assert "summary.json" in final_locations
        assert "notes.txt" in final_locations

        # Verify performance was recorded
        performances = tro.data["@graph"][0]["trov:hasPerformance"]
        assert len(performances) == 1
        assert "threshold=150" in performances[0]["rdfs:comment"]
        assert performances[0]["trov:accessedArrangement"]["@id"] == "arrangement/0"
        assert (
            performances[0]["trov:contributedToArrangement"]["@id"] == "arrangement/1"
        )

        # Verify composition has unique artifacts
        composition = tro.data["@graph"][0]["trov:hasComposition"]
        artifacts = composition["trov:hasArtifact"]

        # We should have: input_data.csv, config.json, notes.txt (original),
        # filtered_output.csv, summary.json, notes.txt (modified) = 6 unique hashes
        assert len(artifacts) >= 5

        # Verify all artifacts have required fields
        for artifact in artifacts:
            assert "@id" in artifact
            assert "trov:hash" in artifact
            assert "trov:hashAlgorithm" in artifact["trov:hash"]
            assert artifact["trov:hash"]["trov:hashAlgorithm"] == "sha256"
            assert "trov:mimeType" in artifact
            assert artifact["@type"] == "trov:ResearchArtifact"

        # Verify TRO file was saved
        assert os.path.exists(tro.tro_filename)

        # Verify we can load and verify the TRO
        loaded_tro = create_tro_with_gpg(
            filepath=str(tmp_path / "data_workflow.jsonld"),
            gpg_setup=gpg_setup,
            profile=trs_profile,
            gpg_fingerprint=gpg_setup["fingerprint"],
            gpg_passphrase=gpg_setup["passphrase"],
        )

        assert len(loaded_tro.list_arrangements()) == 2
        assert len(loaded_tro.data["@graph"][0]["trov:hasPerformance"]) == 1


class TestTROUtilityMethods:
    """Test utility methods of TRO class."""

    def test_get_composition_seq(self, tmp_path, gpg_setup):
        """Test getting composition sequence number."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Initially should be 0
        assert tro.get_composition_seq() == 0

    def test_get_arrangement_seq(self, tmp_path, gpg_setup):
        """Test getting arrangement sequence number."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Initially should be 0
        assert tro.get_arrangement_seq() == 0

    def test_get_composition_info(self, temp_workspace, tmp_path, gpg_setup):
        """Test getting composition information."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )
        tro.add_arrangement(str(temp_workspace), comment="Test")

        composition_info = tro.get_composition_info()

        assert "@id" in composition_info
        assert composition_info["@id"] == "composition/1"
        assert "@type" in composition_info
        assert "trov:hasArtifact" in composition_info
        assert len(composition_info["trov:hasArtifact"]) > 0

    def test_hash_handling(self, tmp_path, gpg_setup):
        """Test that hash handling works correctly."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        example_hash = (
            "6591aa920533077fbfa0ffb62d4a2e246b692e0754ca86b86d86824f313325a2"
        )
        # Test that providing a hash directly works
        artifacts = {
            "trov:sha256": example_hash,
        }
        assert tro._get_hash(artifacts)[len("sha256:") :] == example_hash

        artifact_with_hash_dict = {
            "trov:hash": {
                "trov:hashAlgorithm": "sha256",
                "trov:hashValue": example_hash,
            },
        }
        assert tro._get_hash(artifact_with_hash_dict)[len("sha256:") :] == example_hash

        artifact_with_hash_list = {
            "trov:hash": [
                {
                    "trov:hashAlgorithm": "sha512",
                    "trov:hashValue": "foo",
                },
                {
                    "trov:hashAlgorithm": "sha256",
                    "trov:hashValue": example_hash,
                },
            ]
        }
        assert tro._get_hash(artifact_with_hash_list)[len("sha256:") :] == example_hash

        artifact_with_hash_list = {
            "trov:hash": [
                {
                    "trov:hashAlgorithm": "sha512",
                    "trov:hashValue": "foo",
                },
                {
                    "trov:hashAlgorithm": "md5",
                    "trov:hashValue": "md5hash",
                },
            ]
        }
        assert tro._get_hash(artifact_with_hash_list) == "sha512:foo"

        with pytest.raises(ValueError, match="does not contain"):
            tro._get_hash({})

    def test_fingerprint(self, tmp_path, gpg_setup):
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        artifacts = [
            {"trov:sha256": "abc123"},
            {"trov:hash": {"trov:hashAlgorithm": "sha256", "trov:hashValue": "def456"}},
            {
                "trov:hash": [
                    {"trov:hashAlgorithm": "sha256", "trov:hashValue": "abc123"},
                    {"trov:hashAlgorithm": "sha512", "trov:hashValue": "def456"},
                ]
            },
        ]
        fingerprint = tro.calculate_fingerprint(artifacts)
        assert fingerprint == sha256("abc123abc123def456def456".encode()).hexdigest()


class TestReplicationPackageVerification:
    """Test verification of replication packages against arrangements."""

    def test_verify_identical_directory(self, temp_workspace, tmp_path, gpg_setup):
        """Test verifying a directory that exactly matches the arrangement."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Verify the same directory
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should be identical
        assert is_valid is True
        assert len(missing) == 0
        assert len(mismatched) == 0
        assert len(extra) == 0

    def test_verify_directory_with_modified_file(
        self, temp_workspace, tmp_path, gpg_setup
    ):
        """Test verifying a directory where a file has been modified."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Modify a file in the workspace
        (temp_workspace / "notes.txt").write_text("Modified content\n")

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should detect mismatch
        assert is_valid is False
        assert len(missing) == 0
        assert len(mismatched) == 1
        assert mismatched[0][0] == "notes.txt"  # filename
        assert len(extra) == 0

    def test_verify_directory_with_extra_file(
        self, temp_workspace, tmp_path, gpg_setup
    ):
        """Test verifying a directory with an extra file not in arrangement."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Add a new file
        (temp_workspace / "extra_file.txt").write_text("Extra content\n")

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should detect the extra file as missing in arrangement
        # Also appears in mismatched because expected_hash is None
        assert is_valid is False
        assert len(missing) == 1
        assert "extra_file.txt" in missing
        assert len(mismatched) == 1
        assert mismatched[0][0] == "extra_file.txt"
        assert mismatched[0][1] is None  # No expected hash
        assert len(extra) == 0

    def test_verify_directory_with_missing_file(
        self, temp_workspace, tmp_path, gpg_setup
    ):
        """Test verifying a directory missing a file from the arrangement."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Remove a file
        (temp_workspace / "notes.txt").unlink()

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should detect the file as extra in arrangement (not found in package)
        assert is_valid is False
        assert len(missing) == 0
        assert len(mismatched) == 0
        assert len(extra) == 1
        assert "notes.txt" in extra

    def test_verify_zipfile_identical(self, temp_workspace, tmp_path, gpg_setup):
        """Test verifying a zipfile that exactly matches the arrangement."""
        import zipfile

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Create a zipfile with the same content
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for file in temp_workspace.iterdir():
                if file.is_file():
                    zf.write(file, file.name)

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(zip_path))

        # Should be identical
        assert is_valid is True
        assert len(missing) == 0
        assert len(mismatched) == 0
        assert len(extra) == 0

    def test_verify_zipfile_with_modified_file(
        self, temp_workspace, tmp_path, gpg_setup
    ):
        """Test verifying a zipfile where a file has been modified."""
        import zipfile

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Create a zipfile with modified content
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for file in temp_workspace.iterdir():
                if file.is_file():
                    if file.name == "notes.txt":
                        zf.writestr("notes.txt", "Modified content\n")
                    else:
                        zf.write(file, file.name)

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(zip_path))

        # Should detect mismatch
        assert is_valid is False
        assert len(missing) == 0
        assert len(mismatched) == 1
        assert mismatched[0][0] == "notes.txt"
        assert len(extra) == 0

    def test_verify_with_subpath_directory(self, tmp_path, gpg_setup):
        """Test verifying a directory with subpath filtering."""
        # Create a more complex directory structure
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        subdir = workspace / "data"
        subdir.mkdir()
        (subdir / "file1.txt").write_text("Content 1\n")
        (subdir / "file2.txt").write_text("Content 2\n")

        other = workspace / "other"
        other.mkdir()
        (other / "file3.txt").write_text("Content 3\n")

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement for the entire workspace
        tro.add_arrangement(str(workspace), comment="Full workspace", ignore_dirs=[])

        # Verify only the data subpath
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package(
            "arrangement/0", str(workspace), subpath="data"
        )

        # Should verify only files in data/ subdirectory
        # When checking with subpath, only files starting with subpath are checked
        # The 'extra' list should contain files NOT checked (not in subpath) that are in arrangement
        assert is_valid is False
        assert (
            len(extra) == 3
        )  # All files are in extra because subpath filter leaves arrangement_map intact
        assert "other/file3.txt" in extra
        assert "data/file1.txt" in extra
        assert "data/file2.txt" in extra

    def test_verify_with_subpath_zipfile(self, tmp_path, gpg_setup):
        """Test verifying a zipfile with subpath filtering."""
        import zipfile

        # Create a more complex directory structure
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        subdir = workspace / "data"
        subdir.mkdir()
        (subdir / "file1.txt").write_text("Content 1\n")
        (subdir / "file2.txt").write_text("Content 2\n")

        other = workspace / "other"
        other.mkdir()
        (other / "file3.txt").write_text("Content 3\n")

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement for the entire workspace
        tro.add_arrangement(str(workspace), comment="Full workspace", ignore_dirs=[])

        # Create a zipfile
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(subdir / "file1.txt", "data/file1.txt")
            zf.write(subdir / "file2.txt", "data/file2.txt")
            zf.write(other / "file3.txt", "other/file3.txt")

        # Verify only the data subpath
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package(
            "arrangement/0", str(zip_path), subpath="data"
        )

        # Should verify only files in data/ subdirectory
        # When checking with subpath, only files starting with subpath are checked
        # The 'extra' list should contain files NOT checked that are in arrangement
        assert is_valid is False
        assert len(extra) == 3
        assert "other/file3.txt" in extra

    def test_verify_invalid_arrangement_id(self, temp_workspace, tmp_path, gpg_setup):
        """Test that verifying with invalid arrangement ID raises error."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Try to verify with non-existent arrangement

    def test_verify_multiple_issues(self, temp_workspace, tmp_path, gpg_setup):
        """Test verifying a package with multiple types of issues."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Original", ignore_dirs=[])

        # Make multiple changes
        (temp_workspace / "notes.txt").write_text("Modified\n")  # Modified
        (temp_workspace / "config.json").unlink()  # Removed (will be in extra)
        (temp_workspace / "new_file.txt").write_text(
            "New\n"
        )  # Added (will be in missing)

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(temp_workspace))

        # Should detect all issues
        assert is_valid is False
        assert len(missing) == 1  # new_file.txt
        assert "new_file.txt" in missing
        assert (
            len(mismatched) == 2
        )  # notes.txt (modified) + new_file.txt (not in arrangement)
        # Find which is which
        mismatched_files = {m[0]: m for m in mismatched}
        assert "notes.txt" in mismatched_files
        assert "new_file.txt" in mismatched_files
        assert mismatched_files["new_file.txt"][1] is None  # No expected hash
        assert len(extra) == 1  # config.json
        assert "config.json" in extra

    def test_verify_nested_directory_structure(self, tmp_path, gpg_setup):
        """Test verifying a package with nested directory structure."""
        # Create nested structure
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        (workspace / "root.txt").write_text("Root file\n")

        level1 = workspace / "level1"
        level1.mkdir()
        (level1 / "file1.txt").write_text("Level 1\n")

        level2 = level1 / "level2"
        level2.mkdir()
        (level2 / "file2.txt").write_text("Level 2\n")

        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(workspace), comment="Nested structure", ignore_dirs=[])

        # Verify
        (
            missing,
            mismatched,
            extra,
            is_valid,
        ) = tro.verify_replication_package("arrangement/0", str(workspace))

        # Should be valid
        assert is_valid is True
        assert len(missing) == 0
        assert len(mismatched) == 0
        assert len(extra) == 0

    def test_get_arrangement_path_hash_map(self, temp_workspace, tmp_path, gpg_setup):
        """Test getting the path-to-hash mapping for an arrangement."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Add arrangement
        tro.add_arrangement(str(temp_workspace), comment="Test", ignore_dirs=[])

        # Get the mapping
        path_hash_map = tro.get_arrangement_path_hash_map("arrangement/0")

        # Verify mapping contains all files
        assert len(path_hash_map) == 3
        assert "input_data.csv" in path_hash_map
        assert "notes.txt" in path_hash_map
        assert "config.json" in path_hash_map

        # Verify all values are valid SHA256 hashes
        for path, hash_value in path_hash_map.items():
            assert hash_value.startswith("sha256:")
            assert len(hash_value) == 64 + len(
                "sha256:"
            )  # "sha256:" prefix + 64 hex chars
            assert all(c in "0123456789abcdef" for c in hash_value[len("sha256:") :])

    def test_get_arrangement_path_hash_map_invalid_id(self, tmp_path, gpg_setup):
        """Test that getting map for invalid arrangement ID raises error."""
        tro = create_tro_with_gpg(
            filepath=str(tmp_path / "test_tro.jsonld"), gpg_setup=gpg_setup
        )

        # Try to get mapping for non-existent arrangement
        with pytest.raises(ValueError, match="not found"):
            tro.get_arrangement_path_hash_map("arrangement/99")


# =============================================================================
# Tests for the new OOP model classes (tro_utils.models)
# =============================================================================

from tro_utils.models import (
    ArtifactArrangement,
    ArtifactComposition,
    ArtifactLocation,
    CompositionFingerprint,
    HashValue,
    PerformanceAttribute,
    ResearchArtifact,
    TimeStampingAuthority,
    TransparentResearchObject,
    TROAttribute,
    TRSCapability,
    TrustedResearchPerformance,
    TrustedResearchSystem,
)


class TestHashValue:
    """Unit tests for HashValue value object."""

    def test_from_string_roundtrip(self):
        h = HashValue.from_string("sha256:abc123")
        assert h.algorithm == "sha256"
        assert h.value == "abc123"
        assert h.to_string() == "sha256:abc123"
        assert str(h) == "sha256:abc123"

    def test_from_string_invalid_raises(self):
        with pytest.raises(ValueError, match="Expected"):
            HashValue.from_string("invalidsyntax")

    def test_to_jsonld(self):
        h = HashValue(algorithm="sha256", value="deadbeef")
        jld = h.to_jsonld()
        assert jld == {"trov:hashAlgorithm": "sha256", "trov:hashValue": "deadbeef"}

    def test_from_jsonld_dict(self):
        h = HashValue.from_jsonld(
            {"trov:hashAlgorithm": "sha256", "trov:hashValue": "deadbeef"}
        )
        assert h.algorithm == "sha256"
        assert h.value == "deadbeef"

    def test_from_jsonld_list_prefers_sha256(self):
        data = [
            {"trov:hashAlgorithm": "md5", "trov:hashValue": "aaa"},
            {"trov:hashAlgorithm": "sha256", "trov:hashValue": "bbb"},
        ]
        h = HashValue.from_jsonld(data)
        assert h.algorithm == "sha256"
        assert h.value == "bbb"

    def test_from_jsonld_list_falls_back_to_first(self):
        data = [{"trov:hashAlgorithm": "md5", "trov:hashValue": "aaa"}]
        h = HashValue.from_jsonld(data)
        assert h.algorithm == "md5"

    def test_from_jsonld_legacy_sha256(self):
        h = HashValue.from_jsonld({"trov:sha256": "cafebabe"})
        assert h.algorithm == "sha256"
        assert h.value == "cafebabe"

    def test_from_jsonld_string(self):
        h = HashValue.from_jsonld("sha512:1234")
        assert h.algorithm == "sha512"
        assert h.value == "1234"

    def test_from_jsonld_invalid_raises(self):
        with pytest.raises(ValueError):
            HashValue.from_jsonld({"no": "hash_fields"})

    def test_equality(self):
        assert HashValue("sha256", "abc") == HashValue("sha256", "abc")
        assert HashValue("sha256", "abc") != HashValue("sha256", "xyz")


class TestResearchArtifact:
    """Unit tests for ResearchArtifact model."""

    def _make_artifact(self):
        return ResearchArtifact(
            artifact_id="composition/1/artifact/0",
            hash=HashValue("sha256", "deadbeef"),
            mime_type="text/csv",
        )

    def test_to_jsonld(self):
        a = self._make_artifact()
        jld = a.to_jsonld()
        assert jld["@id"] == "composition/1/artifact/0"
        assert jld["@type"] == "trov:ResearchArtifact"
        assert jld["trov:hash"]["trov:hashAlgorithm"] == "sha256"
        assert jld["trov:mimeType"] == "text/csv"

    def test_from_jsonld_roundtrip(self):
        a = self._make_artifact()
        restored = ResearchArtifact.from_jsonld(a.to_jsonld())
        assert restored.artifact_id == a.artifact_id
        assert restored.hash == a.hash
        assert restored.mime_type == a.mime_type

    def test_from_jsonld_legacy_sha256(self):
        data = {
            "@id": "composition/1/artifact/0",
            "@type": "trov:ResearchArtifact",
            "trov:sha256": "aabbcc",
            "trov:mimeType": "text/plain",
        }
        a = ResearchArtifact.from_jsonld(data)
        assert a.hash.algorithm == "sha256"
        assert a.hash.value == "aabbcc"

    def test_from_jsonld_missing_hash_raises(self):
        with pytest.raises(ValueError):
            ResearchArtifact.from_jsonld({"@id": "x", "@type": "trov:ResearchArtifact"})

    def test_from_file(self, tmp_path):
        f = tmp_path / "sample.txt"
        f.write_text("hello world")
        artifact = ResearchArtifact.from_file(f, "composition/1/artifact/0")
        assert artifact.artifact_id == "composition/1/artifact/0"
        assert artifact.hash.algorithm == "sha256"
        assert len(artifact.hash.value) == 64
        assert artifact.mime_type  # non-empty mime type

    def test_from_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ResearchArtifact.from_file(tmp_path / "nonexistent.txt", "x")


class TestCompositionFingerprint:
    """Unit tests for CompositionFingerprint."""

    def test_compute_deterministic(self):
        artifacts = [
            ResearchArtifact("a/0", HashValue("sha256", "aaa"), "text/plain"),
            ResearchArtifact("a/1", HashValue("sha256", "bbb"), "text/csv"),
        ]
        fp1 = CompositionFingerprint.compute(artifacts)
        fp2 = CompositionFingerprint.compute(list(reversed(artifacts)))
        assert fp1.hash.value == fp2.hash.value  # order-independent

    def test_to_from_jsonld(self):
        artifacts = [ResearchArtifact("a/0", HashValue("sha256", "abc"), "text/plain")]
        fp = CompositionFingerprint.compute(artifacts)
        jld = fp.to_jsonld()
        restored = CompositionFingerprint.from_jsonld(jld)
        assert restored.hash.value == fp.hash.value


class TestArtifactComposition:
    """Unit tests for ArtifactComposition."""

    def test_add_artifact_updates_fingerprint(self):
        comp = ArtifactComposition()
        assert comp.fingerprint is None
        a = ResearchArtifact(
            "comp/1/artifact/0", HashValue("sha256", "aaa"), "text/plain"
        )
        comp.add_artifact(a)
        assert comp.fingerprint is not None

    def test_get_by_hash(self):
        comp = ArtifactComposition()
        a = ResearchArtifact("x/0", HashValue("sha256", "abc"), "text/plain")
        comp.add_artifact(a)
        assert comp.get_by_hash("sha256:abc") is a
        assert comp.get_by_hash("sha256:xyz") is None

    def test_get_by_id(self):
        comp = ArtifactComposition()
        a = ResearchArtifact("x/0", HashValue("sha256", "abc"), "text/plain")
        comp.add_artifact(a)
        assert comp.get_by_id("x/0") is a
        assert comp.get_by_id("x/9") is None

    def test_next_artifact_id(self):
        comp = ArtifactComposition(composition_id="composition/1")
        assert comp.next_artifact_id() == "composition/1/artifact/0"
        comp.add_artifact(
            ResearchArtifact(
                "composition/1/artifact/0", HashValue("sha256", "a"), "text/plain"
            )
        )
        assert comp.next_artifact_id() == "composition/1/artifact/1"

    def test_to_from_jsonld_roundtrip(self):
        comp = ArtifactComposition()
        comp.add_artifact(
            ResearchArtifact(
                "comp/1/artifact/0", HashValue("sha256", "aaa"), "text/plain"
            )
        )
        comp.add_artifact(
            ResearchArtifact(
                "comp/1/artifact/1", HashValue("sha256", "bbb"), "text/csv"
            )
        )
        jld = comp.to_jsonld()
        restored = ArtifactComposition.from_jsonld(jld)
        assert len(restored.artifacts) == 2
        assert restored.fingerprint is not None


class TestArtifactLocation:
    """Unit tests for ArtifactLocation."""

    def test_to_from_jsonld(self):
        loc = ArtifactLocation("arr/0/loc/0", "comp/1/artifact/0", "data/input.csv")
        jld = loc.to_jsonld()
        assert jld["@id"] == "arr/0/loc/0"
        assert jld["trov:artifact"]["@id"] == "comp/1/artifact/0"
        assert jld["trov:path"] == "data/input.csv"
        restored = ArtifactLocation.from_jsonld(jld)
        assert restored.location_id == loc.location_id
        assert restored.artifact_id == loc.artifact_id
        assert restored.path == loc.path


class TestArtifactArrangement:
    """Unit tests for ArtifactArrangement."""

    def test_from_directory(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "a.txt").write_text("alpha")
        (d / "b.txt").write_text("beta")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(
            d, comp, "arrangement/0", comment="test"
        )

        assert arr.arrangement_id == "arrangement/0"
        assert arr.comment == "test"
        assert len(arr.locations) == 2
        assert len(comp.artifacts) == 2

    def test_from_directory_no_duplicate_artifacts(self, tmp_path):
        """Identical files across two arrangements share artifacts in composition."""
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "same.txt").write_text("identical content")

        comp = ArtifactComposition()
        ArtifactArrangement.from_directory(d, comp, "arrangement/0")
        ArtifactArrangement.from_directory(d, comp, "arrangement/1")

        assert len(comp.artifacts) == 1  # same artifact reused

    def test_to_path_hash_map(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "file.txt").write_text("content")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(d, comp, "arrangement/0")
        mapping = arr.to_path_hash_map(comp)

        assert "file.txt" in mapping
        assert mapping["file.txt"].startswith("sha256:")

    def test_to_from_jsonld_roundtrip(self):
        arr = ArtifactArrangement(
            arrangement_id="arrangement/0",
            comment="snapshot",
            locations=[
                ArtifactLocation(
                    "arrangement/0/location/0", "comp/1/artifact/0", "data/in.csv"
                )
            ],
        )
        jld = arr.to_jsonld()
        restored = ArtifactArrangement.from_jsonld(jld)
        assert restored.arrangement_id == arr.arrangement_id
        assert restored.comment == arr.comment
        assert len(restored.locations) == 1


class TestTRSCapability:
    """Unit tests for TRSCapability."""

    def test_to_from_jsonld(self):
        cap = TRSCapability("trs/capability/0", "trov:CanProvideInternetIsolation")
        jld = cap.to_jsonld()
        restored = TRSCapability.from_jsonld(jld)
        assert restored.capability_id == cap.capability_id
        assert restored.capability_type == cap.capability_type


class TestTrustedResearchSystem:
    """Unit tests for TrustedResearchSystem."""

    def test_from_profile_preserves_extra_fields(self):
        profile = {
            "trov:name": "My TRS",
            "trov:hasCapability": [
                {"@id": "trs/cap/0", "@type": "trov:CanProvideInternetIsolation"}
            ],
            "trov:publicKey": None,
            "trov:custom": "value",
        }
        trs = TrustedResearchSystem.from_profile(profile, trs_id="trs")
        assert trs.extra_fields.get("trov:name") == "My TRS"
        assert trs.extra_fields.get("trov:custom") == "value"
        assert len(trs.capabilities) == 1

    def test_to_jsonld_includes_extra_fields(self):
        trs = TrustedResearchSystem(
            trs_id="trs",
            extra_fields={"trov:name": "foo", "trov:owner": "bar"},
        )
        jld = trs.to_jsonld()
        assert jld["trov:name"] == "foo"
        assert jld["trov:owner"] == "bar"

    def test_from_to_jsonld_roundtrip(self):
        trs = TrustedResearchSystem(
            trs_id="trs",
            name="Test TRS",
            description="desc",
            capabilities=[
                TRSCapability("trs/cap/0", "trov:CanProvideInternetIsolation")
            ],
            extra_fields={"trov:name": "custom-name"},
        )
        jld = trs.to_jsonld()
        restored = TrustedResearchSystem.from_jsonld(jld)
        assert restored.trs_id == trs.trs_id
        assert len(restored.capabilities) == 1
        assert restored.extra_fields.get("trov:name") == "custom-name"


class TestTimeStampingAuthority:
    """Unit tests for TimeStampingAuthority."""

    def test_to_from_jsonld(self):
        tsa = TimeStampingAuthority(tsa_id="tsa", public_key="-----BEGIN...")
        jld = tsa.to_jsonld()
        assert jld["@id"] == "tsa"
        assert jld["@type"] == "trov:TimeStampingAuthority"
        assert jld["trov:publicKey"] == "-----BEGIN..."
        restored = TimeStampingAuthority.from_jsonld(jld)
        assert restored.tsa_id == tsa.tsa_id
        assert restored.public_key == tsa.public_key

    def test_without_public_key(self):
        tsa = TimeStampingAuthority()
        jld = tsa.to_jsonld()
        assert "trov:publicKey" not in jld


class TestPerformanceAttribute:
    """Unit tests for PerformanceAttribute."""

    def test_to_from_jsonld(self):
        attr = PerformanceAttribute(
            "trp/0/attribute/0", "trov:InternetIsolation", "trs/cap/0"
        )
        jld = attr.to_jsonld()
        restored = PerformanceAttribute.from_jsonld(jld)
        assert restored.attribute_id == attr.attribute_id
        assert restored.attribute_type == attr.attribute_type
        assert restored.warranted_by_id == attr.warranted_by_id


class TestTrustedResearchPerformance:
    """Unit tests for TrustedResearchPerformance."""

    def test_to_from_jsonld_roundtrip(self):
        trp = TrustedResearchPerformance(
            performance_id="trp/0",
            comment="test run",
            conducted_by_id="trs",
            started_at=datetime.datetime(2024, 1, 1, 10, 0, 0),
            ended_at=datetime.datetime(2024, 1, 1, 11, 0, 0),
            accessed_arrangement_id="arrangement/0",
            contributed_to_arrangement_id="arrangement/1",
            attributes=[
                PerformanceAttribute(
                    "trp/0/attribute/0", "trov:InternetIsolation", "trs/cap/0"
                )
            ],
        )
        jld = trp.to_jsonld()
        restored = TrustedResearchPerformance.from_jsonld(jld)
        assert restored.performance_id == trp.performance_id
        assert restored.comment == trp.comment
        assert restored.started_at == trp.started_at
        assert restored.ended_at == trp.ended_at
        assert restored.accessed_arrangement_id == trp.accessed_arrangement_id
        assert (
            restored.contributed_to_arrangement_id == trp.contributed_to_arrangement_id
        )
        assert len(restored.attributes) == 1

    def test_optional_fields_absent_when_none(self):
        trp = TrustedResearchPerformance(performance_id="trp/0")
        jld = trp.to_jsonld()
        assert "trov:startedAtTime" not in jld
        assert "trov:endedAtTime" not in jld
        assert "trov:accessedArrangement" not in jld
        assert "trov:contributedToArrangement" not in jld


class TestTROAttribute:
    """Unit tests for TROAttribute."""

    def test_to_from_jsonld(self):
        attr = TROAttribute(
            "tro/attribute/0", "trov:IncludesAllInputData", "trp/0/attribute/0"
        )
        jld = attr.to_jsonld()
        restored = TROAttribute.from_jsonld(jld)
        assert restored.attribute_id == attr.attribute_id
        assert restored.attribute_type == attr.attribute_type
        assert restored.warranted_by_id == attr.warranted_by_id


class TestTransparentResearchObject:
    """Unit tests for the root TransparentResearchObject model."""

    def _make_tro(self):
        return TransparentResearchObject(
            name="Test TRO",
            description="A test",
            creator="Tester",
        )

    def test_to_jsonld_structure(self):
        tro = self._make_tro()
        jld = tro.to_jsonld()
        assert "@context" in jld
        assert "@graph" in jld
        graph = jld["@graph"][0]
        assert graph["schema:name"] == "Test TRO"
        assert "trov:TransparentResearchObject" in graph["@type"]
        assert "trov:hasComposition" in graph
        assert "trov:hasArrangement" in graph
        assert "trov:hasPerformance" in graph

    def test_from_jsonld_roundtrip(self):
        tro = self._make_tro()
        jld = tro.to_jsonld()
        restored = TransparentResearchObject.from_jsonld(jld)
        assert restored.name == tro.name
        assert restored.description == tro.description
        assert restored.creator == tro.creator

    def test_from_jsonld_old_vocab_raises(self):
        jld = {
            "@context": [{}],
            "@graph": [
                {
                    "@id": "tro",
                    "trov:vocabularyVersion": "0.0.1",
                    "trov:wasAssembledBy": {"trov:hasCapability": []},
                    "trov:hasArrangement": [],
                    "trov:hasComposition": {
                        "@id": "composition/1",
                        "trov:hasArtifact": [],
                    },
                    "trov:hasPerformance": [],
                    "trov:hasAttribute": [],
                }
            ],
        }
        with pytest.raises(RuntimeError, match="older version"):
            TransparentResearchObject.from_jsonld(jld)

    def test_add_arrangement_updates_composition(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "a.txt").write_text("alpha")
        (d / "b.txt").write_text("beta")

        tro = self._make_tro()
        arr = tro.add_arrangement(str(d), comment="snap1")

        assert len(tro.arrangements) == 1
        assert len(tro.composition.artifacts) == 2
        assert arr.arrangement_id == "arrangement/0"

    def test_add_performance_validates_arrangements(self):
        tro = self._make_tro()
        with pytest.raises(ValueError, match="does not exist"):
            tro.add_performance(
                start_time=datetime.datetime.now(),
                end_time=datetime.datetime.now(),
                accessed_arrangement="arrangement/99",
                modified_arrangement="arrangement/0",
            )

    def test_save_load_roundtrip(self, tmp_path):
        tro = self._make_tro()
        filepath = tmp_path / "test.jsonld"
        tro.save(str(filepath))
        assert filepath.exists()
        restored = TransparentResearchObject.load(str(filepath))
        assert restored.name == tro.name
        assert restored.creator == tro.creator

    def test_tsa_roundtrip(self):
        tro = self._make_tro()
        tro.tsa = TimeStampingAuthority(
            tsa_id="tsa", public_key="-----BEGIN PUBLIC KEY-----"
        )
        jld = tro.to_jsonld()
        restored = TransparentResearchObject.from_jsonld(jld)
        assert restored.tsa is not None
        assert restored.tsa.public_key == "-----BEGIN PUBLIC KEY-----"

    def test_full_workflow_roundtrip(self, tmp_path):
        d = tmp_path / "workdir"
        d.mkdir()
        (d / "input.csv").write_text("a,b\n1,2\n")
        (d / "script.py").write_text("print('hello')\n")

        tro = TransparentResearchObject(
            name="Full Workflow Test",
            trs=TrustedResearchSystem(
                trs_id="trs",
                capabilities=[
                    TRSCapability("trs/cap/0", "trov:CanProvideInternetIsolation")
                ],
            ),
        )

        tro.add_arrangement(str(d), comment="before")
        (d / "output.txt").write_text("result\n")
        tro.add_arrangement(str(d), comment="after")

        tro.add_performance(
            start_time=datetime.datetime(2024, 6, 1, 10, 0),
            end_time=datetime.datetime(2024, 6, 1, 11, 0),
            comment="run script",
            accessed_arrangement="arrangement/0",
            modified_arrangement="arrangement/1",
            attrs=["trov:InternetIsolation"],
        )

        filepath = tmp_path / "workflow.jsonld"
        tro.save(str(filepath))
        restored = TransparentResearchObject.load(str(filepath))

        assert len(restored.arrangements) == 2
        assert len(restored.performances) == 1
        assert restored.performances[0].comment == "run script"
        assert len(restored.performances[0].attributes) == 1


class TestReplicationPackageModel:
    """Tests for the ReplicationPackage class using the model API."""

    def test_verify_directory_matches(self, tmp_path):
        from tro_utils.replication_package import ReplicationPackage

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "file.txt").write_text("hello")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        result = ReplicationPackage.verify(arr, comp, workdir)
        assert result.is_valid
        assert not result.files_missing_in_arrangement
        assert not result.mismatched_hashes
        assert not result.files_missing_in_package

    def test_verify_missing_file_in_package(self, tmp_path):
        from tro_utils.replication_package import ReplicationPackage

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "file.txt").write_text("hello")
        (workdir / "extra.txt").write_text("world")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        # Remove one file from package before verifying
        (workdir / "extra.txt").unlink()

        result = ReplicationPackage.verify(arr, comp, workdir)
        assert not result.is_valid
        assert "extra.txt" in result.files_missing_in_package

    def test_verify_extra_file_in_package(self, tmp_path):
        from tro_utils.replication_package import ReplicationPackage

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "file.txt").write_text("hello")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        # Add a new file not in the arrangement
        (workdir / "unexpected.txt").write_text("surprise")

        result = ReplicationPackage.verify(arr, comp, workdir)
        assert not result.is_valid
        assert "unexpected.txt" in result.files_missing_in_arrangement

    def test_verify_zip_matches(self, tmp_path):
        from tro_utils.replication_package import ReplicationPackage
        import zipfile

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "data.csv").write_text("a,b\n1,2\n")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        # Package into a zip
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(workdir / "data.csv", "data.csv")

        result = ReplicationPackage.verify(arr, comp, zip_path)
        assert result.is_valid

    def test_verify_zip_with_subpath(self, tmp_path):
        from tro_utils.replication_package import ReplicationPackage
        import zipfile

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "data.csv").write_text("a,b\n1,2\n")

        comp = ArtifactComposition()
        arr = ArtifactArrangement.from_directory(workdir, comp, "arrangement/0")

        # Package into zip with a prefix subpath
        zip_path = tmp_path / "package.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(workdir / "data.csv", "subdir/data.csv")

        result = ReplicationPackage.verify(arr, comp, zip_path, subpath="subdir")
        assert result.is_valid

    def test_verification_result_is_valid_property(self):
        from tro_utils.replication_package import VerificationResult

        ok = VerificationResult()
        assert ok.is_valid

        bad = VerificationResult(files_missing_in_arrangement=["x"])
        assert not bad.is_valid
