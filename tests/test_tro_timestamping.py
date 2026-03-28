"""Tests for TRO timestamping operations."""

import os
from unittest.mock import MagicMock, patch

from tests.helpers import create_tro_with_gpg


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
