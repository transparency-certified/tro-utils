"""Tests for package version detection in tro_utils/__init__.py."""

import importlib
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch


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
