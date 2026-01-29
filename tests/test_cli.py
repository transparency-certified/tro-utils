"""Tests for tro_utils CLI module.

Note: These tests focus on CLI command structure and basic functionality.
GPG-based signing/verification tests are excluded due to GPG key_map complexity.
"""
import json
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from click.exceptions import BadParameter

from tro_utils.cli import cli, StringOrPath


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace with sample files."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "data.csv").write_text("id,value\n1,100\n2,200\n")
    (workspace / "readme.txt").write_text("This is a readme file\n")
    (workspace / "config.json").write_text('{"key": "value"}')
    return workspace


@pytest.fixture(scope="session")
def trs_profile(tmp_path_factory):
    """Create a TRS profile file."""
    profile_dir = tmp_path_factory.mktemp("profiles")
    profile_file = profile_dir / "trs.jsonld"
    profile_data = {
        "rdfs:comment": "Test TRS for CLI testing",
        "trov:hasCapability": [
            {"@id": "trs/capability/1", "@type": "trov:CanRecordInternetAccess"},
            {"@id": "trs/capability/2", "@type": "trov:CanProvideInternetIsolation"},
        ],
    }
    profile_file.write_text(json.dumps(profile_data, indent=2))
    return str(profile_file)


class TestStringOrPath:
    """Test the StringOrPath custom parameter type."""

    def test_valid_string(self):
        """Test that valid string options are accepted."""
        param_type = StringOrPath(templates={"default": {}, "custom": {}})
        result = param_type.convert("default", None, None)
        assert result == "default"

    def test_valid_file_path(self, tmp_path):
        """Test that valid file paths are accepted."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        param_type = StringOrPath(templates={"default": {}})
        result = param_type.convert(str(test_file), None, None)
        assert result == str(test_file)

    def test_invalid_option(self):
        """Test that invalid options raise an error."""
        param_type = StringOrPath(templates={"default": {}})
        with pytest.raises(BadParameter):
            param_type.convert("invalid", None, MagicMock())


class TestCLIGroup:
    """Test main CLI group and global options."""

    def test_cli_help(self, runner):
        """Test that CLI help displays correctly."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "declaration" in result.output.lower()

    def test_cli_with_no_args(self, runner):
        """Test CLI with no arguments shows help."""
        result = runner.invoke(cli)
        assert "Usage:" in result.output or result.exit_code == 0


class TestArrangementCommands:
    """Test arrangement-related CLI commands."""

    def test_arrangement_add(self, runner, tmp_path, temp_workspace, trs_profile):
        """Test adding an arrangement via CLI."""
        tro_file = tmp_path / "test_tro.jsonld"
        result = runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                "--comment",
                "Initial",
                str(temp_workspace),
            ],
        )
        assert result.exit_code == 0
        assert tro_file.exists()
        with open(tro_file) as f:
            data = json.load(f)
            assert len(data["@graph"][0]["trov:hasArrangement"]) == 1

    def test_arrangement_add_with_ignore_dirs(
        self, runner, tmp_path, temp_workspace, trs_profile
    ):
        """Test adding an arrangement with ignored directories."""
        (temp_workspace / ".git").mkdir()
        (temp_workspace / ".git" / "config").write_text("git config")
        tro_file = tmp_path / "test_tro.jsonld"
        result = runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                "--ignore_dir",
                ".git",
                str(temp_workspace),
            ],
        )
        assert result.exit_code == 0
        with open(tro_file) as f:
            data = json.load(f)
            locations = [
                loc["trov:hasLocation"]
                for loc in data["@graph"][0]["trov:hasArrangement"][0]["trov:hasLocus"]
            ]
            assert not any(".git" in loc for loc in locations)

    def test_arrangement_list(self, runner, tmp_path, temp_workspace, trs_profile):
        """Test listing arrangements via CLI."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                "--comment",
                "Test",
                str(temp_workspace),
            ],
        )
        result = runner.invoke(
            cli, ["--declaration", str(tro_file), "arrangement", "list"]
        )
        assert result.exit_code == 0
        assert "arrangement/0" in result.output

    def test_arrangement_list_verbose(
        self, runner, tmp_path, temp_workspace, trs_profile
    ):
        """Test listing arrangements with verbose flag."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        result = runner.invoke(
            cli, ["--declaration", str(tro_file), "arrangement", "list", "-v"]
        )
        assert result.exit_code == 0
        assert "Composition:" in result.output


class TestCompositionCommands:
    """Test composition-related CLI commands."""

    def test_composition_info(self, runner, tmp_path, temp_workspace, trs_profile):
        """Test getting composition info via CLI."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        result = runner.invoke(
            cli, ["--declaration", str(tro_file), "composition", "info"]
        )
        assert result.exit_code == 0
        assert "composition/1/artifact/" in result.output

    def test_composition_info_verbose(
        self, runner, tmp_path, temp_workspace, trs_profile
    ):
        """Test composition info with verbose flag."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        result = runner.invoke(
            cli, ["--declaration", str(tro_file), "composition", "info", "-v"]
        )
        assert result.exit_code == 0
        assert "Arrangements:" in result.output


class TestVerifyCommands:
    """Test verification-related CLI commands."""

    def test_verify_package_success(
        self, runner, tmp_path, temp_workspace, trs_profile
    ):
        """Test successful package verification."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        result = runner.invoke(
            cli, ["verify-package", str(tro_file), str(temp_workspace)]
        )
        assert result.exit_code == 0
        assert "✓" in result.output

    def test_verify_package_with_arrangement_id(
        self, runner, tmp_path, temp_workspace, trs_profile
    ):
        """Test package verification with specific arrangement ID."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        result = runner.invoke(
            cli,
            [
                "verify-package",
                str(tro_file),
                str(temp_workspace),
                "--arrangement-id",
                "arrangement/0",
            ],
        )
        assert result.exit_code == 0
        assert "arrangement/0" in result.output

    def test_verify_package_failure(
        self, runner, tmp_path, temp_workspace, trs_profile
    ):
        """Test package verification failure."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        (temp_workspace / "data.csv").write_text("modified")
        result = runner.invoke(
            cli, ["verify-package", str(tro_file), str(temp_workspace)]
        )
        assert result.exit_code == 0
        assert "✗" in result.output


class TestReportCommand:
    """Test report generation CLI command."""

    def test_generate_report_with_template(
        self, runner, tmp_path, temp_workspace, trs_profile
    ):
        """Test generating a report with a custom template."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        template_file = tmp_path / "template.jinja2"
        template_file.write_text("TRO: {{ tro['schema:name'] }}")
        report_file = tmp_path / "report.html"
        result = runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "report",
                "--template",
                str(template_file),
                "--output",
                str(report_file),
            ],
        )
        assert result.exit_code == 0
        assert report_file.exists()

    def test_generate_report_with_default_template(
        self, runner, tmp_path, temp_workspace, trs_profile
    ):
        """Test generating a report with the default template."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        report_file = tmp_path / "report.html"
        result = runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "report",
                "--template",
                "default",
                "--output",
                str(report_file),
            ],
        )
        assert result.exit_code == 0
        assert report_file.exists()


class TestErrorHandling:
    """Test error handling in CLI commands."""

    def test_missing_declaration_file(self, runner):
        """Test error when declaration file doesn't exist."""
        result = runner.invoke(cli, ["verify-timestamp", "/nonexistent/file.jsonld"])
        assert result.exit_code == 2

    def test_missing_directory_for_arrangement(self, runner, tmp_path, trs_profile):
        """Test error when directory doesn't exist."""
        tro_file = tmp_path / "test_tro.jsonld"
        result = runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                "/nonexistent/directory",
            ],
        )
        assert result.exit_code != 0

    def test_invalid_template(self, runner, tmp_path, temp_workspace, trs_profile):
        """Test error with invalid template option."""
        tro_file = tmp_path / "test_tro.jsonld"
        runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "--profile",
                trs_profile,
                "arrangement",
                "add",
                str(temp_workspace),
            ],
        )
        report_file = tmp_path / "report.html"
        result = runner.invoke(
            cli,
            [
                "--declaration",
                str(tro_file),
                "report",
                "--template",
                "nonexistent",
                "--output",
                str(report_file),
            ],
        )
        assert result.exit_code != 0
