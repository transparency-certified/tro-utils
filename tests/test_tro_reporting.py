"""Tests for TRO report generation."""

import datetime
import os

from tro_utils import TRPAttribute

from tests.helpers import create_tro_with_gpg


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
