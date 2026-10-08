"""Tests for TRO report generation."""

import datetime
import os
import pathlib

from tro_utils import TRPAttribute

import tro_utils

from tests.helpers import create_tro_with_gpg

#: The bundled template, resolved off the package as the CLI does rather than
#: relative to the working directory.
DEFAULT_TEMPLATE = (
    pathlib.Path(tro_utils.__file__).parent / "default.jinja2"
).resolve()


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


class TestTRSPropertiesInReport:
    """The TRACE System table reads the organization's schema.org properties.

    It previously read `trov:name`, `trov:owner`, `trov:contact` and
    `trov:url` -- terms the TROV vocabulary never defined for a TRS. Jinja
    renders a missing key as the empty string, so the whole table silently
    went blank rather than failing.
    """

    def _render(self, tmp_path, profile_data):
        import json

        from tro_utils.tro_utils import TRO

        workspace = tmp_path / "w"
        workspace.mkdir()
        (workspace / "main.py").write_text("print(1)")
        profile = tmp_path / "trs.jsonld"
        profile.write_text(json.dumps(profile_data))

        tro = TRO(filepath=str(tmp_path / "t.jsonld"), profile=str(profile))
        tro.add_arrangement(str(workspace), comment="snap")
        tro.save()
        report = tmp_path / "report.md"
        tro.generate_report(str(DEFAULT_TEMPLATE), str(report))
        return report.read_text()

    def test_schema_properties_are_rendered(self, tmp_path):
        body = self._render(
            tmp_path,
            {
                "@id": "https://example.org/trs",
                "schema:name": "shakuras",
                "schema:description": "My local system",
                "schema:email": "root@dev.null",
                "schema:url": "https://example.org/trs",
                "schema:owner": {
                    "@type": "schema:Person",
                    "schema:name": "Some Operator",
                },
                "trov:hasCapability": [],
            },
        )
        assert "| Name         | shakuras |" in body
        assert "| Description  | My local system |" in body
        # schema:owner is a node, so the name has to be reached through it.
        assert "| Owner        | Some Operator |" in body
        assert "| Contact      | root@dev.null |" in body
        assert "| URL          | https://example.org/trs |" in body

    def test_legacy_trov_properties_still_render(self, tmp_path):
        """Reports over declarations written before the schema.org switch."""
        body = self._render(
            tmp_path,
            {
                "@id": "https://example.org/trs",
                "trov:name": "old-trs",
                "trov:description": "Old style",
                "trov:owner": "Someone",
                "trov:contact": "old@example.org",
                "trov:url": "https://example.org/trs",
                "trov:hasCapability": [],
            },
        )
        assert "| Name         | old-trs |" in body
        assert "| Owner        | Someone |" in body
        assert "| Contact      | old@example.org |" in body

    def test_no_blank_trs_rows(self, tmp_path):
        """The regression itself: every row must carry a value."""
        body = self._render(
            tmp_path,
            {
                "@id": "https://example.org/trs",
                "schema:name": "shakuras",
                "schema:description": "d",
                "schema:email": "e@example.org",
                "schema:url": "https://example.org/trs",
                "trov:hasCapability": [],
            },
        )
        trace = body.split("## TRACE System Information")[1]
        for label in ("Name", "Description", "Contact", "URL"):
            assert f"| {label}" in trace
            row = next(l for l in trace.splitlines() if l.startswith(f"| {label}"))
            assert row.split("|")[2].strip(), f"{label} rendered blank: {row!r}"
