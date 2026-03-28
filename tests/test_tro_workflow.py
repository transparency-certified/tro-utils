"""Tests for a complete real-world workflow."""

import datetime
import json
import os

from tro_utils import TRPAttribute

from tests.helpers import create_tro_with_gpg


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
        assert (
            performances[0]["trov:accessedArrangement"]["trov:arrangement"]["@id"]
            == "arrangement/0"
        )
        assert (
            performances[0]["trov:contributedToArrangement"]["trov:arrangement"]["@id"]
            == "arrangement/1"
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
