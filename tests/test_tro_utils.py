#!/usr/bin/env python

"""Tests for `tro_utils` package."""

import pytest

from click.testing import CliRunner

from tro_utils import tro_utils
from tro_utils import cli
import os
import json
import hashlib
import pytest
from click.testing import CliRunner
from tro_utils.tro_utils import TRO


@pytest.fixture
def tro_instance():
    return TRO()


def test_tro_init(tro_instance):
    assert tro_instance.basename == "some_tro"
    # assert tro_instance.profile is None


def test_tro_base_filename(tro_instance):
    tro_instance.basename = "some_tro"
    tro_instance.dirname = "."
    assert tro_instance.base_filename == os.path.abspath(os.path.join(".", "some_tro"))


def test_tro_tro_filename(tro_instance):
    tro_instance.basename = "some_tro"
    assert tro_instance.tro_filename == os.path.abspath("some_tro.jsonld")


def test_tro_sig_filename(tro_instance):
    tro_instance.basename = "some_tro"
    assert tro_instance.sig_filename == os.path.abspath("some_tro.sig")


def test_tro_tsr_filename(tro_instance):
    tro_instance.basename = "some_tro"
    assert tro_instance.tsr_filename == os.path.abspath("some_tro.tsr")


def test_tro_get_composition_seq(tro_instance):
    tro_instance.data = {
        "@graph": [
            {
                "trov:hasComposition": {
                    "trov:hasArtifact": [
                        {"@id": "artifact/1"},
                        {"@id": "artifact/2"},
                        {"@id": "artifact/3"},
                    ]
                }
            }
        ]
    }
    assert tro_instance.get_composition_seq() == 3


def test_tro_get_arrangement_seq(tro_instance):
    tro_instance.data = {
        "@graph": [
            {
                "trov:hasArrangement": [
                    {"@id": "arrangement/1"},
                    {"@id": "arrangement/2"},
                    {"@id": "arrangement/3"},
                ]
            }
        ]
    }
    assert tro_instance.get_arrangement_seq() == 3


def test_tro_get_hash_mapping(tro_instance):
    tro_instance.data = {
        "@graph": [
            {
                "trov:hasComposition": {
                    "trov:hasArtifact": [
                        {
                            "trov:sha256": "hash1",
                            "@id": "artifact/1",
                            "trov:mimeType": "text/plain",
                        },
                        {
                            "trov:sha256": "hash2",
                            "@id": "artifact/2",
                            "trov:mimeType": "application/pdf",
                        },
                        {
                            "trov:sha256": "hash3",
                            "@id": "artifact/3",
                            "trov:mimeType": "image/png",
                        },
                    ]
                }
            }
        ]
    }
    assert tro_instance.get_hash_mapping() == {
        "hash1": {"@id": "artifact/1", "trov:mimeType": "text/plain"},
        "hash2": {"@id": "artifact/2", "trov:mimeType": "application/pdf"},
        "hash3": {"@id": "artifact/3", "trov:mimeType": "image/png"},
    }


def test_tro_update_composition(tro_instance):
    composition = {
        "hash1": {"@id": "artifact/1", "trov:mimeType": "text/plain"},
        "hash2": {"@id": "artifact/2", "trov:mimeType": "application/pdf"},
    }
    tro_instance.data = {
        "@graph": [
            {
                "trov:hasComposition": {
                    "trov:hasArtifact": [
                        {"trov:sha256": "hash1", "@id": "artifact/1"},
                        {"trov:sha256": "hash2", "@id": "artifact/2"},
                    ]
                }
            }
        ]
    }
    tro_instance.update_composition(composition)
    assert tro_instance.data["@graph"][0]["trov:hasComposition"][
        "trov:hasArtifact"
    ] == [
        {
            "@id": "artifact/1",
            "trov:sha256": "hash1",
            "trov:mimeType": "text/plain",
            "@type": "trov:ResearchArtifact",
        },
        {
            "@id": "artifact/2",
            "trov:sha256": "hash2",
            "trov:mimeType": "application/pdf",
            "@type": "trov:ResearchArtifact",
        },
    ]


def test_tro_list_arrangements(tro_instance):
    tro_instance.data = {
        "@graph": [
            {
                "trov:hasArrangement": [
                    {"@id": "arrangement/1"},
                    {"@id": "arrangement/2"},
                    {"@id": "arrangement/3"},
                ]
            }
        ]
    }
    assert tro_instance.list_arrangements() == [
        {
            "@id": "arrangement/1",
            "@type": "trov:Artifact Arrangement",
            "rdfs:comment": None,
            "trov:hasLocus": [],
        },
        {
            "@id": "arrangement/2",
            "@type": "trov:Artifact Arrangement",
            "rdfs:comment": None,
            "trov:hasLocus": [],
        },
        {
            "@id": "arrangement/3",
            "@type": "trov:Artifact Arrangement",
            "rdfs:comment": None,
            "trov:hasLocus": [],
        },
    ]


def test_tro_add_arrangement(tro_instance):
    tro_instance.data = {"@graph": [{"trov:hasArrangement": []}]}
    tro_instance.sha256_for_directory = lambda directory, ignore_dirs=None: {
        "file1.txt": "hash1",
        "file2.pdf": "hash2",
    }
    tro_instance.get_hash_mapping = lambda: {
        "hash1": {"@id": "artifact/1", "trov:mimeType": None},
        "hash2": {"@id": "artifact/2", "trov:mimeType": None},
    }
    tro_instance.update_composition = lambda composition: None
    tro_instance.add_arrangement("directory")
    assert tro_instance.data["@graph"][0]["trov:hasArrangement"] == [
        {
            "@id": "arrangement/0",
            "@type": "trov:Artifact Arrangement",
            "rdfs:comment": "Scanned directory",
            "trov:hasLocus": [
                {
                    "@id": "arrangement/0/locus/0",
                    "@type": "trov:ArtifactLocus",
                    "trov:hasArtifact": {"@id": "artifact/1"},
                    "trov:hasLocation": "file1.txt",
                },
                {
                    "@id": "arrangement/0/locus/1",
                    "@type": "trov:ArtifactLocus",
                    "trov:hasArtifact": {"@id": "artifact/2"},
                    "trov:hasLocation": "file2.pdf",
                },
            ],
        }
    ]


def test_tro_save(tro_instance, mocker):
    mocker.patch("builtins.open", mocker.mock_open())
    tro_instance.data = {"key": "value"}
    tro_instance.save()
    open.assert_called_once_with(os.path.abspath("some_tro.jsonld"), "w")
    open().write.assert_called_once_with(
        json.dumps({"key": "value"}, indent=2, sort_keys=True)
    )


def test_tro_sha256_for_file(tro_instance, mocker):
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"file_content"))
    assert (
        tro_instance.sha256_for_file("file_path")
        == "2ef7bde608ce5404e97d5f042f95f89f1c232871"
    )


def test_tro_sha256_for_directory(tro_instance, mocker):
    mocker.patch("os.walk", return_value=[("root", [], ["file1.txt", "file2.pdf"])])
    mocker.patch.object(tro_instance, "sha256_for_file", side_effect=["hash1", "hash2"])
    assert tro_instance.sha256_for_directory("directory") == {
        "root/file1.txt": "hash1",
        "root/file2.pdf": "hash2",
    }


def test_tro_trs_signature(tro_instance, mocker):
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("datetime.datetime.now", return_value="2022-01-01T00:00:00")
    mocker.patch.object(tro_instance, "gpg", return_value=mocker.Mock())
    mocker.patch.object(tro_instance.gpg, "sign", return_value="signature")
    tro_instance.gpg_key_id = "key_id"
    tro_instance.gpg_passphrase = "passphrase"
    assert tro_instance.trs_signature() == "signature"
    open.assert_called_once_with(tro_instance.sig_filename, "w")
    open().write.assert_called_once_with("signature")


def test_tro_request_timestamp(tro_instance, mocker):
    mocker.patch("rfc3161ng.RemoteTimestamper", return_value=mocker.Mock())
    mocker.patch("hashlib.sha512", return_value=mocker.Mock(hexdigest=lambda: "hash"))
    mocker.patch("json.dumps", return_value="tsr_payload")
    mocker.patch("builtins.open", mocker.mock_open())
    tro_instance.trs_signature = lambda: "trs_signature"
    tro_instance.request_timestamp()
    rfc3161ng.RemoteTimestamper.assert_called_once_with(
        "https://freetsa.org/tsr", hashname="sha512"
    )
    rfc3161ng.RemoteTimestamper().assert_called_once_with(
        data="tsr_payload", return_tsr=True
    )
    open.assert_called_once_with(tro_instance.tsr_filename, "wb")
    open().write.assert_called_once_with("encoded_tsr")


def test_tro_get_composition_info(tro_instance):
    tro_instance.data = {
        "@graph": [
            {
                "trov:hasComposition": {
                    "trov:hasArtifact": [
                        {"@id": "artifact/1"},
                        {"@id": "artifact/2"},
                        {"@id": "artifact/3"},
                    ]
                }
            }
        ]
    }
    assert tro_instance.get_composition_info() == {
        "trov:hasArtifact": [
            {"@id": "artifact/1"},
            {"@id": "artifact/2"},
            {"@id": "artifact/3"},
        ]
    }


def test_tro_verify_timestamp(tro_instance, mocker):
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"trs_signature"))
    mocker.patch("hashlib.sha512", return_value=mocker.Mock(hexdigest=lambda: "hash"))
    mocker.patch("json.dumps", return_value="ts_data")
    tro_instance.trs_signature = lambda: "trs_signature"
    assert tro_instance.verify_timestamp() == None
    os.path.exists.assert_called_once_with(tro_instance.sig_filename)
    open.assert_called_once_with(tro_instance.sig_filename, "rb")
    hashlib.sha512.assert_called_once_with(b"trs_signature")
    json.dumps.assert_called_once_with("ts_data", indent=2, sort_keys=True)
