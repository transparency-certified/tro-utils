"""Main module — TRO facade.

The :class:`TRO` class is a thin facade that delegates data-model operations
to :class:`~tro_utils.models.TransparentResearchObject` while keeping
signing, timestamping, and report-generation logic here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

import gnupg
from jinja2 import Template
import requests
import rfc3161ng
import graphviz
from pyasn1.codec.der import encoder

from .models import TransparentResearchObject
from .models.trs import TrustedResearchSystem

GPG_HOME = os.environ.get("GPG_HOME")


class TRO:
    gpg_key_id = None
    gpg_passphrase = None
    basename = None
    profile = None

    def __init__(
        self,
        filepath=None,
        gpg_fingerprint=None,
        gpg_passphrase=None,
        profile=None,
        tro_creator=None,
        tro_name=None,
        tro_description=None,
    ):
        if filepath is None:
            self.basename = "some_tro"
            self.dirname = "."
        else:
            filepath_obj = pathlib.Path(filepath)
            self.basename = filepath_obj.stem
            self.dirname = (
                str(filepath_obj.parent)
                if filepath_obj.parent != pathlib.Path(".")
                else "."
            )

        if profile is not None and pathlib.Path(profile).exists():
            print(f"Loading profile from {profile}")
            self.profile = json.load(open(profile))
        else:
            self.profile = {
                "schema:description": "Default TRS with no capabilities",
                "trov:hasCapability": [],
                "trov:publicKey": None,
            }

        if not pathlib.Path(self.tro_filename).exists():
            trs = TrustedResearchSystem.from_profile(self.profile)
            self._model = TransparentResearchObject(
                creator=tro_creator or "TRO utils",
                name=tro_name or "Some TRO",
                description=tro_description or "Some description",
                trs=trs,
            )
        else:
            self._model = TransparentResearchObject.load(self.tro_filename)

        self.gpg = gnupg.GPG(gnupghome=GPG_HOME, verbose=False)
        if gpg_fingerprint:
            self.gpg_key_id = self.gpg.list_keys().key_map[gpg_fingerprint]["keyid"]
            self._model.trs.public_key = self.gpg.export_keys(self.gpg_key_id)
        if gpg_passphrase:
            self.gpg_passphrase = gpg_passphrase

    # ------------------------------------------------------------------
    # File path helpers
    # ------------------------------------------------------------------

    @property
    def base_filename(self):
        if not self.basename:
            raise ValueError("basename is not set")
        return str((pathlib.Path(self.dirname) / self.basename).resolve())

    @property
    def tro_filename(self):
        return f"{self.base_filename}.jsonld"

    @property
    def sig_filename(self):
        return f"{self.base_filename}.sig"

    @property
    def tsr_filename(self):
        return f"{self.base_filename}.tsr"

    # ------------------------------------------------------------------
    # data property — computed from the underlying model
    # ------------------------------------------------------------------

    @property
    def data(self) -> dict:
        """Return the current JSON-LD representation of the TRO.

        Computed on every access from the underlying
        :class:`~tro_utils.models.TransparentResearchObject`.
        """
        return self._model.to_jsonld()

    # ------------------------------------------------------------------
    # Delegation helpers
    # ------------------------------------------------------------------

    def get_composition_seq(self):
        return len(self._model.composition.artifacts)

    def get_arrangement_seq(self):
        return len(self._model.arrangements)

    def list_arrangements(self):
        return self.data["@graph"][0]["trov:hasArrangement"]

    def get_arrangement_path_hash_map(self, arrangement_id):
        arrangement = next(
            (a for a in self._model.arrangements if a.arrangement_id == arrangement_id),
            None,
        )
        if arrangement is None:
            available = [a.arrangement_id for a in self._model.arrangements]
            raise ValueError(
                f"Arrangement '{arrangement_id}' not found. "
                f"Available arrangements: {available}"
            )
        return arrangement.to_path_hash_map(self._model.composition)

    def add_arrangement(
        self, directory, ignore_dirs=None, comment=None, resolve_symlinks=True
    ):
        self._model.add_arrangement(
            directory=directory,
            comment=comment,
            ignore_dirs=ignore_dirs,
            resolve_symlinks=resolve_symlinks,
        )

    def save(self):
        self._model.save(self.tro_filename)

    # ------------------------------------------------------------------
    # Hashing utilities
    # ------------------------------------------------------------------

    @staticmethod
    def sha256_for_file(filepath, resolve_symlinks=True):
        from .models.arrangement import ArtifactArrangement

        return ArtifactArrangement._sha256_for_file(filepath, resolve_symlinks)

    # ------------------------------------------------------------------
    # Signing and timestamping
    # ------------------------------------------------------------------

    def trs_signature(self):
        if self.gpg_key_id is None:
            raise RuntimeError("GPG fingerprint was not provided")
        if self.gpg_passphrase is None:
            raise RuntimeError("GPG passphrase was not provided")
        signature = self.gpg.sign(
            json.dumps(self.data, indent=2, sort_keys=True),
            keyid=self.gpg_key_id,
            passphrase=self.gpg_passphrase,
            detach=True,
        )
        with open(self.sig_filename, "w") as fp:
            fp.write(str(signature))
        return signature

    def request_timestamp(self):
        """Request a timestamp from a remote TSA and store the result in a file."""
        rt = rfc3161ng.RemoteTimestamper("https://freetsa.org/tsr", hashname="sha512")
        ts_data = {
            "tro_declaration": hashlib.sha512(
                json.dumps(self.data, indent=2, sort_keys=True).encode("utf-8")
            ).hexdigest(),
            "trs_signature": hashlib.sha512(
                str(self.trs_signature()).encode("utf-8")
            ).hexdigest(),
        }
        tsr_payload = json.dumps(ts_data, indent=2, sort_keys=True).encode()
        tsr = rt(data=tsr_payload, return_tsr=True)
        with open(self.tsr_filename, "wb") as fs:
            fs.write(encoder.encode(tsr))

    def get_composition_info(self):
        return self.data["@graph"][0]["trov:hasComposition"]

    def verify_timestamp(self):
        """Verify that a run is valid and signed."""

        try:
            with open(self.sig_filename, "rb") as fp:
                trs_signature = fp.read()
        except FileNotFoundError:
            raise RuntimeError("Signature file does not exist")

        ts_data = {
            "tro_declaration": hashlib.sha512(
                json.dumps(self.data, indent=2, sort_keys=True).encode("utf-8")
            ).hexdigest(),
            "trs_signature": hashlib.sha512(trs_signature).hexdigest(),
        }
        tsr_payload = json.dumps(ts_data, indent=2, sort_keys=True).encode()

        with (
            tempfile.NamedTemporaryFile() as data_f,
            tempfile.NamedTemporaryFile() as cafile_f,
            tempfile.NamedTemporaryFile() as tsacert_f,
        ):
            data_f.write(tsr_payload)
            data_f.flush()
            data_f.seek(0)

            response = requests.get(
                "https://freetsa.org/files/tsa.crt", allow_redirects=True
            )
            tsacert_f.write(response.content)
            tsacert_f.flush()
            tsacert_f.seek(0)

            response = requests.get(
                "https://freetsa.org/files/cacert.pem", allow_redirects=True
            )
            cafile_f.write(response.content)
            cafile_f.flush()
            cafile_f.seek(0)

            args = [
                "openssl",
                "ts",
                "-verify",
                "-data",
                data_f.name,
                "-in",
                self.tsr_filename,
                "-CAfile",
                cafile_f.name,
                "-untrusted",
                tsacert_f.name,
            ]
            subprocess.check_call(args)

    # ------------------------------------------------------------------
    # Replication package verification
    # ------------------------------------------------------------------

    def verify_replication_package(self, arrangement_id, package, subpath=None):
        from .replication_package import ReplicationPackage

        arrangement = next(
            (a for a in self._model.arrangements if a.arrangement_id == arrangement_id),
            None,
        )
        if arrangement is None:
            available = [a.arrangement_id for a in self._model.arrangements]
            raise ValueError(
                f"Arrangement '{arrangement_id}' not found. "
                f"Available arrangements: {available}"
            )
        result = ReplicationPackage.verify(
            arrangement, self._model.composition, package, subpath
        )
        return (
            result.files_missing_in_arrangement,
            result.mismatched_hashes,
            result.files_missing_in_package,
            result.is_valid,
        )

    # ------------------------------------------------------------------
    # Performance recording
    # ------------------------------------------------------------------

    def add_performance(
        self,
        start_time,
        end_time,
        comment=None,
        accessed_arrangement=None,
        modified_arrangement=None,
        attrs=None,
        extra_attributes=None,
    ):
        self._model.add_performance(
            start_time=start_time,
            end_time=end_time,
            comment=comment,
            accessed_arrangement=accessed_arrangement,
            modified_arrangement=modified_arrangement,
            attrs=attrs,
            extra_attributes=extra_attributes,
        )

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self, template, report):
        graph = self.data["@graph"][0]
        artifact_lookup = {a.artifact_id: a for a in self._model.composition.artifacts}
        arrangements = {}
        for arr in self._model.arrangements:
            artifacts = {
                loc.path: {
                    "hash": artifact_lookup[loc.artifact_id].hash.to_string(),
                    "creator": "trs",
                    "createdDate": "None",
                }
                for loc in sorted(arr.locations, key=lambda _: _.path)
            }
            arrangements[arr.arrangement_id] = {
                "name": arr.comment,
                "artifacts": artifacts,
            }

        dot = graphviz.Digraph("TRO")
        dot.graph_attr["rankdir"] = "LR"
        dot.attr("edge", color="black")
        dot.graph_attr["dpi"] = "200"

        dot.attr("node", shape="box", style="filled, rounded", fillcolor="#FFFFD1")
        for arr_id in arrangements:
            dot.node(arrangements[arr_id]["name"])

        dot.attr("node", shape="box3d", style="filled, rounded", fillcolor="#D6FDD0")
        for perf in self._model.performances:
            dot.node(perf.comment)
            dot.edge(arrangements[perf.accessed_arrangement_id]["name"], perf.comment)
            dot.edge(
                perf.comment, arrangements[perf.contributed_to_arrangement_id]["name"]
            )

        png_bytes = dot.pipe(format="png")
        png_base64 = base64.b64encode(png_bytes).decode("utf-8")

        keys = list(arrangements.keys())

        for n in reversed(range(1, len(keys))):
            for location in arrangements[keys[n]]["artifacts"]:
                if location in arrangements[keys[n - 1]]["artifacts"]:
                    if (
                        arrangements[keys[n]]["artifacts"][location]["hash"]
                        != arrangements[keys[n - 1]]["artifacts"][location]["hash"]
                    ):
                        arrangements[keys[n]]["artifacts"][location]["status"] = (
                            "Changed"
                        )
                    else:
                        arrangements[keys[n]]["artifacts"][location]["status"] = (
                            "Unchanged"
                        )
                else:
                    arrangements[keys[n]]["artifacts"][location]["status"] = "Created"

        data = {
            **graph,
            "workflow_diagram": png_base64,
            "trps": [
                {
                    "id": perf.performance_id,
                    "started": perf.started_at.isoformat() if perf.started_at else None,
                    "ended": perf.ended_at.isoformat() if perf.ended_at else None,
                    "accessed": arrangements[perf.accessed_arrangement_id]["name"],
                    "contributed": arrangements[perf.contributed_to_arrangement_id][
                        "name"
                    ],
                    "description": perf.comment,
                }
                for perf in self._model.performances
            ],
            "arrangements": arrangements,
        }

        with open(template) as file_:
            template = Template(file_.read())

        with open(report, "w") as fh:
            fh.write(template.render(tro=data))
