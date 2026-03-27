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
import zipfile

import gnupg
from jinja2 import Template
import requests
import rfc3161ng
import graphviz
from packaging.version import Version
from pyasn1.codec.der import encoder

from .models import TransparentResearchObject
from .models.trs import TrustedResearchSystem

GPG_HOME = os.environ.get("GPG_HOME")
TROV_VOCABULARY_VERSION = Version("0.1")


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

    @staticmethod
    def _get_hash(artifact):
        if isinstance(artifact, dict):
            if "trov:sha256" in artifact:
                return f"sha256:{artifact['trov:sha256']}"
            elif "trov:hash" in artifact:
                _hash = artifact["trov:hash"]
                if isinstance(_hash, dict):
                    return f"{_hash['trov:hashAlgorithm']}:{_hash['trov:hashValue']}"
                elif isinstance(_hash, list):
                    for h in _hash:
                        if h.get("trov:hashAlgorithm") == "sha256":
                            return f"sha256:{h['trov:hashValue']}"
                    return (
                        f"{_hash[0]['trov:hashAlgorithm']}:{_hash[0]['trov:hashValue']}"
                    )
        raise ValueError(f"Artifact {artifact} does not contain a recognizable hash")

    def get_hash_mapping(self):
        return {
            artifact.hash.to_string(): {
                "@id": artifact.artifact_id,
                "trov:mimeType": artifact.mime_type,
            }
            for artifact in self._model.composition.artifacts
        }

    @staticmethod
    def calculate_fingerprint(artifacts):
        hashes = []
        for art in artifacts:
            if "trov:sha256" in art:
                hashes.append(art["trov:sha256"])
            elif "trov:hash" in art and isinstance(art["trov:hash"], dict):
                hashes.append(art["trov:hash"]["trov:hashValue"])
            elif "trov:hash" in art and isinstance(art["trov:hash"], list):
                hashes += [_["trov:hashValue"] for _ in art["trov:hash"]]
        return hashlib.sha256("".join(sorted(hashes)).encode("utf-8")).hexdigest()

    def update_composition(self, composition):
        """Rebuild the model composition from the legacy hash-map format."""
        from .models.artifact import ResearchArtifact
        from .models.hash_value import HashValue

        artifacts = [
            ResearchArtifact(
                artifact_id=value["@id"],
                hash=HashValue(
                    algorithm=key.split(":")[0],
                    value=key.split(":")[1],
                ),
                mime_type=value["trov:mimeType"],
            )
            for key, value in composition.items()
        ]
        artifacts.sort(key=lambda a: a.artifact_id)
        self._model.composition.artifacts = artifacts
        self._model.composition._recompute_fingerprint()

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

    def sha256_for_directory(self, directory, ignore_dirs=None, resolve_symlinks=True):
        if ignore_dirs is None:
            ignore_dirs = [".git"]
        hashes = {}
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for filename in files:
                filepath = str(pathlib.Path(root) / filename)
                hash_value = self.sha256_for_file(filepath, resolve_symlinks)
                hashes[filepath] = hash_value
        return hashes

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
        files_missing_in_arrangement = []
        mismatched_hashes = []

        arrangement_map = self.get_arrangement_path_hash_map(arrangement_id)

        def iterate_package_files():
            if pathlib.Path(package).is_dir():
                package_path = pathlib.Path(package)
                for root, dirs, files in os.walk(package):
                    for filename in files:
                        filepath = pathlib.Path(root) / filename
                        relative_filename = filepath.relative_to(
                            package_path
                        ).as_posix()
                        yield relative_filename, self.sha256_for_file(str(filepath))
            else:
                with zipfile.ZipFile(package, "r") as zf:
                    for fileinfo in zf.infolist():
                        sha256 = hashlib.sha256()
                        with zf.open(fileinfo.filename) as f:
                            for chunk in iter(lambda: f.read(4096), b""):
                                sha256.update(chunk)
                        file_hash = f"sha256:{sha256.hexdigest()}"
                        yield fileinfo.filename, file_hash

        for original_filename, file_hash in iterate_package_files():
            relative_filename = original_filename

            if subpath is not None:
                import pathlib as _pl
                original_path = _pl.PurePosixPath(original_filename)
                subpath_posix = _pl.PurePosixPath(subpath)
                try:
                    relative_filename = original_path.relative_to(
                        subpath_posix
                    ).as_posix()
                except ValueError:
                    continue

            if relative_filename not in arrangement_map:
                files_missing_in_arrangement.append(relative_filename)

            expected_hash = arrangement_map.pop(relative_filename, None)
            if file_hash != expected_hash:
                mismatched_hashes.append((relative_filename, expected_hash, file_hash))

        dirty = (
            files_missing_in_arrangement
            or mismatched_hashes
            or len(arrangement_map) > 0
        )
        return (
            files_missing_in_arrangement,
            mismatched_hashes,
            list(arrangement_map.keys()),
            not dirty,
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
        composition = {
            obj["@id"]: obj for obj in graph["trov:hasComposition"]["trov:hasArtifact"]
        }
        arrangements = {}
        for arr in self.data["@graph"][0]["trov:hasArrangement"]:
            artifacts = {
                obj["trov:path"]: {
                    "hash": self._get_hash(composition[obj["trov:artifact"]["@id"]]),
                    "creator": obj.get("schema:creator", "trs"),
                    "createdDate": obj.get("schema:createdDate", "None"),
                }
                for obj in sorted(
                    arr["trov:hasArtifactLocation"], key=lambda x: x["trov:path"]
                )
            }

            arrangements[arr["@id"]] = {
                "name": arr["rdfs:comment"],
                "artifacts": artifacts,
            }

        dot = graphviz.Digraph("TRO")
        dot.graph_attr["rankdir"] = "LR"
        dot.attr("edge", color="black")
        dot.graph_attr["dpi"] = "200"

        dot.attr("node", shape="box", style="filled, rounded", fillcolor="#FFFFD1")
        for arrangement in arrangements:
            dot.node(arrangements[arrangement]["name"])

        dot.attr("node", shape="box3d", style="filled, rounded", fillcolor="#D6FDD0")

        if isinstance(graph["trov:hasPerformance"], dict):
            graph["trov:hasPerformance"] = [graph["trov:hasPerformance"]]
        for trp in graph["trov:hasPerformance"]:
            description = trp["rdfs:comment"]
            accessed = arrangements[trp["trov:accessedArrangement"]["@id"]]["name"]
            contributed = arrangements[trp["trov:contributedToArrangement"]["@id"]][
                "name"
            ]
            dot.node(description)
            dot.edge(accessed, description)
            dot.edge(description, contributed)

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
                    "id": trp["@id"],
                    "started": trp["trov:startedAtTime"],
                    "ended": trp["trov:endedAtTime"],
                    "accessed": arrangements[
                        trp.get("trov:accessedArrangement", {"@id": ""})["@id"]
                    ]["name"],
                    "contributed": arrangements[
                        trp.get("trov:contributedToArrangement", {"@id": ""})["@id"]
                    ]["name"],
                    "description": trp.get("rdfs:comment", ""),
                }
                for trp in graph["trov:hasPerformance"]
            ],
            "arrangements": arrangements,
        }

        with open(template) as file_:
            template = Template(file_.read())

        with open(report, "w") as fh:
            fh.write(template.render(tro=data))
