"""Main module."""
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import zipfile

import datetime
import gnupg
from jinja2 import Template
import magic
import requests
import rfc3161ng
import graphviz
from pyasn1.codec.der import encoder

from . import TRPAttribute, caps_mapping

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
            self.basename = os.path.basename(filepath).rsplit(".")[0]
            self.dirname = os.path.dirname(filepath)

        if profile is not None and os.path.exists(profile):
            print(f"Loading profile from {profile}")
            self.profile = json.load(open(profile))
        else:
            self.profile = {
                "schema:description": "Default TRS with no capabilities",
                "trov:hasCapability": [],
                "trov:publicKey": None,
            }

        if not os.path.exists(self.tro_filename):
            self.data = {
                "@context": [
                    {
                        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                        "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
                        "trov": "https://w3id.org/trace/2023/05/trov#",
                        "schema": "https://schema.org",
                    }
                ],
                "@graph": [
                    {
                        "@id": "tro",
                        "@type": [
                            "trov:TransparentResearchObject",
                            "schema:CreativeWork",
                        ],
                        "schema:creator": tro_creator or "TRO utils",
                        "schema:name": tro_name or "Some TRO",
                        "schema:description": tro_description or "Some description",
                        "schema:dateCreated": datetime.datetime.now().isoformat(),
                        "trov:hasArrangement": [],
                        "trov:hasAttribute": [],
                        "trov:hasComposition": {
                            "@id": "composition/1",
                            "@type": "trov:ArtifactComposition",
                            "trov:hasArtifact": [],
                        },
                        "trov:hasPerformance": [],
                        "trov:wasAssembledBy": {
                            "@id": "trs",
                            "@type": [
                                "trov:TrustedResearchSystem",
                                "schema:Organization",
                            ],
                            **self.profile,
                        },
                    },
                ],
            }
        else:
            self.data = json.load(open(self.tro_filename))
        self.gpg = gnupg.GPG(gnupghome=GPG_HOME, verbose=False)
        if gpg_fingerprint:
            self.gpg_key_id = self.gpg.list_keys().key_map[gpg_fingerprint]["keyid"]
            self.data["@graph"][0]["trov:wasAssembledBy"][
                "trov:publicKey"
            ] = self.gpg.export_keys(self.gpg_key_id)
        if gpg_passphrase:
            self.gpg_passphrase = gpg_passphrase

    @property
    def base_filename(self):
        return os.path.abspath(os.path.join(self.dirname, self.basename))

    @property
    def tro_filename(self):
        return f"{self.base_filename}.jsonld"

    @property
    def sig_filename(self):
        return f"{self.base_filename}.sig"

    @property
    def tsr_filename(self):
        return f"{self.base_filename}.tsr"

    def get_composition_seq(self):
        return len(self.data["@graph"][0]["trov:hasComposition"]["trov:hasArtifact"])

    def get_arrangement_seq(self):
        return len(self.data["@graph"][0]["trov:hasArrangement"])

    def get_hash_mapping(self):
        return {
            _["trov:sha256"]: {"@id": _["@id"], "trov:mimeType": _["trov:mimeType"]}
            for _ in self.data["@graph"][0]["trov:hasComposition"]["trov:hasArtifact"]
        }

    def update_composition(self, composition):
        self.data["@graph"][0]["trov:hasComposition"]["trov:hasArtifact"] = [
            {
                "@id": value["@id"],
                "trov:sha256": key,
                "trov:mimeType": value["trov:mimeType"],
                "@type": "trov:ResearchArtifact",
            }
            for key, value in composition.items()
        ]
        self.data["@graph"][0]["trov:hasComposition"]["trov:hasArtifact"].sort(
            key=lambda x: x["@id"],
        )
        hasArtifacts = self.data["@graph"][0]["trov:hasComposition"]["trov:hasArtifact"]
        composition_fingerprint = hashlib.sha256(
            "".join(sorted([art["trov:sha256"] for art in hasArtifacts])).encode(
                "utf-8"
            )
        ).hexdigest()
        self.data["@graph"][0]["trov:hasComposition"]["trov:hasFingerprint"] = {
            "@id": "fingerprint",
            "@type": "trov:CompositionFingerprint",
            "trov:sha256": composition_fingerprint,
        }

    def list_arrangements(self):
        return self.data["@graph"][0]["trov:hasArrangement"]

    def get_arrangement_path_hash_map(self, arrangement_id):
        """
        Get a mapping of paths to hashes for a specific arrangement.

        Args:
            arrangement_id: The ID of the arrangement (e.g., "arrangement/0")

        Returns:
            dict: A dictionary mapping file paths to their SHA256 hashes

        Raises:
            ValueError: If the arrangement ID does not exist
        """
        # Find the arrangement
        arrangement = None
        for arr in self.data["@graph"][0]["trov:hasArrangement"]:
            if arr["@id"] == arrangement_id:
                arrangement = arr
                break

        if arrangement is None:
            available = [
                arr["@id"] for arr in self.data["@graph"][0]["trov:hasArrangement"]
            ]
            raise ValueError(
                f"Arrangement '{arrangement_id}' not found. "
                f"Available arrangements: {available}"
            )

        # Build a composition lookup map (artifact id -> hash)
        composition_map = {
            artifact["@id"]: artifact["trov:sha256"]
            for artifact in self.data["@graph"][0]["trov:hasComposition"][
                "trov:hasArtifact"
            ]
        }

        # Build the path -> hash mapping
        path_hash_map = {}
        for locus in arrangement.get("trov:hasLocus", []):
            path = locus["trov:hasLocation"]
            artifact_id = locus["trov:hasArtifact"]["@id"]
            hash_value = composition_map.get(artifact_id)
            if hash_value:
                path_hash_map[path] = hash_value

        return path_hash_map

    def add_arrangement(
        self, directory, ignore_dirs=None, comment=None, resolve_symlinks=True
    ):
        if ignore_dirs is None:
            ignore_dirs = [".git"]

        if comment is None:
            comment = f"Scanned {directory}"

        hashes = self.sha256_for_directory(
            directory, ignore_dirs=ignore_dirs, resolve_symlinks=resolve_symlinks
        )
        composition = self.get_hash_mapping()
        i = self.get_composition_seq()

        magic_wrapper = magic.Magic(mime=True, uncompress=True)

        for filepath, hash_value in hashes.items():
            if hash_value in composition:
                continue
            if os.path.islink(filepath):
                mime_type = "inode/symlink"
            else:
                mime_type = (
                    magic_wrapper.from_file(filepath) or "application/octet-stream"
                )
            composition[hash_value] = {
                "@id": f"composition/1/artifact/{i}",
                "trov:mimeType": mime_type,
            }
            i += 1

        self.update_composition(composition)

        arrangement_id = f"arrangement/{self.get_arrangement_seq()}"
        arrangement = {
            "@id": arrangement_id,
            "@type": "trov:Artifact Arrangement",
            "rdfs:comment": comment,
            "trov:hasLocus": [],
        }
        i = 0
        directory = pathlib.Path(directory)
        for filepath, hash_value in hashes.items():
            arrangement["trov:hasLocus"].append(
                {
                    "@id": f"{arrangement_id}/locus/{i}",
                    "@type": "trov:ArtifactLocus",
                    "trov:hasArtifact": {"@id": composition[hash_value]["@id"]},
                    "trov:hasLocation": pathlib.Path(filepath)
                    .relative_to(directory)
                    .as_posix(),
                }
            )
            i += 1
        self.data["@graph"][0]["trov:hasArrangement"].append(arrangement)

    def save(self):
        with open(self.tro_filename, "w") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)

    @staticmethod
    def sha256_for_file(filepath, resolve_symlinks=True):
        sha256 = hashlib.sha256()
        if not os.path.isfile(filepath) or os.path.islink(filepath):
            return ""
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def sha256_for_zipfile(zipfilepath):
        hashes = {}
        with zipfile.ZipFile(zipfilepath, "r") as zf:
            for fileinfo in zf.infolist():
                sha256 = hashlib.sha256()
                with zf.open(fileinfo.filename) as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256.update(chunk)
                hashes[fileinfo.filename] = sha256.hexdigest()
        return hashes

    def sha256_for_directory(self, directory, ignore_dirs=None, resolve_symlinks=True):
        if ignore_dirs is None:
            ignore_dirs = [".git"]  # Default ignore list
        hashes = {}
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for filename in files:
                filepath = os.path.join(root, filename)
                hash_value = self.sha256_for_file(
                    filepath, resolve_symlinks=resolve_symlinks
                )
                hashes[filepath] = hash_value
        return hashes

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

            # Download the TSA certificate
            response = requests.get(
                "https://freetsa.org/files/tsa.crt", allow_redirects=True
            )
            tsacert_f.write(response.content)
            tsacert_f.flush()
            tsacert_f.seek(0)

            # Download the CA certificate
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

    def verify_replication_package(self, arrangement_id, package, subpath=None):
        files_missing_in_arrangement = []
        mismatched_hashes = []

        arrangement_map = self.get_arrangement_path_hash_map(arrangement_id)

        # Generator to yield (relative_filename, file_hash) tuples
        def iterate_package_files():
            if os.path.isdir(package):
                for root, dirs, files in os.walk(package):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        relative_filename = os.path.relpath(filepath, package)
                        file_hash = self.sha256_for_file(filepath)
                        yield relative_filename, file_hash
            else:
                with zipfile.ZipFile(package, "r") as zf:
                    for fileinfo in zf.infolist():
                        sha256 = hashlib.sha256()
                        with zf.open(fileinfo.filename) as f:
                            for chunk in iter(lambda: f.read(4096), b""):
                                sha256.update(chunk)
                        file_hash = sha256.hexdigest()
                        yield fileinfo.filename, file_hash

        for original_filename, file_hash in iterate_package_files():
            relative_filename = original_filename

            # Handle subpath filtering
            if subpath is not None:
                if not original_filename.startswith(subpath):
                    continue
                relative_filename = original_filename[len(subpath) :].lstrip("/")

            # Check if file exists in arrangement
            if relative_filename not in arrangement_map:
                files_missing_in_arrangement.append(relative_filename)

            # Verify hash
            expected_hash = arrangement_map.pop(relative_filename, None)
            if file_hash != expected_hash:
                mismatched_hashes.append((relative_filename, expected_hash, file_hash))

        dirty = (
            files_missing_in_arrangement
            or mismatched_hashes
            or len(arrangement_map) > 0
        )
        return files_missing_in_arrangement, mismatched_hashes, list(
            arrangement_map.keys()
        ), not dirty

    def add_performance(
        self,
        start_time,
        end_time,
        comment=None,
        accessed_arrangement=None,
        modified_arrangement=None,
        caps=None,
        extra_attributes=None,
    ):
        trp = {
            "@id": f"trp/{len(self.data['@graph'][0]['trov:hasPerformance'])}",
            "@type": "trov:TrustedResearchPerformance",
            "rdfs:comment": comment or "Some performance",
            "trov:wasConductedBy": {"@id": "trs"},
            "trov:hasPerformanceAttribute": [],
            "trov:startedAtTime": start_time.isoformat(),
            "trov:endedAtTime": end_time.isoformat(),
        }
        if extra_attributes and isinstance(extra_attributes, dict):
            trp.update(extra_attributes)

        available_arrangements = [
            _["@id"] for _ in self.data["@graph"][0]["trov:hasArrangement"]
        ]

        if accessed_arrangement:
            # check if the arrangement exists
            if accessed_arrangement not in available_arrangements:
                raise ValueError(
                    f"Arrangement {accessed_arrangement} does not exist. "
                    f"Available arrangements: {available_arrangements}"
                )
            trp["trov:accessedArrangement"] = {"@id": accessed_arrangement}

        if modified_arrangement:
            # check if the arrangement exists
            if modified_arrangement not in available_arrangements:
                raise ValueError(
                    f"Arrangement {modified_arrangement} does not exist. "
                    f"Available arrangements: {available_arrangements}"
                )
            trp["trov:contributedToArrangement"] = {"@id": modified_arrangement}

        trs_caps = {
            _["@type"]: _["@id"]
            for _ in self.data["@graph"][0]["trov:wasAssembledBy"]["trov:hasCapability"]
        }

        i = 0
        for cap in caps:
            assert cap in [TRPAttribute.RECORD_NETWORK, TRPAttribute.ISOLATION]
            assert caps_mapping[cap] in trs_caps
            trp["trov:hasPerformanceAttribute"].append(
                {
                    "@id": f"{trp['@id']}/attribute/{i}",
                    "@type": cap,
                    "trov:warrantedBy": {"@id": trs_caps[caps_mapping[cap]]},
                }
            )
            i += 1

        self.data["@graph"][0]["trov:hasPerformance"].append(trp)

    def generate_report(self, template, report):
        graph = self.data["@graph"][0]
        composition = {
            obj["@id"]: obj for obj in graph["trov:hasComposition"]["trov:hasArtifact"]
        }
        arrangements = {}
        for arr in self.data["@graph"][0]["trov:hasArrangement"]:
            artifacts = {
                obj["trov:hasLocation"]: {
                    "sha256": composition[obj["trov:hasArtifact"]["@id"]][
                        "trov:sha256"
                    ],
                    "creator": obj.get("schema:creator", "trs"),
                    "createdDate": obj.get("schema:createdDate", "None"),
                }
                for obj in sorted(
                    arr["trov:hasLocus"], key=lambda x: x["trov:hasLocation"]
                )
            }

            arrangements[arr["@id"]] = {
                "name": arr["rdfs:comment"],
                "artifacts": artifacts,
            }

        # Graphviz!
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

        # Detect changes between arrangements
        # Which files were added? Which files changed?
        # Which files were removed?
        keys = list(arrangements.keys())

        for n in reversed(range(1, len(keys))):
            for location in arrangements[keys[n]]["artifacts"]:
                if location in arrangements[keys[n - 1]]["artifacts"]:
                    if (
                        arrangements[keys[n]]["artifacts"][location]["sha256"]
                        != arrangements[keys[n - 1]]["artifacts"][location]["sha256"]
                    ):
                        arrangements[keys[n]]["artifacts"][location][
                            "status"
                        ] = "Changed"
                    else:
                        arrangements[keys[n]]["artifacts"][location][
                            "status"
                        ] = "Unchanged"
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
