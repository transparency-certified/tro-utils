"""Main module."""
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

import gnupg
import magic
import requests
import rfc3161ng
from pyasn1.codec.der import encoder

GPG_HOME = os.environ.get("GPG_HOME")


class TRO:
    gpg_key_id = None
    gpg_passphrase = None
    basename = None
    profile = None

    def __init__(
        self, filepath=None, gpg_fingerprint=None, gpg_passphrase=None, profile=None
    ):
        if filepath is None:
            self.basename = "some_tro"
            self.dirname = "."
        else:
            self.basename = os.path.basename(filepath).rsplit(".")[0]
            self.dirname = os.path.dirname(filepath)

        if profile is not None and os.path.exists(profile):
            self.profile = json.load(open(profile))

        if not os.path.exists(self.tro_filename):
            self.data = {
                "@context": [
                    {
                        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                        "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
                        "trov": "https://w3id.org/trace/2023/05/trov#",
                    }
                ],
                "@graph": [
                    {
                        "@id": "tro",
                        "@type": "trov:TransparentResearchObject",
                        "trov:hasArrangement": [],
                        "trov:hasAttribute": [],
                        "trov:hasComposition": {
                            "@id": "composition/1",
                            "@type": "trov:ArtifactComposition",
                            "trov:hasArtifact": [],
                        },
                        "trov:hasPerformance": {
                            "@id": "trp/1",
                            "@type": "trov:TrustedResearchPerformance",
                            "trov:wasConductedBy": {"@id": "trs"},
                            "trov:hadPerformanceAttribute": [],
                        },
                        "trov:wasAssembledBy": {
                            "@id": "trs",
                            "@type": "trov:TrustedResearchSystem",
                            "trov:hasCapability": [],
                            "trov:publicKey": None,
                        },
                    },
                ],
            }
        else:
            self.data = json.load(open(self.tro_filename))
        self.gpg = gnupg.GPG(gnupghome=GPG_HOME, verbose=False)
        if gpg_fingerprint:
            self.gpg_key_id = self.gpg.list_keys().key_map[gpg_fingerprint]["keyid"]
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

    def get_composition(self):
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

    def scan_directory(self, directory, ignore_dirs=None, comment=None):
        if ignore_dirs is None:
            ignore_dirs = [".git"]

        if comment is None:
            comment = f"Scanned {directory}"

        hashes = self.sha256_for_directory(directory, ignore_dirs=ignore_dirs)
        composition = self.get_composition()
        i = self.get_composition_seq()

        magic_wrapper = magic.Magic(mime=True, uncompress=True)

        for filepath, hash_value in hashes.items():
            if hash_value in composition:
                continue
            composition[hash_value] = {
                "@id": f"composition/1/artifact/{i}",
                "trov:mimeType": magic_wrapper.from_file(filepath)
                or "application/octet-stream",
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
        if arrangement_id.endswith("0"):
            self.data["@graph"][0]["trov:hasPerformance"].update(
                {
                    "trov:accessedArrangement": {"@id": arrangement_id},
                    "trov:startedAtTime": datetime.datetime.now().isoformat(),
                }
            )
        else:
            self.data["@graph"][0]["trov:hasPerformance"].update(
                {
                    "trov:modifiedArrangement": {"@id": arrangement_id},
                    "trov:endedAtTime": datetime.datetime.now().isoformat(),
                }
            )

    def save(self):
        with open(self.tro_filename, "w") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)

    @staticmethod
    def sha256_for_file(filepath):
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def sha256_for_directory(self, directory, ignore_dirs=None):
        if ignore_dirs is None:
            ignore_dirs = [".git"]  # Default ignore list
        hashes = {}
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for filename in files:
                filepath = os.path.join(root, filename)
                hash_value = self.sha256_for_file(filepath)
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

    def get_timestamp(self):
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

    def verify_timestamp(self):
        """Verify that a run is valid and signed."""

        if os.path.exists(self.sig_filename):
            with open(self.sig_filename, "rb") as fp:
                trs_signature = fp.read()
        else:
            print("computing")
            trs_signature = str(self.trs_signature()).encode("utf-8")

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
