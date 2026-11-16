"""Main module — TRO facade.

The :class:`TRO` class is a thin facade that delegates data-model operations
to :class:`~tro_utils.models.TransparentResearchObject` while keeping
signing, timestamping, and report-generation logic here.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass, field

from jinja2 import Template
import requests
import rfc3161ng
import graphviz
from pyasn1.codec.der import encoder

from . import __version__
from .models import TransparentResearchObject
from .models.agent import ORGANIZATION, Agent
from .models.trs import TrustedResearchSystem
from .trs_keys import TRSKeyList, normalize_fingerprint

GPG_HOME = os.environ.get("GPG_HOME")

# A key gpg fetches by itself, from a key server or a URL in the signature,
# is found by the fingerprint the signer chose, so it vouches for nothing.
_VERIFY_OPTIONS = ["--no-auto-key-retrieve"]


def _kill_gpg_agent(gnupghome):
    """Stop the gpg-agent serving *gnupghome*, which would outlive its removal."""
    try:
        subprocess.run(
            ["gpgconf", "--homedir", gnupghome, "--kill", "all"],
            check=False,
            capture_output=True,
        )
    except FileNotFoundError:
        pass


@dataclass
class SignatureVerification:
    """Result of :meth:`TRO.verify_signature`."""

    valid: bool
    status: str
    fingerprint: str | None
    username: str | None = None
    trust: str | None = None
    #: Whether something other than the TRO vouches for the key: an expected
    #: fingerprint it matched, a keyring file it was found in, or at least
    #: marginal validity in the keyring. Mere presence in the keyring does not.
    trusted: bool = False
    used_embedded_key: bool = False
    embedded_key_matches: bool | None = None
    #: The keyring file the key was looked up in, if one was given.
    keyring: str | None = None
    #: Whether the key matched an expected fingerprint; ``None`` if none given.
    fingerprint_matches: bool | None = None
    #: The key's status in the key list, if one was given and lists it.
    listed_status: str | None = None
    #: Time of the TRO's trusted timestamp, when a key list needed it.
    timestamp: datetime.datetime | None = None
    #: Conditions that did not fail the verification but should be reported.
    warnings: list[str] = field(default_factory=list)

    @property
    def key_missing(self) -> bool:
        """``True`` when the signing key is not in the keyring used."""
        return self.status == "no public key"


class TRO:
    gpg_fingerprint = None
    gpg_key_id = None
    gpg_passphrase = None
    basename = None
    profile = None
    _gpg_obj = None

    def __init__(
        self,
        filepath=None,
        gpg_fingerprint=None,
        gpg_passphrase=None,
        profile=None,
        tro_creator=None,
        tro_creator_type=None,
        tro_name=None,
        tro_description=None,
        extra_context=None,
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
            # A bare name carries no type, so honour tro_creator_type and fall
            # back to an organization.  None lets the model credit the TRS.
            creator = None
            if tro_creator:
                creator = Agent(
                    name=tro_creator,
                    agent_type=tro_creator_type or ORGANIZATION,
                )
            self._model = TransparentResearchObject(
                creator=creator,
                name=tro_name or "Some TRO",
                description=tro_description or "Some description",
                trs=trs,
                created_with_name="tro-utils",
                created_with_version=__version__,
            )
        else:
            self._model = TransparentResearchObject.load(self.tro_filename)

        if extra_context:
            self._model.extra_context.update(extra_context)

        # GPG configuration is only recorded here; nothing touches the keyring
        # until a signature is actually produced. See _gpg() and
        # attach_public_key().
        if gpg_fingerprint:
            self.gpg_fingerprint = gpg_fingerprint
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

    def list_performances(self):
        """Return the performances as JSON-LD dicts, in insertion order.

        Unlike the serialised declaration, ``trov:accessedArrangement`` and
        ``trov:contributedToArrangement`` are always lists (possibly empty), so
        callers need not special-case a single binding.
        """
        performances = []
        for perf in self._model.performances:
            data = perf.to_jsonld()
            data["trov:accessedArrangement"] = [
                b.to_jsonld() for b in perf.accessed_arrangements
            ]
            data["trov:contributedToArrangement"] = [
                b.to_jsonld() for b in perf.contributed_to_arrangements
            ]
            performances.append(data)
        return performances

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

    def add_arrangement_from_snapshot(self, filepath, comment=None):
        self._model.add_arrangement_from_snapshot(filepath=filepath, comment=comment)

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

    def _gpg(self):
        """Return the GPG interface, constructing it on first use.

        Instantiating :class:`gnupg.GPG` spawns the ``gpg`` binary, so it is
        deferred until a key is actually needed. Creating, mutating, saving,
        reporting on and verifying a TRO therefore require neither the binary
        nor a keyring.
        """
        if self._gpg_obj is None:
            import gnupg

            self._gpg_obj = gnupg.GPG(gnupghome=GPG_HOME, verbose=False)
        return self._gpg_obj

    def _resolve_key_id(self):
        """Resolve the configured fingerprint against the local keyring."""
        if self.gpg_fingerprint is None:
            raise RuntimeError("GPG fingerprint was not provided")
        if self.gpg_key_id is None:
            try:
                self.gpg_key_id = (
                    self._gpg().list_keys().key_map[self.gpg_fingerprint]["keyid"]
                )
            except KeyError:
                raise RuntimeError(
                    f"GPG key {self.gpg_fingerprint} was not found in the keyring"
                ) from None
        return self.gpg_key_id

    def attach_public_key(self):
        """Record the public half of the signing key in the declaration.

        Called by :meth:`request_timestamp` before the declaration is hashed or
        signed, so that ``trov:publicKey`` is by construction the public half of
        the key that produced the signature. A value supplied by a TRS profile
        acts as a default until it is replaced here.
        """
        self._model.trs.public_key = self._gpg().export_keys(self._resolve_key_id())

    def trs_signature(self):
        if self.gpg_fingerprint is None:
            raise RuntimeError("GPG fingerprint was not provided")
        if self.gpg_passphrase is None:
            raise RuntimeError("GPG passphrase was not provided")
        signature = self._gpg().sign(
            json.dumps(self.data, indent=2, sort_keys=True),
            keyid=self._resolve_key_id(),
            passphrase=self.gpg_passphrase,
            detach=True,
        )
        # The timestamp covers the LF-terminated signature, as for save().
        with open(self.sig_filename, "w", newline="\n") as fp:
            fp.write(str(signature))
        return signature

    def request_timestamp(self):
        """Request a timestamp from a remote TSA and store the result in a file.

        The public key is attached and the declaration written out *before*
        anything is hashed, so that the signature and the timestamp both cover
        the declaration exactly as it ends up on disk. Injecting the key any
        later — inside :meth:`trs_signature`, say — would make every TRO fail
        its own :meth:`verify_timestamp`.
        """
        self.attach_public_key()
        self.save()
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

    def created_with_mismatch(self):
        """Explain why this TRO may not verify with the running tro-utils.

        tro-utils makes no backward-compatibility guarantee, so a TRO is only
        guaranteed to verify with the version recorded in ``trov:createdWith``.

        Returns:
            A human-readable message if the TRO was created by different
            software or a different tro-utils version, otherwise ``None``.
        """
        name = self._model.created_with_name
        version = self._model.created_with_version
        if name == "tro-utils" and version == __version__:
            return None
        if not name and not version:
            return (
                "The TRO does not record which software created it "
                "(no trov:createdWith); it may not verify with "
                f"tro-utils {__version__}."
            )
        created = " ".join(filter(None, [name or "unknown software", version]))
        msg = (
            f"The TRO was created with {created}, but this is "
            f"tro-utils {__version__}."
        )
        if name == "tro-utils" and version:
            msg += f" Verify it with: pip install tro-utils=={version}"
        return msg

    def verify_timestamp(self, quiet=False):
        """Verify that a run is valid and signed.

        Args:
            quiet: Don't pass on what openssl prints.
        """

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
            try:
                if quiet:
                    subprocess.check_call(
                        args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                else:
                    subprocess.check_call(args)
            except subprocess.CalledProcessError as err:
                mismatch = self.created_with_mismatch()
                if mismatch is None:
                    raise
                raise RuntimeError(
                    f"Timestamp verification failed. {mismatch}"
                ) from err

    def timestamp_time(self):
        """Return the time in the TRO's timestamp, without verifying it."""
        with open(self.tsr_filename, "rb") as fp:
            response = rfc3161ng.decode_timestamp_response(fp.read())
        return rfc3161ng.get_timestamp(response.time_stamp_token, naive=False)

    def verify_signature(
        self,
        use_embedded_key=False,
        gnupghome=None,
        keyring=None,
        fingerprints=None,
        trs_keys=None,
    ):
        """Verify the TRS signature against the declaration as stored on disk.

        The signing key is looked up in the verifier's keyring: tro-utils does
        not decide how a TRS key comes to be trusted. The ``trov:publicKey``
        embedded in the TRO is only attested by the TRO itself, so it is used
        for verification only when explicitly requested.

        Args:
            use_embedded_key: Verify with a throwaway keyring holding only the
                key embedded in the TRO instead of the verifier's keyring.
            gnupghome: GnuPG home of the keyring to use; defaults to
                ``GPG_HOME`` or GnuPG's own default.
            keyring: A key file (armored or binary) to verify with instead,
                through a throwaway keyring holding only the keys in it.
            fingerprints: Fingerprints the signing key is expected to have,
                e.g. as published by the TRS. A signature by any other key is
                reported as invalid.
            trs_keys: A key list (path or :class:`TRSKeyList`) saying which
                keys the TRS signed with and when. The key is then judged by
                the list at the time of the TRO's trusted timestamp, which is
                verified too, instead of by its current OpenPGP state. Unless
                ``gnupghome`` or ``keyring`` is given, the key embedded in
                the TRO is used, since the list vouches for its fingerprint.

        Returns:
            A :class:`SignatureVerification`.
        """
        import gnupg

        if use_embedded_key + bool(gnupghome) + bool(keyring) > 1:
            raise ValueError(
                "use_embedded_key, gnupghome and keyring are mutually exclusive"
            )
        expected = {normalize_fingerprint(fp) for fp in fingerprints or ()}
        key_list = None
        if trs_keys is not None:
            key_list = (
                trs_keys
                if isinstance(trs_keys, TRSKeyList)
                else TRSKeyList.load(trs_keys)
            )
            if not gnupghome and not keyring:
                use_embedded_key = True
        if not os.path.exists(self.sig_filename):
            raise RuntimeError("Signature file does not exist")
        with open(self.tro_filename, "rb") as fp:
            declaration = fp.read()
        public_key = self._model.trs.public_key

        if use_embedded_key and not public_key:
            raise RuntimeError("The TRO does not embed a public key")

        throwaway = use_embedded_key or keyring is not None
        with tempfile.TemporaryDirectory() as tmp_home:
            try:
                if throwaway:
                    gpg = gnupg.GPG(gnupghome=tmp_home, options=_VERIFY_OPTIONS)
                    imported = (
                        gpg.import_keys(public_key)
                        if use_embedded_key
                        else gpg.import_keys_file(keyring)
                    )
                    if keyring is not None and not imported.fingerprints:
                        raise RuntimeError(f"No public keys found in {keyring}")
                else:
                    gpg = gnupg.GPG(
                        gnupghome=gnupghome or GPG_HOME, options=_VERIFY_OPTIONS
                    )

                result = gpg.verify_data(self.sig_filename, declaration)
                embedded = set()
                if public_key:
                    for key in gpg.scan_keys_mem(public_key):
                        embedded.add(key["fingerprint"])
                        embedded.update(s[2] for s in key.get("subkeys", []) if s[2])
            finally:
                if throwaway:
                    _kill_gpg_agent(tmp_home)

        fingerprint = (
            getattr(result, "pubkey_fingerprint", None)
            or result.fingerprint
            or result.key_id
        )
        # gpg reports VALIDSIG after EXPKEYSIG/REVKEYSIG, which overwrites
        # status with "signature valid"; key_status keeps the reason.
        status = result.key_status or result.status or "signature error"
        valid = bool(result.valid)
        # Before GnuPG 2.2.7 a missing key is reported by key ID only, which is
        # the tail of its fingerprint.
        signer = {result.fingerprint, fingerprint} - {None}

        warnings = []
        listed = None
        signed_at = None
        # VALIDSIG, i.e. the signature is cryptographically correct, whatever
        # gpg thinks of the key's expiry or revocation today.
        if key_list is not None and result.status == "signature valid":
            if os.path.exists(self.tsr_filename):
                try:
                    self.verify_timestamp(quiet=True)
                except subprocess.CalledProcessError as err:
                    raise RuntimeError(
                        "Timestamp verification failed, so the time of signing "
                        "is unknown"
                    ) from err
                signed_at = self.timestamp_time()
            trs_id = self._model.trs.trs_id
            listed_keys = key_list.keys_for(trs_id)
            listed = next(
                (k for k in listed_keys or () if k.fingerprint in signer), None
            )
            if listed_keys is None:
                valid = False
                status = f"the key list has no TRS with @id {trs_id}"
            elif listed is None:
                valid = False
                status = f"the signing key is not listed for {trs_id}"
            else:
                valid, message = listed.check(signed_at)
                if not valid:
                    status = message
                else:
                    status = "signature valid"
                    if message:
                        warnings.append(message)
                    if result.key_status:
                        warnings.append(
                            f"GnuPG reports: {result.key_status}; the key was "
                            "judged by the key list instead"
                        )
        if result.trust_level == result.TRUST_NEVER:
            valid = False
            status = "signing key is marked as never trusted"
        # The primary key or the subkey that made the signature may be named.
        fingerprint_matches = bool(signer & expected) if expected else None
        if valid and fingerprint_matches is False:
            valid = False
            status = "signing key does not have the expected fingerprint"
        return SignatureVerification(
            valid=valid,
            status=status,
            fingerprint=fingerprint,
            username=result.username,
            trust=result.trust_text if valid else None,
            trusted=valid
            and (
                fingerprint_matches is True
                or listed is not None
                or keyring is not None
                or (
                    not use_embedded_key
                    and result.trust_level is not None
                    and result.trust_level >= result.TRUST_MARGINAL
                )
            ),
            used_embedded_key=use_embedded_key,
            keyring=keyring,
            fingerprint_matches=fingerprint_matches,
            listed_status=listed.status if listed is not None else None,
            timestamp=signed_at,
            warnings=warnings,
            embedded_key_matches=(
                any(fp.endswith(s) for fp in embedded for s in signer)
                if embedded
                else None
            ),
        )

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
        accessed_arrangement=None,  # str | (str, str|None) | list[...] | None
        modified_arrangement=None,  # str | (str, str|None) | list[...] | None
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
            for ref in perf.accessed_arrangements:
                dot.edge(arrangements[ref.arrangement_id]["name"], perf.comment)
            for ref in perf.contributed_to_arrangements:
                dot.edge(perf.comment, arrangements[ref.arrangement_id]["name"])

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
                    "accessed": [
                        arrangements[ref.arrangement_id]["name"]
                        for ref in perf.accessed_arrangements
                    ],
                    "contributed": [
                        arrangements[ref.arrangement_id]["name"]
                        for ref in perf.contributed_to_arrangements
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
