# Transparent Research Object utils

[![PyPI version](https://img.shields.io/pypi/v/tro_utils.svg)](https://pypi.python.org/pypi/tro-utils)
[![Zenodo](https://zenodo.org/badge/765298086.svg)](https://zenodo.org/doi/10.5281/zenodo.11130420)
[![Documentation Status](https://readthedocs.org/projects/tro-utils/badge/?version=latest)](https://tro-utils.readthedocs.io/en/latest/?version=latest)

This package provides a set of utilities for working with Transparent Research Objects (TROs). It is designed to be used in conjunction with the [TRO specification](https://transparency-certified.github.io/trace-specification/docs/specifications/tro/0.1/index.html).

**📚 [Read the Full Documentation](https://tro-utils.readthedocs.io/en/latest/?version=latest)**

It uses the `Click` library to define commands and options. Here's a summary of the main features:

1. **Global Options**: The script defines several global options that can be used with any command, such as `--declaration`, `--profile`, `--gpg-fingerprint`, `--gpg-passphrase`, `--tro-creator`, `--tro-creator-type`, `--tro-name`, and `--tro-description`. These options can be used to specify various parameters for the TRO.

2. **Commands**: The script defines several commands, each with its own set of options and arguments. The commands include:

   - `verify-timestamp`: Verifies the RFC 3161 timestamp and GPG signature on the TRO.

   - `verify-package`: Verifies a replication package (directory or `.zip`) against the hashes stored in an arrangement.

   - `arrangement`: Manages arrangements in the TRO. An arrangement is a snapshot of where files sat at one point in time; adding one records a location per file and registers any file the TRO has not seen before in the composition. Subcommands: `add` (scans a directory, or replays a pre-computed snapshot with `--from-snapshot`), `snapshot` (computes a reusable snapshot file from a directory without touching a TRO, so an expensive scan can be done once and shared across runs — see [Arrangement snapshots](https://tro-utils.readthedocs.io/en/latest/usage.html#arrangement-snapshots)) and `list` (lists available arrangements in the TRO).

   - `composition`: Manages compositions in the TRO. It has a subcommand `info` that gets info about the current composition.

   - `performance`: Manages performances in the TRO. It has a subcommand `add` that adds a performance to the TRO.

   - `sign`: Signs the TRO. This records the public half of the signing key as `trov:publicKey` in the declaration, saves the declaration, and then produces the signature and the RFC 3161 timestamp over it.

   - `report`: Generates a report of the TRO.

3. **TRO Interaction**: The script interacts with the TRO using the `TRO` class from the `tro_utils` module. It uses this class to create a new TRO, add arrangements and performances to the TRO, verify the TRO, and generate a report of the TRO.

4. **GPG is only used for signing**: `--gpg-fingerprint` and `--gpg-passphrase` are recorded but never resolved against a keyring until `sign` runs. Building, inspecting, reporting on and verifying a TRO therefore need no GPG key — and no `gpg` binary at all. As a consequence, `trov:publicKey` appears in the declaration only from `sign` onwards, and is by construction the public half of the key that produced the signature (a value supplied by a TRS profile acts as a default until then).

5. **The TRS is identified by a stable IRI**: the `@id` of the TRS a declaration defines must be an absolute IRI, or a compact IRI whose prefix is not `trov`, so that the same TRS carries the same identifier in every document that mentions it. A bare `"trs"` does not qualify — it resolves against whichever document happens to contain it. The identifier is taken from the profile's `@id`, else its `trov:url`, else a placeholder saying the TRS is unidentified; a non-conforming `@id` is reported rather than quietly replaced, and a declaration carrying one cannot be saved. Whatever the TRS ends up with is also what `trov:wasConductedBy` and the default `schema:creator` reference.

6. **`schema:creator` is a person or an organization**: it serialises as a `schema:Person` or `schema:Organization` node rather than a bare name, including for defaults. `--tro-creator` supplies the name and `--tro-creator-type` says which of the two it is (default: `organization`); with neither given, the TRO credits the TRS that assembled it, by the TRS's own `@id` and `schema:name`.

7. **Timestamps are timezone-aware**: `trov:startedAtTime`, `trov:endedAtTime` and `schema:dateCreated` always carry a UTC offset. A value given without one — `--start 2024-03-01T09:22:01`, or an offset-less timestamp in an older declaration — is read as local wall-clock time and stamped with the local offset, preserving the instant rather than relabelling it. Pass an explicit offset when the recording host and the reading host may sit in different zones.

8. **Declarations are reproducible**: artifacts and their locations are ordered by path, not by the order the filesystem happened to report them, so scanning the same tree twice — on two machines, or on two filesystems — yields the same artifact `@id`s and byte-identical output.

## Installation

### Pre-requisites
Before you begin, you need to have the following installed on your system:

- GPG (only needed to `sign` a TRO)
- OpenSSL
- Python 3.8+

You can do this by running the following commands:

```bash
$ sudo apt-get install gnupg openssl python3 python3-pip    # on Debian/Ubuntu
$ brew install gnupg openssl python3                        # on macOS with Homebrew
```

If you only consume TROs — building, inspecting, reporting or `verify-timestamp` —
GPG is not required; OpenSSL still is.

## Example Usage

Assumes that:

* this package is installed
* your GPG key is present (needed for the `sign` step only)
* `trs.jsonld` is available and defines TRS capabilities (see below for an example)

Example workflow:

```bash
$ cd /tmp
$ cat trs.jsonld
  {
    "@id": "http://127.0.0.1/",
    "rdfs:comment": "TRS that can monitor netowork accesses or provide Internet isolation",
    "trov:hasCapability": [
      {
        "@id": "trs/capability/1",
        "@type": "trov:CanRecordInternetAccess"
      },
      {
        "@id": "trs/capability/2",
        "@type": "trov:CanProvideInternetIsolation"
      }
    ],
    "trov:owner": "Kacper Kowalik",
    "trov:description": "My local system",
    "trov:contact": "root@dev.null",
    "trov:url": "http://127.0.0.1/",
    "trov:name": "shakuras",
    "schema:name": "shakuras"
  }
$ export GPG_FINGERPRINT=...
$ export GPG_PASSPHRASE=...
$ git clone https://github.com/transparency-certified/sample-trace-workflow /tmp/sample
# It's sufficient to pass the profile only once
$ tro-utils --declaration sample_tro.jsonld --profile trs.jsonld arrangement add /tmp/sample \
    -m "Before executing workflow" -i .git
  Loading profile from trs.jsonld
$ tro-utils --declaration sample_tro.jsonld arrangement list
  Arrangement(id=arrangement/0): Before executing workflow
$ pushd /tmp/sample && \
  docker build -t xarthisius/sample . && \
  ./run_locally.sh latest xarthisius && \
  popd
$ tro-utils --declaration sample_tro.jsonld arrangement add /tmp/sample \
    -m "After executing workflow" -i .git
$ tro-utils --declaration sample_tro.jsonld arrangement list
  Arrangement(id=arrangement/0): Before executing workflow
  Arrangement(id=arrangement/1): After executing workflow
$ tro-utils --declaration sample_tro.jsonld performance add \
  -m "My magic workflow" \
  -s 2024-03-01T09:22:01+00:00 \
  -e 2024-03-02T10:00:11+00:00 \
  -a trov:InternetIsolation \
  -a trov:InternetAccessRecording \
  -A arrangement/0 \
  -M arrangement/1
 $ tro-utils --declaration sample_tro.jsonld sign
 $ tro-utils --declaration sample_tro.jsonld verify-timestamp
   ...
   Verification: OK
 $ curl -LO https://raw.githubusercontent.com/craig-willis/trace-report/main/templates/tro.md.jinja2
 $ tro-utils --declaration sample_tro.jsonld report --template tro.md.jinja2 -o report.md
```

## Upgrading to 0.5.0

Declarations written by 0.4.x still load, but three things changed in what gets
written, and a fourth in what is accepted:

- **A TRS profile's `@id` is now honoured.** 0.4.x discarded it and wrote a bare
  `"trs"`; a profile that already declared a proper IRI silently lost it. If your
  profile states an `@id`, it must now conform (see feature 5 above) — and if it
  states none, the identifier comes from `trov:url`, which for most profiles is
  the same string you would have chosen anyway.
- **An existing declaration whose TRS `@id` is `"trs"` cannot be saved.** It
  loads fine, so reading, reporting and `verify-timestamp` keep working; writing
  it back needs the identifier corrected first:

  ```python
  tro = TransparentResearchObject.load("old.jsonld")
  tro.trs.trs_id = "https://example.org/trs"
  tro.save("old.jsonld")
  ```

- **`schema:creator` is a node, not a string**, so `tro.creator` is an `Agent`
  with a `.name`, and anything reading the serialised value as text (a report
  template, say) needs `["schema:name"]`.
- **Serialised output differs even when nothing else changed**: timestamps gain
  an offset and artifacts are path-ordered. Both change the bytes of a
  re-serialised declaration, which matters because a signature covers those
  bytes — re-saving a signed 0.4.x declaration invalidates its existing
  signature, so sign again afterwards.

## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [audreyr/cookiecutter-pypackage](https://github.com/audreyr/cookiecutter-pypackage) project template.
