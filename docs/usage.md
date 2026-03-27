# Usage

## CLI

The `tro-utils` command-line tool is the primary interface for managing TROs.

### Global options

These options (or equivalent environment variables) apply to every command:

| Option | Env var | Description |
|---|---|---|
| `--declaration PATH` | | Path to the `.jsonld` TRO file |
| `--profile PATH` | `TRS_PROFILE` | Path to the TRS profile JSON |
| `--gpg-fingerprint KEY` | `GPG_FINGERPRINT` | GPG key fingerprint for signing |
| `--gpg-passphrase PASS` | `GPG_PASSPHRASE` | GPG key passphrase |
| `--tro-creator TEXT` | | Creator field for a new TRO |
| `--tro-name TEXT` | | Name field for a new TRO |
| `--tro-description TEXT` | | Description field for a new TRO |

### Commands

```
tro-utils verify-timestamp <declaration>
```
Verifies the RFC 3161 timestamp and GPG signature on the TRO.

```
tro-utils verify-package <declaration> <package> [-a ARRANGEMENT] [-s SUBPATH] [-v]
```
Verifies a replication package (directory or `.zip`) against the hashes stored in an arrangement.

```
tro-utils arrangement add <directory> [-m COMMENT] [-i IGNORE]
tro-utils arrangement add --from-snapshot <snapshot.jsonld> [-m COMMENT]
tro-utils arrangement snapshot <directory> -o <snapshot.jsonld> [-m COMMENT] [-i IGNORE]
tro-utils arrangement list [-v]
```
Adds a directory snapshot as a new arrangement, lists existing arrangements, or computes a
reusable arrangement snapshot file without a TRO (see [Arrangement snapshots](#arrangement-snapshots)).

```
tro-utils composition info [-v]
```
Shows artifacts in the current composition with their MIME type and hash.

```
tro-utils performance add [-m COMMENT] [-s START] [-e END] [-a ATTRIBUTE] [-A ACCESSED] [-M CONTRIBUTED]
```
Records a `TrustedResearchPerformance` entry in the TRO.
`-A` and `-M` can be repeated to reference multiple input or output arrangements:

```bash
tro-utils --declaration my.jsonld performance add \
  -m "Processing run" \
  -A arrangement/0 -A arrangement/1 \
  -M arrangement/2
```

```
tro-utils sign
```
GPG-signs the TRO declaration, writing a `.sig` file.

```
tro-utils report -t TEMPLATE -o OUTPUT
```
Renders a Jinja2 report template with an embedded workflow diagram.

---

## Arrangement snapshots

Scanning a large directory is expensive. `arrangement snapshot` decouples the scan from the TRO
creation step: compute the snapshot once and reuse it across multiple TROs or workflow runs.

### Compute a snapshot (no TRO required)

```bash
tro-utils arrangement snapshot /mnt/large-dataset \
  -m "Reference dataset v1.2" \
  -o dataset-v1.2.jsonld
```

This produces a self-contained JSON-LD file that records every file path and its SHA-256 hash,
along with the MIME type of each artifact. No TRO declaration file is needed.

### Reuse a snapshot when building a TRO

```bash
# Use the pre-computed snapshot instead of re-scanning
tro-utils --declaration my.jsonld arrangement add --from-snapshot dataset-v1.2.jsonld

# Optionally override the comment stored in the snapshot
tro-utils --declaration my.jsonld arrangement add \
  --from-snapshot dataset-v1.2.jsonld \
  -m "Static data mount"
```

Artifacts already present in the TRO composition are matched by content hash — no duplicates are
ever inserted, even if the same file appears in multiple snapshots or live arrangements.

---

## Multiple accessed / contributed arrangements

A `TrustedResearchPerformance` can reference more than one input (accessed) or output (contributed)
arrangement. This models workflows that merge several data sources or produce several outputs.

### CLI

Repeat `-A` / `-M` as many times as needed:

```bash
tro-utils --declaration my.jsonld performance add \
  -m "Merge and process" \
  -A arrangement/0 \
  -A arrangement/1 \
  -M arrangement/2
```

When a single arrangement is provided the JSON-LD value is a plain object; when multiple are
provided it becomes a list — both forms are handled transparently on load.

### Python API

```python
tro.add_performance(
    start_time=start,
    end_time=end,
    comment="Merge and process",
    accessed_arrangement=["arrangement/0", "arrangement/1"],  # list accepted
    modified_arrangement="arrangement/2",                     # single string also accepted
    attrs=[TRPAttribute.NET_ISOLATION],
)
```

The `accessed_arrangement` and `modified_arrangement` parameters accept a single `str`,
a `(arrangement_id, mount_path)` tuple, a list of either, or `None`.

---

## Mount paths and `ArrangementBinding`

The same arrangement can be mounted at different paths in different performances (e.g.
`/input` in one run and `/output` in another).  To represent this unambiguously in RDF,
each reference is wrapped in an intermediate `trov:ArrangementBinding` object that ties the
arrangement, the mount path, and the performance together.

```json
"trov:accessedArrangement": [
  {
    "@id": "trp/0/binding/0",
    "@type": "trov:ArrangementBinding",
    "trov:arrangement": { "@id": "arrangement/0" },
    "trov:boundTo": "/mnt/input"
  }
]
```

Binding IDs are generated automatically when you call `add_performance`.
The `boundTo` field is optional — omit it when the path is not meaningful.

### CLI — `ARRANGEMENT_ID:MOUNT_PATH` syntax

Supply a mount path by separating the arrangement ID and path with `:`:

```bash
tro-utils --declaration my.jsonld performance add \
  --start 2024-01-01T10:00:00 \
  --end   2024-01-01T11:00:00 \
  -A arrangement/0:/mnt/input \
  -A arrangement/1 \
  -M arrangement/2:/mnt/output
```

Entries without a `:` are plain arrangement IDs (no mount path recorded).  The two forms
can be mixed freely in a single command.

### Python API

`add_performance` accepts each arrangement as either a plain `str` (no mount path)
or a `(arrangement_id, mount_path)` tuple:

```python
tro.add_performance(
    start_time=start,
    end_time=end,
    comment="Containerised run",
    accessed_arrangement=[
        ("arrangement/0", "/mnt/input"),  # tuple: (id, boundTo path)
        "arrangement/1",                  # plain string: no path
    ],
    modified_arrangement=("arrangement/2", "/mnt/output"),
    attrs=[TRPAttribute.NET_ISOLATION],
)
```

A single value or a list is accepted for both parameters.

The resolved `ArrangementBinding` objects are stored on
`TrustedResearchPerformance.accessed_arrangements` and
`TrustedResearchPerformance.contributed_to_arrangements`:

```python
for binding in perf.accessed_arrangements:
    print(binding.binding_id)       # e.g. "trp/0/binding/0"
    print(binding.arrangement_id)   # e.g. "arrangement/0"
    print(binding.path)             # e.g. "/mnt/input"  (or None)
```

---

### `TRO` — high-level facade

`tro_utils.tro_utils.TRO` is the recommended entry point for programmatic use.
It wraps `TransparentResearchObject` and adds signing, timestamping, and report generation.

```python
from tro_utils.tro_utils import TRO

# Create or load a TRO
tro = TRO(
    filepath="sample_tro.jsonld",
    gpg_fingerprint="ABCD1234...",
    gpg_passphrase="secret",
    profile="trs.jsonld",
    tro_creator="Alice",
    tro_name="My TRO",
    tro_description="A sample transparent research object",
)

# Add an arrangement (scans a directory)
tro.add_arrangement("/path/to/workdir", comment="Before workflow", ignore=[".git"])

# Or load a pre-computed snapshot (avoids rescanning an expensive directory)
tro.add_arrangement_from_snapshot("/path/to/dataset.jsonld", comment="Static mount")

# Record a performance
from datetime import datetime
tro.add_performance(
    start_time=datetime(2024, 3, 1, 9, 22, 1),
    end_time=datetime(2024, 3, 2, 10, 0, 11),
    comment="My workflow run",
    attrs=["trov:InternetIsolation"],
    accessed_arrangement="arrangement/0",   # str | (id, path) tuple | list | None
    modified_arrangement="arrangement/1",   # str | (id, path) tuple | list | None
)

# Save, sign, and timestamp
tro.save()
tro.trs_signature()
tro.request_timestamp()
tro.verify_timestamp()

# Verify a replication package
result = tro.verify_replication_package(
    arrangement_id="arrangement/1",
    package="/path/to/package.zip",
    subpath=None,
)
print(result.is_valid)          # True / False
print(result.mismatched_hashes) # list of (path, expected, actual) tuples

# Render a report
tro.generate_report(template="tro.md.jinja2", report="report.md")
```

#### Key properties

| Property | Returns | Description |
|---|---|---|
| `tro_filename` | `str` | Path to the `.jsonld` file |
| `sig_filename` | `str` | Path to the `.sig` file |
| `tsr_filename` | `str` | Path to the `.tsr` file |
| `data` | `dict` | Full JSON-LD representation (calls `to_jsonld()`) |

---

### `TransparentResearchObject` — data model

`tro_utils.models.TransparentResearchObject` is the root data-model class.
Use it directly when you need fine-grained control or are building tooling on top of the model.

```python
from tro_utils.models import TransparentResearchObject

# Load an existing TRO
tro = TransparentResearchObject.load("sample_tro.jsonld")

# Inspect structure
print(tro.name, tro.description)
print(tro.composition.artifacts)
for arr in tro.arrangements:
    print(arr.arrangement_id, arr.comment)
for perf in tro.performances:
    print(perf.performance_id, perf.started_at, perf.ended_at)

# Save
tro.save("output.jsonld")
```

#### Model hierarchy

```
TransparentResearchObject          tro.py
├── TrustedResearchSystem          trs.py
│   └── TRSCapability[]            trs.py
├── TimeStampingAuthority          tsa.py   (optional)
├── ArtifactComposition            composition.py
│   ├── ResearchArtifact[]         artifact.py
│   │   └── HashValue              hash_value.py
│   └── CompositionFingerprint     composition.py
├── ArtifactArrangement[]          arrangement.py
│   └── ArtifactLocation[]         arrangement.py
├── TrustedResearchPerformance[]   performance.py
│   ├── ArrangementBinding[]       performance.py  (accessed_arrangements)
│   ├── ArrangementBinding[]       performance.py  (contributed_to_arrangements)
│   └── PerformanceAttribute[]     performance.py
└── TROAttribute[]                 attribute.py
```

All model classes inherit from `TROVModel` and implement `to_jsonld()` / `from_jsonld()`.

`ArtifactArrangement` also supports standalone snapshot serialisation:

```python
from tro_utils.models import ArtifactArrangement, ArtifactComposition

# Compute and persist a snapshot (no TRO needed)
comp = ArtifactComposition()
arr = ArtifactArrangement.from_directory(
    "/mnt/large-dataset", comp, arrangement_id="arrangement/0", comment="Dataset v1.2"
)
arr.save_snapshot("dataset-v1.2.jsonld", comp)

# Later — merge the snapshot into any TRO's composition
tro_model = TransparentResearchObject.load("my.jsonld")
tro_model.add_arrangement_from_snapshot("dataset-v1.2.jsonld")
tro_model.save("my.jsonld")
```

---

### Enums

`tro_utils.TROVCapability` maps capability names to `trov:Can*` JSON-LD types.
`tro_utils.TRPAttribute` maps the same names to `trov:*` performance-attribute types.
Use `TROVCapability.translate(trp_member)` to convert between the two.

```python
from tro_utils import TROVCapability, TRPAttribute

cap = TROVCapability.NET_ISOLATION        # "trov:CanProvideInternetIsolation"
attr = TRPAttribute.NET_ISOLATION         # "trov:InternetIsolation"
assert TROVCapability.translate(attr) == cap
```

Available enum keys: `RECORD_NETWORK`, `NET_ISOLATION`, `ENV_ISOLATION`, `NON_INTERACTIVE`,
`EXCLUDE_INPUT`, `EXCLUDE_OUTPUT`, `ALL_DATA_INCLUDED`, `REQUIRE_INPUT_DATA`,
`REQUIRE_LOCAL_DATA`, `DATA_PERSIST`, `OUTPUT_INCLUDED`, `CODE_INCLUDED`,
`SOFTWARE_RECORD`, `NET_ACCESS`, `MACHINE_ENFORCEMENT`.

---

### `ReplicationPackage`

```python
from tro_utils.replication_package import ReplicationPackage

result = ReplicationPackage.verify(
    arrangement=tro.arrangements[1],
    composition=tro.composition,
    package="/path/to/package",   # directory or .zip
    subpath=None,
)

if not result.is_valid:
    print("Missing in arrangement:", result.files_missing_in_arrangement)
    print("Mismatched hashes:", result.mismatched_hashes)
    print("Missing in package:", result.files_missing_in_package)
```
