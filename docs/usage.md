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
tro-utils arrangement list [-v]
```
Adds a directory snapshot as a new arrangement, or lists existing arrangements.

```
tro-utils composition info [-v]
```
Shows artifacts in the current composition with their MIME type and hash.

```
tro-utils performance add [-m COMMENT] [-s START] [-e END] [-a ATTRIBUTE] [-A ACCESSED] [-M CONTRIBUTED]
```
Records a `TrustedResearchPerformance` entry in the TRO.

```
tro-utils sign
```
GPG-signs the TRO declaration, writing a `.sig` file.

```
tro-utils report -t TEMPLATE -o OUTPUT
```
Renders a Jinja2 report template with an embedded workflow diagram.

---

## Python API

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

# Record a performance
from datetime import datetime
tro.add_performance(
    start=datetime(2024, 3, 1, 9, 22, 1),
    end=datetime(2024, 3, 2, 10, 0, 11),
    comment="My workflow run",
    attributes=["trov:InternetIsolation"],
    accessed_arrangement_id="arrangement/0",
    contributed_to_arrangement_id="arrangement/1",
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
│   └── PerformanceAttribute[]     performance.py
└── TROAttribute[]                 attribute.py
```

All model classes inherit from `TROVModel` and implement `to_jsonld()` / `from_jsonld()`.

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
