# CTI exports (schema version 1.0)

Each run that creates an output directory writes `cape_cti_telemetry.json` and
`threat_intel_report.md`. Setup errors before a run directory exists print an error.
Failures after run creation produce a partial advisory with the failure status and
available identity. Tool errors, timeouts and unsupported inputs are not clean verdicts.

The Markdown advisory is deterministic and needs no model or network connection.
It contains five sections: executive triage, configurations, ATT&CK, dynamic telemetry,
and strings. Displayed values are escaped, limited to 2,000 characters and, for most
tables, 150 records. JSON retains the complete collected records, subject to the
analysis engine's documented collection limits. String ordering is a triage heuristic.

## JSON contract

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | `1.0`; consumers should reject unsupported major versions |
| `analysis` | object | Run status, timestamps, mode, core versions, retention policy and error when present |
| `sample` | object | Filename, size, MD5/SHA1/SHA256, entropy and available PE metadata |
| `classification` | object | CAPE YARA matches, reported families, and attribution status; attribution remains unconfirmed |
| `configurations` | array | Raw JSON-compatible parser dictionaries, parser/origin, candidate interpretation and references |
| `capabilities` | array | Full collected capa rule findings and references |
| `attack` | array | Technique ID, tactic, technique/subtechnique names and supporting evidence; deduplicated by ID and tactic |
| `behavior.emulated` | array | Speakeasy calls and available file/registry/network summaries |
| `behavior.cape` | array | Separately supplied Windows guest calls, processes and host/network observations |
| `strings` | array | FLOSS categories, recovered values, offsets when provided, and references |
| `engines` | array | Local engine and enrichment outcomes, versions when supplied, limits and execution metadata |
| `artifacts` | array | Artifact hashes, parent hashes where known, representation, outcome and retention information |
| `coverage` | object | Evidence counts and collection/analysis warnings |

Records retain evidence `id`, `source` (relative report path plus JSON pointer), and
`artifact_sha256`/`evidence_class` when available. `evidence.json` is the full normalized
inventory. Additional per-engine JSON remains the source of truth. Parser byte values
use the existing `{ "encoding": "hex", "value": "…" }` representation; no guessed
normalization of family-specific configuration keys is performed.

ATT&CK mappings come from capa rule metadata. They are explicitly static capabilities,
not proof that the behavior occurred. API return values and sequence/context remain
available. Empty arrays mean no collected finding, not absence of malicious behavior.

This is a project export schema, not STIX or a native MISP/OpenCTI import format.
Integrations must map validated indicators and evidence to the destination model.
Do not promote every recovered URL or string to a confirmed malicious indicator.

## Artifact retention

The container sets `output.retain_artifacts: false`. A private run directory beneath
`output.scratch_directory` (default `/tmp`) holds intermediate payloads and tool outputs.
After analysis and detection checks, an allowlist of text reports is exported with a
SHA256 manifest. Payloads, PCAP, imported binaries, and unrecognized worker files are
not exported. Scratch is cleaned on ordinary success, exceptions and handled interrupts;
container teardown removes its tmpfs after a forced termination. A killed host CLI may
leave scratch behind. Host `/tmp` is not necessarily tmpfs.

The retention flag describes normal pipeline file handling, not containment against a
compromised process. Reports still contain sample-derived strings, extracted keys,
configuration values and byte previews. Speakeasy memory snapshots are disabled and its
top-level compressed payload table is excluded from the report. This is not a universal
binary-content detector for arbitrary imported CAPE reports or parser dictionaries.

The host configuration retains artifacts by default for compatibility with evidence
collection. Use `--ephemeral-artifacts` to select report-only publication. To persist
container payloads intentionally, pass `--retain-artifacts` or change
`output.retain_artifacts` in the container configuration. `retained_after_run: false` marks collected artifact paths
that intentionally will not resolve in the exported run.

The [managed Windows/CAPE workflow](MANAGED-LAB.md) deliberately enables artifact
retention. It preserves raw CAPE evidence, the original input, logs and packet capture,
and retains the enrichment worker's generated/imported artifacts. It deletes the
disposable VM overlay and owned containers after collection, while keeping the clean
Windows base for later runs. Its lifecycle status is recorded in `managed_run.json`.

`tmpfs` may use swap; unmounting does not securely erase physical RAM. Compose limits
container swap by setting `memswap_limit` equal to `mem_limit`; effective enforcement
depends on the host. Use a dedicated analysis VM/host and appropriate host storage policy.
