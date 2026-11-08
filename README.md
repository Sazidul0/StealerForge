# StealerForge

StealerForge combines local static analysis, optional automated unpacking/emulation, CAPE Sandbox evidence collection, and optional Claude synthesis to help analysts investigate Windows infostealers. It produces a source-linked evidence inventory, a bounded LLM dossier, an offline evidence report, and checks for analyst- or LLM-generated YARA/Sigma rules. AI is optional throughout collection and evidence reporting.

The local pipeline also writes **`cape_cti_telemetry.json`** and **`threat_intel_report.md`**
without an LLM. The advisory covers triage, configuration, ATT&CK, emulated telemetry,
and recovered strings. See the [CTI schema and retention contract](docs/CTI-SCHEMA.md).
The container analyzes intermediate payloads under `/tmp` and exports selected text
reports only; ordinary host runs preserve artifacts unless `--ephemeral-artifacts` is used.

> **📖 User guide: [sazidul-islam.gitbook.io/sazidul-islam-docs](https://sazidul-islam.gitbook.io/sazidul-islam-docs)**
>
> Start here if you're new. The guide covers malware analysis basics, step-by-step installation
> and host setup, running the managed Windows lab, reading the evidence, writing and checking
> threat intelligence reports, and a complete real-world case study (a Salat/WebRAT loader)
> with screenshots that you can reproduce yourself.

It is an analysis assistant, not a guarantee of complete unpacking, successful credential recovery, exact family attribution, or production-ready detections. A detailed report depends on the evidence actually collected. Optional local engines model native PE execution in Speakeasy; actual Windows execution uses the managed Windows/CAPE workflow or an external CAPE guest.

- [CAPE lab setup and artifact collection](docs/README-LAB.md): dedicated Linux host, Windows guest, simulated internet, API authentication, submission and retrieval.
- [Automated container setup](docs/README-CONTAINER.md): build, synthetic tests, UPX/Speakeasy/CAPE parsers/FLOSS/capa, outputs and limitations.
- [Readiness assessment and remaining gaps](docs/READINESS.md): repaired defects, actual simulation behavior, deployment prerequisites and next improvements.
- [Managed Windows/CAPE automation](docs/MANAGED-LAB.md): automatic provisioning, benign validation, disposable guests, retained evidence and recovery; includes current validation status.
- [Writing a CTI report with an AI agent](docs/AI-REPORT-GUIDE.md): for Claude Code, Codex and similar agents; report structure, evidence rules, ti2dac compatibility, reproduction, the `scripts/check_report.py` self-check and the styled PDF from `scripts/render_report_pdf.py` (saved to `output/`). A reference report and PDF are in [docs/examples/](docs/examples/).

Use the separate lab machine for real malware. Docker shares its host kernel and is not a guarantee that hostile inputs cannot affect the host.

## What is implemented

| Area | Behavior |
|---|---|
| Static triage | SHA256/SHA1/MD5, entropy, PE metadata, Rich header, TLS callback addresses, PDB paths, resource hashes, imports/exports, sections, overlay and signature information |
| Local YARA | Compiles the configured hunting rules before running; missing or invalid rules fail setup; scans have a timeout |
| Strings | Printable ASCII/UTF-16LE chunks with artifact offsets, priority selection, a configured count limit and omission counts |
| CAPE | Submit one task, poll with a monotonic deadline, resume an existing task, retrieve JSON, payloads, process dumps, dropped files and optional PCAP |
| Download integrity | SHA256 verification for report-listed binaries; streaming byte limits; partial-download cleanup; explicit failed/skipped/duplicate outcomes |
| Evidence | Stable IDs within each run, source file/JSON pointers, original API fields and normalized arguments; preserves status, return, thread, repeat count and order |
| Context selection | Prioritizes collection/crypto/injection/network candidates across processes, samples across the run rather than retaining only the beginning, records omissions and truncated previews |
| Offline reporting | Always writes a deterministic evidence report once evidence preparation completes; exports a prompt without claiming that an LLM report was generated |
| Claude | Counts the full request before synthesis, shrinks the dossier if necessary, reserves output capacity, streams the response and records stop reason/usage |
| Detection checks | YARA compilation and per-public-rule fixture matches; optional benign fixture checks; pySigma parsing including condition references |
| Optional enrichment | Runs separately installed capa/FLOSS executables with JSON output and timeouts; preserves their results and failures |
| Automated local engines | Optional bounded UPX attempts, PE/explicit shellcode emulation, bounded memory capture, CAPE YARA selection and installed configuration parsers |
| Provenance | Run state, tool versions, artifact collection outcomes and a SHA256 manifest of output files |

`pefile`/LIEF metadata does not replace disassembly. A crypto API call does not prove successful decryption. A connection does not prove that credentials were transmitted. The report prompt explicitly separates observed, inferred and unknown behavior and allows unknown attribution or no generated rules.

## Installation

For a full walkthrough (system packages, Docker access, KVM, the lab disk and your first run),
follow the [installation guide](https://sazidul-islam.gitbook.io/sazidul-islam-docs). The short version:

For automated Windows execution on a Linux host with KVM:

```bash
.venv/bin/python main.py --managed -f /path/to/sample.exe \
  --lab-storage '/media/you/LabDisk/StealerForge-Lab'
```

To keep your lab path out of every command, copy `config.local.example.yaml` to
`config.local.yaml` (ignored by git), edit it, and pass `-c config.local.yaml`.

First use builds the tools, installs Windows, and requires a successful benign CAPE
monitoring check. Each analysis keeps its evidence and removes its disposable guest
and containers. See the [managed guide](docs/MANAGED-LAB.md) for prerequisites,
configuration, output paths, and the end-to-end validation status.

For the complete optional container toolchain, see the [container guide](docs/README-CONTAINER.md). Once Docker/Compose are installed:

```bash
mkdir -p samples output
docker compose build analyze test
docker compose run --rm test
docker compose run --rm analyze --preflight
# On the dedicated lab host, after placing the input in samples/:
docker compose run --rm analyze -f /samples/sample.exe
```

The analysis service has no runtime network and exports evidence without calling an LLM. CAPE execution and API collection use the separate [lab workflow](docs/README-LAB.md).

Tested with Python 3.12 on Linux. Use Python 3.12 for the supplied pinned environment. Windows/macOS and other Python versions have not been validated here; native package wheels and optional tools may differ.

From the project directory, with [uv](https://docs.astral.sh/uv/):

```bash
uv venv .venv --python python3.12
uv pip install --python .venv/bin/python -r requirements.lock
source .venv/bin/activate
python main.py --check
```

Alternatively, with Python's venv and pip:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python main.py --check
```

`requirements.txt` specifies supported dependency ranges. `requirements.lock` pins the resolved runtime environment. `requirements-dev.lock` also includes the test tools. If a native wheel is unavailable, follow that dependency's platform installation requirements.

`python3 main.py --help` works before dependencies are installed. Other commands require the project environment. `--check` checks local configuration, dependency presence/versions and YARA compilation. It does not validate API credentials, a remote model, sandbox instrumentation or VM readiness.

## Configure the lab and credentials

Copy `config.yaml` to `config.local.yaml` if you want local overrides kept out of version control. Relative rules/output/tool paths are resolved beside the selected configuration file. The default config is located relative to `main.py`, so commands also work from other directories.

Set these values for your own CAPE deployment:

- `cape.base_url`: the actual API v2 base URL, including `/apiv2`.
- `cape.vm_tags`: tags that exist on your guest, or an empty string.
- `cape.route`: a route configured on the CAPE host. The default is `inetsim`.
- `cape.package`: optional analysis package, for samples needing a particular launch mode.
- `cape.options`: monitor options verified against your installed CAPE/capemon build.
- Time, file-size and collection limits suitable for the analysis.

The CLI does not provision CAPE, configure its hypervisor, seed browser profiles, or guarantee evasion resistance. Use a dedicated, isolated malware-analysis lab with synthetic browser/wallet/messaging data. INetSim can exercise some network paths, but it does not reproduce an arbitrary real C2 protocol; missing server responses can prevent later stages from running.

Read credentials into environment variables without putting literal secrets into shell history:

```bash
read -rsp 'CAPE API token: ' CAPE_API_TOKEN
export CAPE_API_TOKEN
read -rsp 'Anthropic API key: ' ANTHROPIC_API_KEY
export ANTHROPIC_API_KEY
```

The key environment names are configurable through `api_token_env` and `api_key_env`. Legacy `api_token` / `anthropic_api_key` YAML fields are supported; environment values take precedence. Placeholder keys are treated as absent. Keep credentials out of committed configuration.

Check the remote CAPE status endpoint without submitting a sample:

```bash
python main.py -c config.local.yaml --check-cape
```

CAPE must permit task submission/view, JSON report retrieval and any requested artifact downloads. An HTTP 200 API error or a failed binary hash check is recorded as a failure, not a retrieved payload.

The client follows current upstream API v2 routes:

```text
POST /tasks/create/file/
GET  /tasks/view/{task_id}/
GET  /tasks/get/report/{task_id}/json/
GET  /files/get/sha256/{sha256}/
GET  /tasks/get/pcap/{task_id}/
```

Your CAPE fork/version may differ. Inspect its own API documentation and test with a known lab fixture. Monitor flags alone do not guarantee plaintext crypto buffers, reconstructed imports, family configurations or complete unpacking.

## Run analyses

### Local static analysis and offline evidence report

```bash
python main.py -f /path/to/sample.exe --static-only --offline-llm
```

This performs no CAPE or LLM requests. The default configuration has `llm.use_api: false`; `--offline-llm` also explicitly overrides API mode in a custom config.

### Import an existing CAPE report and unpacked artifacts

```bash
python main.py -f /path/to/sample.exe \
  --cape-report /path/to/report.json \
  --artifact /path/to/unpacked_payload.bin \
  --artifact /path/to/dropped_file.bin \
  --offline-llm
```

`--skip-cape` is an alias for `--cape-report`; `--unpacked` is an alias for `--artifact`. These inputs are optional and repeatable. Imported artifacts are hashed and copied into the run directory. Their relationship to the sample must still be supported by analysis. The original input sample is analyzed in place and identified by hash; keep that sample in your own evidence store.

The raw imported report is preserved byte-for-byte. If it provides a target SHA256, that hash must match the supplied sample. If it does not, the report records that identity is unverified. Standard `CAPE` and legacy lowercase `cape` fields, direct/wrapped reports, and list/dictionary API arguments are supported. Reports without embedded API calls explicitly lose chronology coverage.

### Submit to CAPE

```bash
python main.py -c config.local.yaml -f /path/to/sample.exe --offline-llm
```

The sample is submitted to CAPE, not executed on the workstation. Report-listed payloads, process dumps and dropped files are combined and deduplicated. Binary downloads are limited by `max_artifacts` and `max_download_bytes`; every collection outcome is recorded. PCAP is preserved when enabled, but is not automatically decoded into exfiltrated secrets.

Submission POSTs are not retried automatically: a timeout can occur after CAPE accepted the task. Inspect CAPE before submitting again. Once a task ID is known, resume with:

```bash
python main.py -c config.local.yaml -f /path/to/sample.exe --task-id 123 --offline-llm
```

The task ID is saved as soon as submission succeeds. GETs have bounded retry counts and per-request timeouts. `max_wait_seconds` controls polling; an in-flight HTTP request/retry may finish after that polling deadline.

### Generate an LLM threat intelligence report

```bash
python main.py -f /path/to/sample.exe \
  --cape-report /path/to/report.json \
  --artifact /path/to/unpacked_payload.bin \
  --llm-api
```

This sends the selected dossier, including sample-derived strings and available telemetry, to Anthropic. API mode requires a real key and does not silently fall back to prompt export. The model defaults to `claude-sonnet-4-6`; model availability and limits must match your account. The old Claude 3.7 model is no longer the default.

The report is written for two readers: researchers and responders who need to understand and act on the
sample, and [ti2dac](../Multi-SIEM%20Sigma%20Rule/README.md), which reads the Markdown report and generates and
tests Sigma rules and SIEM queries per behaviour. The prompt requests these sections:

1. Key findings, with confidence and evidence IDs.
2. Sample and analysis context: identity, runtime, network conditions, process lifetime, coverage gaps.
3. Execution flow, with results and where/why execution stopped.
4. Attacker behaviours and techniques: one `### B<n>. Name (T<id>)` sub-section each, with status
   (observed, attempted-failed or static capability), a quotable procedure paragraph, telemetry and the
   detection opportunity.
5. Configuration, command and control.
6. Host artifacts and forensic footprint.
7. Mitigations and hardening, prioritised and tied to behaviours.
8. Hunting and response guidance.
9. Assessment, confidence and open questions.
10. Indicators of compromise, then `Appendix B: YARA rules`.

So that ti2dac can ingest the report unchanged, the prompt also requires a `TLP:` line (from `llm.report_tlp`,
default `clear`), environment-variable paths instead of the lab user's profile path, no incident-report wording
(which would switch ti2dac to incident mode), no single-line JSON objects (ti2dac would replay them as log events),
no Sigma (ti2dac writes and tests rules itself), and IOCs and YARA only in the two final sections, which ti2dac
strips before its AI step. It also lists the managed lab's own artefacts (agent traffic on 127.0.0.1:8000,
10.0.2.0/24, the renamed sample) so they are not reported as malware behaviour.

Feed the report to ti2dac with `ti2dac run Threat_Intel_and_SOC_Rules.md --threat-intel`.

The dossier has a hard **serialized character** ceiling, an estimated token budget for offline use, and exact API token-count preflight for API mode. The complete system/user input is counted; output tokens are reserved separately. If the minimum useful dossier still cannot fit, synthesis stops with an error. A larger context does not make missing evidence appear.

Prompt caching marks the stable system prompt; it does not promise a cache hit or cache the complete changing dossier. Clipboard copying is disabled unless `llm.copy_to_clipboard` is enabled in offline mode.

Output stopped by a token limit/refusal or another non-completion reason is saved as `Threat_Intel.partial.md`. Citation checks detect missing/unknown evidence IDs, but cannot establish whether a cited record actually supports the claim. Analyst review remains necessary.

### Validate a report produced in a web UI or by an analyst

```bash
python main.py -f /path/to/sample.exe \
  --cape-report /path/to/report.json \
  --artifact /path/to/unpacked_payload.bin \
  --report-markdown /path/to/analyst_report.md \
  --benign /path/to/known_clean_fixture.exe
```

`--report-markdown` bypasses LLM synthesis. Repeat `--benign` to add more known-clean fixtures. Evidence IDs are deterministic for identical evidence inputs and ordering; import the same sample/report/artifacts used to prepare the prompt. Changes to inputs or ordering can change IDs.

YARA blocks are compiled with includes disabled. Every public rule must match at least one supplied positive artifact; any match on a supplied benign fixture fails the checks. Helpers should be private rules. Missing fixtures and scan timeouts also fail checks. Compilation alone does not pass validation.

Sigma blocks are parsed with pySigma and their condition references resolved. This is **syntax validation only**: no SIEM backend conversion, event replay, telemetry availability check or detection-quality certification is performed. A file creation event does not establish that a browser database was read. Use a representative event dataset and the intended backend before deployment.

### Optional capa and FLOSS

The container supplies these tools and their rule/signature data. For a separate installation, set `enrichment.capa_path` / `enrichment.floss_path` to executable names or absolute paths, `enrichment.capa_rules_path` to your capa rules directory, and `enrichment.capa_signatures_path` to its library-signature directory. Each is invoked with JSON output, without a shell, on the input sample and collected/imported/generated artifacts. capa receives `-r` and `-s` when those directories are configured.

Results are saved under `enrichment/` and incorporated into evidence. Timeouts, invalid JSON and unavailable tools are recorded. On Linux, workers enforce per-file output, address-space and CPU limits as well as a wall-clock deadline; stdout/stderr and execution outcomes are retained. These integrations are disabled in the ordinary host configuration and enabled in the container configuration.

`--local-engines` additionally enables the optional preprocessing/emulation pipeline. See the [engine configuration guide](docs/README-CONTAINER.md#configuration-and-non-container-usage) for its separate dependencies. It can supplement either imported reports or live CAPE results. With `--static-only`, CAPE is disabled but explicitly enabled local emulation still runs. Emulated API calls, extracted configurations, static capabilities and actual CAPE observations remain distinguishable in evidence.

Raw code requires an explicit architecture: `--shellcode-arch x86` or
`--shellcode-arch amd64`. This enables local engines for the primary input only; no
architecture is guessed for collected regions. Raw emulator mappings still receive
YARA/config scans but are marked unsupported for disassembly until reconstructed or
explicitly supplied as code. `--preflight` checks configured tools, rule assets, storage,
and required container controls without analyzing a sample.

## Outputs and exit status

Every run uses a unique UTC timestamp plus random suffix under the configured output directory. `--output /path/to/runs` overrides the parent directory.

```text
output/<run>/
├── run_status.json                  # Run state, task ID, versions, warnings/errors
├── stage1_initial_static.json
├── raw_cape_report.json             # Original report; static-only uses an explicit stub
├── artifact_collection.json         # Download/import outcomes and provenance
├── artifacts/                      # Hash-named retrieved/imported files
├── dump.pcap                       # When requested and available
├── stage3_artifact_static.json
├── local_analysis.json             # Optional engine outcomes and results
├── engine_assets.json              # Pinned rules/tool provenance when configured
├── local_engines/                  # Worker logs/JSON; memory files only in persistent mode
├── enrichment.json
├── enrichment/                     # Optional tool output and stderr
├── evidence.json                   # Full normalized evidence and source pointers
├── cape_cti_telemetry.json           # Versioned CTI export with provenance and coverage
├── threat_intel_report.md           # Deterministic five-section analyst advisory
├── report_publication.json          # Ephemeral export status and omitted worker reports
├── stage4_maximized_dossier.json    # Exact compact JSON selected for the prompt
├── Evidence_Report.md              # Deterministic evidence inventory
├── claude_maximized_prompt.txt
├── llm_status.json
├── Threat_Intel_and_SOC_Rules.md    # Only for a completed/imported report
├── Threat_Intel.partial.md          # Instead, for incomplete model output
├── generated_rule_*.yar
├── generated_sigma_*.yml
├── stage6_rule_validation.json
└── manifest.json                   # SHA256/size of outputs; excludes itself
```

Not every optional file exists in every mode. Partial runs retain completed artifacts and a failure state. The manifest provides integrity hashes, not a cryptographically signed chain of custody. The original report remains the source of truth; normalized API arguments can differ in shape while retaining original values.

In ephemeral mode, payload/dump/PCAP files are excluded from publication; hashes,
parent relationships and `retained_after_run: false` remain in artifact records.
Report-only export still contains sample-derived strings, configuration keys and byte
previews. `/tmp` is tmpfs in Compose but may be disk-backed on a host; neither cleanup
nor tmpfs guarantees secure erasure. See the retention contract linked above.

| Exit | Meaning |
|---|---|
| `0` | Requested operation completed. May mean `evidence_ready` with prompt export only, or `report_ready_for_review`; does not mean complete malware coverage |
| `1` | Setup, input, collection/report preparation or API operation failed |
| `2` | Report/rule checks or partial local-engine/enrichment results require review, or invalid CLI arguments |
| `130` | Interrupted by the user |

`no_rules` is an explicit outcome, not a claim of validated detections. Optional artifact/enrichment failures appear in coverage warnings and do not necessarily abort the rest of an analysis. Requested engine/enrichment failures also produce review status. A completed LLM response can still need citation or detection review. Always inspect `run_status.json` and coverage before using the report.

## Coverage boundaries

- The pipeline focuses on Windows PE triage and CAPE-compatible reports. Non-PE artifacts receive hashes, printable strings and applicable YARA scans; there is no dedicated JavaScript, PowerShell, .NET, macOS or Linux reverse-engineering pipeline.
- It does not autonomously decompile code, solve arbitrary custom encryption, recover every configuration, or prove that a sandbox run exercised all branches.
- Browser App-Bound Encryption and application/OS versions matter. The prompt does not assume that every modern stealer follows the older DPAPI-only path.
- Prefetch, Amcache, filesystem journals, registry hive diffs, EVTX and full-memory forensic reconstruction are not automatically acquired or parsed. Collect them separately when the investigation requires persistent footprints.
- PCAP is retained, but encrypted network traffic is not automatically decrypted. CAPE JSON network fields are used only when available.
- Normalized evidence keeps embedded calls; dossier previews intentionally omit/truncate records and disclose the loss. Offline report tables also have explicit display limits.
- Local hunting rules are generic capability heuristics, not reliable family identifiers. Benign software can share imports, strings and high-entropy sections.

## Tests and maintenance

```bash
uv pip install --python .venv/bin/python -r requirements-dev.lock
.venv/bin/python -m pytest -q
.venv/bin/python main.py --check
```

The regression suite uses synthetic PE bytes, synthetic reports and mocked remote responses. It covers real local PE/YARA parsing, CAPE endpoints/argument formats, hash and size failures, evidence retention/budgeting, model completion handling, Sigma conditions, and offline CLI runs. No malware execution, live C2 interaction, sandbox detonation or paid API request is part of the tests.

The optional engine tests use installed packages when `STEALERFORGE_ENGINE_PYTHON` points to their interpreter (the container test service sets this automatically). Live CAPE connectivity, monitor coverage and actual model access still need verification in your environment. A useful lab acceptance test checks that a known sample/report yields its expected payload/configuration, process/file/network events, and source-backed conclusions; compare against analyst ground truth rather than report length.

## Project layout

```text
StealerForge/
├── README.md
├── docs/README-LAB.md
├── docs/README-CONTAINER.md
├── Dockerfile
├── compose.yaml
├── container/                      # Container config and pinned asset sources
├── scripts/fetch_assets.py
├── config.yaml
├── requirements.txt
├── requirements.lock
├── requirements-dev.txt
├── requirements-dev.lock
├── requirements-engines.txt
├── requirements-engines.lock
├── main.py
├── rules/local_stealer_hunting.yar
├── core/
│   ├── config.py
│   ├── static_engine.py
│   ├── cape_client.py
│   ├── evidence.py
│   ├── context_maximizer.py
│   ├── enrichment.py
│   ├── local_engines.py
│   ├── engine_worker.py
│   ├── process_runner.py
│   ├── reporting.py
│   ├── llm_intelligence.py
│   └── rule_validator.py
└── tests/
```

## Reference documentation

- [StealerForge user guide](https://sazidul-islam.gitbook.io/sazidul-islam-docs): how to set up and use this tool, and how to do the malware analysis around it.
- [CAPE API v2 routes](https://github.com/kevoreilly/CAPEv2/blob/master/web/apiv2/urls.py) and [analysis artifacts](https://capev2.readthedocs.io/en/latest/usage/results.html).
- [Anthropic token counting](https://platform.claude.com/docs/en/build-with-claude/token-counting) and [model lifecycle](https://platform.claude.com/docs/en/about-claude/model-deprecations).
- [Sigma tooling and backend concepts](https://sigmahq.io/docs/guide/getting-started.html).
- [capa](https://github.com/mandiant/capa) and [FLOSS](https://github.com/mandiant/flare-floss).
- [Chrome App-Bound Encryption background](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html).
