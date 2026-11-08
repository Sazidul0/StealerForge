# Automation readiness and remaining gaps

Updated 4 November 2026. Managed provisioning is implemented; Windows installation
and the required benign monitoring validation are still in progress. See the
[managed workflow status](MANAGED-LAB.md) for the current deployment checks.

## Current verdict

The project supports automated static triage, optional native-PE emulation, bounded artifact processing, evidence reporting and optional LLM synthesis. Managed mode provisions a Windows/CAPE lab, uses disposable guests, retains evidence and recovers interrupted resources. Its external CAPE client remains available. Windows monitoring must pass the managed benign validation gate before real submissions are permitted; that end-to-end deployment check is still pending.

Use [the lab guide](README-LAB.md) to establish the Windows execution environment and [the container guide](README-CONTAINER.md) for the local pipeline. An API health response alone does not test snapshot restoration, telemetry, routing or containment.

## Defects repaired and checks added

- Deterministic CTI JSON and a five-section advisory now consolidate configuration, capa ATT&CK metadata, FLOSS strings and separately labeled emulated/CAPE telemetry, preserving evidence references.
- Container analysis now uses private scratch storage and publishes selected text reports only. Payload files are removed after analysis; cleanup is also exercised on failures. The host workflow can select this with `--ephemeral-artifacts`.
- Explicit x86/amd64 shellcode input is supported. Raw emulator mappings receive YARA/config scans but are marked unsupported for disassembly rather than being mistaken for disk-layout executables.
- `--preflight` now exposes configured engine/import/asset/storage/runtime checks. It is a point-in-time diagnostic, not proof of real-malware coverage or escape resistance.
- The installed community Vidar configuration parser required NumPy, which CAPE-parsers did not install. NumPy is now explicitly pinned in the engine requirements and lockfile. A synthetic configuration test verifies actual extraction through the bounded worker.
- Engine inventory previously listed parser filenames without checking whether their dependencies imported. It now checks RedLine, Vidar, Stealc, Lumma and explicitly configured parser names; failures produce partial status and appear in evidence. Other listed parser files remain an inventory, not proof of working support.
- Native math libraries are constrained to one thread per worker so importing NumPy does not unexpectedly multiply thread and virtual-memory use.
- Container tests check the effective non-root identity, zero effective capabilities, no-new-privileges, seccomp filtering, read-only root, loopback-only interfaces and absence of a mounted Docker socket. These checks exercise a harmless test process, not an escape attempt or a proof against kernel/parser vulnerabilities.

## What “simulated internet” currently means

| Layer | Present behavior | Limit |
|---|---|---|
| Compose | Runtime network disabled | Disconnection alone is not internet simulation |
| Speakeasy | Modeled DNS plus canned HTTP GET/socket response data | Only supported emulated APIs; no real browser, complete TLS/C2 service or full Windows networking |
| Windows CAPE guest with INetSim | Documented deployment plan | Not deployed or verified in this environment |

A benign direct test of Speakeasy's installed network model returned a synthetic DNS address, a 4,096-byte HTTP response and 12 bytes of socket response data without opening a real network connection. That establishes availability of the canned responses, not that any particular malware will accept them. Authentication, signed/encrypted responses, certificate checks and missing server stages can prevent further behavior.

Docker isolation depends on the host kernel, daemon and configuration. The writable output mount also remains a host interface and does not impose a total disk quota. Use a dedicated lab host/analysis VM and bounded storage for hostile inputs. No setting here can establish that malware cannot escape. [Docker security model](https://docs.docker.com/engine/security/)

For real Windows execution, configure an isolated guest network with simulated services, deny ordinary LAN/real-internet access including IPv6, restrict host services, remove guest sharing and verify restoration of a clean snapshot. Validate this with benign probes before submitting malware. INetSim routes traffic to fake services; selecting a route in the client does not provision or verify that service. [CAPE routing documentation](https://capev2.readthedocs.io/en/latest/installation/host/routing.html)

## Known coverage limits

- RedLine's parser is installed but has no matching family rule in the bundled CAPE YARA directory. Select `parser_names: [RedLine]` when an explicit attempt is desired; this is not an attribution verdict.
- Stealc, Vidar and Lumma have bundled signatures and parsers, but extraction depends on variant and unpacking state. Import checks and synthetic tests do not measure real-family detection rates.
- CryptBot has no dedicated configuration parser or family signature in this build. Generic triage and separately collected CAPE observations still apply.
- Local emulation skips .NET, does not implement a dedicated Lua analysis pipeline, and cannot universally unpack arbitrary protectors. Raw memory regions may be unsupported by capa/FLOSS.
- The CLI does not automatically decrypt/extract password-protected ZIPs. An archive scan does not analyze its encrypted member. Extraction requires a separate isolated, bounded workflow before supplying a payload or submitting it through the appropriate CAPE package.
- Full-memory forensics, EVTX/Sysmon correlation, Prefetch/Amcache/USN interpretation, packet decoding and automatic reverse engineering remain outside the implemented pipeline. Refer to the lab guide's evidence collection matrix.

## Supplied test archive

Only archive metadata and the archive's hash were read. The password was not used, the member was not decrypted, and no supplied malware was executed or emulated.

| Field | Observed value |
|---|---|
| Archive | `f7856dc0d9a74e8bccfc47b55b24fe170f568b87feb7a8cb9c54fd81eee0f68d.zip` |
| Archive SHA256 | `024d725478b401d4bdb77a962c0eb8d9618bc62e4d1b9cb98e299095d4d2db76` |
| Archive size | 153,443 bytes |
| Members | One encrypted `.exe`, ZIP method 99 |
| Declared member size | 329,216 bytes |

The hash-looking member name is untrusted metadata; it is not a verified payload hash or a family identification. Neither a family verdict nor a behavioral report can be derived from these observations.

## Highest-value next work

1. **Establish and validate CAPE/INetSim:** snapshot restoration, expected benign file/process/network telemetry, and verified denial of guest access to the management LAN/internet. This is the prerequisite for live automation.
2. **Use the preflight command:** `--preflight` checks selected engine versions/imports/assets, storage and required runtime controls. The local container preflight does not establish Windows lab readiness; validate that deployment separately.
3. **Broaden forensic collection:** retain EVTX/Sysmon, registry/file changes and memory captures, then correlate them with process IDs, timestamps and evidence sources.
4. **Add bounded encrypted-archive intake and a task queue:** size/depth limits, explicit member selection, input hashes, retry/resume behavior and per-run storage quotas, with execution restricted to the configured lab.
5. **Build family regression fixtures:** known expected configurations and behaviors, benign negatives and coverage metrics. Separate “parser imported,” “rule matched,” “config extracted” and “behavior observed.”

More LLM context is lower priority than reliable execution, collection and coverage measurement. AI remains optional.
