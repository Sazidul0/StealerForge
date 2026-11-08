# Automated Windows/CAPE analysis

The managed workflow provisions a Windows VM, runs one CAPE task, retains the
collected data, enriches it with the offline analysis toolchain, and removes the
run's containers and disposable VM disk. The clean base image and Docker images
are cached so Windows does not need to be reinstalled for every sample.

Windows media comes only from the fixed Microsoft HTTPS URL. The host downloader
resumes interrupted transfers, keeps completed media outside the launcher's temporary
directory, and verifies a saved SHA256 before reuse. It checks the expected release
size; the saved hash records download integrity and is not a Microsoft-published
signature. Download failures do not fall back to third-party Windows mirrors.

**Validation status (2026-11-04):** the test suite passes (132 passed, 2 skipped). A new base
(Windows 10 Enterprise evaluation, persona "DESKTOP-8JPXX5B", Chrome 157, Edge 156, Firefox 159,
Sysmon) was provisioned unattended with all 13 provisioning steps passing, Defender disabled
offline, and validated: monitored file write, HTTPS through the simulator with certificate checks,
Sysmon events, Defender stopped, Sysmon running. On the RedLine test sample
(`f7856dc0…0f68d`), pass 1 quit early as before; the adaptive re-run created the developer folder
and RedLine then ran its full collection: Chrome/Edge Login Data, Web Data, cookies and Local
State, Firefox logins/key4 (loading Firefox's nss3/softokn3/freebl3), wallet extensions, desktop
wallets, Telegram, Discord, Steam, FileZilla/VPN/Pidgin and documents, followed by WMI profiling
and a retry loop to its loopback C2 (127.0.0.1:1912). Being a test build with a loopback C2, it
sent nothing out, so no canary appeared in captures. One of three RedLine pass-2 runs got no API
calls (a CAPE monitor hang at start-up); re-run when a report shows a live process with no calls.
The CLI refuses malware submission until its benign monitoring check succeeds.

## Run it

From the Linux host, with Docker access, KVM enabled, and the project Python
3.12 environment installed:

```bash
.venv/bin/python main.py --managed -f /path/to/sample.exe \
  --lab-storage '/media/you/LabDisk/StealerForge-Lab'
```

That command handles first-time setup as well as later analysis runs. Downloads
and installation can make the first run considerably longer. Subsequent runs
create a fresh QCOW2 overlay on the cached base and boot it automatically.
No CAPE API service, libvirt service, or manually started Windows desktop is needed.

To avoid repeating the path, put it in a `config.local.yaml` beside `config.yaml` (git ignores
this file; copy `config.local.example.yaml` to start):

```bash
.venv/bin/python main.py -c config.local.yaml --managed -f /path/to/sample.exe
```

If a sample needs a particular folder before it continues (for example a developer
path it writes logs to), create it in the guest before the sample starts:

```bash
.venv/bin/python main.py -c config.local.yaml --managed -f /path/to/sample.exe \
  --guest-path 'C:\Users\artem\Documents\vbiv\kovarstvo\scripts'
```

Re-run only the offline enrichment and reports for a finished run (for example after upgrading
StealerForge); no guest is booted and the previous analysis folder is kept:

```bash
.venv/bin/python main.py -c config.local.yaml --managed-reanalyze \
  '/media/you/LabDisk/StealerForge-Lab/evidence/<run-id>'
```

Optional commands to install/validate before submitting any sample, or recover
resources left by a power failure or forced process termination:

```bash
.venv/bin/python main.py -c config.local.yaml --managed-prepare
.venv/bin/python main.py -c config.local.yaml --managed-cleanup
```

Normal completion, exceptions, Ctrl+C, and SIGTERM trigger cleanup automatically.
After SIGKILL, host shutdown, or a Docker outage, the next managed invocation
recovers unfinished runs before proceeding. Cleanup only removes resources with
the matching run ID and ownership label. If ownership cannot be verified, or Docker
is unreachable, cleanup reports failure and retains the working disk for recovery.
It never runs a global Docker prune or deletes retained analysis directories.

Exit codes: `0` completed, `2` reports produced but coverage/checks need review,
`1` failed, `130` interrupted. A failed run keeps partial evidence and diagnostics.

## What happens automatically

1. Acquire a local lock, recover unfinished runs, and check KVM and disk space.
2. Pull the pinned Windows launcher and build the pinned CAPE and offline analysis
   images if absent. Build logs remain in `.managed/`.
3. On first use, download official Windows 10 Enterprise evaluation media, install
   Windows under a generated victim persona (user, `DESKTOP-XXXXXXX` host name, owner,
   organisation, time zone), and run `managed/guest/provision.py` (see "Victim
   environment"). Only this clean installation stage has internet access. No sample is
   mounted. The host refuses to seal a base whose provisioning report has a failed step.
4. Wait for the agent, shut Windows down, disable Microsoft Defender offline (see
   below), check the disk, and seal the base.
5. Boot a disposable clone and submit the compiled benign probe. Validation requires:
   the monitored `canary.txt` write in CAPE API telemetry; an HTTPS POST that passed
   fake DNS, redirection and TLS interception with certificate checks on; Sysmon
   process events collected from the guest; Defender not running; Sysmon running.
   Failed validation blocks real submissions.
6. For the requested sample, start the network simulator, boot another fresh overlay
   and verify that it contains no previous run marker. Optionally create analyst-named
   folders (`--guest-path`). Run a single CAPE task with the configured deadline.
7. Preserve the original sample, raw CAPE output, extracted payloads, process dumps,
   packet capture, simulator capture, task database, and logs. Scan the simulator
   capture for the base's canary values. Run UPX/Speakeasy/CAPE parsers/FLOSS/capa,
   lab-evidence import (simulated internet, canary hits, Sysmon sample tree) and report
   generation in the separate offline analysis container.
8. Stop/remove the owned containers, remove the QMP volume and disposable disk,
   and publish `managed_run.json`. Keep the clean base and collected evidence.

The CAPE adapter controls QEMU through a private Unix QMP socket. It permits one
analysis per guest and terminates QEMU when CAPE finishes. It does not pretend that
an already-used guest has been restored. Each later task starts from a new overlay;
the base is mounted read-only during analysis.

## Retained data

By default, each run has a unique directory under the HDD storage directory:

```text
StealerForge-Lab/
  bases/<guest-recipe>/          # Clean Windows disk, installation assets, validation record
  provisioning/<id>/            # Installation diagnostics
  validation/<id>/              # Benign CAPE validation evidence
  evidence/<run-id>/
    sample.bin
    managed_run.json
    controller_status.json
    cape.sqlite
    guest.pcap                   # Raw guest capture (CAPE gets a copy without agent traffic)
    netsim/events.jsonl          # Every DNS query, connection, TLS handshake and request
    netsim/blobs/                # Request bodies, SMTP messages, FTP uploads, raw streams (by SHA-256)
    canary_hits.json             # Planted canary values found in what the sample sent
    cape-scheduler.log
    cape-processing.log
    sf-<run-id>-*.log
    cape/analyses/1/             # Original CAPE logs, reports, payloads and process dumps
    analysis/<analysis-id>/
      cape_cti_telemetry.json
      lab_summary.json          # Simulator counts, canary summary, Sysmon coverage
      sandbox_events.jsonl      # Sysmon events of the sample's process tree (Sigma field names)
      threat_intel_report.md
      evidence.json
      manifest.json
      artifacts/                # Imported and locally generated payloads, when produced
      ...
```

`--output /path/to/results` changes the evidence parent for sample runs; base images
remain under `--lab-storage`. Installation and validation diagnostics stay with lab
storage. Raw CAPE payloads are retained even when only a bounded subset is selected
for additional enrichment. Full guest RAM dumps are disabled by default; process
dumps and CAPE payload dumps depend on the monitor and sample behavior.

Unlike the report-only local Compose workflow, managed analysis explicitly retains
collected and generated artifacts. The HDD can therefore contain executable malware
and sensitive extracted configuration; retain it as analysis evidence. The tool does
not automatically expire evidence or delete old base versions.

## Isolation and constraints

During sample execution, a namespace container has `--network none`. The QEMU
launcher, CAPE controller and network simulator share that namespace. The guest uses a
QEMU user-mode NIC; agent forwarding binds only to namespace loopback, and the guest
reaches the result server through QEMU's `10.0.2.2` address. There is no routable host
or LAN interface, published port, Docker socket, or host desktop share. The launcher
has its automatic networking and SMB sharing disabled.

### Simulated internet

A short-lived container with only `NET_ADMIN` adds a **dummy** device (`sfsink0`, no
carrier) as the namespace's default route and iptables rules that redirect all
outbound TCP and DNS to `managed/netsim.py` on namespace loopback. A packet that is not
redirected is dropped by the dummy device, so no rule can open a path to a real network.
The controller refuses to run unless the namespace holds only `lo` and that dummy device.

The simulator runs without capabilities and answers:

- **DNS:** every name gets a stable address from `198.18.0.0/15` (benchmarking range,
  never routed); `dns.msftncsi.com` gets the answer Windows expects, so the guest
  believes it is online.
- **TLS:** intercepted with a per-base lab CA trusted by Windows and Firefox; a
  certificate is minted per SNI name, so certificate validation stays on.
- **HTTP(S):** IP-lookup and geolocation services (fake public IP `managed_lab.public_ip`,
  Boston, US), Telegram Bot API and Discord webhook success replies, connectivity
  checks, `200 OK` for other requests and `404` for executable downloads.
- **SMTP** (25/587 with STARTTLS, 465) including AUTH and DATA, **FTP** including
  passive-mode uploads, DNS over TCP, and raw capture of any other protocol.

Family-specific C2 protocols are not emulated: a stealer may stop after its first C2
exchange. Remote CAPE with INetSim remains available through the
[external lab workflow](README-LAB.md).

One exception: a raw TCP client that opens with `REGISTER <os> <arch>` (plain-text DDoS bots such
as the Go `apex2` bot) gets a scripted command sequence (`LINE_C2_SCRIPT` in `managed/netsim.py`)
on its first session. Every target is a documentation address or a `.example` name, so TCP floods
return to the simulator and UDP floods die on the sink device; only the guest packet capture
(`dump.pcap`) sees UDP floods. Events: `c2_session`, `c2_command`, `c2_keepalives`, `c2_session_end`.

- **HTTP floods:** after 40 bodiless requests per host, they are counted in `http_suppressed`
  events rather than logged one by one.
- **Cloudflare-style challenge:** hosts named `cf-*.example` answer with a 503 and a
  `cf_clearance` cookie until a request carries that cookie.
- **Accuracy:** the simulator serves at most 128 connections at once, and a 500-worker flood
  backs the rest up in the accept queue. Use the packet capture for flood rates and
  connection counts; netsim timestamps lag under load.

`managed_lab.monitor_options` sets the CAPE monitor options for managed tasks. capemon disables a
hook when one API reaches `api-cap` (5000 calls). In validation (2026-11-05), that hook removal
crashed a highly multithreaded Go bot twice. Add `api-cap=1000000` for such samples; the rate cap
still bounds log size.

### Victim environment

Each base gets a random persona (`managed/persona.py`, stored as `bases/<recipe>/persona.json`)
and `managed/guest/provision.py` plants it:

- Chrome, current Edge and Firefox with canary logins, session cookies, a test card and
  autofill (Chromium v10 encryption with the profile's DPAPI key; Firefox stores its
  logins itself through Marionette and they are verified with Firefox's NSS);
- ten wallet browser extensions, Electrum/Exodus/Ethereum/Atomic wallets, Discord (plain
  and DPAPI-protected token), Telegram `tdata`, Steam, FileZilla, NordVPN/ProtonVPN
  (DPAPI), OpenVPN, Pidgin, and documents/recent files with credentials and a seed phrase;
- realistic owner/organisation/OEM registry values; the launcher's `Z:` share and
  desktop link removed; browser updaters disabled so they do not pollute captures;
- Sysmon (renamed service, malware-analysis configuration in `managed/guest/sysmon.xml`),
  PowerShell script-block/module logging and process-creation command-line auditing.

The Sysmon channel is exported whole when the analysis stops (`managed/sysmon_export.py`, an
analyzer module added to CAPE). CAPE's own evtx module, which still collects the other
channels, would wipe Sysmon after the sample has started and between snapshots, so the Sysmon
channel is removed from it at image build time. On the host, events are kept only for the
sample's process tree (anchored on CAPE's monitored PIDs), without the CAPE monitor's own pipe,
file and key-creation noise; they become `sysmon_event` evidence and `sandbox_events.jsonl`.
Simulator traffic is attributed to the sample when its Sysmon network events name the same
destination; unattributed traffic (Windows, browsers) is kept but ranked low.
Screenshots are taken from the host through QMP, so nothing runs in the guest for them.

All planted values are fake. `canary_hits.json` lists every canary found in simulator
captures (also inside gzip/zlib/ZIP/base64 layers and in UTF-16/URL encodings): direct
evidence of what the sample read and sent.

### Hardware identity and evasion resistance

QEMU's defaults are among the first things anti-VM code checks. Each base gets a hardware
profile (`bases/<recipe>/hardware.json`, `core/hardware.py`) matching the persona's machine,
applied at every boot without reinstalling:

- SMBIOS BIOS, system, baseboard, chassis and memory tables with real-vendor strings
  (Dell/HP/Lenovo models, service-tag-style serials) instead of "QEMU"/"Bochs";
- ACPI OEM ID and table ID (`x-oem-id`/`x-oem-table-id`) instead of "BOCHS"/"BXPC";
- disk vendor/product/serial instead of "QEMU HARDDISK"; a NIC MAC from the vendor's OUI
  instead of QEMU's `52:54:00`;
- CPU identity `cpu_identity: default`: Hyper-V enlightenments, so the hypervisor CPUID leaf
  reports "Microsoft Hv" as on a physical PC with virtualization-based security; 4 vCPUs and
  4 GiB RAM. Hiding more was tested and rejected: `hyperv` (KVM leaves hidden) made monitored
  processes hang and `bare` (no hypervisor bit or enlightenments) made them crash with heap
  corruption under the pinned CAPE monitor. The hypervisor bit therefore stays visible;
- 1920x1080 display, persona user and host name, CAPE's human-interaction, screenshot,
  disguise and recent-files modules.

Still detectable: VirtIO/QEMU PCI devices and drivers (balloon, display), short uptime (each
clone boots fresh), the evaluation-licence watermark, the agent folder `C:\StealerForge`,
and the CAPE monitor itself. Treat "no behaviour" from evasive samples accordingly.

### Run length and adaptive re-runs

CAPE does not enforce the timeout: a task ends when every monitored process has exited, or
after `analysis_seconds` (300 by default). When a sample ends within two minutes after
failing to open a folder under another user's profile with "path not found" (a developer
build logging to its author's machine), the lab automatically runs it once more in a fresh
guest with those folders created (`adaptive_rerun`). Both evidence folders are kept;
`adaptive_rerun.json` in the second links to the first.

### Payloads and static depth

The controller collects CAPE payloads, process dumps, dropped files and PE images CAPE carved
from process memory (header-only pages skipped). Payloads CAPE typed as shellcode are passed
to capa and FLOSS as `sc64`/`sc32`. .NET inputs get a metadata stage (assembly identity, types,
P/Invoke imports, resources and the complete user-string heap), which surfaces C2 strings,
developer paths and class names such as credential-store decryptors.

### Microsoft Defender

Tamper Protection blocks every in-guest way to turn Defender off, and signatures
updated during installation would quarantine samples. After provisioning shuts the
guest down, `managed/diskedit` edits the offline registry with libguestfs (inside its
own small VM; nothing is mounted on the host): WinDefend, WdFilter, WdBoot, WdNisSvc and
WdNisDrv are disabled and Tamper Protection is set off. Validation confirms Defender is
not running.

The offline enrichment container uses a read-only root, no network, dropped Linux
capabilities, no-new-privileges, bounded memory/CPU, and temporary scratch mounts.
The Windows launcher and CAPE controller have separate resource limits and writable
working storage. They are not equivalent to the hardened offline container. KVM and
Docker still share the Linux host kernel; these controls do not prove immunity to
hypervisor or kernel vulnerabilities.

The Windows guest is a full QEMU/KVM VM managed by Docker, not a native Windows
container. The baseline uses an official Windows edition instead of a stripped image
that may remove APIs or services needed for analysis. Evaluation media is time-limited;
use within Microsoft's terms. The evaluation needs online activation to start its
trial period, and the guest is never online, so the installed guest reports
`TIMEBASED_EVAL` licensing in Notification mode (`0xC004F009`, grace time expired)
and shows a "Windows license is expired" watermark. Analysis still works, and each
disposable guest is destroyed well within an hour. Samples that check activation
state or the desktop watermark may behave differently. The tool does not try to
bypass licensing; use properly licensed media if this matters for your samples.

## Capacity and settings

Use one guest at a time. Targets are 4 vCPUs and 4 GiB guest RAM. The launcher
is limited to 6 GiB, the controller to 4 GiB, and the subsequent enrichment worker to
4 GiB. The virtual disk has 64 GiB logical capacity and grows as data is written.
The host must have at least 8 GiB available RAM. The launcher uses an explicit 4 GiB
guest size: its automatic memory heuristic can incorrectly subtract the downloaded
ISO's reclaimable page cache from the cgroup allowance. The host check and Docker's
hard memory limit remain enforced.
The default 80 GiB free-space requirement is a planning reserve, not an immediate
allocation. A separate 8 GiB reserve stops stages before exhausting the evidence disk.
Docker build layers and the controller's temporary database live on Docker's storage
filesystem, so that filesystem also needs free space.

The storage directory can live on a separate HDD. QCOW2 creation and checks have worked
on an NTFS-formatted data disk, so no reformatting is required. The QMP socket and trusted
recovery journals always use Linux filesystem storage rather than the data disk. The default
boot deadline is 15 minutes, which allows for slower HDD installation and boot.

Settings in `managed_lab` include `storage_directory`, `state_directory`,
`min_free_gib`, `reserve_free_gib`, `min_available_gib` (8), `provision_timeout_seconds` (7200),
`boot_timeout_seconds` (900), `analysis_seconds` (180),
`task_timeout_seconds` (1200), `enrichment_timeout_seconds` (3600), and
`max_enrichment_artifacts` (8). Paths are relative to the selected config file.
Keep the state directory local and outside directories exposed to analysis containers.
Use a dedicated storage directory; do not point it at a filesystem root.

Host readiness checks:

```bash
python3 -m core.lab_readiness --storage '/media/you/LabDisk/StealerForge-Lab'
# If KVM is unavailable after a reboot, enable the matching CPU module as administrator:
sudo modprobe kvm_intel
```

On an Intel host, an administrator can make KVM load at boot once (use `kvm_amd` on AMD):

```bash
echo kvm_intel | sudo tee /etc/modules-load.d/stealerforge-kvm.conf
```

The data disk must be mounted before starting the tool. A missing storage parent
causes a clear failure rather than creating replacement directories on the SSD.

Readiness checks alone do not establish successful Windows monitoring. The managed
benign validation is the additional submission gate. Build pins are recorded in
`managed/assets.lock.json` and `managed/Dockerfile`; changing guest installation
assets creates a new base recipe, while controller-only edits reuse the clean base.

Upstream references: [Dockur Windows](https://github.com/dockur/windows),
[CAPE](https://github.com/kevoreilly/CAPEv2),
[QEMU disk images](https://www.qemu.org/docs/master/system/images.html).
