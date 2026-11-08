"""StealerForge CLI. --help works before third-party packages are installed."""
import argparse
import importlib.metadata
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parent


def parser():
    cli = argparse.ArgumentParser(description='Evidence-grounded static + CAPE infostealer analysis')
    cli.add_argument('-f', '--file', help='Sample file (never launched natively on the CLI host)')
    cli.add_argument('-c', '--config', default=str(ROOT / 'config.yaml'))
    mode = cli.add_mutually_exclusive_group()
    mode.add_argument('--skip-cape', '--cape-report', dest='cape_report', help='Import CAPE JSON without contacting CAPE')
    mode.add_argument('--task-id', type=int, help='Resume collection from an existing CAPE task')
    mode.add_argument('--static-only', action='store_true', help='Disable CAPE; configured local engines may still run')
    mode.add_argument('--managed', action='store_true', help='Provision an isolated Windows/CAPE lab, analyze, retain evidence and clean up')
    mode.add_argument('--managed-prepare', action='store_true', help='Build and validate the managed Windows base using a benign probe')
    mode.add_argument('--managed-cleanup', action='store_true', help='Recover unfinished managed runs, retaining their evidence')
    mode.add_argument('--managed-reanalyze', metavar='EVIDENCE_DIR',
                      help='Re-run offline enrichment and reports for a finished managed run (no guest is booted)')
    cli.add_argument('--lab-storage', help='Dedicated managed lab directory, including base VM and retained evidence')
    cli.add_argument('--lab-evidence', help='Managed-lab evidence folder (simulated internet, canary hits, Sysmon) to include')
    cli.add_argument('--guest-path', action='append', default=[],
                     help='Managed mode: create this Windows folder in the guest before the sample runs (repeatable)')
    cli.add_argument('--artifact', '--unpacked', dest='artifacts', action='append', default=[],
                     help='Import an unpacked/dropped artifact; repeat as needed')
    cli.add_argument('--benign', action='append', default=[], help='Benign YARA test fixture; repeat as needed')
    cli.add_argument('--local-engines', action='store_true', help='Run optional local preprocessing/emulation engines')
    cli.add_argument('--shellcode-arch', choices=['x86', 'amd64'],
                     help='Explicitly treat the primary input as raw shellcode; enables local engines')
    retention = cli.add_mutually_exclusive_group()
    retention.add_argument('--ephemeral-artifacts', action='store_true',
                     help='Analyze in scratch storage and export text reports only')
    retention.add_argument('--retain-artifacts', action='store_true', help='Retain collected and generated analysis artifacts')
    cli.add_argument('--report-markdown', help='Validate an analyst/Web UI report instead of calling an LLM')
    llm = cli.add_mutually_exclusive_group()
    llm.add_argument('--offline-llm', action='store_true', help='Export prompt; generate deterministic evidence report')
    llm.add_argument('--llm-api', action='store_true', help='Enable Claude API synthesis')
    cli.add_argument('--output', help='Output parent directory; each run gets a unique subdirectory')
    cli.add_argument('--check', action='store_true', help='Check local dependencies, configuration and YARA rules')
    cli.add_argument('--check-cape', action='store_true', help='Also query CAPE health; does not submit a sample')
    cli.add_argument('--preflight', action='store_true', help='Check configured engines, assets, storage and required runtime controls')
    return cli


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    if not (args.check or args.check_cape or args.preflight or args.file or args.managed_prepare or args.managed_cleanup or args.managed_reanalyze):
        cli.error('--file is required unless using --check or --check-cape')
    out_dir = None
    workspace = None
    initial, evidence = {}, None
    state = {'status': 'initializing', 'started_at_utc': datetime.now(timezone.utc).isoformat()}
    try:
        from core.config import DEPENDENCIES, credential, load_config, missing_dependencies
        from core.evidence import artifact_manifest, sha256_file, unwrap_report, write_json
        cfg = load_config(args.config)
        if args.managed or args.managed_prepare or args.managed_cleanup or args.managed_reanalyze:
            if any((args.check, args.check_cape, args.preflight, args.artifacts, args.benign,
                    args.shellcode_arch, args.report_markdown, args.llm_api, args.ephemeral_artifacts)):
                raise ValueError('Managed mode accepts a sample and lab/output settings; other workflows must run separately')
            if (args.managed_prepare or args.managed_cleanup or args.managed_reanalyze) and (args.file or args.guest_path):
                raise ValueError('Preparation and cleanup do not accept a sample or guest paths')
            sample = Path(args.file).resolve() if args.file else None
            if args.managed and (sample is None or not sample.is_file()
                                 or sample.stat().st_size > cfg['static_analysis']['max_file_bytes']):
                raise ValueError('Managed input must be a regular file within max_file_bytes')
            if args.lab_storage:
                cfg['managed_lab']['storage_directory'] = str(Path(args.lab_storage).resolve())
            from core.managed_lab import ManagedLab
            return ManagedLab(cfg['managed_lab']).run(sample, prepare_only=args.managed_prepare,
                                                      cleanup_only=args.managed_cleanup, output=args.output,
                                                      guest_paths=args.guest_path, reanalyze=args.managed_reanalyze)
        if args.lab_storage or args.guest_path:
            raise ValueError('--lab-storage and --guest-path require a managed mode')
        if args.output:
            cfg['output']['directory'] = str(Path(args.output).resolve())
        if args.ephemeral_artifacts:
            cfg['output']['retain_artifacts'] = False
        if args.retain_artifacts:
            cfg['output']['retain_artifacts'] = True
        if args.shellcode_arch:
            cfg['local_analysis'].update(shellcode_arch=args.shellcode_arch, enabled=True)
        if args.offline_llm:
            cfg['llm']['use_api'] = False
        if args.llm_api:
            cfg['llm']['use_api'] = True
        if args.local_engines:
            cfg['local_analysis']['enabled'] = True
        missing = missing_dependencies()
        if missing:
            raise RuntimeError('Missing packages: ' + ', '.join(missing) +
                               '. Run .venv/bin/python -m pip install -r requirements.txt (or uv pip install).')
        from core.cape_client import CapeSandboxClient
        from core.context_maximizer import ContextWindowMaximizer
        from core.enrichment import run_enrichment
        from core.evidence import build_evidence
        from core.llm_intelligence import ClaudeIntelligenceEngine
        from core.reporting import audit_citations, render_evidence_report
        from core.rule_validator import AutomatedRuleValidator
        from core.static_engine import StaticAnalyzer
        from core.cti import write_cti
        from core.workspace import RunWorkspace
        static_cfg = cfg['static_analysis']
        analyzer = StaticAnalyzer(static_cfg['yara_rules_path'], static_cfg['min_string_length'],
                                  static_cfg['max_strings_per_binary'], static_cfg['max_file_bytes'],
                                  static_cfg['yara_timeout_seconds'])
        if args.preflight:
            from core.preflight import run_preflight
            diagnostics = run_preflight(cfg, include_cape=args.check_cape)
            print(json.dumps(diagnostics, indent=2))
            return 0 if diagnostics['status'] == 'passed' else 1
        if args.check or args.check_cape:
            diagnostics = {'local_setup': 'ok', 'python': sys.version.split()[0],
                           'versions': {name: importlib.metadata.version(package) for name, package in DEPENDENCIES.items()},
                           'llm_mode': 'api' if cfg['llm']['use_api'] else 'offline',
                           'llm_credential_present': bool(credential(cfg['llm'], 'anthropic_api_key', 'api_key_env', 'ANTHROPIC_API_KEY')),
                           'cape_credential_present': bool(credential(cfg['cape'], 'api_token', 'api_token_env', 'CAPE_API_TOKEN')),
                           'cape_health': 'not_checked',
                           'note': 'Local setup does not verify sandbox monitor capabilities or model/account access'}
            if args.check_cape:
                cape = CapeSandboxClient(cfg['cape'])
                try:
                    cape.check_health()
                    diagnostics['cape_health'] = 'ok'
                finally:
                    cape.close()
            print(json.dumps(diagnostics, indent=2))
            return 0
        if cfg['safety']['require_container_controls']:
            from core.preflight import container_controls
            controls = container_controls()
            if not all(controls.values()):
                raise ValueError('Required runtime controls failed: ' + ', '.join(k for k, v in controls.items() if not v))
        if args.task_id is not None and args.task_id <= 0:
            raise ValueError('--task-id must be positive')
        # Validate all explicit inputs before any sandbox submission.
        sample = Path(args.file).resolve()
        extra = [Path(p).resolve() for p in args.artifacts]
        benign = [Path(p).resolve() for p in args.benign]
        paths = [sample] + extra + benign
        for path in paths:
            if not path.is_file():
                raise ValueError(f'Input is not a regular file: {path}')
            if path.stat().st_size > static_cfg['max_file_bytes']:
                raise ValueError(f'Input exceeds max_file_bytes: {path.name}')
        for path in [args.cape_report, args.report_markdown]:
            if path and not Path(path).is_file():
                raise ValueError(f'Input does not exist: {path}')
        if cfg['llm']['use_api'] and not args.report_markdown:
            if not credential(cfg['llm'], 'anthropic_api_key', 'api_key_env', 'ANTHROPIC_API_KEY'):
                raise ValueError('API mode requires ANTHROPIC_API_KEY; use --offline-llm to export a prompt')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
        destination = Path(cfg['output']['directory']).resolve() / f'{stamp}_{uuid4().hex[:8]}'
        workspace = RunWorkspace(destination, cfg['output']['retain_artifacts'],
                                 cfg['output']['scratch_directory'], cfg['output']['max_run_bytes'])
        out_dir = workspace.path
        state['output_directory'] = str(destination)
        state['artifact_retention'] = 'persistent' if cfg['output']['retain_artifacts'] else 'ephemeral'
        state['versions'] = {name: importlib.metadata.version(package) for name, package in DEPENDENCIES.items()}
        print(f'Output: {destination}', flush=True)
        print('Analyzing sample statically...', flush=True)
        initial = analyzer.analyze_binary(sample, 'initial_disk_sample')
        if cfg['local_analysis']['shellcode_arch'] and initial.get('pefile_analysis', {}).get('is_valid_pe'):
            raise ValueError('--shellcode-arch requires raw code, not a PE input')
        write_json(out_dir / 'stage1_initial_static.json', initial)
        state['sample_sha256'] = initial['hashes']['sha256']
        collection, artifacts = [], []
        if args.cape_report:
            report_path = Path(args.cape_report)
            if report_path.stat().st_size > cfg['cape']['max_report_bytes']:
                raise ValueError('Imported CAPE report exceeds max_report_bytes')
            raw = json.loads(report_path.read_text(encoding='utf-8'))
            shutil.copyfile(report_path, out_dir / 'raw_cape_report.json')
            state['analysis_mode'] = 'imported_cape_report'
        elif args.static_only:
            raw = {'info': {'analysis_mode': 'local_engines' if cfg['local_analysis']['enabled'] else 'static_only',
                            'note': 'No CAPE guest execution; any local emulator evidence is stored separately'}}
            write_json(out_dir / 'raw_cape_report.json', raw)
            state['analysis_mode'] = raw['info']['analysis_mode']
        else:
            cape = CapeSandboxClient(cfg['cape'])
            state['analysis_mode'] = 'cape'
            try:
                task_id = args.task_id or cape.submit_sample(str(sample))
                state['cape_task_id'] = task_id
                state['network_route_requested'] = cfg['cape'].get('route', 'inetsim') if not args.task_id else 'existing_task'
                write_json(out_dir / 'run_status.json', state)
                print(f'Waiting for CAPE task {task_id}...', flush=True)
                cape.wait_for_report(task_id)
                raw = cape.download_json_report(task_id, out_dir / 'raw_cape_report.json')
                # Check identity before downloading further task artifacts.
                report, _ = unwrap_report(raw)
                reported_hash = ((report.get('target') or {}).get('file') or {}).get('sha256')
                if reported_hash and reported_hash.lower() != state['sample_sha256']:
                    raise ValueError('CAPE report target SHA256 differs from the supplied sample')
                artifacts = cape.download_artifacts(raw, out_dir / 'artifacts')
                if cfg['cape']['download_pcap']:
                    cape.download_pcap(task_id, out_dir / 'dump.pcap')
                collection = cape.collection
            finally:
                write_json(out_dir / 'artifact_collection.json', cape.collection)
                cape.close()
        report, _ = unwrap_report(raw)
        reported_hash = ((report.get('target') or {}).get('file') or {}).get('sha256')
        if reported_hash and reported_hash.lower() != state['sample_sha256']:
            raise ValueError('CAPE report target SHA256 differs from the supplied sample')
        seen = {sha256_file(path) for path in artifacts}
        unwrapped = unwrap_report(raw)[0]
        cape_payloads = {p.get('sha256'): p for p in (unwrapped.get('CAPE') or {}).get('payloads') or [] if isinstance(p, dict)}
        target_type = ((unwrapped.get('target') or {}).get('file') or {}).get('type', '')
        for path in extra:
            digest = sha256_file(path)
            if digest in seen:
                continue
            seen.add(digest)
            dest = out_dir / 'artifacts' / f'{digest}.bin'
            dest.parent.mkdir(exist_ok=True)
            shutil.copyfile(path, dest)
            entry = {'kind': 'analyst_import', 'status': 'imported', 'sha256': digest,
                     'path': f'artifacts/{dest.name}', 'original_name': path.name,
                     'note': 'Imported by analyst; relationship to the sample must be established separately'}
            payload = cape_payloads.get(digest)
            if payload and 'shellcode' in str(payload.get('cape_type', '')).lower():
                # CAPE typed this dump as shellcode: capa and FLOSS can analyse it with an explicit architecture.
                entry['representation'] = 'shellcode_' + ('amd64' if '64' in str(target_type) else 'x86')
                entry['cape_type'] = payload.get('cape_type')
            collection.append(entry)
            artifacts.append(dest)
        write_json(out_dir / 'artifact_collection.json', collection)
        local_results = None
        if cfg['local_analysis']['enabled']:
            from core.local_engines import run_local_engines
            print('Running optional local engines...', flush=True)
            local_results, local_artifacts, local_collection = run_local_engines(
                [sample] + artifacts, cfg['local_analysis'], out_dir, static_cfg['max_file_bytes'])
            artifacts.extend(local_artifacts)
            collection.extend(local_collection)
            state['local_analysis'] = local_results['status']
            write_json(out_dir / 'artifact_collection.json', collection)
        print(f'Analyzing {len(artifacts)} collected/imported artifacts...', flush=True)
        statics = []
        for artifact in artifacts:
            try:
                statics.append(analyzer.analyze_binary(artifact, 'collected_or_imported_artifact'))
            except (OSError, ValueError) as exc:
                statics.append({'filename': artifact.name, 'status': 'failed', 'error': str(exc)})
        write_json(out_dir / 'stage3_artifact_static.json', statics)
        for entry in collection:
            if entry.get('path'):
                entry['retained_after_run'] = cfg['output']['retain_artifacts']
        write_json(out_dir / 'artifact_collection.json', collection)
        representations = {entry['sha256']: entry.get('representation', 'file') for entry in collection
                           if entry.get('sha256') and entry.get('status') in ('generated', 'imported', 'downloaded')}
        if cfg['local_analysis']['shellcode_arch']:
            representations[state['sample_sha256']] = 'shellcode_' + cfg['local_analysis']['shellcode_arch']
        enrichment = run_enrichment([sample] + artifacts, cfg['enrichment'], out_dir, representations)
        write_json(out_dir / 'enrichment.json', enrichment)
        lab_records, replay_events = None, []
        if args.lab_evidence:
            from core.lab_evidence import load as load_lab
            lab_records, replay_events, lab_summary = load_lab(args.lab_evidence, unwrap_report(raw)[0])
            write_json(out_dir / 'lab_summary.json', lab_summary)
            if replay_events:
                (out_dir / 'sandbox_events.jsonl').write_text(
                    ''.join(json.dumps(e, ensure_ascii=True) + '\n' for e in replay_events), encoding='utf-8')
        evidence = build_evidence(initial, statics, raw, collection, enrichment, local_results, lab_records)
        if not reported_hash and not args.static_only:
            evidence['coverage']['warnings'].append('CAPE report lacks target SHA256; sample/report identity is unverified')
        for static in [initial] + statics:
            if static.get('status') == 'failed' or static.get('warnings'):
                evidence['coverage']['warnings'].append(f'Static analysis incomplete for {static.get("filename")}')
        write_json(out_dir / 'evidence.json', evidence)
        state['status'] = 'evidence_prepared'
        write_cti(out_dir, initial, evidence, state)
        limits = cfg['token_maximizer']
        maximizer = ContextWindowMaximizer(limits['target_token_budget'], limits['chars_per_token_estimate'],
                                           limits['max_api_calls_per_process'])
        dossier = maximizer.build_from_evidence(evidence)
        (out_dir / 'Evidence_Report.md').write_text(render_evidence_report(evidence, dossier), encoding='utf-8')
        engine_cfg = dict(cfg['llm'])
        if args.report_markdown:
            engine_cfg['use_api'] = False
        engine = ClaudeIntelligenceEngine(engine_cfg)
        print('Preparing evidence dossier and report...', flush=True)
        markdown = engine.analyze_dossier(dossier, out_dir)
        dossier = engine.final_dossier
        state['llm'] = engine.last_result
        if args.report_markdown:
            markdown = Path(args.report_markdown).read_text(encoding='utf-8')
            (out_dir / 'Threat_Intel_and_SOC_Rules.md').write_text(markdown, encoding='utf-8')
            state['llm'] = {'status': 'analyst_report_imported', 'citation_audit': audit_citations(markdown, evidence)}
            write_json(out_dir / 'llm_status.json', state['llm'])
        if markdown and replay_events and (out_dir / 'Threat_Intel_and_SOC_Rules.md').is_file():
            from core.reporting import with_replay_appendix
            markdown = with_replay_appendix(markdown, replay_events)
            (out_dir / 'Threat_Intel_and_SOC_Rules.md').write_text(markdown, encoding='utf-8')
        (out_dir / 'Evidence_Report.md').write_text(render_evidence_report(evidence, dossier), encoding='utf-8')
        validator = AutomatedRuleValidator(static_cfg['yara_timeout_seconds'])
        validation = validator.extract_and_validate(markdown, [sample] + artifacts, out_dir, benign)
        write_json(out_dir / 'stage6_rule_validation.json', validation)
        failed_checks = validation['status'] == 'checks_failed'
        llm_status = state['llm']['status']
        citation_failure = args.report_markdown and not state['llm']['citation_audit']['passed']
        local_partial = local_results is not None and local_results['status'] != 'completed'
        enrichment_partial = any(item['status'] != 'completed' for item in enrichment)
        state['status'] = ('needs_review' if failed_checks or citation_failure or local_partial or enrichment_partial or llm_status in ('incomplete', 'needs_review')
                           else 'evidence_ready' if llm_status == 'prompt_exported' else 'report_ready_for_review')
        state['rule_validation'] = validation['status']
        state['coverage_warnings'] = evidence['coverage']['warnings']
        state['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
        write_cti(out_dir, initial, evidence, state)
        write_json(out_dir / 'run_status.json', state)
        write_json(out_dir / 'manifest.json', artifact_manifest(out_dir))
        print(f'Status: {state["status"]}; rules: {validation["status"]}; coverage warnings: {len(state["coverage_warnings"])}')
        print(f'Read {destination / "threat_intel_report.md"}')
        return 2 if state['status'] == 'needs_review' else 0
    except (Exception, KeyboardInterrupt) as exc:
        # Keep partial artifacts and status; never print configuration/credentials.
        state.update(status='interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed',
                     error=f'{type(exc).__name__}: {exc}')
        if out_dir:
            (out_dir / 'run_status.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
            try:
                from core.cti import write_cti
                if evidence is None:
                    evidence = {'records': [], 'coverage': {'warnings': [], 'record_counts': {}}}
                evidence['coverage']['warnings'].append(state['error'])
                write_cti(out_dir, initial, evidence, state)
                from core.evidence import artifact_manifest, write_json
                write_json(out_dir / 'manifest.json', artifact_manifest(out_dir))
            except Exception:
                pass
        print(f'Error: {state["error"]}', file=sys.stderr)
        if isinstance(exc, ModuleNotFoundError):
            print('Activate .venv and install requirements.txt first.', file=sys.stderr)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1
    finally:
        if workspace:
            try:
                omitted = workspace.finish()
                if omitted and state['status'] not in ('failed', 'interrupted'):
                    print('Status: needs_review; some worker reports could not be exported', file=sys.stderr)
                    return 2
            except Exception as exc:
                print(f'Error publishing reports: {exc}', file=sys.stderr)
                return 1


if __name__ == '__main__':
    raise SystemExit(main())
