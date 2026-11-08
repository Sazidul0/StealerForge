"""Keep analysis intermediates in scratch storage and publish selected text reports."""
import json
import shutil
import tempfile
from pathlib import Path

from core.evidence import artifact_manifest, write_json


REPORTS = {
    'run_status.json', 'stage1_initial_static.json', 'raw_cape_report.json',
    'artifact_collection.json', 'stage3_artifact_static.json', 'local_analysis.json',
    'engine_assets.json', 'enrichment.json', 'evidence.json', 'stage4_maximized_dossier.json',
    'Evidence_Report.md', 'claude_maximized_prompt.txt', 'llm_status.json',
    'Threat_Intel_and_SOC_Rules.md', 'Threat_Intel.partial.md', 'stage6_rule_validation.json',
    'cape_cti_telemetry.json', 'threat_intel_report.md',
}


def publish_reports(source, destination, max_bytes):
    """Allowlist files, rejecting symlinks and binary artifacts regardless of extension."""
    selected = []
    for path in source.rglob('*'):
        relative = path.relative_to(source)
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != source.parent):
            raise ValueError('Symbolic link in report workspace')
        if not path.is_file():
            continue
        parts = relative.parts
        allowed = len(parts) == 1 and (path.name in REPORTS or
            (path.name.startswith('generated_rule_') and path.suffix == '.yar') or
            (path.name.startswith('generated_sigma_') and path.suffix == '.yml'))
        allowed |= (len(parts) == 3 and parts[0] == 'local_engines' and
                    path.name in ('options.json', 'result.json', 'report.json', 'stdout.log', 'stderr.log'))
        allowed |= (len(parts) == 3 and parts[0] == 'enrichment' and path.name in ('stdout.log', 'stderr.log'))
        if allowed:
            selected.append((path, relative))
    if sum(path.stat().st_size for path, _ in selected) > max_bytes:
        raise ValueError('Report export exceeds output.max_run_bytes')
    # A timed-out worker can leave truncated JSON or non-UTF8 logs. Preserve other reports.
    validated, omitted = [], []
    for path, relative in selected:
        try:
            text = path.read_text(encoding='utf-8', errors='strict')
            if '\x00' in text:
                raise ValueError('Binary content in a text report')
            if path.suffix == '.json':
                json.loads(text)
            validated.append((path, relative))
        except (ValueError, UnicodeError) as exc:
            if relative.parts[0] not in ('local_engines', 'enrichment'):
                raise
            omitted.append({'path': str(relative), 'reason': type(exc).__name__})
    for path, relative in validated:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    write_json(destination / 'report_publication.json', {'status': 'partial' if omitted else 'completed',
                                                       'omitted_worker_reports': omitted})
    return omitted


class RunWorkspace:
    def __init__(self, destination, retain_artifacts=True, scratch_directory='/tmp', max_bytes=2147483648):
        self.destination = Path(destination)
        self.destination.mkdir(parents=True)
        self.max_bytes = max_bytes
        self.temporary = None
        if retain_artifacts:
            self.path = self.destination
        else:
            self.temporary = tempfile.TemporaryDirectory(prefix='stealerforge-run-', dir=scratch_directory)
            self.path = Path(self.temporary.name)

    def finish(self):
        omitted = []
        try:
            if self.temporary:
                omitted = publish_reports(self.path, self.destination, self.max_bytes)
                if omitted:
                    status_path = self.destination / 'run_status.json'
                    status = json.loads(status_path.read_text()) if status_path.is_file() else {}
                    if status.get('status') not in ('failed', 'interrupted'):
                        status['status'] = 'needs_review'
                    status['report_publication'] = 'partial'
                    write_json(status_path, status)
                    cti_path = self.destination / 'cape_cti_telemetry.json'
                    if cti_path.is_file():
                        from core.cti import render_advisory
                        cti = json.loads(cti_path.read_text())
                        cti['analysis']['status'] = status['status']
                        cti['coverage']['warnings'].append('Some worker reports were not exportable; see report_publication.json')
                        write_json(cti_path, cti)
                        (self.destination / 'threat_intel_report.md').write_text(render_advisory(cti), encoding='utf-8')
            write_json(self.destination / 'manifest.json', artifact_manifest(self.destination))
            return omitted
        except Exception as exc:
            write_json(self.destination / 'run_status.json', {
                'status': 'failed', 'error': f'Report publication failed: {type(exc).__name__}: {exc}'})
            write_json(self.destination / 'manifest.json', artifact_manifest(self.destination))
            raise
        finally:
            if self.temporary:
                self.temporary.cleanup()
