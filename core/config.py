"""Configuration and local setup checks. Never include credentials in diagnostics."""
import importlib.util
import math
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

DEPENDENCIES = {
    'requests': 'requests', 'pefile': 'pefile', 'lief': 'lief', 'yara': 'yara-python',
    'anthropic': 'anthropic', 'yaml': 'pyyaml', 'rich': 'rich',
    'pyperclip': 'pyperclip', 'sigma': 'pysigma', 'plyara': 'plyara',
    'pyzipper': 'pyzipper', 'Evtx': 'python-evtx', 'defusedxml': 'defusedxml',
}


def credential(section, key, env_key, default_env):
    value = os.environ.get(section.get(env_key, default_env), '') or section.get(key, '')
    if not isinstance(value, str):
        raise ValueError(f'{key} must be a string')
    if 'YOUR' in value.upper():
        return ''
    return value.strip()


def load_config(path):
    path = Path(path).resolve()
    cfg = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(cfg, dict):
        raise ValueError('Configuration must be a YAML mapping')
    for name in ('cape', 'static_analysis', 'token_maximizer', 'llm', 'enrichment', 'local_analysis', 'output',
                 'intake', 'forensics', 'safety', 'lab', 'batch', 'managed_lab'):
        cfg.setdefault(name, {})
        if not isinstance(cfg[name], dict):
            raise ValueError(f'{name} must be a mapping')
    defaults = {
        'cape': {'base_url': '', 'timeout_seconds': 180, 'poll_interval_seconds': 10,
                 'max_wait_seconds': 900, 'request_timeout_seconds': 30, 'max_artifacts': 20,
                 'max_download_bytes': 134217728, 'max_report_bytes': 268435456,
                 'download_unpacked_payloads': True, 'download_dropped_files': True,
                 'download_pcap': True, 'enforce_timeout': True, 'machine': '',
                 'download_evtx': False, 'download_process_memory': False, 'download_full_memory': False,
                 'max_forensic_bytes': 536870912},
        'static_analysis': {'yara_rules_path': 'rules/local_stealer_hunting.yar',
                            'min_string_length': 6, 'max_strings_per_binary': 800,
                            'max_file_bytes': 134217728, 'yara_timeout_seconds': 30},
        'token_maximizer': {'target_token_budget': 100000, 'chars_per_token_estimate': 3.0,
                            'max_api_calls_per_process': 450},
        'llm': {'use_api': False, 'model': 'claude-sonnet-4-6', 'max_output_tokens': 16384,
                'context_window_tokens': 200000, 'input_token_budget': 110000,
                'timeout_seconds': 300, 'copy_to_clipboard': False, 'prompt_caching': True,
                'report_tlp': 'clear'},
        'enrichment': {'timeout_seconds': 120, 'max_output_bytes': 16777216, 'memory_mb': 2048},
        'local_analysis': {'enabled': False, 'python_path': '', 'upx_path': '',
                           'shellcode_arch': '',
                           'speakeasy': True, 'cape_parsers': True, 'cape_yara_path': '',
                           'all_entrypoints': False, 'timeout_seconds': 120,
                           'emulation_seconds': 45, 'max_api_calls': 10000,
                           'max_instructions': 2000000, 'memory_mb': 2048,
                           'max_input_artifacts': 4, 'max_generated_artifacts': 24,
                           'max_generated_bytes': 134217728, 'max_region_bytes': 8388608,
                           'max_output_bytes': 33554432, 'yara_timeout_seconds': 10,
                           'max_parsers_per_artifact': 8},
        'output': {'directory': 'output', 'min_free_bytes': 268435456, 'max_run_bytes': 2147483648,
                   'retain_artifacts': True, 'scratch_directory': '/tmp'},
        'intake': {'max_archive_bytes': 134217728, 'max_member_bytes': 134217728,
                   'max_total_bytes': 268435456, 'max_members': 64, 'max_ratio': 1000,
                   'password_env': 'STEALERFORGE_ARCHIVE_PASSWORD', 'timeout_seconds': 60},
        'forensics': {'max_events': 25000, 'max_file_bytes': 134217728, 'timeout_seconds': 120,
                      'max_output_bytes': 67108864, 'archive_password_env': 'CAPE_ARCHIVE_PASSWORD'},
        'safety': {'require_container_controls': False},
        'lab': {'acceptance_file': '', 'snapshot': '', 'acceptance_max_age_hours': 24},
        'batch': {'max_total_bytes': 10737418240, 'max_job_seconds': 3600},
        'managed_lab': {'storage_directory': 'managed-data', 'state_directory': '.managed',
                        'min_free_gib': 80, 'reserve_free_gib': 8, 'min_available_gib': 8,
                        'provision_timeout_seconds': 7200, 'boot_timeout_seconds': 900,
                        'analysis_seconds': 300, 'task_timeout_seconds': 1200,
                        'enrichment_timeout_seconds': 3600, 'max_enrichment_artifacts': 8,
                        'adaptive_rerun': True, 'cpu_identity': 'default', 'guest_cpus': 4,
                        'monitor_options': 'procmemdump=1,import_reconstruction=1',
                        'public_ip': '203.0.113.24', 'persona_username': '', 'persona_hostname': '',
                        'persona_organization': '', 'persona_timezone': ''},
    }
    for section, values in defaults.items():
        for key, default in values.items():
            cfg[section].setdefault(key, default)
            value = cfg[section][key]
            if isinstance(default, bool):
                if not isinstance(value, bool):
                    raise ValueError(f'{section}.{key} must be a YAML boolean')
            elif isinstance(default, (int, float)):
                if (isinstance(value, bool) or not isinstance(value, (int, float))
                        or not math.isfinite(value) or value <= 0
                        or (isinstance(default, int) and not isinstance(value, int))):
                    raise ValueError(f'{section}.{key} must be a positive {type(default).__name__}')
            elif not isinstance(value, str):
                raise ValueError(f'{section}.{key} must be a string')
    if cfg['static_analysis']['min_string_length'] > 200:
        raise ValueError('min_string_length must be at most 200')
    if cfg['token_maximizer']['target_token_budget'] * cfg['token_maximizer']['chars_per_token_estimate'] < 4096:
        raise ValueError('Dossier budget must allow at least 4096 characters')
    llm = cfg['llm']
    if llm['input_token_budget'] + llm['max_output_tokens'] >= llm['context_window_tokens']:
        raise ValueError('LLM input + output budgets must leave room in context_window_tokens')
    if str(llm['report_tlp']).lower() not in ('clear', 'green', 'amber', 'amber+strict', 'red'):
        raise ValueError('llm.report_tlp must be clear, green, amber, amber+strict or red')
    for section, key in [('static_analysis', 'yara_rules_path'), ('output', 'directory'), ('output', 'scratch_directory'),
                         ('managed_lab', 'storage_directory'), ('managed_lab', 'state_directory')]:
        cfg[section][key] = str((path.parent / cfg[section][key]).resolve())
    if cfg['managed_lab']['reserve_free_gib'] >= cfg['managed_lab']['min_free_gib']:
        raise ValueError('managed_lab.reserve_free_gib must be below min_free_gib')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+=[A-Za-z0-9_.:-]+(,[A-Za-z0-9_.-]+=[A-Za-z0-9_.:-]+)*',
                        cfg['managed_lab']['monitor_options']):
        raise ValueError('managed_lab.monitor_options must be comma-separated key=value CAPE options')
    if cfg['managed_lab']['cpu_identity'] not in ('hyperv', 'bare', 'default'):
        raise ValueError('managed_lab.cpu_identity must be hyperv, bare or default')
    if cfg['managed_lab']['analysis_seconds'] >= cfg['managed_lab']['task_timeout_seconds']:
        raise ValueError('managed_lab.task_timeout_seconds must exceed analysis_seconds')
    for key in ('capa_path', 'floss_path'):
        value = cfg['enrichment'].get(key, '')
        if not isinstance(value, str):
            raise ValueError(f'enrichment.{key} must be a string')
        if value and ('/' in value or '\\' in value):
            cfg['enrichment'][key] = os.path.abspath(path.parent / value)
    for section, keys in [('local_analysis', ('python_path', 'upx_path', 'cape_yara_path', 'asset_manifest_path')),
                          ('enrichment', ('capa_rules_path', 'capa_signatures_path')),
                          ('lab', ('acceptance_file',))]:
        for key in keys:
            value = cfg[section].get(key, '')
            if not isinstance(value, str):
                raise ValueError(f'{section}.{key} must be a string')
            if value and (key in ('cape_yara_path', 'asset_manifest_path', 'capa_rules_path', 'capa_signatures_path', 'acceptance_file')
                          or '/' in value or '\\' in value):
                # Resolving a venv Python symlink selects the base interpreter and loses its packages.
                cfg[section][key] = os.path.abspath(path.parent / value)
    names = cfg['local_analysis'].setdefault('parser_names', [])
    if cfg['local_analysis']['shellcode_arch'] not in ('', 'x86', 'amd64'):
        raise ValueError('local_analysis.shellcode_arch must be empty, x86 or amd64')
    if not isinstance(names, list) or any(not isinstance(name, str) or not name.isidentifier() for name in names):
        raise ValueError('local_analysis.parser_names must be a list of installed Python module names')
    if not Path(cfg['static_analysis']['yara_rules_path']).is_file():
        raise ValueError('Configured YARA rules file does not exist')
    return cfg


def require_live_cape(cfg):
    parsed = urlparse(cfg.get('base_url', ''))
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError('cape.base_url must be an HTTP(S) API base URL without query or fragment')
    if parsed.username or parsed.password:
        raise ValueError('Use CAPE_API_TOKEN rather than credentials in cape.base_url')


def missing_dependencies():
    return [package for module, package in DEPENDENCIES.items() if importlib.util.find_spec(module) is None]
