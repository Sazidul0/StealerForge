"""Generate a private, single-task CAPE configuration from the pinned defaults."""
import configparser
from pathlib import Path


def configure(root=Path('/opt/CAPEv2'), evidence=Path('/evidence'), timeout=180):
    custom = root / 'custom/conf'
    custom.mkdir(parents=True, exist_ok=True)

    def write(name, changes, enabled=None):
        config = configparser.ConfigParser(interpolation=None, strict=False)
        config.read(root / f'conf/default/{name}.conf.default')
        if enabled is not None:
            for section in config.sections():
                if config.has_option(section, 'enabled'):
                    config[section]['enabled'] = 'yes' if section in enabled else 'no'
        for section, values in changes.items():
            if not config.has_section(section):
                config.add_section(section)
            config[section].update({key: str(value) for key, value in values.items()})
        with (custom / f'{name}.conf').open('w') as stream:
            config.write(stream)

    write('cuckoo', {
        'cuckoo': {'machinery': 'stealerforge', 'machinery_screenshots': 'on', 'memory_dump': 'off',
                   'delete_original': 'off', 'delete_bin_copy': 'off', 'reschedule': 'off',
                   # Default 'yes' makes the max_analysis_count stop call sys.exit() before the task runs.
                   'ignore_signals': 'no',
                   'max_analysis_count': 1, 'max_machines_count': 1, 'freespace': 1024},
        'database': {'connection': 'sqlite:////opt/CAPEv2/db/cuckoo.db'},
        'resultserver': {'ip': '0.0.0.0', 'port': 2042, 'force_port': 'yes',
                         'upload_max_size': 134217728, 'do_upload_max_size': 'yes'},
        'processing': {'resolve_dns': 'off', 'reverse_dns': 'off', 'sort_pcap': 'off'},
        'timeouts': {'default': timeout, 'critical': 90, 'vm_state': 90},
    })
    write('stealerforge', {'stealerforge': {'machines': 'windows', 'interface': 'lo'},
          'windows': {'label': 'windows', 'platform': 'windows', 'arch': 'x64', 'tags': 'win10',
                      'ip': '127.0.0.1', 'resultserver_ip': '10.0.2.2', 'resultserver_port': 2042}})
    write('routing', {'routing': {'route': 'none', 'internet': 'none'}}, enabled=set())
    # Guest-side collectors: event logs (including the preinstalled Sysmon channel; CAPE's own sysmon module
    # only supports installing its renamed copy), AMSI/DNS/WMI ETW and human-like interaction. Screenshots are
    # taken by the machinery through QMP instead of inside the guest.
    write('auxiliary', {'auxiliary_modules': {
        'sysmon_windows': 'no', 'sysmon_export': 'yes', 'evtx': 'yes', 'amsi_etw': 'yes', 'dns_etw': 'yes', 'wmi_etw': 'yes',
        'human_windows': 'yes', 'screenshots_windows': 'no', 'disguise': 'yes', 'recentfiles': 'yes',
        'tlsdump': 'yes', 'filecollector': 'yes', 'browser': 'no'}}, enabled=set())
    write('reporting', {'jsondump': {'enabled': 'yes', 'indent': 2}}, enabled={'jsondump'})
    # CAPE_extractors loads the family config parsers; without it YARA hits never yield C2/botnet configs.
    write('processing', {}, enabled={'amsi_etw', 'analysisinfo', 'behavior', 'CAPE', 'CAPE_extractors', 'debug', 'dropped',
                                    'metadata', 'network', 'procmemory', 'static', 'target', 'strings'})
    write('integrations', {}, enabled=set())

    for directory in ('storage', 'log'):
        target = evidence / ('cape' if directory == 'storage' else 'cape-log')
        target.mkdir(parents=True, exist_ok=True)
        path = root / directory
        if not path.exists():
            path.symlink_to(target, target_is_directory=True)
    (root / 'db').mkdir(exist_ok=True)
