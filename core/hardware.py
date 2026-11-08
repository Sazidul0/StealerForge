"""Guest hardware identity: SMBIOS, ACPI OEM IDs, disk strings and MAC address matching the persona's machine.

QEMU's defaults ("QEMU", "BOCHS"/"BXPC", "QEMU HARDDISK", 52:54:00 MAC) are among the first things anti-VM code
checks. Values are applied at boot through a QEMU -readconfig file (spaces allowed) and machine properties, so
they can change without reinstalling the base. One profile is generated per base and reused for every clone.
"""
import secrets
import string
import uuid

MODELS = {
    'OptiPlex 7090': {'vendor': 'Dell Inc.', 'bios': '2.18.0', 'board': '0K240Y', 'sku': '0A5C', 'family': 'OptiPlex',
                      'oem': ('DELL', 'CBX3'), 'oui': 'B0:7B:25'},
    'Latitude 5420': {'vendor': 'Dell Inc.', 'bios': '1.31.2', 'board': '0X6D5G', 'sku': '0A1F', 'family': 'Latitude',
                      'oem': ('DELL', 'CBX3'), 'oui': 'B0:7B:25'},
    'HP EliteDesk 800 G6 Desktop Mini PC': {'vendor': 'HP', 'bios': 'S22 Ver. 02.18.00', 'board': '8715', 'sku': '1D2E6EC',
                                            'family': '103C_53307F HP EliteDesk', 'oem': ('HPQOEM', 'SLIC-BPC'),
                                            'oui': '9C:7B:EF'},
    'ThinkCentre M70q': {'vendor': 'LENOVO', 'bios': 'M2WKT49A', 'board': '3139', 'sku': 'LENOVO_MT_11DT',
                         'family': 'ThinkCentre M70q', 'oem': ('LENOVO', 'TC-M2W'), 'oui': 'E8:6A:64'},
}
DISKS = [('Samsung', 'SSD 870 EVO 500GB'), ('WDC', 'WDS500G2B0A'), ('Crucial', 'CT500MX500SSD1')]


def _token(length, alphabet=string.ascii_uppercase + string.digits):
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate(identity):
    model = MODELS.get(identity.get('model')) or MODELS['OptiPlex 7090']
    product = identity.get('model') if identity.get('model') in MODELS else 'OptiPlex 7090'
    disk_vendor, disk_product = secrets.choice(DISKS)
    serial = _token(7) if model['vendor'] == 'Dell Inc.' else ('MXL' + _token(7) if model['vendor'] == 'HP' else 'MJ0' + _token(5))
    year = secrets.choice([2024, 2025])
    return {
        'vendor': model['vendor'], 'product': product, 'serial': serial, 'uuid': str(uuid.uuid4()).upper(),
        'bios_version': model['bios'], 'bios_date': f'{secrets.randbelow(12) + 1:02d}/{secrets.randbelow(27) + 1:02d}/{year}',
        'board': model['board'], 'sku': model['sku'], 'family': model['family'],
        'acpi_oem_id': model['oem'][0], 'acpi_table_id': model['oem'][1],
        'mac': model['oui'] + ':' + ':'.join(f'{secrets.randbelow(256):02X}' for _ in range(3)),
        'disk_vendor': disk_vendor, 'disk_product': disk_product, 'disk_serial': 'S' + _token(14),
        'memory_vendor': 'Samsung', 'memory_part': 'M378A1K43EB2-CWE', 'memory_serial': _token(8, '0123456789ABCDEF'),
    }


def readconfig(profile):
    """QEMU -readconfig text: [smbios] and [global] groups accept values with spaces. The system UUID and serial
    also go to the launcher's UUID/BIOS_SERIAL variables, which emit their own -uuid and type-1 serial."""
    def group(name, **values):
        body = ''.join(f'  {key} = "{str(value).replace(chr(34), "")}"\n' for key, value in values.items())
        return f'[{name}]\n{body}\n'
    p = profile
    return (group('smbios', type='0', vendor=p['vendor'], version=p['bios_version'], date=p['bios_date'])
            + group('smbios', type='1', manufacturer=p['vendor'], product=p['product'], version='1.0',
                    serial=p['serial'], sku=p['sku'], family=p['family'])
            + group('smbios', type='2', manufacturer=p['vendor'], product=p['board'], version='A01',
                    serial=f'/{p["serial"]}/CN{p["disk_serial"][-10:]}/', asset='')
            + group('smbios', type='3', manufacturer=p['vendor'], version='', serial=p['serial'], asset='', sku='')
            + group('smbios', type='17', manufacturer=p['memory_vendor'], part=p['memory_part'],
                    serial=p['memory_serial'], speed='3200')
            + group('global', driver='scsi-hd', property='vendor', value=p['disk_vendor'][:8])
            + group('global', driver='scsi-hd', property='product', value=p['disk_product'][:16])
            + group('global', driver='scsi-hd', property='serial', value=p['disk_serial']))
