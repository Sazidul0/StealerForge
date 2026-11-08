"""Victim persona and canary data for one clean base. Random per base; nothing here is a real account.

The guest provisioning script (guest/provision.py) plants these values into browsers, wallets and
applications. canary_strings() lists the exact values that prove theft when seen in captured traffic.
"""
import secrets
import string

FIRST = ['Michael', 'Sarah', 'David', 'Emily', 'James', 'Jessica', 'Daniel', 'Laura', 'Robert', 'Megan']
LAST = ['Reed', 'Carter', 'Hughes', 'Bennett', 'Foster', 'Russell', 'Coleman', 'Hayes', 'Palmer', 'Warren']
COMPANIES = ['Brightline Logistics', 'Northwind Advisory', 'Harbor Peak Dental', 'Summit Ridge Realty']
MACHINES = [('Dell Inc.', 'OptiPlex 7090'), ('HP', 'HP EliteDesk 800 G6 Desktop Mini PC'),
            ('LENOVO', 'ThinkCentre M70q'), ('Dell Inc.', 'Latitude 5420')]
WORDS = ('abandon ability absorb acoustic actress adjust afford agent alarm album alley amazing anchor ancient '
         'animal antique apple arena armor arrow artist august autumn avocado bamboo banner barrel basket beach '
         'believe bicycle blanket blossom bracket breeze bridge bronze bubble buffalo cabin cactus camera canyon '
         'carbon castle cattle cement century cherry chimney cinnamon circle climb clover coconut comfort copper '
         'cotton coyote crater crystal cushion dolphin donkey dragon eagle echo elephant ember emerald engine').split()
# Public Chrome Web Store IDs of wallet extensions that stealers enumerate.
WALLET_EXTENSIONS = {
    'nkbihfbeogaeaoehlefnkodbefgpgknn': 'MetaMask', 'bfnaelmomeimhlpmgjnjophhpkkoljpa': 'Phantom',
    'hnfanknocfeofbddgcijnmhnfnkdnaad': 'Coinbase Wallet', 'ibnejdfjmmkpcnlpebklmnkoeoihofec': 'TronLink',
    'fhbohimaelbohpjbbldcngcnapndodjp': 'Binance Wallet', 'fnjhmkhhmkbjkkabndcnnogagogbneec': 'Ronin Wallet',
    'egjidjbpglichdcondbcbdnbeeppgdph': 'Trust Wallet', 'acmacodkjbdgmoleebolmdjonilkdbch': 'Rabby',
    'dmkamcknogkgcdfhhbddcghachkejeap': 'Keplr', 'aholpfdialjgjfhomihkjbmgjidlcdno': 'Exodus Web3',
}
LOGIN_SITES = [('https://accounts.google.com/', 'Google'), ('https://login.live.com/', 'Microsoft'),
               ('https://www.facebook.com/', 'Facebook'), ('https://www.paypal.com/', 'PayPal'),
               ('https://www.binance.com/', 'Binance'), ('https://www.coinbase.com/', 'Coinbase'),
               ('https://github.com/', 'GitHub'), ('https://www.amazon.com/', 'Amazon'),
               ('https://discord.com/', 'Discord'), ('https://steamcommunity.com/', 'Steam'),
               ('https://www.netflix.com/', 'Netflix'), ('https://outlook.office.com/', 'Office 365')]
SESSION_COOKIES = [('.google.com', 'SID'), ('.google.com', '__Secure-3PSID'), ('.facebook.com', 'xs'),
                   ('.facebook.com', 'c_user'), ('.instagram.com', 'sessionid'), ('.roblox.com', '.ROBLOSECURITY'),
                   ('.discord.com', '__dcfduid'), ('.coinbase.com', 'cb_session'), ('.binance.com', 'p20t'),
                   ('.twitch.tv', 'auth-token'), ('.amazon.com', 'session-token'), ('.paypal.com', 'login_email'),
                   ('.tiktok.com', 'sessionid'), ('.x.com', 'auth_token'), ('.live.com', 'ESTSAUTHPERSISTENT')]
HISTORY = [('https://mail.google.com/mail/u/0/#inbox', 'Inbox - Gmail'), ('https://www.youtube.com/', 'YouTube'),
           ('https://www.binance.com/en/my/dashboard', 'Dashboard | Binance'),
           ('https://www.paypal.com/myaccount/summary', 'PayPal: Summary'),
           ('https://www.amazon.com/gp/css/order-history', 'Your Orders'),
           ('https://outlook.office.com/mail/', 'Mail - Outlook'), ('https://github.com/', 'GitHub'),
           ('https://www.chase.com/', 'Chase Online')]


def _token(length, alphabet=string.ascii_letters + string.digits):
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _password():
    return (_token(4, string.ascii_uppercase) + _token(4, string.ascii_lowercase) + secrets.choice('!#$%&*?')
            + _token(4, string.digits))


def generate(settings=None):
    settings = settings or {}
    rng = secrets.SystemRandom()
    first, last = rng.choice(FIRST), rng.choice(LAST)
    manufacturer, model = rng.choice(MACHINES)
    tail = str(rng.randint(10, 99))
    email = f'{first.lower()}.{last.lower()}{tail}'
    marker = _token(20)
    seed = ' '.join(rng.choice(WORDS) for _ in range(12))
    identity = {
        'username': settings.get('username') or first,
        'full_name': f'{first} {last}',
        'hostname': settings.get('hostname') or 'DESKTOP-' + _token(7, string.ascii_uppercase + string.digits),
        'organization': settings.get('organization') or rng.choice(COMPANIES),
        'manufacturer': manufacturer, 'model': model,
        'timezone': settings.get('timezone') or 'Eastern Standard Time',
    }
    canaries = {
        'marker': marker,
        'logins': [{'url': url, 'realm': url, 'age_days': rng.randint(40, 600),
                    'username': f'{email}@gmail.com' if name in ('Google', 'Discord', 'Steam') else f'{email}@outlook.com',
                    'password': _password()} for url, name in LOGIN_SITES],
        'cookies': [{'host': host, 'name': name, 'value': _token(48)} for host, name in SESSION_COOKIES],
        # Issuer-published test card number: never a real card.
        'card': {'name': f'{first} {last}', 'number': '4111111111111111', 'month': rng.randint(1, 12),
                 'year': rng.randint(2028, 2031)},
        'autofill': [('email', f'{email}@gmail.com'), ('phone', f'+1617555{rng.randint(1000, 9999)}'),
                     ('address', f'{rng.randint(10, 999)} Maple Street {marker[:6]}')],
        'wallet_vault': _token(64),
        'discord_token': (_token(24, string.ascii_letters + string.digits) + '.' + _token(6) + '.'
                          + _token(27, string.ascii_letters + string.digits + '-_')),
        'steam_account': f'{first.lower()}{last.lower()}_{tail}',
        'steam_id_suffix': str(rng.randint(100000000, 999999999)),
        'steam_token': _token(40),
        'ftp': {'host': f'ftp.{identity["organization"].split()[0].lower()}-files.com', 'user': email,
                'password': _password()},
        'vpn': {'user': f'{email}@outlook.com', 'password': _password(), 'server': f'vpn{tail}.example-corp.net'},
        'desktop_wallets': {'seed': seed, 'xpub': 'xpub' + _token(107), 'passphrase': _password(),
                            'eth_address': secrets.token_hex(20), 'eth_ciphertext': secrets.token_hex(32)},
        'im': {'user': f'{email}@jabber.org', 'password': _password()},
    }
    login = canaries['logins']
    documents = {
        'Desktop\\passwords.txt': '\n'.join(f'{item["realm"]}  {item["username"]}  {item["password"]}' for item in login[:6]),
        'Documents\\crypto\\seed backup.txt': f'Metamask recovery phrase - DO NOT SHARE\n{seed}\n',
        'Documents\\Finance\\bank details.txt': f'Chase checking\nAccount: 4{rng.randint(10**8, 10**9 - 1)}\n'
                                                f'Online banking user: {email}\nPassword: {canaries["logins"][3]["password"]}\n',
        'Desktop\\to do.txt': 'call dentist\nrenew car insurance\nsend invoice to Mark\n',
        'Documents\\Work\\meeting notes.txt': f'Q3 planning\nVPN login {canaries["vpn"]["user"]} / {canaries["vpn"]["password"]}\n',
    }
    return {'identity': identity, 'canaries': canaries, 'history': HISTORY,
            'wallet_extensions': WALLET_EXTENSIONS, 'documents': documents,
            'sysmon': {'service': 'PerfDiagSvc', 'driver': 'PerfDiag'}}


def canary_strings(persona):
    """(kind, value) pairs whose appearance in captured traffic or archives shows that data was stolen."""
    c = persona['canaries']
    values = [('marker', c['marker']), ('wallet_vault', c['wallet_vault']), ('discord_token', c['discord_token']),
              ('steam_token', c['steam_token']), ('ftp_password', c['ftp']['password']),
              ('vpn_password', c['vpn']['password']), ('wallet_seed', c['desktop_wallets']['seed']),
              ('wallet_passphrase', c['desktop_wallets']['passphrase']),
              ('eth_ciphertext', c['desktop_wallets']['eth_ciphertext']), ('im_password', c['im']['password'])]
    values += [(f'browser_password:{item["realm"]}', item['password']) for item in c['logins']]
    values += [(f'browser_cookie:{item["host"]}:{item["name"]}', item['value']) for item in c['cookies']]
    values += [('card_holder_and_number', c['card']['number'])]
    return values
