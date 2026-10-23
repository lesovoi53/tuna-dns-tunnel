"""Validated standalone settings and native MasterDnsVPN server configuration."""
import ipaddress
import json
import re
import secrets

METHODS = ('NONE (без шифрования)', 'XOR', 'ChaCha20', 'AES-128-GCM', 'AES-192-GCM', 'AES-256-GCM')
METHOD_NAMES = METHODS
CONFIG_PATH = '/etc/tuna-dns-tunnel/server_config.toml'


def key_length(method):
    if type(method) is not int or not 0 <= method < len(METHODS):
        raise ValueError('Метод шифрования должен быть целым числом от 0 до 5.')
    # The native core consumes UTF-8 text, not hex-decoded bytes.
    return {3: 16, 4: 24}.get(method, 32)


def generate_key(method):
    return secrets.token_hex(key_length(method) // 2)


def defaults():
    return dict(name='TUNA DNS Tunnel', domains=[], listen_host='0.0.0.0', port=53,
                encryption_method=5, key=generate_key(5),
                route=dict(mode='direct', host='127.0.0.1', port=10808, username='', password=''))


def validate_domains(domains):
    if not isinstance(domains, list) or not 1 <= len(domains) <= 16:
        raise ValueError('Нужно от 1 до 16 доменов.')
    seen = set()
    for domain in domains:
        if (not isinstance(domain, str) or len(domain) > 253 or '.' not in domain
                or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p)
                           for p in domain.split('.'))):
            raise ValueError('Некорректный домен: используйте DNS-имя без пробелов и завершающей точки.')
        if domain.lower() in seen:
            raise ValueError('Этот домен уже есть в списке (регистр не учитывается).')
        seen.add(domain.lower())
    return list(domains)


def _text(value, field, maximum, empty=False):
    if not isinstance(value, str):
        raise ValueError(f'{field}: требуется текст.')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        raise ValueError(f'{field}: требуется корректный UTF-8.') from None
    if (not empty and not value.strip()) or size > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f'{field}: некорректная длина или управляющие символы.')
    return value


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('Порт должен быть целым числом от 1 до 65535.')
    return value


def _host(value, numeric=False):
    _text(value, 'Адрес', 253)
    try:
        if '%' in value:
            raise ValueError
        ipaddress.ip_address(value)
    except ValueError:
        if numeric or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p)
                              for p in value.split('.')):
            raise ValueError('Некорректный адрес сервера.') from None
    return value


def validate(settings):
    expected = {'name', 'domains', 'listen_host', 'port', 'encryption_method', 'key', 'route'}
    if not isinstance(settings, dict) or set(settings) != expected:
        raise ValueError('Неизвестные или отсутствующие параметры сервера.')
    result = dict(settings)
    result['name'] = _text(settings['name'], 'Имя профиля', 256)
    result['domains'] = validate_domains(settings['domains'])
    result['listen_host'] = _host(settings['listen_host'], numeric=True)
    result['port'] = _port(settings['port'])
    length = key_length(settings['encryption_method'])
    key = _text(settings['key'], 'Ключ', 256).strip()
    if len(key.encode('utf-8')) != length:
        raise ValueError(f'Для выбранного метода ключ должен содержать {length} байт текста UTF-8.')
    result['key'] = key
    route = settings['route']
    if not isinstance(route, dict) or set(route) != {'mode', 'host', 'port', 'username', 'password'}:
        raise ValueError('Неизвестные или отсутствующие параметры маршрута.')
    route = dict(route)
    if route['mode'] not in ('direct', 'socks5'):
        raise ValueError('Маршрут должен быть direct или socks5.')
    route['host'] = _host(route['host'])
    route['port'] = _port(route['port'])
    for field in ('username', 'password'):
        route[field] = _text(route[field], 'Учётные данные SOCKS5', 255, empty=True)
    if bool(route['username']) != bool(route['password']):
        raise ValueError('SOCKS5 требует одновременно имя пользователя и пароль либо оба пустых поля.')
    result['route'] = route
    return result


def render(settings, key_file):
    settings = validate(settings)
    _text(key_file, 'Путь к ключу', 4096)
    route = settings['route']
    native = dict(DOMAIN=settings['domains'], PROTOCOL_TYPE='SOCKS5', UDP_HOST=settings['listen_host'],
                  UDP_PORT=settings['port'], UDP_READERS=4, DNS_REQUEST_WORKERS=4,
                  MAX_CONCURRENT_REQUESTS=16384, SOCKET_BUFFER_SIZE=8388608, MAX_PACKET_SIZE=4096,
                  DNS_UPSTREAM_SERVERS=['1.1.1.1:53', '8.8.8.8:53'],
                  USE_EXTERNAL_SOCKS5=route['mode'] == 'socks5',
                  SOCKS5_AUTH=route['mode'] == 'socks5' and bool(route['username']),
                  SOCKS5_USER=route['username'], SOCKS5_PASS=route['password'],
                  FORWARD_IP=route['host'], FORWARD_PORT=route['port'],
                  DATA_ENCRYPTION_METHOD=settings['encryption_method'], ENCRYPTION_KEY_FILE=key_file,
                  # Native INFO startup prints the active encryption key.
                  LOG_LEVEL='WARN')
    return ''.join(f'{key} = {json.dumps(value, ensure_ascii=False)}\n' for key, value in native.items())
