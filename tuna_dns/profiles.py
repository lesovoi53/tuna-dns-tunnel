#!/usr/bin/env python3
"""Local client-link presets. Does not edit or restart the DNS tunnel server."""
import argparse
from contextlib import contextmanager
import ipaddress
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile


RESOLVERS = '\n'.join(('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9',
                       '77.88.8.8', '77.88.8.1', '77.88.8.2', '77.88.8.3', '77.88.8.7', '77.88.8.88'))
BASE = dict(resolvers=RESOLVERS, resolver_balancing_strategy=5,
            upload_compression_type=2, download_compression_type=2,
            rx_tx_workers=16, tunnel_process_workers=0, max_packets_per_batch=8,
            arq_window_size=600, arq_max_rto_seconds=5)
PRESETS = {
    1: dict(packet_duplication_count=4, setup_packet_duplication_count=4, base_encode_data=True,
            min_upload_mtu=28, max_upload_mtu=200, min_download_mtu=60, max_download_mtu=900,
            arq_initial_rto_seconds=2, ping_aggressive_interval_seconds=0.05,
            ping_lazy_interval_seconds=0.5, ping_cooldown_interval_seconds=2, ping_cold_interval_seconds=15),
    2: dict(packet_duplication_count=2, setup_packet_duplication_count=2, base_encode_data=False,
            min_upload_mtu=38, max_upload_mtu=150, min_download_mtu=100, max_download_mtu=500,
            arq_initial_rto_seconds=1, ping_aggressive_interval_seconds=0.1,
            ping_lazy_interval_seconds=0.75, ping_cooldown_interval_seconds=2, ping_cold_interval_seconds=15),
    3: dict(packet_duplication_count=1, setup_packet_duplication_count=2, base_encode_data=False,
            min_upload_mtu=38, max_upload_mtu=150, min_download_mtu=100, max_download_mtu=500,
            arq_initial_rto_seconds=1, ping_aggressive_interval_seconds=0.1,
            ping_lazy_interval_seconds=0.75, ping_cooldown_interval_seconds=4, ping_cold_interval_seconds=30),
}
# Bounds follow the native client configuration. Zero workers means core defaults/automatic.
LIMITS = {
    'resolver_balancing_strategy': (int, 0, 8),
    'upload_compression_type': (int, 0, 3), 'download_compression_type': (int, 0, 3),
    'rx_tx_workers': (int, 0, 128), 'tunnel_process_workers': (int, 0, 128),
    'max_packets_per_batch': (int, 1, 64), 'arq_window_size': (int, 1, 8000),
    'packet_duplication_count': (int, 1, 10), 'setup_packet_duplication_count': (int, 1, 12),
    'min_upload_mtu': (int, 1, 65535), 'max_upload_mtu': (int, 1, 65535),
    'min_download_mtu': (int, 1, 65535), 'max_download_mtu': (int, 1, 65535),
    'arq_initial_rto_seconds': (float, 0.01, 60), 'arq_max_rto_seconds': (float, 0.01, 120),
    'ping_aggressive_interval_seconds': (float, 0.01, 30),
    'ping_lazy_interval_seconds': (float, 0.01, 60),
    'ping_cooldown_interval_seconds': (float, 0.01, 300),
    'ping_cold_interval_seconds': (float, 0.01, 3600),
}
GROUPS = (
    ('Резолверы', ('resolvers',)),
    ('Балансировка и дублирование', ('resolver_balancing_strategy', 'packet_duplication_count', 'setup_packet_duplication_count')),
    ('Сжатие', ('upload_compression_type', 'download_compression_type')),
    ('Рабочие потоки', ('rx_tx_workers', 'tunnel_process_workers')),
    ('MTU туннеля', ('min_upload_mtu', 'max_upload_mtu', 'min_download_mtu', 'max_download_mtu')),
    ('ARQ', ('arq_window_size', 'arq_initial_rto_seconds', 'arq_max_rto_seconds')),
    ('Интервалы ping', ('ping_aggressive_interval_seconds', 'ping_lazy_interval_seconds',
                       'ping_cooldown_interval_seconds', 'ping_cold_interval_seconds')),
    ('Другие параметры', ('max_packets_per_batch', 'base_encode_data')),
)
LABELS = {
    'resolvers': 'DNS-резолверы', 'resolver_balancing_strategy': 'Стратегия балансировки',
    'packet_duplication_count': 'Копии пакетов данных', 'setup_packet_duplication_count': 'Копии пакетов подключения',
    'upload_compression_type': 'Сжатие исходящего трафика', 'download_compression_type': 'Сжатие входящего трафика',
    'rx_tx_workers': 'Потоки приёма/передачи', 'tunnel_process_workers': 'Потоки обработки туннеля',
    'min_upload_mtu': 'Минимальный MTU отправки', 'max_upload_mtu': 'Максимальный MTU отправки',
    'min_download_mtu': 'Минимальный MTU приёма', 'max_download_mtu': 'Максимальный MTU приёма',
    'arq_window_size': 'Размер окна ARQ', 'arq_initial_rto_seconds': 'Начальный RTO, секунды',
    'arq_max_rto_seconds': 'Максимальный RTO, секунды',
    'ping_aggressive_interval_seconds': 'Активный ping, секунды', 'ping_lazy_interval_seconds': 'Редкий ping, секунды',
    'ping_cooldown_interval_seconds': 'Ping при снижении активности, секунды',
    'ping_cold_interval_seconds': 'Ping при простое, секунды',
    'max_packets_per_batch': 'Максимум пакетов в пачке', 'base_encode_data': 'Base64-кодирование данных',
}


def defaults(preset):
    if type(preset) is not int or preset not in PRESETS:
        raise ValueError('Номер профиля должен быть 1, 2 или 3.')
    return {**BASE, **PRESETS[preset]}


def validate_resolvers(value):
    if not isinstance(value, str) or len(value) > 16384:
        raise ValueError('Резолверы должны быть списком IP-адресов.')
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not 1 <= len(lines) <= 128:
        raise ValueError('Нужно от 1 до 128 резолверов, каждый на отдельной строке.')
    seen = set()
    for line in lines:
        host, port = line, 53
        if line.startswith('['):
            closing = line.find(']')
            if closing < 0:
                raise ValueError('Неверный IPv6-адрес резолвера.')
            host, tail = line[1:closing], line[closing + 1:]
            if ':' not in host or (tail and not tail.startswith(':')):
                raise ValueError('Используйте [IPv6]:порт.')
            if tail:
                port_text = tail[1:]
                if not port_text.isascii() or not port_text.isdigit():
                    raise ValueError('Порт резолвера должен быть числом.')
                port = int(port_text)
        elif line.count(':') == 1:
            host, port_text = line.split(':')
            if not port_text.isascii() or not port_text.isdigit():
                raise ValueError('Порт резолвера должен быть числом.')
            port = int(port_text)
        if '%' in host or not 1 <= port <= 65535:
            raise ValueError('Неверный адрес или порт резолвера.')
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError('Нужен числовой IP резолвера, без имени хоста.') from None
        identity = (address.ipv4_mapped or address if isinstance(address, ipaddress.IPv6Address) else address, port)
        if identity in seen:
            raise ValueError('В списке есть повторяющийся резолвер.')
        seen.add(identity)
    return '\n'.join(lines)


def validate(settings):
    if not isinstance(settings, dict) or set(settings) != set(defaults(1)):
        raise ValueError('Неизвестные или отсутствующие параметры профиля ссылки.')
    result = dict(settings)
    result['resolvers'] = validate_resolvers(result['resolvers'])
    if type(result['base_encode_data']) is not bool:
        raise ValueError('base_encode_data должен быть true или false.')
    for field, (kind, low, high) in LIMITS.items():
        value = result[field]
        valid_type = type(value) is int if kind is int else type(value) in (int, float)
        if not valid_type or not low <= value <= high or not math.isfinite(value):
            raise ValueError(f'{field}: допустимый диапазон {low}–{high}.')
    pairs = [('min_upload_mtu', 'max_upload_mtu'), ('min_download_mtu', 'max_download_mtu'),
             ('packet_duplication_count', 'setup_packet_duplication_count'),
             ('arq_initial_rto_seconds', 'arq_max_rto_seconds'),
             ('ping_aggressive_interval_seconds', 'ping_lazy_interval_seconds'),
             ('ping_lazy_interval_seconds', 'ping_cooldown_interval_seconds'),
             ('ping_cooldown_interval_seconds', 'ping_cold_interval_seconds')]
    for low, high in pairs:
        if result[low] > result[high]:
            raise ValueError(f'{low} не должен превышать {high}.')
    return result


def storage_path(config):
    return Path(config).with_name('client_link_profiles.json')


def snapshot(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Файл настроек ссылок не должен быть symlink.')
    try:
        metadata = path.stat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 262144:
        raise ValueError('Некорректный файл настроек ссылок.')
    return path.read_bytes()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Повторяющееся поле в настройках ссылок.')
        result[key] = value
    return result


def decode(data):
    if data is None:
        return {'version': 1, 'profiles': {}}
    try:
        stored = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('Повреждён JSON настроек ссылок; автоматическая замена запрещена.') from None
    if (not isinstance(stored, dict) or set(stored) != {'version', 'profiles'}
            or type(stored['version']) is not int or stored['version'] != 1
            or not isinstance(stored['profiles'], dict)
            or not set(stored['profiles']) <= {'1', '2', '3'}):
        raise ValueError('Неподдерживаемый формат настроек ссылок.')
    return {'version': 1, 'profiles': {key: validate(value) for key, value in stored['profiles'].items()}}


def effective(config, preset):
    baseline = defaults(preset)
    stored = decode(snapshot(storage_path(config)))
    return dict(stored['profiles'].get(str(preset), baseline))


@contextmanager
def locked(path):
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    lock_path = Path(str(path) + '.lock')
    if lock_path.is_symlink():
        raise ValueError('Файл блокировки не должен быть symlink.')
    fd = os.open(lock_path, flags, 0o600)
    try:
        if os.name == 'posix':
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'0')
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        yield
    finally:
        os.close(fd)


def save(path, preset, settings, expected):
    defaults(preset)
    settings = validate(settings)
    path = Path(path)
    with locked(path):
        current = snapshot(path)
        if current != expected:
            raise ValueError('Настройки уже изменились. Откройте меню заново.')
        stored = decode(current)
        stored['profiles'][str(preset)] = settings
        data = (json.dumps(stored, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')
        metadata = path.stat() if current is not None else None
        fd, temporary = tempfile.mkstemp(prefix='.masterdns-link-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o600)
            if metadata and os.name == 'posix':
                os.chown(temporary, metadata.st_uid, metadata.st_gid)
            os.replace(temporary, path)
            if os.name == 'posix':
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def edit_group(draft, fields, ask=input):
    print('\n0) Назад')
    for index, field in enumerate(fields, 1):
        print(f'{index}) {LABELS[field]} ({field}): {draft[field]}')
    selected = ask('Параметр: ').strip()
    if selected == '0':
        return
    if not selected.isdigit() or not 1 <= int(selected) <= len(fields):
        raise ValueError('Выберите номер параметра.')
    field = fields[int(selected) - 1]
    if field == 'resolvers':
        print('IP или IP:порт, IPv6: [адрес]:порт. По одному на строке; пустая строка завершает ввод.')
        lines = []
        while True:
            line = ask('> ').strip()
            if not line:
                break
            lines.append(line)
            if len(lines) > 128:
                raise ValueError('Не более 128 резолверов.')
        draft[field] = validate_resolvers('\n'.join(lines))
    elif field == 'base_encode_data':
        value = ask('true / false: ').strip().lower()
        if value not in ('true', 'false'):
            raise ValueError('Введите true или false.')
        draft[field] = value == 'true'
    else:
        kind, low, high = LIMITS[field]
        if field == 'resolver_balancing_strategy':
            print('0: Round Robin по умолчанию; 1: случайно; 2: Round Robin; 3: минимум потерь; '
                  '4: минимум задержки; 5: общая оценка; 6: потери, затем задержка; '
                  '7: случайно среди лучших по потерям; 8: Round Robin среди лучших по потерям.')
        elif field.endswith('_compression_type'):
            print('0: без сжатия; 1: ZSTD; 2: LZ4; 3: ZLIB.')
        suffix = ' · 0 = автоматически/по умолчанию ядра' if field.endswith('_workers') else ''
        value = kind(ask(f'{field} ({low}–{high}{suffix}): ').strip())
        if not math.isfinite(value) or not low <= value <= high:
            raise ValueError('Значение вне допустимого диапазона.')
        draft[field] = value
    # Cross-field checks run on save, allowing both bounds to be edited in either order.


def menu(config, preset, ask=input):
    path = storage_path(config)
    expected = snapshot(path)
    stored = decode(expected)
    draft = dict(stored['profiles'].get(str(preset), defaults(preset)))
    while True:
        print(f'\nПараметры клиентской ссылки · профиль {preset}')
        print('Изменения относятся к новым ссылкам; существующие профили клиентов не меняются.')
        for index, (title, _) in enumerate(GROUPS, 1):
            print(f'{index}) {title}')
        print('p) Просмотр всех параметров\nr) Сбросить черновик к исходному пресету\ns) Сохранить\n0) Выйти без сохранения')
        try:
            choice = ask('Выбор: ').strip().lower()
            if choice == '0':
                return False
            if choice == 'p':
                print(json.dumps(draft, ensure_ascii=False, indent=2))
            elif choice == 'r':
                draft = defaults(preset)
                print('Сброшен только черновик. Для применения выберите «Сохранить».')
            elif choice == 's':
                save(path, preset, draft, expected)
                print('Параметры ссылок сохранены. Служба и пользователи не изменены.')
                return True
            elif choice.isdigit() and 1 <= int(choice) <= len(GROUPS):
                edit_group(draft, GROUPS[int(choice) - 1][1], ask)
            else:
                print('Выберите пункт меню.')
        except (ValueError, OverflowError) as error:
            print(f'Ошибка: {error}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/etc/tuna-dns-tunnel/server_config.toml'))
    parser.add_argument('command', choices=('effective', 'menu'))
    parser.add_argument('preset', type=int, choices=(1, 2, 3))
    args = parser.parse_args()
    try:
        if args.command == 'effective':
            print(json.dumps(effective(args.config, args.preset), ensure_ascii=False, allow_nan=False))
        else:
            menu(args.config, args.preset)
    except (OSError, ValueError, EOFError) as error:
        print(f'Ошибка настроек ссылок MasterDNS: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nИзменения не сохранены.', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())
