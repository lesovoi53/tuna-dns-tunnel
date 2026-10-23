"""Isolated, transactional Linux installation of TUNA DNS Tunnel.

The alternate root and injected subprocess runner are for tests only. No host
commands or sockets are used with an alternate root.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

from . import config

UNIT = 'tuna-dns-tunnel.service'
FW_UNIT = 'tuna-dns-tunnel-firewall.service'
MARKER = '# Managed by TUNA DNS Tunnel'
COMMENT = 'TUNA_DNS_TUNNEL'
ASSET_URL = 'https://github.com/lesovoi53/x-manager-lite/releases/download/v2026.10.23.2/masterdns-amd64.tar.gz'
ASSET_SHA256 = '597bdc510b896a3b4ac89865ee7cefa73191025c64093f5e0f85c76a70430de9'
ASSET_MEMBER = 'MasterDnsVPN_Server_Linux_AMD64_v2026.06.13.234407-7de2476'
ETC = '/etc/tuna-dns-tunnel'
LIB = '/usr/local/lib/tuna-dns-tunnel'
SHARE = '/usr/local/share/tuna-dns-tunnel'
WRAPPER = '/usr/local/bin/tuna-dns'
UNIT_PATH = '/etc/systemd/system/' + UNIT
FW_PATH = '/etc/systemd/system/' + FW_UNIT
STATE = ETC + '/installation.json'
SETTINGS = ETC + '/settings.json'
KEY = ETC + '/encrypt_key.txt'
NATIVE_CONFIG = ETC + '/server_config.toml'
LIMIT = 128 * 1024 * 1024
OWN_DIRS = (ETC, LIB, SHARE)
OWN_FILES = (WRAPPER, UNIT_PATH, FW_PATH)


class BackendError(RuntimeError):
    """An operation failed; its message is safe to show without credentials."""


@dataclass
class Snapshot:
    files: dict
    services: dict
    firewall: dict | None
    firewall_open: bool


class Manager:
    def __init__(self, root=Path('/'), source=None, runner=None):
        self.root = Path(root).absolute()
        self.live = self.root == Path('/').absolute()
        if not self.live and runner is None:
            raise BackendError('Тестовый root требует явно заданного runner; команды хоста запрещены.')
        self.runner = runner or subprocess.run
        self.source = Path(source).absolute() if source else Path(__file__).resolve().parent.parent

    def path(self, name):
        return self.root / name.lstrip('/')

    def _safe(self, path, directory=None):
        path = Path(path)
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            raise BackendError('Путь находится вне корня установки.') from None
        current = self.root
        for part in ('', *relative.parts):
            if part:
                current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode):
                raise BackendError(f'Символическая ссылка запрещена: {current}')
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise BackendError(f'Недопустимый тип файла: {current}')
            shared_lock_directory = current == self.path('/run/lock') and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX
            if self.live and (info.st_uid != 0 or (info.st_mode & 0o022 and not shared_lock_directory)):
                raise BackendError(f'Небезопасный владелец или права: {current}')
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise BackendError(f'Жёсткие ссылки запрещены: {current}')
        if path.exists() and directory is not None and path.is_dir() != directory:
            raise BackendError(f'Неверный тип пути: {path}')
        return path

    def _read(self, name):
        path = self._safe(self.path(name), False)
        if path.stat().st_size > LIMIT:
            raise BackendError(f'Слишком большой файл: {path}')
        return path.read_bytes()

    def _write(self, name, data, mode=0o600):
        path = self._safe(self.path(name), False)
        self._safe(path.parent, True)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.tuna-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.chmod(temporary, mode)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _json(self, name, data):
        self._write(name, (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode())

    def _run(self, args, allowed=(0,)):
        try:
            result = self.runner(list(args), capture_output=True, text=True, timeout=90, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise BackendError(f'Команда {args[0]} не выполнена: {error}') from error
        if result.returncode not in allowed:
            details = (result.stderr or result.stdout or '').strip()[:1500]
            raise BackendError(f'Команда {shlex.join(args)}: код {result.returncode}. {details}')
        return result

    def _service_state(self, unit):
        active = self._run(['systemctl', 'is-active', unit], (0, 3, 4)).stdout.strip()
        enabled = self._run(['systemctl', 'is-enabled', unit], (0, 1, 3, 4)).stdout.strip()
        if active not in ('active', 'inactive', 'failed', 'unknown', ''):
            raise BackendError(f'Служба {unit} занята: {active}')
        if enabled not in ('enabled', 'disabled', 'not-found', ''):
            raise BackendError(f'Неподдерживаемое состояние службы {unit}: {enabled}')
        return {'active': active == 'active', 'enabled': enabled == 'enabled'}

    def _state(self):
        if not self._safe(self.path(STATE), False).exists():
            return None
        try:
            value = json.loads(self._read(STATE))
            if value.get('owner') != COMMENT or value.get('schema') != 1 or type(value.get('installed')) is not bool:
                raise ValueError
            self._validate_firewall(value['firewall'])
            return value
        except (ValueError, KeyError, TypeError):
            raise BackendError('Некорректный манифест установки; автоматическое присвоение файлов запрещено.') from None

    def _check_owned(self):
        state = self._state()
        for unit in (UNIT, FW_UNIT):
            for directory in ('/usr/lib/systemd/system', '/lib/systemd/system', '/run/systemd/system', '/run/systemd/generator'):
                if self.path(directory + '/' + unit).exists():
                    raise BackendError(f'Имя службы уже занято внешним unit: {directory}/{unit}')
        for name in (*OWN_DIRS, *OWN_FILES):
            path = self._safe(self.path(name))
            if path.exists() and state is None:
                raise BackendError(f'Путь уже существует и не принадлежит этой установке: {path}')
        for name in (UNIT_PATH, FW_PATH, WRAPPER):
            path = self.path(name)
            if path.exists() and MARKER.encode() not in self._read(name):
                raise BackendError(f'Файл не содержит маркер владельца: {path}')
        self._files()  # Reject links or special files anywhere inside owned directories.
        return state

    def _preflight(self):
        if self.live:
            if platform.system() != 'Linux' or os.geteuid() != 0:
                raise BackendError('Нужен Linux и запуск от root.')
            if platform.machine() not in ('x86_64', 'amd64'):
                raise BackendError('Поддерживается только amd64/x86_64.')
            if sys.version_info < (3, 11):
                raise BackendError('Нужен Python 3.11 или новее.')
            if not self.path('/run/systemd/system').is_dir():
                raise BackendError('Нужна работающая systemd.')
        release_path = self.path('/etc/os-release')
        if release_path.is_symlink():
            # Debian uses this standard read-only symlink. Installation
            # destinations still reject all symbolic links.
            if release_path.resolve() != self.path('/usr/lib/os-release').resolve():
                raise BackendError('Неожиданная ссылка /etc/os-release.')
            os_release = self._read('/usr/lib/os-release').decode()
        else:
            os_release = self._read('/etc/os-release').decode()
        values = {}
        for line in os_release.splitlines():
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                tokens = shlex.split(value)
                values[key] = tokens[0] if len(tokens) == 1 else ''
        if values.get('ID') != 'debian' or values.get('VERSION_ID') not in ('12', '13'):
            raise BackendError('Поддерживаются только Debian 12 и Debian 13.')
        self._check_owned()
        if self.live:
            for name in ('systemctl', 'python3'):
                if not shutil.which(name):
                    raise BackendError(f'Нет зависимости: {name}')

    @contextmanager
    def _lock(self):
        path = self._safe(self.path('/run/lock/tuna-dns-tunnel.lock'), False)
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags, 0o600)
        try:
            if os.name == 'posix':
                import fcntl
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise BackendError('Другая операция TUNA DNS Tunnel уже выполняется.') from None
            yield
        finally:
            os.close(fd)

    def status(self):
        state = self._check_owned()
        installed = bool(state and state['installed'])
        settings = config.validate(json.loads(self._read(SETTINGS))) if state else None
        services = self._service_state(UNIT) if installed else {'active': False, 'enabled': False}
        return dict(installed=installed, settings=settings, **services)

    def _validated(self, settings):
        settings = config.validate(settings)
        if ipaddress.ip_address(settings['listen_host']).version != 4:
            raise BackendError('Эта версия установщика поддерживает только IPv4 UDP listener.')
        return settings

    def _bind_check(self, settings):
        if not self.live:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
                listener.bind((settings['listen_host'], settings['port']))
        except OSError as error:
            raise BackendError(f"Нельзя занять {settings['listen_host']}:{settings['port']}/UDP; существующая DNS-служба не изменена: {error}") from error

    def _firewall_backend(self):
        path = self._safe(self.path('/etc/ufw/ufw.conf'), False)
        enabled = path.exists() and any(line.strip().replace(' ', '') in ('ENABLED=yes', 'ENABLED="yes"', "ENABLED='yes'") for line in path.read_text().splitlines())
        kind = 'ufw' if enabled else 'iptables'
        if self.live and not shutil.which(kind):
            raise BackendError(f'Нет зависимости {kind}; установите её системным пакетным менеджером.')
        return kind

    @staticmethod
    def _validate_firewall(firewall):
        if (not isinstance(firewall, dict) or set(firewall) != {'kind', 'host', 'port', 'open'}
                or firewall['kind'] not in ('ufw', 'iptables') or type(firewall['open']) is not bool
                or type(firewall['port']) is not int or not 1 <= firewall['port'] <= 65535
                or ipaddress.ip_address(firewall['host']).version != 4):
            raise ValueError('Некорректная запись firewall.')

    def _fw_args(self, firewall):
        host = firewall['host']
        destination = '0.0.0.0/0' if host == '0.0.0.0' else host
        if firewall['kind'] == 'ufw':
            return ['allow', 'proto', 'udp', 'from', '0.0.0.0/0', 'to', destination, 'port', str(firewall['port']), 'comment', COMMENT]
        return ['INPUT', '-p', 'udp', '-d', destination, '--dport', str(firewall['port']), '-m', 'comment', '--comment', COMMENT, '-j', 'ACCEPT']

    def _fw_has(self, firewall):
        self._validate_firewall(firewall)
        if firewall['kind'] == 'iptables':
            return self._run(['iptables', '-w', '10', '-C', *self._fw_args(firewall)], (0, 1)).returncode == 0
        return any(owned for owned in self._ufw_matching(firewall))

    def _ufw_matching(self, firewall):
        """Read both canonical UFW forms; comments are part of ownership.

        UFW can shorten `proto udp from any to any port N` to `N/udp`.
        Never issue `allow` for an equivalent foreign rule: UFW may replace
        its comment instead of creating a separate rule.
        """
        matches = []
        lines = self._run(['ufw', 'show', 'added']).stdout.splitlines()
        for line in lines:
            tokens = shlex.split(line)
            if tokens and tokens[0] == 'ufw':
                tokens = tokens[1:]
            comment = ''
            if 'comment' in tokens:
                index = tokens.index('comment')
                if len(tokens) != index + 2:
                    continue
                comment = tokens[index + 1]
                tokens = tokens[:index]
            if not tokens or tokens.pop(0) != 'allow':
                continue
            if tokens and tokens[0] == 'in':
                tokens.pop(0)
            host, source, port, protocol = '0.0.0.0/0', '0.0.0.0/0', None, None
            if len(tokens) == 1 and '/' in tokens[0]:
                port, protocol = tokens[0].rsplit('/', 1)
            elif len(tokens) == 8 and tokens[::2] == ['proto', 'from', 'to', 'port']:
                protocol, source, host, port = tokens[1::2]
            else:
                continue
            try:
                source = ipaddress.ip_network('0.0.0.0/0' if source == 'any' else source, strict=False)
                host = ipaddress.ip_network('0.0.0.0/0' if host == 'any' else host, strict=False)
                expected = ipaddress.ip_network('0.0.0.0/0' if firewall['host'] == '0.0.0.0' else firewall['host'])
            except ValueError:
                continue
            if (source == ipaddress.ip_network('0.0.0.0/0') and host == expected
                    and protocol == 'udp' and port == str(firewall['port'])):
                matches.append(comment == COMMENT)
        return matches

    def _fw_set(self, firewall, opened):
        present = self._fw_has(firewall)
        if present == opened:
            return
        args = self._fw_args(firewall)
        if firewall['kind'] == 'ufw':
            if opened and any(not owned for owned in self._ufw_matching(firewall)):
                raise BackendError('Эквивалентное правило UFW принадлежит администратору; изменение его комментария запрещено.')
            self._run(['ufw', *(args if opened else ['--force', 'delete', *args])])
        else:
            self._run(['iptables', '-w', '10', '-I' if opened else '-D', *args])
        if self._fw_has(firewall) != opened:
            raise BackendError('Firewall не подтвердил собственное правило; чужие правила не изменялись.')

    def _files(self):
        files = {}
        for name in OWN_DIRS:
            directory = self._safe(self.path(name), True)
            if directory.exists():
                for path in directory.rglob('*'):
                    self._safe(path)
                    if path.is_file():
                        relative = '/' + path.relative_to(self.root).as_posix()
                        files[relative] = (self._read(relative), stat.S_IMODE(path.stat().st_mode))
        for name in OWN_FILES:
            if self._safe(self.path(name), False).exists():
                files[name] = (self._read(name), stat.S_IMODE(self.path(name).stat().st_mode))
        return files

    def _snapshot(self):
        state = self._state()
        firewall = state['firewall'] if state and state['installed'] else None
        return Snapshot(self._files(), {unit: self._service_state(unit) for unit in (UNIT, FW_UNIT)},
                        firewall, self._fw_has(firewall) if firewall else False)

    def _remove(self, names):
        for name in names:
            path = self._safe(self.path(name), False)
            if path.exists():
                path.unlink()
        for name in OWN_DIRS:
            directory = self._safe(self.path(name), True)
            if directory.exists():
                for child in sorted(directory.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                    self._safe(child)
                    if child.is_dir() and not any(child.iterdir()):
                        child.rmdir()
                if not any(directory.iterdir()):
                    directory.rmdir()

    def _restore_files(self, files):
        self._remove(set(self._files()) - set(files))
        self._make_dirs()
        for name, (data, mode) in files.items():
            self._write(name, data, mode)
        self._remove(())

    def _restore_services(self, services):
        for unit in (FW_UNIT, UNIT):
            wanted = services[unit]
            path = FW_PATH if unit == FW_UNIT else UNIT_PATH
            if self.path(path).exists():
                self._run(['systemctl', 'enable' if wanted['enabled'] else 'disable', unit])
                if self._service_state(unit)['active'] != wanted['active']:
                    self._run(['systemctl', 'start' if wanted['active'] else 'stop', unit])

    @contextmanager
    def _transaction(self):
        before = self._snapshot()
        try:
            yield before
        except Exception as original:
            failures = []
            def attempt(action):
                try:
                    action()
                except Exception as error:
                    failures.append(str(error))
            try:
                current = self._state()
            except Exception as error:
                current = None
                failures.append('Не удалось прочитать текущее состояние: ' + str(error))
            for unit in (UNIT, FW_UNIT):
                if self.path(UNIT_PATH if unit == UNIT else FW_PATH).exists():
                    attempt(lambda unit=unit: self._run(['systemctl', 'stop', unit]))
                    attempt(lambda unit=unit: self._run(['systemctl', 'disable', unit]))
            if current and current['installed']:
                attempt(lambda: self._fw_set(current['firewall'], False))
            attempt(lambda: self._restore_files(before.files))
            attempt(lambda: self._run(['systemctl', 'daemon-reload']))
            attempt(lambda: self._restore_services(before.services))
            if before.firewall:
                attempt(lambda: self._fw_set(before.firewall, before.firewall_open))
            if failures:
                raise BackendError(f'Операция не выполнена: {original}. Откат завершился ошибками: ' + '; '.join(failures)) from original
            raise BackendError(f'Операция не выполнена, прежнее состояние восстановлено: {original}') from original

    def _make_dirs(self):
        for name in OWN_DIRS:
            path = self._safe(self.path(name), True)
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700 if name == ETC else 0o755)

    def _binary(self, archive):
        if archive is None and (self.source / 'assets/masterdns-amd64.tar.gz').exists():
            archive = self.source / 'assets/masterdns-amd64.tar.gz'
        if archive is None:
            try:
                with urllib.request.urlopen(ASSET_URL, timeout=60) as response:
                    payload = response.read(LIMIT + 1)
            except OSError as error:
                raise BackendError(f'Не удалось скачать закреплённый архив: {error}') from error
        else:
            path = Path(archive)
            if not path.is_file() or path.is_symlink() or path.stat().st_size > LIMIT:
                raise BackendError('Архив должен быть обычным файлом допустимого размера.')
            payload = path.read_bytes()
        if len(payload) > LIMIT or hashlib.sha256(payload).hexdigest() != ASSET_SHA256:
            raise BackendError('SHA256 архива MasterDNS не совпадает с закреплённым значением.')
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive_file:
                members = archive_file.getmembers()
                if (len(members) != 2 or {m.name for m in members} != {ASSET_MEMBER, 'server_config.toml'}
                        or any(not m.isfile() or m.size > LIMIT for m in members)):
                    raise BackendError('Неожиданная структура закреплённого архива MasterDNS.')
                binary = archive_file.extractfile(ASSET_MEMBER).read(LIMIT + 1)
                if len(binary) > LIMIT or binary[:6] != b'\x7fELF\x02\x01' or binary[18:20] != b'\x3e\x00':
                    raise BackendError('В архиве отсутствует Linux ELF amd64 binary.')
                return binary
        except (tarfile.TarError, OSError) as error:
            raise BackendError(f'Невозможно прочитать архив MasterDNS: {error}') from error

    def _distribution(self):
        package = self.source / 'tuna_dns'
        wrapper = self.source / 'bin/tuna-dns'
        if package.is_symlink() or wrapper.is_symlink() or not wrapper.is_file():
            raise BackendError('Нужна полная папка дистрибутива с bin/tuna-dns и tuna_dns.')
        files = {}
        for path in sorted(package.glob('*.py')):
            if path.is_symlink() or not path.is_file():
                raise BackendError('Недопустимый файл в исходном дистрибутиве.')
            files[SHARE + '/tuna_dns/' + path.name] = path.read_bytes()
        required = {'__init__.py', 'backend.py', 'config.py', 'cli.py'}
        if not required.issubset({p.rsplit('/', 1)[-1] for p in files}):
            raise BackendError('Неполный Python-пакет в дистрибутиве.')
        raw = wrapper.read_bytes()
        if not raw.startswith(b'#!'):
            raise BackendError('Wrapper должен содержать shebang.')
        if MARKER.encode() not in raw:
            first, separator, body = raw.partition(b'\n')
            raw = first + separator + MARKER.encode() + b'\n' + body
        files[WRAPPER] = raw
        return files

    def _install_files(self, binary, distribution, firewall):
        self._make_dirs()
        self._write(LIB + '/masterdns-server', binary, 0o755)
        # Remove obsolete package modules, but never unknown administrator files.
        for name in self._files():
            if name.startswith(SHARE + '/tuna_dns/') and name.endswith('.py') and name not in distribution:
                self._remove([name])
        for name, data in distribution.items():
            self._write(name, data, 0o755 if name == WRAPPER else 0o644)
        unit = f'''{MARKER}
[Unit]
Description=TUNA DNS Tunnel (MasterDNS)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory={ETC}
ExecStart={LIB}/masterdns-server -config {NATIVE_CONFIG}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths={ETC}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
'''
        self._write(UNIT_PATH, unit.encode(), 0o644)
        if firewall['kind'] == 'iptables':
            unit = f'''{MARKER}
[Unit]
Description=TUNA DNS Tunnel owned IPv4 UDP firewall rule
After=network-pre.target
Before={UNIT}
[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PYTHONPATH={SHARE}
ExecStart=/usr/bin/python3 -m tuna_dns.backend firewall-start
ExecStop=/usr/bin/python3 -m tuna_dns.backend firewall-stop
[Install]
WantedBy=multi-user.target
'''
            self._write(FW_PATH, unit.encode(), 0o644)

    def _save_settings(self, settings):
        self._json(SETTINGS, settings)
        self._write(KEY, settings['key'].encode() + b'\n')
        self._write(NATIVE_CONFIG, config.render(settings, KEY).encode())

    def install(self, settings, archive=None):
        settings = self._validated(settings)
        self._preflight()
        with self._lock():
            state = self._check_owned()
            if state and state['installed']:
                raise BackendError('Уже установлено; используйте update или apply.')
            self._bind_check(settings)
            kind = self._firewall_backend()
            firewall = dict(kind=kind, host=settings['listen_host'], port=settings['port'], open=True)
            if self._fw_has(firewall):
                raise BackendError('Обнаружено осиротевшее правило TUNA DNS Tunnel; автоматическое присвоение запрещено.')
            binary = self._binary(archive)
            distribution = self._distribution()
            with self._transaction():
                self._make_dirs()
                self._json(STATE, dict(owner=COMMENT, schema=1, installed=True, firewall=firewall))
                self._install_files(binary, distribution, firewall)
                self._save_settings(settings)
                self._run(['systemctl', 'daemon-reload'])
                self._fw_set(firewall, True)
                if kind == 'iptables':
                    self._run(['systemctl', 'enable', FW_UNIT])
                    self._run(['systemctl', 'start', FW_UNIT])
                self._run(['systemctl', 'enable', UNIT])
                self._run(['systemctl', 'start', UNIT])
                if not self._service_state(UNIT)['active']:
                    raise BackendError('Служба не перешла в active.')
        return self.status()

    def _installed(self):
        state = self._check_owned()
        if not state or not state['installed']:
            raise BackendError('TUNA DNS Tunnel ещё не установлен.')
        return state

    def apply(self, settings):
        settings = self._validated(settings)
        self._preflight()
        with self._lock():
            state = self._installed()
            old = config.validate(json.loads(self._read(SETTINGS)))
            changed = (old['listen_host'], old['port']) != (settings['listen_host'], settings['port'])
            with self._transaction() as before:
                if before.services[UNIT]['active']:
                    self._run(['systemctl', 'stop', UNIT])
                if changed:
                    self._bind_check(settings)
                    self._fw_set(state['firewall'], False)
                state['firewall'].update(host=settings['listen_host'], port=settings['port'], open=before.firewall_open)
                self._json(STATE, state)
                self._save_settings(settings)
                if changed:
                    self._fw_set(state['firewall'], before.firewall_open)
                self._restore_services(before.services)
        return self.status()

    def update(self, archive=None):
        self._preflight()
        with self._lock():
            state = self._installed()
            binary = self._binary(archive)
            distribution = self._distribution()
            with self._transaction() as before:
                if before.services[UNIT]['active']:
                    self._run(['systemctl', 'stop', UNIT])
                state['firewall']['open'] = before.firewall_open
                self._json(STATE, state)
                self._install_files(binary, distribution, state['firewall'])
                self._run(['systemctl', 'daemon-reload'])
                self._restore_services(before.services)
        return self.status()

    def service(self, action):
        if action not in ('start', 'stop', 'restart', 'enable', 'disable'):
            raise BackendError('Неизвестная операция службы.')
        self._preflight()
        with self._lock():
            self._installed()
            with self._transaction():
                self._run(['systemctl', action, UNIT])
                if action in ('start', 'restart') and not self._service_state(UNIT)['active']:
                    raise BackendError('Служба не перешла в active.')
        return self.status()

    def backup(self):
        self._preflight()
        with self._lock():
            self._installed()
            before = self._snapshot()
            folder = self._safe(self.path('/var/backups'), True)
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / ('tuna-dns-tunnel-' + time.strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(4).hex() + '.tar.gz')
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            metadata = json.dumps(dict(schema=1, owner=COMMENT, services=before.services,
                                       firewall_open=before.firewall_open)).encode()
            try:
                with os.fdopen(descriptor, 'wb') as raw:
                    with tarfile.open(fileobj=raw, mode='w:gz') as archive:
                        for name, (data, mode) in {'metadata.json': (metadata, 0o600), **before.files}.items():
                            info = tarfile.TarInfo(name.lstrip('/'))
                            info.size, info.mode = len(data), mode
                            archive.addfile(info, io.BytesIO(data))
                    raw.flush()
                    os.fsync(raw.fileno())
            except Exception:
                path.unlink(missing_ok=True)
                raise
            return str(path)

    def _read_backup(self, path):
        path = Path(path).absolute()
        if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
            raise BackendError('Резервная копия должна быть обычным файлом допустимого размера.')
        if self.live and (path.stat().st_uid != 0 or path.stat().st_mode & 0o077):
            raise BackendError('Резервная копия должна принадлежать root и иметь права 0600.')
        files, metadata, total = {}, None, 0
        try:
            with tarfile.open(path, 'r:gz') as archive:
                seen = set()
                for member in archive:
                    name = member.name
                    total += member.size
                    if name in seen or not member.isfile() or member.size > LIMIT or total > 2 * LIMIT:
                        raise BackendError('Некорректные записи в резервной копии.')
                    seen.add(name)
                    absolute = '/' + name
                    if (name.startswith('/') or '..' in name.split('/') or '\\' in name
                            or not (name == 'metadata.json' or absolute in OWN_FILES
                                    or any(absolute.startswith(base + '/') for base in OWN_DIRS))):
                        raise BackendError('Резервная копия содержит чужой путь.')
                    data = archive.extractfile(member).read(LIMIT + 1)
                    if name == 'metadata.json':
                        metadata = json.loads(data)
                    else:
                        mode = 0o600 if absolute.startswith(ETC + '/') else (0o755 if absolute in (WRAPPER, LIB + '/masterdns-server') else 0o644)
                        files[absolute] = (data, mode)
            if not metadata or metadata['schema'] != 1 or metadata['owner'] != COMMENT:
                raise ValueError('Неверный формат резервной копии.')
            for unit in (UNIT, FW_UNIT):
                if set(metadata['services'][unit]) != {'active', 'enabled'} or any(type(v) is not bool for v in metadata['services'][unit].values()):
                    raise ValueError('Неверное состояние службы.')
            if type(metadata['firewall_open']) is not bool:
                raise ValueError('Неверное состояние firewall.')
            settings = self._validated(json.loads(files[SETTINGS][0]))
            state = json.loads(files[STATE][0])
            if state['owner'] != COMMENT or state['schema'] != 1 or state['installed'] is not True:
                raise ValueError('Неверный манифест резервной копии.')
            self._validate_firewall(state['firewall'])
            if (state['firewall']['host'], state['firewall']['port']) != (settings['listen_host'], settings['port']):
                raise ValueError('Firewall не соответствует адресу и порту конфигурации.')
            for name in (WRAPPER, UNIT_PATH):
                if MARKER.encode() not in files[name][0]:
                    raise ValueError('Отсутствует маркер владельца.')
            if files[KEY][0] != settings['key'].encode() + b'\n' or files[NATIVE_CONFIG][0] != config.render(settings, KEY).encode():
                raise ValueError('Конфигурация резервной копии не соответствует settings.json.')
            if state['firewall']['kind'] == 'iptables' and MARKER.encode() not in files[FW_PATH][0]:
                raise ValueError('Отсутствует firewall unit.')
            if LIB + '/masterdns-server' not in files or SHARE + '/tuna_dns/backend.py' not in files:
                raise ValueError('Неполная резервная копия.')
            state['firewall']['open'] = metadata['firewall_open']
            files[STATE] = ((json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode(), 0o600)
            return Snapshot(files, metadata['services'], state['firewall'], metadata['firewall_open']), settings
        except (ValueError, KeyError, TypeError, tarfile.TarError, OSError) as error:
            raise BackendError(f'Невозможно восстановить резервную копию: {error}') from error

    def restore(self, path):
        self._preflight()
        restored, settings = self._read_backup(path)
        with self._lock():
            self._check_owned()
            with self._transaction() as before:
                if before.services[UNIT]['active']:
                    self._run(['systemctl', 'stop', UNIT])
                if before.services[FW_UNIT]['active']:
                    self._run(['systemctl', 'stop', FW_UNIT])
                self._bind_check(settings)
                if before.firewall:
                    self._fw_set(before.firewall, False)
                self._restore_files(restored.files)
                self._run(['systemctl', 'daemon-reload'])
                self._fw_set(restored.firewall, restored.firewall_open)
                self._restore_services(restored.services)
        return self.status()

    def uninstall(self, purge=False):
        self._preflight()
        with self._lock():
            state = self._installed()
            with self._transaction():
                for unit in (UNIT, FW_UNIT):
                    if self.path(UNIT_PATH if unit == UNIT else FW_PATH).exists():
                        self._run(['systemctl', 'stop', unit])
                        self._run(['systemctl', 'disable', unit])
                self._fw_set(state['firewall'], False)
                files = self._files()
                self._remove([name for name in files if purge or not name.startswith(ETC + '/')])
                if not purge:
                    state['installed'] = False
                    state['firewall']['open'] = False
                    self._json(STATE, state)
                self._run(['systemctl', 'daemon-reload'])
        return self.status()


def _firewall_entry(action):
    manager = Manager()
    manager._preflight()
    state = manager._installed()
    firewall = state['firewall']
    if firewall['kind'] != 'iptables':
        raise BackendError('Firewall unit предназначен только для iptables.')
    manager._fw_set(firewall, action == 'firewall-start' and firewall['open'])


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ('firewall-start', 'firewall-stop'):
            raise BackendError('Внутренний интерфейс firewall: недопустимые аргументы.')
        _firewall_entry(sys.argv[1])
    except (BackendError, ValueError, OSError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
