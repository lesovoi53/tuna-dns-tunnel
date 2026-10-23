"""Backend acceptance fixtures: every command targets an injected fake runner."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tuna_dns import backend, config


class FakeRunner:
    def __init__(self):
        self.services = {unit: dict(active=False, enabled=False) for unit in (backend.UNIT, backend.FW_UNIT)}
        self.rules = set()
        self.ufw_rules = set()
        self.calls = []
        self.fail = None

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if self.fail and self.fail(args):
            self.fail = None
            return subprocess.CompletedProcess(args, 7, '', 'injected failure')
        code, output = 0, ''
        if args[0] == 'systemctl':
            action = args[1]
            if action != 'daemon-reload':
                state = self.services[args[2]]
                if action == 'is-active':
                    code, output = (0, 'active') if state['active'] else (3, 'inactive')
                elif action == 'is-enabled':
                    code, output = (0, 'enabled') if state['enabled'] else (1, 'disabled')
                elif action in ('start', 'restart', 'stop'):
                    state['active'] = action != 'stop'
                elif action in ('enable', 'disable'):
                    state['enabled'] = action == 'enable'
                else:
                    raise AssertionError(args)
        elif args[0] == 'iptables':
            action, rule = args[3], tuple(args[4:])
            if action == '-C':
                code = 0 if rule in self.rules else 1
            elif action == '-I':
                self.rules.add(rule)
            elif action == '-D':
                self.rules.remove(rule)
            else:
                raise AssertionError(args)
        elif args[0] == 'ufw':
            if args[1:] == ['show', 'added']:
                output = '\n'.join('ufw ' + shlex.join(rule) for rule in self.ufw_rules)
            elif args[1:3] == ['--force', 'delete']:
                self.ufw_rules.remove(tuple(args[3:]))
            else:
                self.ufw_rules.add(tuple(args[1:]))
        else:
            raise AssertionError('Unexpected command ' + str(args))
        return subprocess.CompletedProcess(args, code, output + '\n' if output else '', '')


def make_archive(path, member=backend.ASSET_MEMBER, symlink=False):
    binary = b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\0' + b'test masterdns binary'
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in ((member, binary), ('server_config.toml', b'unused')):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            if symlink:
                info.type, info.linkname, info.size = tarfile.SYMTYPE, '/etc/passwd', 0
            archive.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'root'
        (self.root / 'etc').mkdir(parents=True)
        (self.root / 'etc/os-release').write_text('ID=debian\nVERSION_ID="12"\n')
        self.source = self.base / 'source'
        (self.source / 'tuna_dns').mkdir(parents=True)
        (self.source / 'bin').mkdir()
        for name in ('__init__.py', 'backend.py', 'config.py', 'cli.py'):
            (self.source / 'tuna_dns' / name).write_text('# fixture\n')
        (self.source / 'bin/tuna-dns').write_text('#!/usr/bin/env python3\n# fixture\n')
        self.archive = self.base / 'masterdns.tar.gz'
        digest = make_archive(self.archive)
        self.pinned = patch.object(backend, 'ASSET_SHA256', digest)
        self.pinned.start()
        self.addCleanup(self.pinned.stop)
        self.runner = FakeRunner()
        self.manager = backend.Manager(root=self.root, source=self.source, runner=self.runner)
        self.settings = config.defaults()
        self.settings['domains'] = ['dns.example.org']

    def install(self):
        return self.manager.install(self.settings, self.archive)

    def files(self):
        return {name: value[0] for name, value in self.manager._files().items()}

    def test_install_uses_only_own_paths_and_udp_rule(self):
        foreign = self.root / 'etc/masterdns/server_config.toml'
        foreign.parent.mkdir()
        foreign.write_text('foreign DNS config')
        status = self.install()
        self.assertTrue(status['installed'] and status['active'] and status['enabled'])
        self.assertEqual(foreign.read_text(), 'foreign DNS config')
        self.assertEqual(len(self.runner.rules), 1)
        rule = next(iter(self.runner.rules))
        self.assertIn(backend.COMMENT, rule)
        self.assertEqual(rule[rule.index('-p') + 1], 'udp')
        self.assertEqual(rule[rule.index('--dport') + 1], '53')
        self.assertTrue(self.manager.path(backend.FW_PATH).is_file())
        self.assertFalse(any('masterdns.service' in call for call in self.runner.calls))

    def test_update_preserves_exact_configs_and_manual_stop_closed_port(self):
        self.install()
        self.manager.service('stop')
        self.manager.service('disable')
        self.runner.rules.clear()  # Administrator manually removed the owned rule.
        before = {name: self.manager._read(name) for name in (backend.SETTINGS, backend.KEY, backend.NATIVE_CONFIG)}
        self.runner.calls.clear()
        result = self.manager.update(self.archive)
        self.assertFalse(result['active'])
        self.assertFalse(result['enabled'])
        self.assertEqual(self.runner.rules, set())
        self.assertFalse(self.manager._state()['firewall']['open'])
        for name, data in before.items():
            self.assertEqual(self.manager._read(name), data)
        self.assertNotIn(['systemctl', 'start', backend.FW_UNIT], self.runner.calls)

    def test_failed_restart_rolls_back_config_service_and_firewall(self):
        self.install()
        before, rules, services = self.files(), copy.deepcopy(self.runner.rules), copy.deepcopy(self.runner.services)
        updated = copy.deepcopy(self.settings)
        updated['domains'], updated['port'] = ['new.example.org'], 5353
        self.runner.fail = lambda args: args == ['systemctl', 'start', backend.UNIT]
        with self.assertRaisesRegex(backend.BackendError, 'прежнее состояние восстановлено'):
            self.manager.apply(updated)
        self.assertEqual(self.files(), before)
        self.assertEqual(self.runner.rules, rules)
        self.assertEqual(self.runner.services, services)

    def test_failed_install_removes_new_files_and_rules(self):
        self.runner.fail = lambda args: args == ['systemctl', 'start', backend.UNIT]
        with self.assertRaisesRegex(backend.BackendError, 'прежнее состояние восстановлено'):
            self.install()
        self.assertEqual(self.files(), {})
        self.assertEqual(self.runner.rules, set())
        self.assertFalse(self.manager.status()['installed'])
        self.assertFalse(any(s['active'] or s['enabled'] for s in self.runner.services.values()))

    def test_update_failure_restores_distribution(self):
        self.install()
        before = self.files()
        (self.source / 'tuna_dns/new.py').write_text('new module')
        self.runner.fail = lambda args: args == ['systemctl', 'daemon-reload']
        with self.assertRaises(backend.BackendError):
            self.manager.update(self.archive)
        self.assertEqual(self.files(), before)
        self.assertTrue(self.manager.status()['active'])

    def test_backup_restore_and_uninstall_preserve_foreign_files(self):
        self.install()
        self.manager.service('stop')
        backup = self.manager.backup()
        original = self.files()
        changed = copy.deepcopy(self.settings)
        changed['port'] = 5353
        self.manager.apply(changed)
        restored = self.manager.restore(backup)
        self.assertFalse(restored['active'])
        self.assertEqual(self.files(), original)
        foreign_rule = ('foreign', 'ssh')
        self.runner.rules.add(foreign_rule)
        result = self.manager.uninstall()
        self.assertFalse(result['installed'])
        self.assertEqual(result['settings'], self.settings)
        self.assertEqual(self.runner.rules, {foreign_rule})
        self.assertTrue(self.manager.path(backend.SETTINGS).is_file())
        self.assertFalse(self.manager.path(backend.LIB).exists())
        self.manager.restore(backup)
        self.assertTrue(self.manager.status()['installed'])
        self.manager.uninstall(purge=True)
        self.assertFalse(self.manager.path(backend.ETC).exists())
        self.assertEqual(self.runner.rules, {foreign_rule})

    def test_ufw_only_deletes_own_rule(self):
        folder = self.root / 'etc/ufw'
        folder.mkdir()
        (folder / 'ufw.conf').write_text('ENABLED=yes\n')
        foreign = ('allow', '22/tcp')
        self.runner.ufw_rules.add(foreign)
        self.install()
        self.assertEqual(len(self.runner.ufw_rules), 2)
        self.assertEqual(self.runner.rules, set())
        self.assertFalse(self.manager.path(backend.FW_PATH).exists())
        self.manager.uninstall(purge=True)
        self.assertEqual(self.runner.ufw_rules, {foreign})

    def test_ufw_failure_rolls_back_files_and_services(self):
        folder = self.root / 'etc/ufw'
        folder.mkdir()
        (folder / 'ufw.conf').write_text('ENABLED=yes\n')
        self.runner.fail = lambda args: args[0] == 'ufw' and args[1] == 'allow'
        with self.assertRaises(backend.BackendError):
            self.install()
        self.assertEqual(self.files(), {})
        self.assertEqual(self.runner.ufw_rules, set())

    def test_ufw_normalized_port_rule_recognized(self):
        firewall = dict(kind='ufw', host='0.0.0.0', port=53, open=True)
        self.runner.ufw_rules.add(('allow', '53/udp', 'comment', backend.COMMENT))
        self.assertTrue(self.manager._fw_has(firewall))

    def test_ufw_equivalent_foreign_rule_never_adopted_or_deleted(self):
        folder = self.root / 'etc/ufw'
        folder.mkdir()
        (folder / 'ufw.conf').write_text('ENABLED=yes\n')
        foreign = ('allow', '53/udp', 'comment', 'administrator DNS')
        self.runner.ufw_rules.add(foreign)
        with self.assertRaisesRegex(backend.BackendError, 'принадлежит администратору'):
            self.install()
        self.assertEqual(self.runner.ufw_rules, {foreign})
        self.assertFalse(any(call[0] == 'ufw' and 'delete' in call for call in self.runner.calls))

    def test_port_change_does_not_reopen_manually_closed_port(self):
        self.install()
        self.runner.rules.clear()
        changed = copy.deepcopy(self.settings)
        changed['port'] = 5353
        self.manager.apply(changed)
        self.assertFalse(self.runner.rules)
        self.assertFalse(self.manager._state()['firewall']['open'])

    def test_bound_port_failure_restores_running_service(self):
        self.install()
        before = self.files()
        changed = copy.deepcopy(self.settings)
        changed['port'] = 5353
        with patch.object(self.manager, '_bind_check', side_effect=backend.BackendError('UDP port busy')):
            with self.assertRaisesRegex(backend.BackendError, 'UDP port busy'):
                self.manager.apply(changed)
        self.assertEqual(self.files(), before)
        self.assertTrue(self.manager.status()['active'])

    def test_tampered_archive_is_rejected_before_changes(self):
        self.archive.write_bytes(b'bad archive')
        with self.assertRaisesRegex(backend.BackendError, 'SHA256'):
            self.install()
        self.assertEqual(self.files(), {})
        self.assertFalse(any(call[:2] == ['systemctl', 'start'] for call in self.runner.calls))

    def test_archive_path_traversal_or_symlink_rejected(self):
        for traversal, symlink in (('../../etc/passwd', False), (backend.ASSET_MEMBER, True)):
            digest = make_archive(self.archive, traversal, symlink)
            with patch.object(backend, 'ASSET_SHA256', digest):
                with self.assertRaisesRegex(backend.BackendError, 'структура'):
                    self.install()
        self.assertEqual(self.files(), {})

    def test_platform_rejected_before_changes(self):
        (self.root / 'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        with self.assertRaisesRegex(backend.BackendError, 'Поддерживаются'):
            self.install()
        self.assertEqual(self.runner.calls, [])
        self.assertFalse((self.root / 'run').exists())

    def test_foreign_owned_path_not_adopted(self):
        path = self.manager.path(backend.ETC)
        path.mkdir()
        (path / 'foreign').write_text('keep')
        with self.assertRaisesRegex(backend.BackendError, 'не принадлежит'):
            self.install()
        self.assertEqual((path / 'foreign').read_text(), 'keep')
        self.assertEqual(self.runner.calls, [])

    def test_foreign_vendor_unit_not_overridden(self):
        path = self.root / 'usr/lib/systemd/system' / backend.UNIT
        path.parent.mkdir(parents=True)
        path.write_text('foreign vendor unit')
        with self.assertRaisesRegex(backend.BackendError, 'внешним unit'):
            self.install()
        self.assertEqual(path.read_text(), 'foreign vendor unit')
        self.assertEqual(self.runner.calls, [])

    def test_symlink_and_hardlink_destinations_rejected(self):
        self.install()
        target = self.base / 'unrelated-secret'
        target.write_text('keep this')
        destination = self.manager.path(backend.KEY)
        destination.unlink()
        try:
            destination.symlink_to(target)
        except OSError:
            destination.hardlink_to(target)
        with self.assertRaisesRegex(backend.BackendError, 'ссылк'):
            self.manager.update(self.archive)
        self.assertEqual(target.read_text(), 'keep this')

    def test_private_permissions_on_posix(self):
        import os
        import stat
        if os.name != 'posix':
            self.skipTest('POSIX file mode acceptance')
        self.install()
        self.assertEqual(stat.S_IMODE(self.manager.path(backend.ETC).stat().st_mode), 0o700)
        for name in (backend.SETTINGS, backend.KEY, backend.NATIVE_CONFIG, backend.STATE):
            self.assertEqual(stat.S_IMODE(self.manager.path(name).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(Path(self.manager.backup()).stat().st_mode), 0o600)

    def test_backup_traversal_rejected_before_service_changes(self):
        self.install()
        path = self.base / 'bad-backup.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            item = tarfile.TarInfo('../../etc/passwd')
            item.size = 4
            archive.addfile(item, io.BytesIO(b'evil'))
        self.runner.calls.clear()
        with self.assertRaisesRegex(backend.BackendError, 'чужой путь'):
            self.manager.restore(path)
        self.assertEqual(self.runner.calls, [])

    def test_no_live_commands_without_explicit_fixture_runner(self):
        with self.assertRaisesRegex(backend.BackendError, 'runner'):
            backend.Manager(root=self.root)

    def test_local_bundled_asset_does_not_download(self):
        (self.source / 'assets').mkdir()
        (self.source / 'assets/masterdns-amd64.tar.gz').write_bytes(self.archive.read_bytes())
        with patch.object(backend.urllib.request, 'urlopen', side_effect=AssertionError('network forbidden')):
            self.manager.install(self.settings)

    def test_ipv6_rejected_before_mutation(self):
        self.settings['listen_host'] = '::'
        with self.assertRaisesRegex(backend.BackendError, 'IPv4'):
            self.install()
        self.assertEqual(self.runner.calls, [])

    def test_rollback_error_is_reported_not_hidden(self):
        self.install()
        changed = copy.deepcopy(self.settings)
        changed['port'] = 5353
        with patch.object(self.manager, '_restore_files', side_effect=OSError('restore disk error')):
            self.runner.fail = lambda args: args == ['systemctl', 'start', backend.UNIT]
            with self.assertRaisesRegex(backend.BackendError, 'Откат завершился ошибками.*restore disk error'):
                self.manager.apply(changed)


if __name__ == '__main__':
    unittest.main()
