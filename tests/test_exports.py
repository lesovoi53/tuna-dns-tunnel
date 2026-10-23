import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
import zlib

from tuna_dns import config, exports, profiles


def decode(link):
    if link.startswith('tuna://'):
        encoded = link.removeprefix('tuna://')
        wrapper = json.loads(zlib.decompress(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))))
        if set(wrapper) != {'name', 'uri'}:
            raise AssertionError('TUNA must be one quick-input profile')
        link = wrapper['uri']
    return json.loads(base64.b64decode(link.removeprefix('stormdns://')))


class ExportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'server_config.toml'
        self.settings = config.defaults()
        self.settings.update(domains=['one.example', 'two.example'], name='Имя "Тест"')

    def test_tuna_all_domains_and_storm_separate_roundtrip(self):
        for preset in (1, 2, 3):
            for format in ('tuna', 'storm'):
                links = exports.links(self.settings, preset, format, self.path)
                expected_domains = [self.settings['domains']] if format == 'tuna' else [['one.example'], ['two.example']]
                self.assertEqual(len(expected_domains), len(links))
                for link, domains in zip(links, expected_domains):
                    raw = decode(link)
                    self.assertEqual(('whitedns.profile', 1), (raw['schema'], raw['version']))
                    profile = raw['profile']
                    self.assertEqual(domains, profile['domains'])
                    self.assertEqual(self.settings['name'], profile['name'])
                    self.assertEqual(dict(domain=domains[0], encryption_key=self.settings['key'], encryption_method=5), profile['server'])
                    self.assertEqual(profiles.defaults(preset), {k: v for k, v in profile.items() if k not in ('name', 'domains', 'server')})

    def test_exact_lite_preset_parity(self):
        expected_base = dict(resolvers='\n'.join(('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9',
            '77.88.8.8', '77.88.8.1', '77.88.8.2', '77.88.8.3', '77.88.8.7', '77.88.8.88')),
            resolver_balancing_strategy=5, upload_compression_type=2, download_compression_type=2,
            rx_tx_workers=16, tunnel_process_workers=0, max_packets_per_batch=8, arq_window_size=600, arq_max_rto_seconds=5)
        fields = ('packet_duplication_count', 'setup_packet_duplication_count', 'base_encode_data',
            'min_upload_mtu', 'max_upload_mtu', 'min_download_mtu', 'max_download_mtu', 'arq_initial_rto_seconds',
            'ping_aggressive_interval_seconds', 'ping_lazy_interval_seconds', 'ping_cooldown_interval_seconds',
            'ping_cold_interval_seconds')
        expected = ((4, 4, True, 28, 200, 60, 900, 2, .05, .5, 2, 15),
                    (2, 2, False, 38, 150, 100, 500, 1, .1, .75, 2, 15),
                    (1, 2, False, 38, 150, 100, 500, 1, .1, .75, 4, 30))
        for preset, values in enumerate(expected, 1):
            self.assertEqual({**expected_base, **dict(zip(fields, values))}, profiles.defaults(preset))

    def test_saved_profile_used_without_server_changes(self):
        self.path.write_text('unchanged server', encoding='utf-8')
        tuning = profiles.defaults(2)
        tuning.update(resolvers='192.0.2.1:5353\n[2001:db8::1]:53', rx_tx_workers=0)
        profiles.save(profiles.storage_path(self.path), 2, tuning, None)
        profile = decode(exports.links(self.settings, 2, 'tuna', self.path)[0])['profile']
        self.assertEqual(tuning['resolvers'], profile['resolvers'])
        self.assertEqual(0, profile['rx_tx_workers'])
        self.assertEqual('unchanged server', self.path.read_text(encoding='utf-8'))
        self.assertEqual(profiles.defaults(1), profiles.effective(self.path, 1))

    def test_invalid_stored_profile_fails_closed(self):
        path = profiles.storage_path(self.path)
        for data in ('garbage', '{}', '{"version":1,"profiles":{"1":{}}}', '{"version":1,"version":1,"profiles":{}}'):
            path.write_text(data, encoding='utf-8')
            with self.assertRaises(ValueError):
                exports.links(self.settings, 1, 'tuna', self.path)
            self.assertEqual(data, path.read_text(encoding='utf-8'))

    def test_editor_stale_write_and_cancel_preserve_saved_settings(self):
        path = profiles.storage_path(self.path)
        profiles.save(path, 1, profiles.defaults(1), None)
        previous = path.read_bytes()
        with self.assertRaises(ValueError):
            profiles.save(path, 2, profiles.defaults(2), None)
        with redirect_stdout(io.StringIO()):
            self.assertFalse(profiles.menu(self.path, 1, ask=lambda _: '0'))
        self.assertEqual(previous, path.read_bytes())

    def test_bad_format_preset_and_no_stdout_secret(self):
        stream = io.StringIO()
        with redirect_stdout(stream):
            exports.links(self.settings, 1, 'tuna', self.path)
            for preset, format in ((0, 'tuna'), (True, 'tuna'), (1, 'bad')):
                with self.assertRaises(ValueError):
                    exports.links(self.settings, preset, format, self.path)
        self.assertEqual('', stream.getvalue())


if __name__ == '__main__':
    unittest.main()
