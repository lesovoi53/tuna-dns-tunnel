import copy
import io
import tomllib
import unittest
from contextlib import redirect_stdout

from tuna_dns import config


class ConfigTests(unittest.TestCase):
    def settings(self):
        settings = config.defaults()
        settings['domains'] = ['dns.example.org', 'second.example.org']
        return settings

    def test_defaults_and_generated_keys(self):
        first, second = self.settings(), self.settings()
        self.assertNotEqual(first['key'], second['key'])
        self.assertEqual(first, config.validate(first))
        self.assertEqual(('0.0.0.0', 53, 'direct', 5),
                         (first['listen_host'], first['port'], first['route']['mode'], first['encryption_method']))
        for method, length in enumerate((32, 32, 32, 16, 24, 32)):
            settings = self.settings()
            settings.update(encryption_method=method, key=config.generate_key(method))
            self.assertEqual(length, len(config.validate(settings)['key'].encode()))

    def test_native_direct_config_matches_lite_defaults(self):
        settings = self.settings()
        text = config.render(settings, '/etc/tuna-dns-tunnel/encrypt_key.txt')
        native = tomllib.loads(text)
        self.assertEqual(settings['domains'], native['DOMAIN'])
        self.assertEqual('SOCKS5', native['PROTOCOL_TYPE'])
        self.assertEqual((4, 4, 16384, 8388608, 4096), tuple(native[key] for key in
            ('UDP_READERS', 'DNS_REQUEST_WORKERS', 'MAX_CONCURRENT_REQUESTS', 'SOCKET_BUFFER_SIZE', 'MAX_PACKET_SIZE')))
        self.assertEqual(['1.1.1.1:53', '8.8.8.8:53'], native['DNS_UPSTREAM_SERVERS'])
        self.assertFalse(native['USE_EXTERNAL_SOCKS5'])
        self.assertFalse(native['SOCKS5_AUTH'])
        self.assertEqual('WARN', native['LOG_LEVEL'])
        self.assertNotIn(settings['key'], text)

    def test_socks_credentials_and_toml_escaping(self):
        settings = self.settings()
        settings['route'].update(mode='socks5', host='::1', username='имя"\\', password='пароль"\\')
        native = tomllib.loads(config.render(settings, '/private/a"b\\key'))
        self.assertTrue(native['USE_EXTERNAL_SOCKS5'])
        self.assertTrue(native['SOCKS5_AUTH'])
        self.assertEqual(settings['route']['username'], native['SOCKS5_USER'])
        self.assertEqual(settings['route']['password'], native['SOCKS5_PASS'])
        self.assertEqual('::1', native['FORWARD_IP'])
        self.assertEqual('/private/a"b\\key', native['ENCRYPTION_KEY_FILE'])
        settings['route'].update(username='', password='')
        self.assertFalse(tomllib.loads(config.render(settings, '/key'))['SOCKS5_AUTH'])

    def test_invalid_domains_and_duplicate_case(self):
        invalid = ([], ['one'], ['a.example.'], ['a.example', 'A.EXAMPLE'], ['-a.example'],
                   ['a..example'], ['a".example'], ['a' * 64 + '.example'], ['a.example'] * 17)
        for domains in invalid:
            with self.subTest(domains=domains), self.assertRaises(ValueError):
                settings = self.settings()
                settings['domains'] = domains
                config.validate(settings)
        self.assertEqual(16, len(config.validate_domains([f'd{i}.example' for i in range(16)])))

    def test_invalid_fields_and_types(self):
        invalid = (('port', True), ('port', 0), ('port', 65536), ('port', '53'),
                   ('listen_host', 'dns.example'), ('listen_host', '0.0.0.0\n'),
                   ('encryption_method', True), ('encryption_method', 6), ('encryption_method', '5'),
                   ('key', 'secret-short'), ('name', ''), ('name', 'bad\nname'), ('unexpected', 1))
        for field, value in invalid:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                settings = self.settings()
                settings[field] = value
                config.validate(settings)

    def test_auth_byte_limits_and_both_required(self):
        for user, password in (('user', ''), ('', 'pass'), ('a' * 256, 'pass'),
                               ('user', 'я' * 128), ('user', 'bad\x00password')):
            with self.subTest(lengths=(len(user), len(password))), self.assertRaises(ValueError):
                settings = self.settings()
                settings['route'].update(mode='socks5', username=user, password=password)
                config.validate(settings)
        settings = self.settings()
        settings['route'].update(mode='socks5', username='a' * 255, password='я' * 127)
        config.validate(settings)

    def test_utf8_key_length_is_text_not_hex(self):
        settings = self.settings()
        settings['key'] = 'я' * 16
        self.assertEqual(settings['key'], config.validate(settings)['key'])
        settings['key'] = '0f' * 32
        with self.assertRaises(ValueError):
            config.validate(settings)

    def test_validation_is_pure_and_errors_never_print_secrets(self):
        settings = self.settings()
        original = copy.deepcopy(settings)
        validated = config.validate(settings)
        validated['domains'].append('extra.example')
        validated['route']['password'] = 'changed'
        self.assertEqual(original, settings)
        secret = 'DO-NOT-PRINT-THIS-SECRET'
        settings['key'] = secret
        stream = io.StringIO()
        with redirect_stdout(stream), self.assertRaises(ValueError) as error:
            config.validate(settings)
        self.assertEqual('', stream.getvalue())
        self.assertNotIn(secret, str(error.exception))


if __name__ == '__main__':
    unittest.main()
