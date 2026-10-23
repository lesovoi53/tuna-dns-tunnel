import contextlib
import copy
import io
import subprocess
import unittest
from unittest.mock import patch

from tuna_dns import cli, config


class CliTests(unittest.TestCase):
    def setUp(self):
        self.settings = config.defaults()
        self.settings['domains'] = ['d.example.org']
        self.settings['route'].update(username='fixture', password='fixture-private-password')

    def test_summary_and_journal_hide_current_and_historical_keys(self):
        raw = 'Active Encryption Key: old-private-key\n' + self.settings['key'] + '\nfixture-private-password'
        output = io.StringIO()
        with patch.object(cli.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, raw)), contextlib.redirect_stdout(output):
            print(cli.summary(self.settings))
            cli.journal(self.settings)
        for value in (self.settings['key'], 'old-private-key', 'fixture-private-password'):
            self.assertNotIn(value, output.getvalue())

    def test_route_draft_cancel_and_save_do_not_mutate_original(self):
        original = copy.deepcopy(self.settings)
        with patch.object(cli, 'ask', side_effect=['2', '0']), contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(cli.route_editor(self.settings))
        self.assertEqual(original, self.settings)
        with patch.object(cli, 'ask', side_effect=['2', 's']), contextlib.redirect_stdout(io.StringIO()):
            saved = cli.route_editor(self.settings)
        self.assertEqual(saved['route']['mode'], 'socks5')
        self.assertEqual(original, self.settings)

    def test_preview_does_not_construct_backend(self):
        with patch('tuna_dns.backend.Manager', side_effect=AssertionError('Host access')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--preview']), 0)

    def test_delete_all_then_replace_domains(self):
        self.settings['domains'] = ['d.tuna.invalid', 'd1.tuna.invalid']
        with patch.object(cli, 'ask', side_effect=['2', '1', '2', '1', 's', '1', 'dns.example.org', 's']), contextlib.redirect_stdout(io.StringIO()):
            result = cli.domains_editor(self.settings)
        self.assertEqual(result['domains'], ['dns.example.org'])
        self.assertEqual(self.settings['domains'], ['d.tuna.invalid', 'd1.tuna.invalid'])

    def test_invalid_input_keeps_domain_draft(self):
        self.settings['domains'] = ['d.example.org', 'd1.example.org']
        with patch.object(cli, 'ask', side_effect=['2', '1', '1', '', '2', 'oops', '2', '99', 's']), contextlib.redirect_stdout(io.StringIO()):
            result = cli.domains_editor(self.settings)
        self.assertEqual(result['domains'], ['d1.example.org'])
