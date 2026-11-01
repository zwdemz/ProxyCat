"""Time-controlled tests for generated token renewal and authenticated link display."""

import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

with patch.dict(os.environ, {'PROXYCAT_DISABLE_CREDENTIAL_BOOTSTRAP': 'true'}):
    import app as web_app

from modules.credentials import INITIAL_CREDENTIALS_FILENAME, TOKEN_ROTATION_SECONDS
from modules.modules import load_config


class TokenRotationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_path = Path(self.directory.name) / 'config.ini'
        self.config_path.write_text('[Server]\ntoken =\nrequire_proxy_auth = false\n'
                                    '[Users]\nalice = existing-password\n', encoding='utf-8')
        self.original_bytes = self.config_path.read_bytes()
        self.environment = patch.dict(os.environ, {}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        for name in ('PROXYCAT_MANAGEMENT_TOKEN', 'PROXYCAT_DISABLE_CREDENTIAL_BOOTSTRAP'):
            os.environ.pop(name, None)
        self.original_server_config = web_app.server.config
        self.addCleanup(setattr, web_app.server, 'config', self.original_server_config)
        self.now = 2_000_000_000.0

    def load_at(self, instant):
        with patch('modules.credentials.time.time', return_value=instant):
            return load_config(str(self.config_path))

    def test_restart_reuses_token_until_exact_fifteen_day_boundary(self):
        first = self.load_at(self.now)
        before = self.load_at(self.now + TOKEN_ROTATION_SECONDS - 1)
        renewed = self.load_at(self.now + TOKEN_ROTATION_SECONDS)
        self.assertEqual(first['token'], before['token'])
        self.assertEqual(first['_management_token_expires_at'], before['_management_token_expires_at'])
        self.assertNotEqual(first['token'], renewed['token'])
        self.assertEqual(self.now + TOKEN_ROTATION_SECONDS * 2,
                         renewed['_management_token_expires_at'])
        self.assertEqual(first['Users'], renewed['Users'])
        self.assertEqual(self.original_bytes, self.config_path.read_bytes())

    def test_concurrent_expired_reads_generate_one_shared_token(self):
        first = self.load_at(self.now)
        with patch('modules.credentials.time.time', return_value=self.now + TOKEN_ROTATION_SECONDS):
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = list(executor.map(lambda _: load_config(str(self.config_path)), range(4)))
        self.assertEqual(1, len({result['token'] for result in results}))
        self.assertNotEqual(first['token'], results[0]['token'])

    def test_expired_token_is_rejected_without_a_configuration_file_change(self):
        first = self.load_at(self.now)
        web_app.server.config = first
        client = web_app.app.test_client()
        with patch.object(web_app, 'CONFIG_INI_PATH', str(self.config_path)), \
             patch('modules.credentials.time.time', return_value=self.now + TOKEN_ROTATION_SECONDS):
            response = client.get('/api/management-access', headers={'X-ProxyCat-Token': first['token']})
            self.assertEqual(401, response.status_code)
            current = web_app.server.config['token']
            response = client.get('/api/management-access', headers={'X-ProxyCat-Token': current})
        self.assertEqual(200, response.status_code)
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertEqual(current, parse_qs(urlsplit(response.json['access_path']).query)['token'][0])
        self.assertTrue(response.json['automatically_generated'])
        self.assertEqual(self.original_bytes, self.config_path.read_bytes())

    def test_explicit_token_does_not_expire_and_its_link_is_encoded(self):
        token = 'manual-token&+?value'
        self.config_path.write_text('[Server]\ntoken = ' + token + '\nrequire_proxy_auth = false\n',
                                    encoding='utf-8')
        first = self.load_at(self.now)
        later = self.load_at(self.now + TOKEN_ROTATION_SECONDS * 3)
        self.assertEqual(token, later['token'])
        self.assertFalse(first['_management_token_generated'])
        self.assertIsNone(later['_management_token_expires_at'])
        web_app.server.config = later
        response = web_app.app.test_client().get('/api/management-access',
            headers={'X-ProxyCat-Token': token})
        self.assertEqual(token, parse_qs(urlsplit(response.json['access_path']).query)['token'][0])
        self.assertFalse((self.config_path.parent / INITIAL_CREDENTIALS_FILENAME).exists())

    def test_legacy_credential_file_gets_timestamp_without_rotating_immediately(self):
        path = self.config_path.parent / INITIAL_CREDENTIALS_FILENAME
        path.write_text('Management token: legacy-random-token\n', encoding='utf-8')
        loaded = self.load_at(self.now)
        self.assertEqual('legacy-random-token', loaded['token'])
        self.assertEqual(self.now + TOKEN_ROTATION_SECONDS, loaded['_management_token_expires_at'])

    def test_anonymous_clients_cannot_read_access_link(self):
        web_app.server.config = self.load_at(self.now)
        response = web_app.app.test_client().get('/api/management-access')
        self.assertEqual(401, response.status_code)
        self.assertNotIn('access_path', response.json)

    def test_saving_other_settings_keeps_generated_token_and_expiry(self):
        first = self.load_at(self.now)
        with patch.object(web_app, 'CONFIG_INI_PATH', str(self.config_path)), \
             patch('modules.credentials.time.time', return_value=self.now + 100):
            updated = web_app._persist_config({'interval': '120'}, {})
        self.assertEqual(first['token'], updated['token'])
        self.assertEqual(first['_management_token_expires_at'], updated['_management_token_expires_at'])
        self.assertTrue(updated['_management_token_generated'])
