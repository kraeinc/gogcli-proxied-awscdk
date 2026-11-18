import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


class DiscoveryStopped(Exception):
    pass


class OwnerLoginTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scripts = self.root / 'scripts'
        scripts.mkdir()
        self.script = scripts / 'configure_owner_login.py'
        self.script.write_text((ROOT / 'scripts/configure_owner_login.py').read_text())
        self.environment = self.root / 'env/gogcli-prd'
        self.environment.mkdir(parents=True)
        (self.environment / 'access.json').write_text(json.dumps({'GogcliGoogleProxyApi': {}}))
        self.binding = {'oidc_issuer': 'https://auth.example.com:8443/application/o/fixture/',
            'owner_login': {'api_credential': 'fixture-authentik-api'}}

    def write_binding(self):
        (self.environment / 'binding.json').write_text(json.dumps(self.binding))

    def test_api_origin_and_credential_come_from_local_binding(self):
        self.write_binding()
        session = Mock()
        session.headers = {}
        session.request.side_effect = DiscoveryStopped
        with patch('requests.Session', return_value=session), \
                patch('subprocess.check_output', return_value='synthetic-token\n') as credential:
            with self.assertRaises(DiscoveryStopped):
                runpy.run_path(str(self.script))
        credential.assert_called_once_with(
            ['keyring', 'credential', 'get-field', 'fixture-authentik-api', 'token'], text=True)
        session.request.assert_called_once_with('GET',
            'https://auth.example.com:8443/api/v3/schema/?format=json', json=None, timeout=30)

    def test_invalid_issuer_or_credential_stops_before_secret_access(self):
        for issuer in ('http://auth.example.com/', 'https://user:password@auth.example.com/',
                       'https://auth.example.com/?query=value', 'https://auth.example.com/#fragment',
                       'https:///application/o/fixture/'):
            with self.subTest(issuer=issuer):
                self.binding['oidc_issuer'] = issuer
                self.write_binding()
                with patch('subprocess.check_output') as credential, patch('requests.Session') as session:
                    with self.assertRaises(ValueError):
                        runpy.run_path(str(self.script))
                credential.assert_not_called()
                session.assert_not_called()
        self.binding['oidc_issuer'] = 'https://auth.example.com/application/o/fixture/'
        for locator in ('', ' ', None):
            with self.subTest(locator=locator):
                self.binding['owner_login']['api_credential'] = locator
                self.write_binding()
                with patch('subprocess.check_output') as credential, patch('requests.Session') as session:
                    with self.assertRaises(ValueError):
                        runpy.run_path(str(self.script))
                credential.assert_not_called()
                session.assert_not_called()


if __name__ == '__main__':
    unittest.main()
