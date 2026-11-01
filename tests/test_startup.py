import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.auth import PASSWORD_HASH_PREFIX, verify_proxy_password
from modules.modules import INITIAL_CREDENTIALS_FILENAME, load_config


class CredentialBootstrapTests(unittest.TestCase):
    """Verify secure, repeatable first-run credential generation."""

    def test_missing_credentials_are_generated_once_and_persisted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_directory = Path(temporary_directory) / "config"
            config_directory.mkdir()
            config_path = config_directory / "config.ini"
            config_path.write_text(
                "[Server]\n"
                "port = 1080\n"
                "web_port = 5000\n"
                "require_proxy_auth = true\n"
                "token =\n\n"
                "[Users]\n",
                encoding="utf-8",
            )

            original_config_bytes = config_path.read_bytes()
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("PROXYCAT_MANAGEMENT_TOKEN", None)
                os.environ.pop("PROXYCAT_PROXY_USERNAME", None)
                os.environ.pop("PROXYCAT_PROXY_PASSWORD", None)
                first_config = load_config(str(config_path))

            credentials_path = config_directory / INITIAL_CREDENTIALS_FILENAME
            self.assertTrue(credentials_path.exists())
            credentials_text = credentials_path.read_text(encoding="utf-8")
            management_token = self._value(credentials_text, "Management token")
            proxy_username = self._value(credentials_text, "Proxy username")
            proxy_password = self._value(credentials_text, "Proxy password")

            self.assertGreaterEqual(len(management_token), 40)
            self.assertGreaterEqual(len(proxy_password), 30)
            self.assertEqual(management_token, first_config["token"])
            self.assertEqual("proxycat", proxy_username)
            stored_password = first_config["Users"][proxy_username]
            self.assertTrue(stored_password.startswith(PASSWORD_HASH_PREFIX))
            self.assertNotIn(proxy_password, config_path.read_text(encoding="utf-8"))
            self.assertNotIn(management_token, config_path.read_text(encoding="utf-8"))
            self.assertNotIn(stored_password, config_path.read_text(encoding="utf-8"))
            self.assertTrue(verify_proxy_password(stored_password, proxy_password))

            original_credentials = credentials_text
            second_config = load_config(str(config_path))
            self.assertEqual(first_config["token"], second_config["token"])
            self.assertEqual(first_config["Users"], second_config["Users"])
            self.assertEqual(original_credentials, credentials_path.read_text(encoding="utf-8"))
            self.assertEqual(original_config_bytes, config_path.read_bytes())

    def test_complete_environment_credentials_skip_generated_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_directory = Path(temporary_directory) / "config"
            config_directory.mkdir()
            config_path = config_directory / "config.ini"
            config_path.write_text(
                "[Server]\nrequire_proxy_auth = true\ntoken =\n\n[Users]\n",
                encoding="utf-8",
            )
            environment = {
                "PROXYCAT_MANAGEMENT_TOKEN": "environment-management-token",
                "PROXYCAT_PROXY_USERNAME": "environment-user",
                "PROXYCAT_PROXY_PASSWORD": "environment-password",
            }

            with patch.dict(os.environ, environment, clear=False):
                loaded_config = load_config(str(config_path))

            self.assertEqual(
                "environment-management-token", loaded_config["token"]
            )
            self.assertFalse(
                (config_directory / INITIAL_CREDENTIALS_FILENAME).exists()
            )

    def test_blank_configured_password_is_replaced_with_generated_credentials(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_directory = Path(temporary_directory) / "config"
            config_directory.mkdir()
            config_path = config_directory / "config.ini"
            config_path.write_text(
                "[Server]\nrequire_proxy_auth = true\ntoken = existing-token\n\n"
                "[Users]\nalice =\n",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("PROXYCAT_PROXY_USERNAME", None)
                os.environ.pop("PROXYCAT_PROXY_PASSWORD", None)
                loaded_config = load_config(str(config_path))

            self.assertIn("proxycat", loaded_config["Users"])
            self.assertTrue(
                loaded_config["Users"]["proxycat"].startswith(PASSWORD_HASH_PREFIX)
            )
            self.assertNotIn("alice", {
                username: password
                for username, password in loaded_config["Users"].items()
                if password
            })

    @staticmethod
    def _value(credentials_text, label):
        prefix = f"{label}: "
        for line in credentials_text.splitlines():
            if line.startswith(prefix):
                return line[len(prefix):]
        raise AssertionError(f"Missing credential field: {label}")


class WindowsLauncherTests(unittest.TestCase):
    """Keep Windows launchers UTF-8 and prevent duplicate listeners."""

    def test_web_launcher_starts_only_app_entrypoint(self):
        launcher = Path("app_start.bat").read_text(encoding="utf-8")
        self.assertIn("chcp 65001", launcher)
        self.assertIn("app.py", launcher)
        self.assertNotIn("python ProxyCat.py", launcher)
        self.assertNotIn("py -3 ProxyCat.py", launcher)

    def test_terminal_launcher_starts_only_console_entrypoint(self):
        launcher = Path("ProxyCat_start.bat").read_text(encoding="utf-8")
        self.assertIn("chcp 65001", launcher)
        self.assertIn("ProxyCat.py", launcher)
        self.assertNotIn("python app.py", launcher)
        self.assertNotIn("py -3 app.py", launcher)


if __name__ == "__main__":
    unittest.main()
