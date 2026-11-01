import asyncio
import base64
import os
import socket
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["PROXYCAT_DISABLE_CREDENTIAL_BOOTSTRAP"] = "true"
import app as web_app
os.environ.pop("PROXYCAT_DISABLE_CREDENTIAL_BOOTSTRAP", None)
from modules.auth import hash_proxy_password
from modules.proxyserver import AsyncProxyServer


class ManagementAuthorizationTests(unittest.TestCase):
    """Verify that every management API uses the centralized token boundary."""

    def setUp(self):
        self.original_config = web_app.server.config
        self.original_users = web_app.server.users
        self.original_require_proxy_auth = web_app.server.require_proxy_auth
        self.original_auth_required = web_app.server.auth_required
        self.original_users_from_environment = web_app.server.users_from_environment
        web_app.server.config = {"token": "management-secret"}
        self.client = web_app.app.test_client()

    def tearDown(self):
        web_app.server.config = self.original_config
        web_app.server.users = self.original_users
        web_app.server.require_proxy_auth = self.original_require_proxy_auth
        web_app.server.auth_required = self.original_auth_required
        web_app.server.users_from_environment = self.original_users_from_environment

    def test_every_api_route_rejects_anonymous_requests(self):
        api_rules = [
            rule for rule in web_app.app.url_map.iter_rules()
            if rule.rule.startswith("/api/")
        ]
        self.assertGreaterEqual(len(api_rules), 10)

        for rule in api_rules:
            method = "POST" if "POST" in rule.methods else "GET"
            response = self.client.open(rule.rule, method=method, json={})
            self.assertEqual(401, response.status_code, rule.rule)

    def test_header_bearer_and_legacy_query_tokens_are_supported(self):
        responses = [
            self.client.get(
                "/api/config",
                headers={"X-ProxyCat-Token": "management-secret"},
            ),
            self.client.get(
                "/api/config",
                headers={"Authorization": "Bearer management-secret"},
            ),
            self.client.get("/api/config?token=management-secret"),
        ]

        for response in responses:
            self.assertEqual(200, response.status_code)
            self.assertNotIn("token", response.get_json()["server"])

    def test_missing_server_token_fails_closed(self):
        web_app.server.config = {"token": ""}

        response = self.client.get("/api/status")

        self.assertEqual(503, response.status_code)

    def test_browser_login_sets_strict_cookie_for_refresh(self):
        response = self.client.get("/web?token=management-secret")

        self.assertEqual(200, response.status_code)
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", response.headers["Set-Cookie"])
        self.assertEqual(200, self.client.get("/web").status_code)

    def test_pool_status_uses_the_same_authentication_boundary(self):
        self.assertEqual(401, self.client.get('/api/pool/status').status_code)
        response = self.client.get('/api/pool/status', headers={
            'X-ProxyCat-Token': 'management-secret'})
        self.assertEqual(200, response.status_code)
        self.assertFalse(response.get_json()['is_running'])

    def test_unchanged_password_survives_user_updates(self):
        stored_hash = hash_proxy_password('existing-password')
        web_app.server.users = {'alice': stored_hash}
        web_app.server.users_from_environment = False
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / 'config.ini'
            config_path.write_text('[Server]\ntoken = management-secret\n[Users]\n', encoding='utf-8')
            with patch.object(web_app, 'CONFIG_INI_PATH', str(config_path)):
                response = self.client.post('/api/users',
                    headers={'X-ProxyCat-Token': 'management-secret'},
                    json={'users': {'alice': web_app.UNCHANGED_PASSWORD}})
        self.assertEqual(200, response.status_code)
        self.assertEqual(stored_hash, web_app.server.users['alice'])

    def test_default_password_flag_matches_the_actual_password(self):
        web_app.server.users = {
            'default-user': hash_proxy_password('123456'),
            'custom-user': hash_proxy_password('custom-secret'),
        }
        response = self.client.get('/api/users', headers={
            'X-ProxyCat-Token': 'management-secret'})
        self.assertEqual(['default-user'], response.json['default_password_users'])
        self.assertNotIn('123456', response.get_data(as_text=True))
        self.assertNotIn('custom-secret', response.get_data(as_text=True))

    def test_user_api_hashes_password_and_never_returns_it(self):
        original_directory = os.getcwd()
        web_app.server.users = {}
        web_app.server.require_proxy_auth = True
        web_app.server.users_from_environment = False

        with tempfile.TemporaryDirectory() as temporary_directory:
            try:
                os.chdir(temporary_directory)
                Path("config").mkdir()
                Path("config/config.ini").write_text(
                    "[Server]\nrequire_proxy_auth = true\ntoken = management-secret\n\n[Users]\n",
                    encoding="utf-8",
                )
                with patch.object(web_app, 'CONFIG_INI_PATH', str(Path('config/config.ini').resolve())):
                    response = self.client.post(
                        "/api/users",
                        headers={"X-ProxyCat-Token": "management-secret"},
                        json={"users": {"alice": "do-not-store-plaintext"}},
                    )

                self.assertEqual(200, response.status_code)
                persisted_config = Path("config/config.ini").read_text(encoding="utf-8")
                self.assertNotIn("do-not-store-plaintext", persisted_config)
                self.assertIn("{WZ-SCRYPT}", persisted_config)

                response = self.client.get(
                    "/api/users",
                    headers={"X-ProxyCat-Token": "management-secret"},
                )
                self.assertEqual(["alice"], list(response.get_json()["users"]))
                self.assertNotIn("do-not-store-plaintext", response.get_data(as_text=True))
            finally:
                os.chdir(original_directory)


class ProxyAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    """Exercise HTTP Basic and SOCKS5 authentication at the public listener."""

    def make_server(self, users=None, require_proxy_auth=True):
        config = {
            "port": "1080",
            "mode": "cycle",
            "interval": "300",
            "use_getip": "False",
            "check_proxies": "False",
            "require_proxy_auth": str(require_proxy_auth),
            "proxy_file": "missing-test-file.txt",
            "exit_wait_timeout": "0",
        }
        if users is not None:
            config["Users"] = users
        return AsyncProxyServer(config)

    def test_http_basic_authentication_accepts_only_exact_credentials(self):
        server = self.make_server({"alice": "correct-horse"})
        valid = base64.b64encode(b"alice:correct-horse").decode()
        invalid = base64.b64encode(b"alice:wrong-password").decode()

        self.assertEqual(
            ("alice", "correct-horse"),
            server._authenticate({"proxy-authorization": f"Basic {valid}"}),
        )
        self.assertFalse(
            server._authenticate({"proxy-authorization": f"Basic {invalid}"})
        )
        self.assertFalse(
            server._authenticate({"proxy-authorization": "Basic not-base64!"})
        )

    def test_scrypt_password_hash_is_accepted(self):
        password_hash = hash_proxy_password("correct-horse")
        server = self.make_server({"alice": password_hash})

        self.assertTrue(server._verify_credentials("alice", "correct-horse"))
        self.assertFalse(server._verify_credentials("alice", "wrong-password"))

    async def test_required_auth_without_users_refuses_to_listen(self):
        server = self.make_server(users=None, require_proxy_auth=True)
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        server.port = probe.getsockname()[1]
        probe.close()

        await server.start()

        self.assertFalse(server.running)
        self.assertIn("认证", server.last_start_error)

    async def test_socks5_rejects_missing_method_and_wrong_password(self):
        server = self.make_server({"alice": "correct-horse"})
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        server.port = probe.getsockname()[1]
        probe.close()
        start_task = asyncio.create_task(server.start())

        for _ in range(100):
            if server.running:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(server.running)

        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(b"\x05\xff", await reader.readexactly(2))
        writer.close()
        await writer.wait_closed()

        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        self.assertEqual(b"\x05\x02", await reader.readexactly(2))
        writer.write(b"\x01\x05alice\x05wrong")
        await writer.drain()
        self.assertEqual(b"\x01\x01", await reader.readexactly(2))
        writer.close()
        await writer.wait_closed()

        await server.stop()
        await start_task

    async def test_http_listener_requires_valid_basic_credentials(self):
        server = self.make_server({"alice": "correct-horse"})
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        server.port = probe.getsockname()[1]
        probe.close()
        start_task = asyncio.create_task(server.start())

        for _ in range(100):
            if server.running:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(server.running)

        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await writer.drain()
        self.assertTrue((await reader.readline()).startswith(b"HTTP/1.1 407"))
        writer.close()
        await writer.wait_closed()

        credentials = base64.b64encode(b"alice:correct-horse")
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(
            b"GET http://example.com/ HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Proxy-Authorization: Basic " + credentials + b"\r\n\r\n"
        )
        await writer.drain()
        self.assertTrue((await reader.readline()).startswith(b"HTTP/1.1 503"))
        writer.close()
        await writer.wait_closed()

        await server.stop()
        await start_task

    async def test_successful_socks5_authentication_never_logs_password(self):
        password = "do-not-log-this-password"
        server = self.make_server({"alice": password})
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        server.port = probe.getsockname()[1]
        probe.close()

        with patch("modules.proxyserver.logging.info") as log_info:
            start_task = asyncio.create_task(server.start())
            for _ in range(100):
                if server.running:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(server.running)

            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            self.assertEqual(b"\x05\x02", await reader.readexactly(2))
            encoded_password = password.encode()
            writer.write(
                b"\x01\x05alice" + bytes((len(encoded_password),)) + encoded_password
            )
            await writer.drain()
            self.assertEqual(b"\x01\x00", await reader.readexactly(2))
            writer.close()
            await writer.wait_closed()

            await server.stop()
            await start_task

        rendered_logs = " ".join(
            " ".join(str(value) for value in call.args)
            for call in log_info.call_args_list
        )
        self.assertNotIn(password, rendered_logs)


class ServiceLifecycleAuthorizationTests(unittest.TestCase):
    """Protect the shared server from simultaneous authenticated start requests."""

    def test_concurrent_start_calls_share_one_listener(self):
        original_port = web_app.server.port
        original_auth_error = web_app.server.auth_configuration_error
        original_require_auth = web_app.server.require_proxy_auth
        original_auth_required = web_app.server.auth_required
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        web_app.server.port = port
        web_app.server.auth_configuration_error = None
        web_app.server.require_proxy_auth = False
        web_app.server.auth_required = False
        barrier = threading.Barrier(3)
        results = []
        original_config = web_app.server.config
        web_app.server.config = {'token': 'lifecycle-test-token'}

        def start_service():
            barrier.wait()
            with web_app.app.test_client() as client:
                response = client.post('/api/service', json={'action': 'start'},
                                       headers={'X-ProxyCat-Token': 'lifecycle-test-token'})
                results.append(response.get_json()['status'])

        threads = [threading.Thread(target=start_service) for _ in range(2)]
        try:
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=3)

            self.assertEqual(['success', 'success'], sorted(results))
            self.assertTrue(web_app.server.running)
            with web_app.app.test_client() as client:
                response = client.post('/api/service', json={'action': 'stop'},
                                       headers={'X-ProxyCat-Token': 'lifecycle-test-token'})
                self.assertEqual('success', response.get_json()['status'])

            rebound = socket.socket()
            try:
                rebound.bind(("0.0.0.0", port))
            finally:
                rebound.close()
        finally:
            web_app.server.stop_server = True
            web_app.server.close_listener()
            web_app._wait_proxy_thread_exit(timeout=3)
            web_app.server.config = original_config
            web_app.server.port = original_port
            web_app.server.auth_configuration_error = original_auth_error
            web_app.server.require_proxy_auth = original_require_auth
            web_app.server.auth_required = original_auth_required


if __name__ == "__main__":
    unittest.main()
