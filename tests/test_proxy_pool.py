import unittest
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.proxyserver import AsyncProxyServer


class ProxyPoolSelectionTests(unittest.IsolatedAsyncioTestCase):
    def make_server(self, mode="cycle"):
        server = AsyncProxyServer({
            "port": "1080",
            "mode": mode,
            "interval": "300",
            "use_getip": "False",
            "check_proxies": "False",
            "proxy_file": "missing-test-file.txt",
        })
        server.proxies = ["http://127.0.0.1:18080", "http://127.0.0.1:18081"]
        server.proxy_cycle = iter(server.proxies)
        server.current_proxy = server.proxies[0]
        return server

    async def test_manual_switch_moves_to_next_proxy(self):
        server = self.make_server()
        server.last_switch_attempt = 0

        switched = await server.switch_proxy()

        self.assertTrue(switched)
        self.assertEqual("http://127.0.0.1:18081", server.current_proxy)

    async def test_load_balance_selects_next_proxy_without_self_blocking(self):
        server = self.make_server(mode="loadbalance")

        selected = await server.get_next_proxy()

        self.assertEqual("http://127.0.0.1:18081", selected)

    async def test_invalid_proxy_entries_are_excluded_from_file_pool(self):
        server = self.make_server()
        self.assertFalse(await server._validate_proxy("not-a-proxy"))

    async def test_getip_failures_do_not_stop_the_proxy_service(self):
        server = self.make_server()
        server.use_getip = True

        with patch("modules.proxyserver.getip.newip", side_effect=ValueError("provider unavailable")):
            self.assertIsNone(await server._load_getip_proxy())


if __name__ == "__main__":
    unittest.main()
