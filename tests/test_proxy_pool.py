import asyncio
import socket
import threading
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


    async def test_occupied_port_does_not_report_service_running(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("0.0.0.0", 0))
        blocker.listen()
        server = self.make_server()
        server.port = blocker.getsockname()[1]

        try:
            await server.start()
            self.assertFalse(server.running)
            self.assertTrue(server.last_start_error)
        finally:
            blocker.close()

    async def test_stop_releases_port_before_restart(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        server = self.make_server()
        server.port = port
        start_task = asyncio.create_task(server.start())

        for _ in range(100):
            if server.running:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(server.running)

        await server.stop()
        await start_task

        rebound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            rebound.bind(("0.0.0.0", port))
        finally:
            rebound.close()


    async def test_stop_does_not_wait_for_idle_clients(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        server = self.make_server()
        server.port = port
        start_task = asyncio.create_task(server.start())

        for _ in range(100):
            if server.running:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(server.running)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            for _ in range(100):
                if server.active_connections:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(server.active_connections)

            await asyncio.wait_for(server.stop(), timeout=1)
            await asyncio.wait_for(start_task, timeout=1)
            self.assertFalse(server.running)
        finally:
            writer.close()
            await writer.wait_closed()


    async def test_threaded_shutdown_does_not_race_final_cleanup(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        server = self.make_server()
        server.port = port
        thread_errors = []

        async def lifecycle():
            try:
                await server.start()
            finally:
                await server.stop()

        def run_lifecycle():
            try:
                asyncio.run(lifecycle())
            except Exception as error:
                thread_errors.append(error)

        proxy_thread = threading.Thread(target=run_lifecycle)
        proxy_thread.start()

        for _ in range(100):
            if server.running:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(server.running)

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            future = asyncio.run_coroutine_threadsafe(
                server.stop(), server.event_loop
            )
            await asyncio.wait_for(asyncio.wrap_future(future), timeout=1)
        finally:
            writer.close()
            await writer.wait_closed()

        proxy_thread.join(timeout=1)
        self.assertFalse(proxy_thread.is_alive())
        self.assertEqual([], thread_errors)


if __name__ == "__main__":
    unittest.main()
