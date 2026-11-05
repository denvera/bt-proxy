"""Run with: uv run python -m unittest discover -s tests -v."""

from __future__ import annotations

import contextlib
import io
import socket
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch

from bt_proxy import __main__ as proxy
from bt_proxy.api_server import APIServer


class ResolveBindTests(unittest.TestCase):
    def test_explicit_ipv4(self):
        self.assertEqual(proxy.resolve_bind("127.0.0.1"), "127.0.0.1")

    def test_linux_interface(self):
        self.assertEqual(proxy.resolve_bind("lo"), "127.0.0.1")

    def test_missing_interface(self):
        with patch.object(socket, "if_nametoindex", side_effect=OSError("missing")):
            with self.assertRaisesRegex(ValueError, "existing interface"):
                proxy.resolve_bind("missing-iface")

    def test_interface_without_ipv4(self):
        with patch.object(socket, "if_nametoindex", return_value=2):
            with patch.object(proxy.fcntl, "ioctl", side_effect=OSError("no address")):
                with self.assertRaisesRegex(ValueError, "Cannot get IPv4"):
                    proxy.resolve_bind("eth0")

    def test_unsupported_addresses(self):
        for address in ("0.0.0.0", "224.0.0.251", "255.255.255.255", "::1"):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    proxy.resolve_bind(address)

    def test_unavailable_address(self):
        with patch.object(socket, "socket") as make_socket:
            make_socket.return_value.__enter__.return_value.bind.side_effect = (
                OSError("Cannot assign requested address")
            )
            with self.assertRaisesRegex(ValueError, "Cannot bind to 192.0.2.1"):
                proxy.resolve_bind("192.0.2.1")

    def test_invalid_cli_bind_fails_before_async_startup(self):
        with patch.object(sys, "argv", ["bt-proxy", "--bind", "0.0.0.0"]):
            with patch.object(proxy.asyncio, "run") as run:
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    with self.assertRaises(SystemExit) as error:
                        proxy.main()
                self.assertEqual(error.exception.code, 2)
                self.assertIn("specific local unicast IPv4", stderr.getvalue())
                run.assert_not_called()


class NetworkBindTests(unittest.IsolatedAsyncioTestCase):
    async def test_mdns_uses_selected_address(self):
        with patch.object(proxy, "AsyncZeroconf") as make_zeroconf:
            zc = make_zeroconf.return_value
            zc.async_register_service = AsyncMock()
            with patch.object(proxy, "get_local_ip") as automatic_ip:
                _, info = await proxy.register_mdns(
                    "test-proxy", 6053, "00:11:22:33:44:55", "127.0.0.1"
                )
            automatic_ip.assert_not_called()
            make_zeroconf.assert_called_once_with(
                interfaces=["127.0.0.1"], ip_version=proxy.IPVersion.V4Only
            )
            self.assertEqual(info.addresses, [socket.inet_aton("127.0.0.1")])
            zc.async_register_service.assert_awaited_once_with(info)

    async def test_mdns_without_bind_keeps_default_interfaces(self):
        with patch.object(proxy, "AsyncZeroconf") as make_zeroconf:
            make_zeroconf.return_value.async_register_service = AsyncMock()
            with patch.object(proxy, "get_local_ip", return_value="192.0.2.1"):
                _, info = await proxy.register_mdns(
                    "test-proxy", 6053, "00:11:22:33:44:55"
                )
            make_zeroconf.assert_called_once_with(ip_version=proxy.IPVersion.V4Only)
            self.assertEqual(info.addresses, [socket.inet_aton("192.0.2.1")])

    async def test_api_listener_binds_selected_address(self):
        server = APIServer(Mock(), host="127.0.0.1", port=0)
        try:
            await server.start()
            self.assertTrue(server._server.sockets)
            for listener in server._server.sockets:
                self.assertEqual(listener.getsockname()[0], "127.0.0.1")
        finally:
            await server.stop()

    async def test_api_without_bind_keeps_wildcard(self):
        server = APIServer(Mock())
        with patch.object(proxy.asyncio, "start_server", new_callable=AsyncMock) as start:
            await server.start()
        start.assert_awaited_once_with(server._handle_client, "0.0.0.0", 6053)


if __name__ == "__main__":
    unittest.main()
