"""Run with: uv run python -m unittest discover -s tests -v."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, Mock, patch

from dbus_fast import MessageType, Variant

from bt_proxy import __main__ as proxy


def _reply(message_type: MessageType, body: list | None = None) -> Mock:
    reply = Mock()
    reply.message_type = message_type
    reply.body = body or []
    return reply


def _bus_returning(reply: Mock) -> Mock:
    bus = Mock()
    bus.call = AsyncMock(return_value=reply)
    bus.disconnect = Mock()
    return bus


class GetAdapterMacTests(unittest.IsolatedAsyncioTestCase):
    async def _with_bus(self, bus: Mock, adapter: str = "hci1") -> str:
        with patch.object(proxy, "MessageBus") as make_bus:
            make_bus.return_value.connect = AsyncMock(return_value=bus)
            return await proxy.get_adapter_mac(adapter)

    async def test_reads_named_adapter_address(self):
        bus = _bus_returning(
            _reply(MessageType.METHOD_RETURN, [Variant("s", "04:42:1a:59:e6:c7")])
        )
        self.assertEqual(await self._with_bus(bus), "04:42:1A:59:E6:C7")
        message = bus.call.await_args.args[0]
        self.assertEqual(message.path, "/org/bluez/hci1")
        self.assertEqual(message.body, ["org.bluez.Adapter1", "Address"])
        bus.disconnect.assert_called_once()

    async def test_unknown_adapter_is_unknown_mac(self):
        bus = _bus_returning(_reply(MessageType.ERROR, ["No such object"]))
        self.assertEqual(await self._with_bus(bus, "hci7"), proxy.UNKNOWN_MAC)
        bus.disconnect.assert_called_once()

    async def test_no_reply_is_unknown_mac(self):
        bus = Mock()
        bus.call = AsyncMock(return_value=None)
        self.assertEqual(await self._with_bus(bus), proxy.UNKNOWN_MAC)

    async def test_system_bus_unavailable_is_unknown_mac(self):
        with patch.object(proxy, "MessageBus") as make_bus:
            make_bus.return_value.connect = AsyncMock(
                side_effect=FileNotFoundError("no system bus")
            )
            self.assertEqual(await proxy.get_adapter_mac("hci0"), proxy.UNKNOWN_MAC)


class WaitForBtMacTests(unittest.IsolatedAsyncioTestCase):
    async def test_named_adapter_never_uses_default_controller(self):
        with patch.object(
            proxy, "get_adapter_mac", AsyncMock(return_value="04:42:1A:59:E6:C7")
        ) as named, patch.object(proxy, "get_bt_mac") as default:
            self.assertEqual(await proxy.wait_for_bt_mac("hci1"), "04:42:1A:59:E6:C7")
        named.assert_awaited_once_with("hci1")
        default.assert_not_called()

    async def test_named_adapter_waits_instead_of_falling_back(self):
        answers = [proxy.UNKNOWN_MAC, proxy.UNKNOWN_MAC, "04:42:1A:59:E6:C7"]
        with patch.object(
            proxy, "get_adapter_mac", AsyncMock(side_effect=answers)
        ), patch.object(proxy, "get_bt_mac", return_value="88:A2:9E:D7:38:B6") as default, \
                patch.object(proxy.asyncio, "sleep", AsyncMock()) as sleep:
            self.assertEqual(await proxy.wait_for_bt_mac("hci1"), "04:42:1A:59:E6:C7")
        self.assertEqual(sleep.await_count, 2)
        default.assert_not_called()

    async def test_without_adapter_uses_default_controller(self):
        with patch.object(proxy, "get_bt_mac", return_value="88:A2:9E:D7:38:B6"), \
                patch.object(proxy, "get_adapter_mac", AsyncMock()) as named:
            self.assertEqual(await proxy.wait_for_bt_mac(None), "88:A2:9E:D7:38:B6")
        named.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
