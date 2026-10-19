"""Regression tests for remote disconnect, retries and cancellation cleanup."""
import asyncio
import unittest
from unittest.mock import patch

from bt_proxy import ble_manager as bm



class FakeClient:
    """A fake BLE client whose bus stays open until explicit disconnect()."""
    made = []
    plans = []

    def __init__(self, target, disconnected_callback=None, timeout=None):
        self.callback = disconnected_callback
        self.is_connected = False
        self.bus_open = True
        self.disconnect_calls = 0
        self.services = None
        self.made.append(self)

    async def connect(self):
        """Play the next planned transport outcome, including a stale callback."""
        plan = self.plans.pop(0) if self.plans else "ok"
        if plan == "fail":
            self.callback(self)
            raise bm.BleakError("test connection failed")
        if plan == "cancel":
            raise asyncio.CancelledError()
        if plan == "stale":
            self.made[-2].callback(self.made[-2])
        self.is_connected = True

    async def disconnect(self):
        """Release bus resources even if the peripheral has already left."""
        self.disconnect_calls += 1
        was_connected = self.is_connected
        self.is_connected = False
        self.bus_open = False
        if was_connected:
            self.callback(self)


class CleanupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        FakeClient.made = []
        FakeClient.plans = []
        self.client_patch = patch.object(bm, "BleakClient", FakeClient)
        self.retry_patch = patch.object(bm, "CONNECT_RETRY_DELAY", 0)
        self.client_patch.start()
        self.retry_patch.start()
        self.addCleanup(self.client_patch.stop)
        self.addCleanup(self.retry_patch.stop)

    def connection(self):
        """Create one connection with observable upstream disconnect callbacks."""
        self.dropped = []
        return bm.BLEConnection(1, self.dropped.append, lambda *args: None)

    async def test_explicit_disconnect_releases_bus(self):
        conn = self.connection()
        await conn.connect()
        client = conn.client
        await conn.disconnect()
        self.assertFalse(client.bus_open)
        self.assertEqual(client.disconnect_calls, 1)

    async def test_already_disconnected_client_still_gets_cleaned(self):
        conn = self.connection()
        await conn.connect()
        client = conn.client
        client.is_connected = False
        await conn.disconnect()
        self.assertFalse(client.bus_open)

    async def test_300_remote_disconnects_do_not_accumulate_sockets(self):
        # Repeated remote link losses must not reach the real D-Bus limit of 256.
        for _ in range(300):
            conn = self.connection()
            await conn.connect()
            client = conn.client
            client.is_connected = False
            client.callback(client)
            await asyncio.sleep(0)
            self.assertFalse(client.bus_open)
            await conn.disconnect()
            self.assertEqual(client.disconnect_calls, 1)
        self.assertTrue(all(not c.bus_open for c in FakeClient.made))

    async def test_duplicate_remote_callback_only_cleans_once(self):
        conn = self.connection()
        await conn.connect()
        client = conn.client
        client.is_connected = False
        client.callback(client)
        client.callback(client)
        await conn.disconnect()
        self.assertEqual(client.disconnect_calls, 1)
        self.assertEqual(self.dropped, [1])

    async def test_cancelled_connect_releases_bus(self):
        FakeClient.plans = ["cancel"]
        with self.assertRaises(asyncio.CancelledError):
            await self.connection().connect()
        self.assertFalse(FakeClient.made[0].bus_open)

    async def manager(self):
        """Stub only host cleanup; the manager and retry loop remain real."""
        manager = bm.BLEManager()
        self.disconnections = []
        manager.set_callbacks(lambda *a: None, self.disconnections.append, lambda *a: None)
        async def clear(mac):
            pass
        manager._bluez_clear_state = clear
        return manager

    async def test_failed_retry_and_stale_callback_keep_success_tracked(self):
        FakeClient.plans = ["fail", "stale"]
        manager = await self.manager()
        ok, _, _ = await manager.connect_device(1)
        self.assertTrue(ok)
        self.assertIn(1, manager._connections)
        self.assertEqual(self.disconnections, [])
        self.assertFalse(FakeClient.made[0].bus_open)
        self.assertTrue(FakeClient.made[1].bus_open)
        await manager.disconnect_device(1)
        self.assertTrue(all(not c.bus_open for c in FakeClient.made))

    async def test_exhausted_retries_release_all_clients(self):
        FakeClient.plans = ["fail"] * 3
        manager = await self.manager()
        ok, _, _ = await manager.connect_device(1)
        self.assertFalse(ok)
        self.assertNotIn(1, manager._connections)
        self.assertTrue(all(not c.bus_open for c in FakeClient.made))


if __name__ == "__main__":
    unittest.main(verbosity=2)
