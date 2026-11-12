"""Run with: uv run python -m unittest discover -s tests -v.

Regression tests for #13: a failed connect attempt fires bleak's
disconnected_callback mid-retry, which must not untrack a later successful
attempt. No Bluetooth adapter, BlueZ or Home Assistant is needed.
"""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from bleak.exc import BleakError

from bt_proxy import ble_manager as bm

ADDR = 0xAABBCCDDEEFF
MAC = "AA:BB:CC:DD:EE:FF"


class FakeClient:
    """Stands in for BleakClient. Each instance takes the next step of `plan`.

    "cb_then_fail"     fire the disconnect callback, then raise (a failed attempt)
    "late_cb_then_ok"  fire the PREVIOUS client's callback late, then connect
    "ok"               connect
    "fail"             raise without a callback
    """

    plan: list[str] = []
    made: list["FakeClient"] = []

    def __init__(self, target, disconnected_callback=None, timeout=None):
        self.cb = disconnected_callback
        self.is_connected = False
        self.disconnects = 0
        self.step = FakeClient.plan[len(FakeClient.made)]
        FakeClient.made.append(self)

    async def connect(self):
        if self.step == "cb_then_fail":
            self.cb(self)
            raise BleakError("[org.bluez.Error.Failed] br-connection-canceled")
        if self.step == "fail":
            raise BleakError("[org.bluez.Error.Failed] le-connection-abort-by-local")
        if self.step == "late_cb_then_ok":
            prev = FakeClient.made[-2]
            prev.cb(prev)
        self.is_connected = True

    async def disconnect(self):
        self.disconnects += 1
        self.is_connected = False


class ConnectRetryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        FakeClient.made = []
        patches = [
            patch.object(bm, "BleakClient", FakeClient),
            patch.object(bm, "CONNECT_RETRY_DELAY", 0),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.mgr = bm.BLEManager(max_connections=3)
        self.ha_disconnects: list[int] = []
        self.mgr.set_callbacks(
            on_advertisement=lambda *a: None,
            on_disconnect=self.ha_disconnects.append,
            on_notify=lambda *a: None,
        )
        self.mgr._bluez_clear_state = AsyncMock()
        self.mgr._bluez_remove_device = AsyncMock()

    async def test_mid_retry_callback_keeps_successful_link_tracked(self):
        FakeClient.plan = ["cb_then_fail", "ok"]
        ok, _, _ = await self.mgr.connect_device(ADDR)
        self.assertTrue(ok)
        self.assertIn(ADDR, self.mgr._connections)
        self.assertEqual(self.ha_disconnects, [], "HA was told 'disconnected' mid-retry")

        # HA's disconnect must now reach the live client.
        await self.mgr.disconnect_device(ADDR)
        self.assertEqual(FakeClient.made[-1].disconnects, 1)
        self.assertNotIn(ADDR, self.mgr._connections)

    async def test_late_callback_from_earlier_attempt_is_ignored(self):
        FakeClient.plan = ["fail", "late_cb_then_ok"]
        ok, _, _ = await self.mgr.connect_device(ADDR)
        self.assertTrue(ok)
        self.assertIn(ADDR, self.mgr._connections)
        self.assertIs(self.mgr._connections[ADDR].client, FakeClient.made[-1])
        self.assertEqual(self.ha_disconnects, [])

    async def test_real_disconnect_after_connect_still_reported(self):
        FakeClient.plan = ["ok"]
        ok, _, _ = await self.mgr.connect_device(ADDR)
        self.assertTrue(ok)
        live = FakeClient.made[-1]
        live.is_connected = False
        live.cb(live)
        self.assertEqual(self.ha_disconnects, [ADDR])
        self.assertNotIn(ADDR, self.mgr._connections)

    async def test_all_attempts_failed_clears_bluez_state(self):
        FakeClient.plan = ["cb_then_fail"] * bm.CONNECT_MAX_RETRIES
        ok, _, _ = await self.mgr.connect_device(ADDR)
        self.assertFalse(ok)
        self.assertNotIn(ADDR, self.mgr._connections)
        self.mgr._bluez_clear_state.assert_awaited_with(MAC)

    async def test_disconnect_for_untracked_address_clears_bluez_state(self):
        await self.mgr.disconnect_device(ADDR)
        self.mgr._bluez_clear_state.assert_awaited_once_with(MAC)


if __name__ == "__main__":
    unittest.main()
