"""Test fixtures: a fake BleakClient, so the connection lifecycle can be
exercised without a radio.

Everything here stands in for BlueZ. The behaviour under test is entirely in
bt_proxy's bookkeeping — who asked for a link, and whether it is still wanted
by the time it is established — so a fake that can be told to fail the first N
attempts, or to take a while, is enough to reproduce every race that matters.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable

import pytest


class FakeBleakClient:
    """Minimal stand-in for bleak's client.

    Class attributes steer every instance, which is what the tests set: how
    many connects fail before one succeeds, and how long each takes.
    """

    #: connects that raise before one is allowed to succeed
    fail_first: int = 0
    #: seconds each connect attempt takes
    connect_delay: float = 0.0
    #: every instance created, in order, for assertions
    instances: list["FakeBleakClient"] = []
    #: how many connect() calls have been made across all instances
    attempts: int = 0
    #: when set, a connect that is about to succeed blocks here first. Lets a
    #: test hold the radio mid-connect and act while it is in flight, which is
    #: the only way to reproduce the race deterministically rather than by
    #: sleeping and hoping.
    gate: asyncio.Event | None = None

    def __init__(
        self,
        target: Any,
        disconnected_callback: Callable[[Any], None] | None = None,
        timeout: float = 10.0,
    ):
        self.target = target
        self._connected = False
        self._disconnected_callback = disconnected_callback
        self.disconnect_calls = 0
        # bt_proxy reads the MTU off the backend; there is no _acquire_mtu here,
        # so the best-effort branch is skipped and this value is taken as-is.
        self._mtu_size = 23
        FakeBleakClient.instances.append(self)

    @classmethod
    def reset(cls) -> None:
        cls.fail_first = 0
        cls.connect_delay = 0.0
        cls.instances = []
        cls.attempts = 0
        cls.gate = None

    @classmethod
    async def wait_for_attempt(cls, n: int) -> None:
        """Block until the nth connect() call has begun."""
        for _ in range(2000):
            if cls.attempts >= n:
                return
            await asyncio.sleep(0.001)
        raise AssertionError(
            f"only {cls.attempts} connect attempts were made, wanted {n}"
        )

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        FakeBleakClient.attempts += 1
        if self.connect_delay:
            await asyncio.sleep(self.connect_delay)
        if FakeBleakClient.attempts <= FakeBleakClient.fail_first:
            raise RuntimeError(
                f"fake connect failure {FakeBleakClient.attempts}"
            )
        if FakeBleakClient.gate is not None:
            # Held mid-connect: the radio is committed, nothing has returned.
            await FakeBleakClient.gate.wait()
        self._connected = True

    async def disconnect(self) -> None:
        self.disconnect_calls += 1
        was_connected = self._connected
        self._connected = False
        if was_connected and self._disconnected_callback:
            self._disconnected_callback(self)


@pytest.fixture
def fake_bleak(monkeypatch):
    """Swap bleak's client for the fake, and neuter the bluetoothctl helpers.

    _bluez_clear_state shells out to bluetoothctl, which is neither present nor
    meaningful here; left alone it would only add subprocess noise to results
    that are about bookkeeping.
    """
    from bt_proxy import ble_manager

    FakeBleakClient.reset()
    monkeypatch.setattr(ble_manager, "BleakClient", FakeBleakClient)

    async def _noop(self, mac):  # noqa: ANN001
        return None

    monkeypatch.setattr(ble_manager.BLEManager, "_bluez_clear_state", _noop)
    monkeypatch.setattr(ble_manager.BLEManager, "_bluez_remove_device", _noop)
    return FakeBleakClient


@pytest.fixture
def manager(fake_bleak):
    from bt_proxy.ble_manager import BLEManager

    return BLEManager(max_connections=3)
