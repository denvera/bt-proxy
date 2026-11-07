"""A scanner start that returns cleanly is not proof of a working radio.

BlueZ accepts a passive-scan request against an unpowered adapter and then
refuses to register the advertisement monitor — `Failed to Add Adv Patterns
Monitor with status 0x0a` (MGMT_STATUS_NOT_POWERED). That refusal never reaches
the client, so bleak's start() returns success and the proxy reports RUNNING
for a controller that cannot receive anything. Unchecked, a dead radio goes on
looking healthy to Home Assistant indefinitely; the only sign is the advert
watchdog tripping repeatedly in the log.

These tests pin both halves: refuse to report a dead radio as running, and
never refuse a working one.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from bt_proxy import ble_manager, proto

pytestmark = pytest.mark.asyncio


class Recorder:
    """Captures the scanner states reported to the client."""

    def __init__(self):
        self.states: list[int] = []

    def __call__(self, state: int) -> None:
        self.states.append(state)


def wire(manager, powered):
    """Attach a state recorder and stub the adapter power answer."""
    rec = Recorder()
    manager.set_callbacks(
        on_advertisement=lambda *a: None,
        on_disconnect=lambda *a: None,
        on_notify=lambda *a: None,
        on_scanner_state=rec,
    )

    async def _powered(self=None):
        return powered

    manager._adapter_powered = _powered
    return rec


@pytest.fixture(autouse=True)
def _no_real_scanner(monkeypatch):
    """Let the scanner "start" successfully without a radio."""

    async def _ok(self, passive):  # noqa: ANN001
        self._scanner = object()

    monkeypatch.setattr(ble_manager.BLEManager, "_start_scanner_with_retry", _ok)

    async def _teardown(self):  # noqa: ANN001
        self._scanner = None

    monkeypatch.setattr(ble_manager.BLEManager, "_teardown_scanner", _teardown)
    monkeypatch.setattr(
        ble_manager.BLEManager, "_schedule_scan_rearm", lambda self: None
    )

    async def _passive_no(self):  # noqa: ANN001
        return False

    monkeypatch.setattr(
        ble_manager.BLEManager, "_passive_scan_available", _passive_no
    )


async def test_unpowered_adapter_is_reported_failed_not_running(manager):
    """A start against a dead controller must not read as running."""
    rec = wire(manager, powered=False)

    await manager.start_scanning()

    assert proto.SCANNER_STATE_RUNNING not in rec.states, (
        "reported RUNNING for an adapter that cannot receive anything"
    )
    assert rec.states[-1] == proto.SCANNER_STATE_FAILED
    assert manager._scanning is False


async def test_powered_adapter_still_reports_running(manager):
    """The half that must not regress: a working radio is not refused."""
    rec = wire(manager, powered=True)

    await manager.start_scanning()

    assert rec.states[-1] == proto.SCANNER_STATE_RUNNING
    assert manager._scanning is True


async def test_unknown_power_state_is_treated_as_working(manager):
    """When we cannot ask, we must not invent a failure.

    _adapter_powered returns None on any error — no D-Bus, no dbus_fast, a
    timeout. Treating that as "dead" would take out every proxy on a platform
    where the query simply is not available.
    """
    rec = wire(manager, powered=None)

    await manager.start_scanning()

    assert rec.states[-1] == proto.SCANNER_STATE_RUNNING
    assert manager._scanning is True


async def test_failed_start_re_arms_so_recovery_is_picked_up(
    manager, monkeypatch
):
    """A refusal must still schedule the re-arm, or recovery never lands."""
    rearmed = []
    monkeypatch.setattr(
        ble_manager.BLEManager,
        "_schedule_scan_rearm",
        lambda self: rearmed.append(True),
    )
    wire(manager, powered=False)

    await manager.start_scanning()

    assert rearmed, "gave up permanently instead of re-arming"


async def test_power_query_cannot_hang_the_start(manager, monkeypatch):
    """A wedged bluetoothd is exactly when this D-Bus call hangs.

    The real _adapter_powered wraps its calls in asyncio.wait_for; this pins
    that a hung query degrades to "cannot tell" rather than blocking the
    scanner forever.
    """
    monkeypatch.setattr(ble_manager, "ADAPTER_POWER_QUERY_TIMEOUT", 0.05)

    class HangingBus:
        def __init__(self, *a, **kw):
            pass

        async def connect(self):
            await asyncio.sleep(10)
            return self

    monkeypatch.setattr(ble_manager, "MessageBus", HangingBus)

    result = await asyncio.wait_for(manager._adapter_powered(), timeout=2.0)
    assert result is None


# --- advertisement watchdog -------------------------------------------------


@pytest.fixture
def fast_watchdog(monkeypatch):
    """Check every 10 ms instead of every 30 s."""
    monkeypatch.setattr(ble_manager, "ADVERT_WATCHDOG_INTERVAL", 0.01)


async def test_silent_scanner_is_torn_down_and_re_armed(
    manager, monkeypatch, fast_watchdog
):
    """No advertisements for the timeout: report FAILED and hand to re-arm."""
    rearmed = []
    monkeypatch.setattr(
        ble_manager.BLEManager,
        "_schedule_scan_rearm",
        lambda self: rearmed.append(True),
    )
    manager._advert_timeout = 0.05
    rec = wire(manager, powered=True)

    await manager.start_scanning()
    assert rec.states[-1] == proto.SCANNER_STATE_RUNNING

    await asyncio.sleep(0.2)

    assert rec.states[-1] == proto.SCANNER_STATE_FAILED
    assert manager._scanning is False
    assert manager._scanner is None
    assert rearmed, "the watchdog tripped but nothing re-arms the scanner"


async def test_advertisements_keep_the_scanner_running(manager, fast_watchdog):
    """The half that must not regress: a receiving scanner is left alone."""
    manager._advert_timeout = 0.05
    rec = wire(manager, powered=True)

    await manager.start_scanning()
    for _ in range(20):
        manager._last_advert = time.monotonic()
        await asyncio.sleep(0.01)

    assert proto.SCANNER_STATE_FAILED not in rec.states
    assert manager._scanning is True
    await manager.stop_scanning()


async def test_deliberate_stop_is_not_a_dead_radio(manager, fast_watchdog):
    """Stopping the scanner cancels the watchdog; silence after it is expected."""
    manager._advert_timeout = 0.05
    rec = wire(manager, powered=True)

    await manager.start_scanning()
    await manager.stop_scanning()
    await asyncio.sleep(0.2)

    assert proto.SCANNER_STATE_FAILED not in rec.states
    assert manager._advert_watchdog_task is None


async def test_scan_mode_switch_keeps_exactly_one_watchdog(manager, fast_watchdog):
    """The stop/start inside set_scan_mode must leave a live watchdog behind.

    The cancelled watchdog finishes after its replacement has started; it must
    not clear the replacement's handle on the way out.
    """
    manager._advert_timeout = 60
    wire(manager, powered=True)

    await manager.start_scanning()
    first = manager._advert_watchdog_task
    await asyncio.sleep(0.02)  # let it run into its first sleep
    await manager.set_scan_mode(not manager._scan_active)
    for _ in range(5):
        await asyncio.sleep(0)

    task = manager._advert_watchdog_task
    assert first.done()
    assert task is not None and task is not first and not task.done()
    await manager.stop_scanning()


async def test_timeout_zero_disables_the_watchdog(manager, fast_watchdog):
    manager._advert_timeout = 0
    wire(manager, powered=True)

    await manager.start_scanning()

    assert manager._advert_watchdog_task is None
    assert manager._scanning is True
