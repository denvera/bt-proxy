"""BLE manager using bleak for scanning and GATT connections."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable

from bleak import BleakClient, BleakScanner
from bleak.assigned_numbers import AdvertisementDataType
from bleak.exc import BleakError
from bleak.backends.bluezdbus.version import _get_bluetoothctl_version
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

try:  # bleak >= 1.0 exposes these from bleak.args.bluez
    from bleak.args.bluez import BlueZScannerArgs, OrPattern
except ImportError:  # pragma: no cover - older bleak layout
    from bleak.backends.bluezdbus.scanner import BlueZScannerArgs  # type: ignore
    from bleak.backends.bluezdbus.advertisement_monitor import (  # type: ignore
        OrPattern,
    )

from . import proto

logger = logging.getLogger(__name__)

# Default MTU for BLE connections
DEFAULT_MTU = 23
MTU_ACQUIRE_TIMEOUT = 10.0

# Connection retry settings
CONNECT_TIMEOUT = 30.0
CONNECT_RETRY_DELAY = 2.0
CONNECT_MAX_RETRIES = 3

# Per-device connect-failure backoff. Home Assistant retries failed connections
# aggressively; without a brake we relay every retry straight to BlueZ and the
# controller, and that churn can tip a flaky single-radio adapter over the edge
# (it's what triggered a bluetoothd wedge in testing). Each consecutive failure
# pushes the next allowed attempt out (linear, capped); a success clears it.
CONNECT_FAIL_BACKOFF_STEP = 5.0
CONNECT_FAIL_BACKOFF_MAX = 60.0
# A connect that "succeeds" instantly but isn't really connected (a phantom
# connection — BlueZ returns success yet the link is dead, MTU acquire reports
# "Not connected"), or D-Bus calls returning NoReply, means bluetoothd itself
# is wedged. The proxy can't fix that (it's a host daemon), so we back off hard
# and log how to recover rather than flapping every reconnect.
DAEMON_WEDGE_BACKOFF = 120.0

# Scanner start can fail transiently — most commonly BlueZ "InProgress" when a
# previous discovery session hasn't been fully torn down yet. We make a few
# gentle attempts, releasing the stale session between them, rather than either
# crashing (a supervisor restart-loop hammers a flaky adapter) or retrying in a
# tight loop. A persistent failure usually means the controller is wedged at the
# HCI level (dmesg "hci0: Opcode 0x200c failed"), which only an adapter reset
# clears — so we stop and report FAILED instead of flooding it with more scan
# commands.
SCAN_START_MAX_RETRIES = 3
SCAN_START_RETRY_DELAY = 2.0
# While the scanner is down we re-arm it on a slow, single-attempt cadence so it
# self-heals from a transient failure (or a manual adapter reset) without
# hammering the controller.
SCAN_REARM_INTERVAL = 60.0

# Passive scanning via the BlueZ AdvertisementMonitor1 D-Bus interface needs
# BlueZ >= 5.56 (and the daemon started with --experimental). On older BlueZ
# we must not even attempt it. See:
# https://github.com/hbldh/bleak/commit/2d70d1c0727b1319d57effac36c70c1c891e51e9
PASSIVE_MIN_BLUEZ_VERSION = (5, 56)

# BlueZ passive scanning requires "or_patterns"; without them bleak raises.
# Matching the advertising FLAGS field (LE General / Limited Discoverable)
# captures effectively all connectable advertisements, mirroring what Home
# Assistant's own habluetooth passive scanner uses.
PASSIVE_SCAN_OR_PATTERNS = [
    OrPattern(0, AdvertisementDataType.FLAGS, b"\x06"),
    OrPattern(0, AdvertisementDataType.FLAGS, b"\x1a"),
]


def _is_link_dead_error(error: Exception) -> bool:
    """Whether an exception means the BLE link is actually dead.

    Distinguishes a real disconnect / wedged-daemon condition from a benign
    transient: "Not connected" and D-Bus "NoReply" mean the link is gone (or
    bluetoothd is wedged holding stale state), as opposed to e.g. a slow MTU
    negotiation that shouldn't fail an otherwise good connection.
    """
    err = str(error)
    return "Not connected" in err or "NoReply" in err


def _is_daemon_wedge_error(error: Exception | None) -> bool:
    """Whether a connect failure looks like a wedged bluetoothd daemon.

    The tells are a phantom connection (BlueZ claims success but the link is
    dead) or D-Bus calls timing out with NoReply — neither is fixable from the
    proxy, so we treat them specially (hard backoff + a recovery hint).
    """
    if error is None:
        return False
    err = str(error)
    return "phantom" in err or "NoReply" in err or "Not connected" in err


class BLEConnection:
    """Manages a single active BLE GATT connection."""

    def __init__(
        self,
        address: int,
        on_disconnect: Callable[[int], None],
        on_notify: Callable[[int, int, bytes], None],
    ):
        self.address = address
        self.mac = proto.int_to_mac(address)
        self.client: BleakClient | None = None
        self._mtu_size = DEFAULT_MTU
        self._on_disconnect = on_disconnect
        self._on_notify = on_notify
        self._notify_handles: set[int] = set()

    @property
    def connected(self) -> bool:
        return self.client is not None and self.client.is_connected

    @property
    def mtu_size(self) -> int:
        return self._mtu_size

    def _disconnected_callback(self, client: BleakClient) -> None:
        logger.info("Device %s disconnected", self.mac)
        self._notify_handles.clear()
        self._on_disconnect(self.address)

    async def connect(self, ble_device: BLEDevice | None = None) -> None:
        """Connect to the BLE device.

        If ble_device is provided (from scanner cache), use it directly.
        Otherwise fall back to MAC string.
        """
        logger.info("Connecting to %s", self.mac)
        target: BLEDevice | str = ble_device if ble_device else self.mac
        self.client = BleakClient(
            target,
            disconnected_callback=self._disconnected_callback,
            timeout=CONNECT_TIMEOUT,
        )
        await self.client.connect()
        await self._acquire_mtu()
        # A genuine connection is actually connected once connect() returns.
        # If BlueZ reports success but the link isn't really up (a phantom
        # connection — typically when bluetoothd is wedged and holding stale
        # state), treat it as a failure so the caller backs off instead of
        # "succeeding" with a dead handle that fails every subsequent GATT op.
        if not self.client.is_connected:
            raise BleakError(
                f"phantom connection to {self.mac}: BlueZ reported success "
                f"but the device is not connected"
            )
        logger.info("Connected to %s (MTU=%d)", self.mac, self.mtu_size)

    async def _acquire_mtu(self) -> None:
        """Ask Bleak/BlueZ to negotiate and cache the ATT MTU."""
        if not self.client:
            return

        backend = getattr(self.client, "_backend", self.client)
        acquire_mtu = getattr(backend, "_acquire_mtu", None)
        if acquire_mtu is not None:
            try:
                await asyncio.wait_for(acquire_mtu(), timeout=MTU_ACQUIRE_TIMEOUT)
            except Exception as e:
                # MTU acquire is best-effort and a hiccup shouldn't fail a good
                # connection — but "Not connected"/"NoReply" here means the link
                # is actually dead (phantom connection / wedged daemon), so let
                # it propagate to fail the connect rather than report MTU=23.
                if _is_link_dead_error(e):
                    raise
                logger.warning("Failed to acquire MTU for %s: %s", self.mac, e)

        mtu_size = getattr(backend, "_mtu_size", None)
        if isinstance(mtu_size, int) and mtu_size >= DEFAULT_MTU:
            self._mtu_size = mtu_size

    async def disconnect(self) -> None:
        """Disconnect from the BLE device."""
        self._notify_handles.clear()
        if self.client and self.client.is_connected:
            logger.info("Disconnecting from %s", self.mac)
            await self.client.disconnect()

    async def get_services(self) -> list[bytes]:
        """Discover GATT services and return encoded service messages."""
        if not self.client or not self.client.is_connected:
            return []

        services = self.client.services
        encoded_services: list[bytes] = []

        for service in services:
            uuid_ints = proto.uuid_to_128bit_ints(str(service.uuid))
            encoded_chars: list[bytes] = []

            for char in service.characteristics:
                char_uuid_ints = proto.uuid_to_128bit_ints(str(char.uuid))
                encoded_descs: list[bytes] = []

                for desc in char.descriptors:
                    desc_uuid_ints = proto.uuid_to_128bit_ints(str(desc.uuid))
                    encoded_descs.append(
                        proto.encode_ble_gatt_descriptor(
                            desc_uuid_ints, desc.handle
                        )
                    )

                encoded_chars.append(
                    proto.encode_ble_gatt_characteristic(
                        char_uuid_ints,
                        char.handle,
                        _bleak_props_to_int(char.properties),
                        encoded_descs,
                    )
                )

            encoded_services.append(
                proto.encode_ble_gatt_service(
                    uuid_ints, service.handle, encoded_chars
                )
            )

        return encoded_services

    async def read_characteristic(self, handle: int) -> bytes:
        """Read a GATT characteristic by handle."""
        if not self.client:
            raise RuntimeError("Not connected")
        char = _find_char_by_handle(self.client, handle)
        return bytes(await self.client.read_gatt_char(char))

    async def write_characteristic(
        self, handle: int, data: bytes, response: bool
    ) -> None:
        """Write to a GATT characteristic by handle."""
        if not self.client:
            raise RuntimeError("Not connected")
        char = _find_char_by_handle(self.client, handle)
        await self.client.write_gatt_char(char, data, response=response)

    async def read_descriptor(self, handle: int) -> bytes:
        """Read a GATT descriptor by handle."""
        if not self.client:
            raise RuntimeError("Not connected")
        return bytes(await self.client.read_gatt_descriptor(handle))

    async def write_descriptor(self, handle: int, data: bytes) -> None:
        """Write to a GATT descriptor by handle.

        On BlueZ, CCCD (0x2902) descriptor writes must be converted to
        start_notify/stop_notify calls since BlueZ manages the CCCD
        internally and rejects direct writes.
        """
        if not self.client:
            raise RuntimeError("Not connected")

        # Check if this is a CCCD descriptor write
        cccd_char = self._find_cccd_parent(handle)
        if cccd_char is not None:
            if data in (b"\x01\x00", b"\x02\x00"):
                # Enable notifications/indications
                logger.debug(
                    "Converting CCCD write on handle %d to start_notify "
                    "on char handle %d",
                    handle,
                    cccd_char.handle,
                )
                await self.start_notify(cccd_char.handle)
                return
            elif data == b"\x00\x00":
                # Disable notifications
                logger.debug(
                    "Converting CCCD write on handle %d to stop_notify "
                    "on char handle %d",
                    handle,
                    cccd_char.handle,
                )
                await self.stop_notify(cccd_char.handle)
                return

        await self.client.write_gatt_descriptor(handle, data)

    def _find_cccd_parent(self, desc_handle: int) -> BleakGATTCharacteristic | None:
        """If desc_handle points to a CCCD (UUID 2902), return the parent char."""
        if not self.client or not self.client.services:
            return None
        for service in self.client.services:
            for char in service.characteristics:
                for desc in char.descriptors:
                    if desc.handle == desc_handle and "2902" in str(desc.uuid):
                        return char
        return None

    async def start_notify(self, handle: int) -> None:
        """Enable notifications for a characteristic."""
        if handle in self._notify_handles:
            logger.debug("Notifications already active for handle %d", handle)
            return
        if not self.client:
            raise RuntimeError("Not connected")
        char = _find_char_by_handle(self.client, handle)

        def callback(sender: BleakGATTCharacteristic, data: bytearray) -> None:
            self._on_notify(self.address, handle, bytes(data))

        await self.client.start_notify(char, callback)
        self._notify_handles.add(handle)

    async def stop_notify(self, handle: int) -> None:
        """Disable notifications for a characteristic."""
        if not self.client:
            raise RuntimeError("Not connected")
        char = _find_char_by_handle(self.client, handle)
        await self.client.stop_notify(char)
        self._notify_handles.discard(handle)


def _find_char_by_handle(
    client: BleakClient, handle: int
) -> BleakGATTCharacteristic | int:
    """Find a characteristic by its handle. Falls back to handle int."""
    if client.services:
        for service in client.services:
            for char in service.characteristics:
                if char.handle == handle:
                    return char
    return handle


def _bleak_props_to_int(properties: list[str]) -> int:
    """Convert bleak property strings to the ESPHome property bitmask."""
    prop_map = {
        "broadcast": 0x01,
        "read": 0x02,
        "write-without-response": 0x04,
        "write": 0x08,
        "notify": 0x10,
        "indicate": 0x20,
        "authenticated-signed-writes": 0x40,
        "extended-properties": 0x80,
    }
    result = 0
    for prop in properties:
        result |= prop_map.get(prop.lower(), 0)
    return result


class BLEManager:
    """Manages BLE scanning and active connections."""

    def __init__(self, max_connections: int = 3, adapter: str | None = None):
        self.max_connections = max_connections
        self._adapter = adapter
        self._connections: dict[int, BLEConnection] = {}
        self._connecting: set[int] = set()
        # Per-device connect-failure backoff: address -> (fail_count, next_ts).
        # Throttles reconnect storms so we don't hammer a flaky controller.
        self._connect_backoff: dict[int, tuple[int, float]] = {}
        # Latch so the "bluetoothd is wedged" recovery hint is logged once per
        # episode, not on every flapping reconnect.
        self._daemon_wedge_logged = False
        self._scanner: BleakScanner | None = None
        # Mode requested by the client (Home Assistant).
        self._scan_active = True
        # Mode actually in use; falls back to active when passive scanning
        # is requested but unavailable on this BlueZ stack.
        self._effective_scan_active = True
        # Passive-scan capability is probed once and cached for the process
        # lifetime: once ruled out (old BlueZ, or a runtime failure such as
        # the daemon not running with --experimental) we stop attempting it.
        self._passive_checked = False
        self._passive_unavailable = False
        self._scanning = False
        # Background task that slowly re-arms the scanner after a failed start.
        self._scan_rearm_task: asyncio.Task | None = None
        self._adv_callback: Callable[
            [int, int, int, bytes], None
        ] | None = None
        self._disconnect_callback: Callable[[int], None] | None = None
        self._notify_callback: Callable[[int, int, bytes], None] | None = None
        self._scanner_state_callback: Callable[[int], None] | None = None
        # Cache BLEDevice objects from scanner for use in connections
        self._device_cache: dict[str, BLEDevice] = {}

    def set_callbacks(
        self,
        on_advertisement: Callable[[int, int, int, bytes], None],
        on_disconnect: Callable[[int], None],
        on_notify: Callable[[int, int, bytes], None],
        on_scanner_state: Callable[[int], None] | None = None,
    ) -> None:
        self._adv_callback = on_advertisement
        self._disconnect_callback = on_disconnect
        self._notify_callback = on_notify
        self._scanner_state_callback = on_scanner_state

    @property
    def free_connections(self) -> int:
        return self.max_connections - len(self._connections)

    @property
    def allocated_addresses(self) -> list[int]:
        return list(self._connections.keys())

    def _detection_callback(
        self, device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        """Called by BleakScanner for each advertisement."""
        # Cache the BLEDevice object for use in connections
        self._device_cache[device.address.upper()] = device

        if self._adv_callback is None:
            return

        address_int = proto.mac_to_int(device.address)

        # Build raw advertisement data from the advertisement_data
        raw_data = _build_raw_adv_data(advertisement_data)

        # Determine address type (public=0, random=1)
        details = getattr(device, "details", None)
        address_type = 0
        if details:
            if isinstance(details, dict):
                address_type = details.get("address_type", 0)
            elif hasattr(details, "address_type"):
                address_type = getattr(details, "address_type", 0)

        rssi = advertisement_data.rssi if advertisement_data.rssi else -127

        self._adv_callback(address_int, rssi, address_type, raw_data)

    async def start_scanning(self) -> None:
        """Start BLE scanning.

        Honours the client-requested mode, but only runs passive scanning if
        BlueZ supports it. If a requested passive scan can't be started it
        falls back to active scanning for the rest of the process.

        The scanner is long-lived: it keeps running across GATT connections
        (BlueZ time-slices discovery and connections on a single radio just
        fine — that's the normal proxy behaviour). Start is retried a few times
        for transient BlueZ errors but never hammered — see the constants.
        """
        if self._scanning:
            return

        use_passive = (
            not self._scan_active and await self._passive_scan_available()
        )
        self._effective_scan_active = not use_passive

        configured = "active" if self._scan_active else "passive"
        effective = "active" if self._effective_scan_active else "passive"
        logger.info(
            f"Starting BLE scanner (configured={configured}, mode={effective})"
        )
        if self._scanner_state_callback:
            self._scanner_state_callback(proto.SCANNER_STATE_STARTING)

        try:
            if use_passive:
                try:
                    await self._start_scanner_with_retry(passive=True)
                except Exception as e:
                    # Passive failed at runtime (e.g. BlueZ not started with
                    # --experimental). Fall back to active scanning. If active
                    # also fails the problem isn't passive-specific (e.g. the
                    # adapter is powered off), so leave passive enabled for a
                    # later retry rather than permanently disabling it.
                    logger.warning(
                        f"Passive scanning failed to start ({e}); "
                        f"falling back to active scanning"
                    )
                    await self._start_scanner_with_retry(passive=False)
                    # Active works but passive doesn't: don't attempt passive
                    # again for the rest of the process.
                    self._passive_unavailable = True
                    self._effective_scan_active = True
            else:
                await self._start_scanner_with_retry(passive=False)
        except Exception as e:
            # Couldn't start even after a few gentle retries. Don't crash (a
            # supervisor restart-loop just hammers the adapter) and don't retry
            # in a tight loop. Report FAILED and re-arm slowly in the background
            # so we self-heal from a transient fault (or a manual reset).
            adapter = self._adapter or "hci0"
            logger.error(
                f"Could not start BLE scanner after {SCAN_START_MAX_RETRIES} "
                f"attempts: {e}. The Bluetooth controller may be wedged at the "
                f"HCI level (look for 'hci0: Opcode 0x200c failed' in dmesg); "
                f"if so only an adapter reset clears it, e.g. 'sudo hciconfig "
                f"{adapter} reset' (or 'sudo hciconfig {adapter} down && sudo "
                f"hciconfig {adapter} up', or reboot) — restarting bluetoothd "
                f"is not enough. Will re-try every {int(SCAN_REARM_INTERVAL)}s."
            )
            await self._teardown_scanner()
            self._scanning = False
            if self._scanner_state_callback:
                self._scanner_state_callback(proto.SCANNER_STATE_FAILED)
            self._schedule_scan_rearm()
            return

        self._scanning = True
        if self._scanner_state_callback:
            self._scanner_state_callback(proto.SCANNER_STATE_RUNNING)

    async def _start_scanner(self, passive: bool) -> None:
        """Create and start a BleakScanner in the given mode."""
        kwargs: dict[str, Any] = {
            "detection_callback": self._detection_callback,
            "scanning_mode": "passive" if passive else "active",
        }
        if passive:
            kwargs["bluez"] = BlueZScannerArgs(
                or_patterns=PASSIVE_SCAN_OR_PATTERNS
            )
        if self._adapter:
            kwargs["adapter"] = self._adapter

        self._scanner = BleakScanner(**kwargs)
        await self._scanner.start()

    async def _start_scanner_with_retry(self, passive: bool) -> None:
        """Start the scanner, making a few gentle attempts on transient errors.

        Before each retry the previous (failed) scanner is torn down so its
        discovery session is released — that, not another raw scan command, is
        what clears a BlueZ "InProgress". Raises the last error if it still
        can't start after the retry budget.
        """
        last_error: Exception | None = None
        for attempt in range(1, SCAN_START_MAX_RETRIES + 1):
            try:
                await self._start_scanner(passive=passive)
                return
            except Exception as e:
                last_error = e
                if attempt >= SCAN_START_MAX_RETRIES:
                    break
                logger.warning(
                    f"BLE scanner start attempt "
                    f"{attempt}/{SCAN_START_MAX_RETRIES} failed ({e}); "
                    f"releasing session and retrying"
                )
                await self._teardown_scanner()
                await asyncio.sleep(SCAN_START_RETRY_DELAY)
        assert last_error is not None
        raise last_error

    async def _teardown_scanner(self) -> None:
        """Best-effort stop of the current scanner to release its session.

        A half-started or stale BleakScanner keeps a BlueZ discovery session
        registered on our D-Bus connection; until it's released, fresh starts
        return "InProgress". Stopping the scanner object is the correct way to
        release it (a `bluetoothctl scan off` from another client cannot).
        """
        scanner = self._scanner
        self._scanner = None
        if scanner is None:
            return
        try:
            await scanner.stop()
        except Exception:
            pass

    def _schedule_scan_rearm(self) -> None:
        """Ensure a single background task is slowly re-arming the scanner."""
        if self._scan_rearm_task is None or self._scan_rearm_task.done():
            self._scan_rearm_task = asyncio.ensure_future(
                self._scan_rearm_loop()
            )

    async def _scan_rearm_loop(self) -> None:
        """Slowly retry scanner start until it succeeds (gentle self-heal).

        One attempt per interval — deliberately not a tight loop: if the
        controller is wedged only an adapter reset will help, and hammering it
        just floods the logs and keeps it busy. This does mean recovery from a
        manual `hciconfig reset` happens within one interval.
        """
        try:
            while not self._scanning:
                await asyncio.sleep(SCAN_REARM_INTERVAL)
                if self._scanning:
                    break
                logger.info("Re-arming BLE scanner after earlier failure")
                await self.start_scanning()
        finally:
            self._scan_rearm_task = None

    async def _passive_scan_available(self) -> bool:
        """Whether a passive scan may be attempted on this BlueZ stack.

        The BlueZ version is probed only once per process; a negative result
        (old BlueZ, or a previous runtime failure) is cached so we don't keep
        retrying something that can't work.
        """
        if self._passive_unavailable:
            return False
        if not self._passive_checked:
            self._passive_checked = True
            if not await self._bluez_supports_passive():
                self._passive_unavailable = True
                return False
        return True

    async def _bluez_supports_passive(self) -> bool:
        """Check bluetoothd/BlueZ is new enough for passive scanning."""
        version = await _get_bluetoothctl_version()
        if version is None:
            # bluetoothctl unavailable (e.g. a container with only the D-Bus
            # API). Optimistically attempt passive and rely on the runtime
            # failover if it turns out not to work.
            logger.warning(
                "Could not determine BlueZ version; "
                "will attempt passive scanning"
            )
            return True
        major, minor = (int(g) for g in version.groups())
        if (major, minor) < PASSIVE_MIN_BLUEZ_VERSION:
            need_major, need_minor = PASSIVE_MIN_BLUEZ_VERSION
            logger.info(
                f"BlueZ {major}.{minor} does not support passive scanning "
                f"(need >= {need_major}.{need_minor}); using active scanning"
            )
            return False
        return True

    async def stop_scanning(self) -> None:
        """Stop BLE scanning."""
        if not self._scanning or not self._scanner:
            return

        logger.info("Stopping BLE scanner")
        if self._scanner_state_callback:
            self._scanner_state_callback(proto.SCANNER_STATE_STOPPING)

        await self._teardown_scanner()
        self._scanning = False

        if self._scanner_state_callback:
            self._scanner_state_callback(proto.SCANNER_STATE_STOPPED)

    async def set_scan_mode(self, active: bool) -> None:
        """Change scan mode, restarting the scanner if needed."""
        if self._scan_active == active:
            return
        self._scan_active = active
        if self._scanning:
            await self.stop_scanning()
            await self.start_scanning()

    def _handle_disconnect(self, address: int) -> None:
        """Internal disconnect handler."""
        conn = self._connections.pop(address, None)
        if conn:
            # Schedule BlueZ cleanup in background
            asyncio.ensure_future(self._bluez_clear_state(conn.mac))
        if self._disconnect_callback:
            self._disconnect_callback(address)

    def _handle_notify(self, address: int, handle: int, data: bytes) -> None:
        """Internal notification handler."""
        if self._notify_callback:
            self._notify_callback(address, handle, data)

    def _connect_backoff_remaining(self, address: int) -> float:
        """Seconds left before another connect to this device is allowed."""
        _, next_ts = self._connect_backoff.get(address, (0, 0.0))
        return max(0.0, next_ts - time.monotonic())

    def _note_connect_failure(
        self, address: int, mac: str, error: Exception | None
    ) -> None:
        """Log a failed connect and extend this device's backoff window."""
        fails = self._connect_backoff.get(address, (0, 0.0))[0] + 1

        if _is_daemon_wedge_error(error):
            # Not fixable from here — bluetoothd needs restarting on the host.
            # Back off hard and say so once, instead of flapping every retry.
            delay = DAEMON_WEDGE_BACKOFF
            if not self._daemon_wedge_logged:
                self._daemon_wedge_logged = True
                adapter = self._adapter or "hci0"
                logger.error(
                    f"Connect to {mac} is failing like bluetoothd is wedged "
                    f"(phantom connection / no D-Bus reply). This usually needs "
                    f"the daemon restarted on the host: 'sudo systemctl restart "
                    f"bluetooth' (if that doesn't help, also reset the adapter: "
                    f"'sudo hciconfig {adapter} reset'). Backing off "
                    f"{int(delay)}s between attempts until it recovers."
                )
        else:
            delay = min(CONNECT_FAIL_BACKOFF_MAX, CONNECT_FAIL_BACKOFF_STEP * fails)

        self._connect_backoff[address] = (fails, time.monotonic() + delay)
        logger.error(
            f"Failed to connect to {mac} after {CONNECT_MAX_RETRIES} attempts: "
            f"{error} (next attempt blocked for {int(delay)}s)"
        )

    async def connect_device(self, address: int) -> tuple[bool, int, int]:
        """Connect to a BLE device.

        Returns (success, mtu, error_code).

        Scanning is left running throughout — BlueZ interleaves discovery and
        connection establishment itself, so there's no need to stop the scanner
        (and toggling it per connect just churns the adapter).
        """
        if len(self._connections) >= self.max_connections:
            logger.warning("No free connection slots")
            return False, 0, -1

        if address in self._connections:
            conn = self._connections[address]
            if conn.connected:
                return True, conn.mtu_size, 0

        if address in self._connecting:
            logger.debug(
                "Connection already in progress for %s",
                proto.int_to_mac(address),
            )
            return False, 0, -1

        mac = proto.int_to_mac(address)

        # Honour the per-device backoff: if recent connects keep failing, don't
        # relay Home Assistant's retries to the controller — that churn is what
        # tips a flaky adapter into a wedge. Fail fast until the window expires.
        remaining = self._connect_backoff_remaining(address)
        if remaining > 0:
            logger.debug(
                "Backing off connect to %s (%.0fs remaining)", mac, remaining
            )
            return False, 0, -1

        self._connecting.add(address)

        try:
            # Look up cached BLEDevice from scanner
            ble_device = self._device_cache.get(mac.upper())

            conn = BLEConnection(
                address, self._handle_disconnect, self._handle_notify
            )
            self._connections[address] = conn

            last_error: Exception | None = None
            for attempt in range(1, CONNECT_MAX_RETRIES + 1):
                try:
                    await conn.connect(ble_device)
                    # Success clears any backoff and the wedge latch.
                    self._connect_backoff.pop(address, None)
                    self._daemon_wedge_logged = False
                    return True, conn.mtu_size, 0
                except Exception as e:
                    last_error = e
                    err_str = str(e)
                    logger.warning(
                        "Connect attempt %d/%d to %s failed: %s",
                        attempt,
                        CONNECT_MAX_RETRIES,
                        mac,
                        err_str,
                    )
                    if attempt >= CONNECT_MAX_RETRIES:
                        break
                    if _is_daemon_wedge_error(e):
                        # Retrying a wedged daemon just churns (and bluetoothctl
                        # cleanup would hang on NoReply); stop and let the hard
                        # backoff in _note_connect_failure take over.
                        break
                    if "InProgress" in err_str:
                        # BlueZ still has stale state for this device — clear it
                        # and let the always-on scanner re-populate the cache.
                        await self._bluez_remove_device(mac)
                        self._device_cache.pop(mac.upper(), None)
                        ble_device = None
                    await asyncio.sleep(CONNECT_RETRY_DELAY)
                    # The scanner stays running, so re-check the cache in case it
                    # (re)discovered the device while we waited.
                    if ble_device is None:
                        ble_device = self._device_cache.get(mac.upper())

            # All retries exhausted — record the failure and arm the backoff.
            self._note_connect_failure(address, mac, last_error)
            self._connections.pop(address, None)
            return False, 0, -1
        finally:
            self._connecting.discard(address)

    async def _bluez_clear_state(self, mac: str) -> None:
        """Disconnect a device in BlueZ to clear stale connection state."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "disconnect", mac,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except Exception:
            pass

    async def _bluez_remove_device(self, mac: str) -> None:
        """Remove a device from BlueZ to completely reset its state."""
        await self._bluez_clear_state(mac)
        try:
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "remove", mac,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except Exception:
            pass

    async def disconnect_device(self, address: int) -> None:
        """Disconnect from a BLE device."""
        conn = self._connections.pop(address, None)
        if conn:
            await conn.disconnect()
            # Also clear BlueZ state to prevent InProgress on next connect
            await self._bluez_clear_state(conn.mac)

    def get_connection(self, address: int) -> BLEConnection | None:
        """Get an active connection by address."""
        conn = self._connections.get(address)
        if conn and conn.connected:
            return conn
        return None

    async def cleanup(self) -> None:
        """Clean up all connections and stop scanning."""
        if self._scan_rearm_task is not None:
            self._scan_rearm_task.cancel()
            self._scan_rearm_task = None
        for conn in list(self._connections.values()):
            try:
                await conn.disconnect()
            except Exception:
                pass
        self._connections.clear()
        await self.stop_scanning()


def _build_raw_adv_data(adv_data: AdvertisementData) -> bytes:
    """Build raw BLE advertisement data bytes from bleak AdvertisementData.

    Constructs AD structures (length + type + data) for the available data.
    """
    result = bytearray()

    # Flags (AD type 0x01)
    # Most BLE devices advertise flags, but bleak doesn't always expose them.
    # We include a generic flags byte.
    result.extend(bytes([2, 0x01, 0x06]))

    # Complete local name (AD type 0x09)
    if adv_data.local_name:
        name_bytes = adv_data.local_name.encode("utf-8")
        if len(name_bytes) + 2 <= 31:
            result.extend(bytes([len(name_bytes) + 1, 0x09]) + name_bytes)

    # Service UUIDs
    if adv_data.service_uuids:
        for uuid_str in adv_data.service_uuids:
            uuid_clean = uuid_str.replace("-", "").lower()
            if len(uuid_clean) == 4:
                # 16-bit UUID (AD type 0x03)
                uuid_bytes = bytes.fromhex(uuid_clean)
                result.extend(
                    bytes([len(uuid_bytes) + 1, 0x03])
                    + uuid_bytes[::-1]
                )
            elif len(uuid_clean) == 32:
                # 128-bit UUID (AD type 0x07)
                uuid_bytes = bytes.fromhex(uuid_clean)
                result.extend(
                    bytes([len(uuid_bytes) + 1, 0x07])
                    + uuid_bytes[::-1]
                )

    # Service data (AD type 0x16 for 16-bit, 0x21 for 128-bit)
    if adv_data.service_data:
        for uuid_str, data in adv_data.service_data.items():
            uuid_clean = uuid_str.replace("-", "").lower()
            if len(uuid_clean) == 8:
                uuid_bytes = bytes.fromhex(uuid_clean)[::-1]
                ad_data_bytes = uuid_bytes + (
                    data if isinstance(data, bytes) else bytes(data)
                )
                result.extend(
                    bytes([len(ad_data_bytes) + 1, 0x16]) + ad_data_bytes
                )
            elif len(uuid_clean) == 32:
                uuid_bytes = bytes.fromhex(uuid_clean)[::-1]
                ad_data_bytes = uuid_bytes + (
                    data if isinstance(data, bytes) else bytes(data)
                )
                result.extend(
                    bytes([len(ad_data_bytes) + 1, 0x21]) + ad_data_bytes
                )

    # Manufacturer data (AD type 0xFF)
    if adv_data.manufacturer_data:
        for company_id, data in adv_data.manufacturer_data.items():
            mfr_bytes = (
                company_id.to_bytes(2, "little")
                + (data if isinstance(data, bytes) else bytes(data))
            )
            result.extend(bytes([len(mfr_bytes) + 1, 0xFF]) + mfr_bytes)

    return bytes(result)
