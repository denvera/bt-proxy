"""BLE manager using bleak for scanning and GATT connections."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from . import proto

logger = logging.getLogger(__name__)

# Default MTU for BLE connections
DEFAULT_MTU = 23

# Connection retry settings
CONNECT_TIMEOUT = 30.0
CONNECT_RETRY_DELAY = 2.0
CONNECT_MAX_RETRIES = 3


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
        self._on_disconnect = on_disconnect
        self._on_notify = on_notify
        self._notify_handles: set[int] = set()

    @property
    def connected(self) -> bool:
        return self.client is not None and self.client.is_connected

    @property
    def mtu_size(self) -> int:
        if self.client is None:
            return DEFAULT_MTU
        return getattr(self.client, "mtu_size", DEFAULT_MTU)

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
        logger.info("Connected to %s (MTU=%d)", self.mac, self.mtu_size)

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
        self._scanner: BleakScanner | None = None
        self._scan_active = True
        self._scanning = False
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
        """Start BLE scanning."""
        if self._scanning:
            return

        logger.info("Starting BLE scanner (active=%s)", self._scan_active)
        if self._scanner_state_callback:
            self._scanner_state_callback(proto.SCANNER_STATE_STARTING)

        kwargs: dict[str, Any] = {
            "detection_callback": self._detection_callback,
            "scanning_mode": "active" if self._scan_active else "passive",
        }
        if self._adapter:
            kwargs["adapter"] = self._adapter

        self._scanner = BleakScanner(**kwargs)
        await self._scanner.start()
        self._scanning = True

        if self._scanner_state_callback:
            self._scanner_state_callback(proto.SCANNER_STATE_RUNNING)

    async def stop_scanning(self) -> None:
        """Stop BLE scanning."""
        if not self._scanning or not self._scanner:
            return

        logger.info("Stopping BLE scanner")
        if self._scanner_state_callback:
            self._scanner_state_callback(proto.SCANNER_STATE_STOPPING)

        await self._scanner.stop()
        self._scanning = False
        self._scanner = None

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

    async def connect_device(self, address: int) -> tuple[bool, int, int]:
        """Connect to a BLE device.

        Returns (success, mtu, error_code).
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
        self._connecting.add(address)

        try:
            # Look up cached BLEDevice from scanner
            ble_device = self._device_cache.get(mac.upper())

            # Pause scanning during connection to avoid BlueZ contention
            was_scanning = self._scanning
            if was_scanning:
                logger.debug("Pausing scanner for connection to %s", mac)
                await self.stop_scanning()

            conn = BLEConnection(
                address, self._handle_disconnect, self._handle_notify
            )
            self._connections[address] = conn

            last_error: Exception | None = None
            for attempt in range(1, CONNECT_MAX_RETRIES + 1):
                try:
                    await conn.connect(ble_device)
                    # Resume scanning after successful connect
                    if was_scanning:
                        await self.start_scanning()
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
                    if "InProgress" in err_str and attempt < CONNECT_MAX_RETRIES:
                        # BlueZ still busy — remove device and retry
                        await self._bluez_remove_device(mac)
                        self._device_cache.pop(mac.upper(), None)
                        ble_device = None
                        # Brief scan to let BlueZ re-discover the device
                        await self.start_scanning()
                        await asyncio.sleep(CONNECT_RETRY_DELAY)
                        await self.stop_scanning()
                    elif "not found" in err_str and attempt < CONNECT_MAX_RETRIES:
                        # Device not in BlueZ yet — briefly scan to discover
                        await self.start_scanning()
                        await asyncio.sleep(CONNECT_RETRY_DELAY)
                        await self.stop_scanning()
                        ble_device = self._device_cache.get(mac.upper())
                    elif attempt < CONNECT_MAX_RETRIES:
                        await asyncio.sleep(CONNECT_RETRY_DELAY)
                    else:
                        break

            # All retries exhausted
            logger.error(
                "Failed to connect to %s after %d attempts: %s",
                mac,
                CONNECT_MAX_RETRIES,
                last_error,
            )
            self._connections.pop(address, None)
            # Resume scanning on failure too
            if was_scanning:
                await self.start_scanning()
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
