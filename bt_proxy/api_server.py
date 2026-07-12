"""ESPHome Native API server for the Bluetooth Proxy."""

from __future__ import annotations

import asyncio
import enum
import logging
import time
from typing import Any, Union

from . import EMULATED_ESPHOME_VERSION, proto
from .ble_manager import BLEManager
from .noise import (
    HANDSHAKE_FAILURE,
    NoiseFrameHelper,
    NoiseHandshakeError,
    encode_frame,
)

logger = logging.getLogger(__name__)

# How often to flush batched advertisements (seconds)
ADV_BATCH_INTERVAL = 0.1


class State(enum.Enum):
    """Connection lifecycle state; drives the dispatch gate.

    States are ordered so that a handler's minimum requirement can be checked
    with a simple ``>=`` on ``.value``.
    """

    HANDSHAKE = 0  # transport not yet selected
    CONNECTED = 1  # transport up, pre-authentication (plaintext mode)
    AUTHENTICATED = 2  # Noise handshake done, or plaintext Connect completed


class _PrefixReader:
    """Wraps a stream reader, yielding a small already-consumed prefix first.

    Transport selection peeks the first byte off the socket; this replays it so
    the chosen frame helper sees a pristine stream and needs no special-casing
    of the first message.
    """

    def __init__(self, reader: asyncio.StreamReader, prefix: bytes) -> None:
        self._reader = reader
        self._prefix = prefix

    async def readexactly(self, n: int) -> bytes:
        if not self._prefix:
            return await self._reader.readexactly(n)
        if n <= len(self._prefix):
            chunk, self._prefix = self._prefix[:n], self._prefix[n:]
            return chunk
        chunk, self._prefix = self._prefix, b""
        return chunk + await self._reader.readexactly(n - len(chunk))


class PlaintextFrameHelper:
    """Plaintext ESPHome framing over an asyncio stream pair.

    A faithful extraction of the original ``_read_message`` / ``_read_varint``
    logic, exposing the same interface as
    :class:`~bt_proxy.noise.NoiseFrameHelper` so that :class:`APIConnection`
    has a single dispatch loop for both transports.

    Wire format: ``0x00`` + varint(data_length) + varint(msg_type) + data.
    """

    def __init__(
        self,
        reader: _PrefixReader | asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._closed = False

    async def read_message(self) -> tuple[int, bytes]:
        """Read one framed message from the wire."""
        preamble = await self._reader.readexactly(1)
        if preamble[0] != 0x00:
            raise ValueError(f"Invalid preamble: 0x{preamble[0]:02x}")

        data_length = await self._read_varint()
        msg_type = await self._read_varint()

        if data_length > 0:
            data = await self._reader.readexactly(data_length)
        else:
            data = b""

        return msg_type, data

    async def _read_varint(self) -> int:
        """Read a varint from the stream."""
        result = 0
        shift = 0
        while True:
            byte_data = await self._reader.readexactly(1)
            byte = byte_data[0]
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                return result
            shift += 7
            if shift >= 64:
                raise ValueError("Varint too long")

    def write_message(self, msg_type: int, data: bytes) -> None:
        """Send a framed message to the client."""
        if self._closed:
            return
        self._writer.write(proto.frame_message(msg_type, data))

    async def drain(self) -> None:
        """Flush the write buffer."""
        if self._closed:
            return
        await self._writer.drain()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._writer.close()
        except Exception:  # noqa: BLE001 - already going away
            pass


class APIConnection:
    """A single client connection to the ESPHome Native API."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        server: APIServer,
    ):
        self.reader = reader
        self.writer = writer
        self.server = server
        self._subscribed_ble = False
        self._subscribed_connections_free = False
        self._adv_batch: list[tuple[int, int, int, bytes]] = []
        self._adv_flush_task: asyncio.Task[None] | None = None
        self._closed = False
        self._peer = writer.get_extra_info("peername", ("unknown", 0))
        # Transport (plaintext or Noise) and connection state are established
        # by _select_transport() before the dispatch loop runs.
        self._transport: PlaintextFrameHelper | NoiseFrameHelper | None = None
        self._state = State.HANDSHAKE

    async def run(self) -> None:
        """Main loop: select transport, then read and dispatch messages."""
        logger.info("Client connected from %s", self._peer)
        try:
            # Peek at the first byte to select the transport.
            first = await self.reader.readexactly(1)
            if not await self._select_transport(first[0]):
                return

            while not self._closed:
                msg_type, data = await self._transport.read_message()
                await self._handle_message(msg_type, data)
                await self._transport.drain()
        except NoiseHandshakeError as err:
            logger.warning(
                "Noise handshake with %s failed: %s", self._peer, err
            )
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
            logger.info("Client %s disconnected", self._peer)
        except Exception:
            logger.exception("Error handling client %s", self._peer)
        finally:
            await self._cleanup()

    async def _select_transport(self, first_byte: int) -> bool:
        """Choose the transport from the first byte. Returns False to close.

        - ``0x01`` + key    -> Noise handshake; state becomes AUTHENTICATED.
        - ``0x01`` + no key  -> refuse (nothing to hand the client).
        - ``0x00`` + key     -> signal encryption-required (0x01 frame), close.
        - ``0x00`` + no key  -> plaintext; deprecation warning; state CONNECTED.
        - anything else      -> refuse.
        """
        key = self.server.encryption_key
        # Replay the peeked byte so the frame helper sees a pristine stream.
        reader = _PrefixReader(self.reader, bytes((first_byte,)))

        if first_byte == 0x01:
            if key is None:
                logger.warning(
                    "Client %s requested Noise encryption (0x01) but no "
                    "encryption key is configured; refusing",
                    self._peer,
                )
                return False
            helper = NoiseFrameHelper(
                reader,
                self.writer,
                key,
                self.server.name,
                self.server.mac_address,
            )
            # A PSK mismatch raises NoiseHandshakeError, handled by run().
            await helper.perform_handshake()
            self._transport = helper
            # The handshake IS the authentication.
            self._state = State.AUTHENTICATED
            return True

        if first_byte == 0x00:
            if key is not None:
                # Encryption is required, but the client probed with plaintext.
                # Home Assistant always tries plaintext first and only prompts
                # for the key once it learns the device is encrypted -- which it
                # learns from a reply whose indicator byte is 0x01. So match
                # ESPHome and send a 0x01-led frame: the client's plaintext
                # helper reads that preamble and raises RequiresEncryptionAPIError
                # (the signal HA needs), instead of the bare socket close it
                # would otherwise surface as a generic connection error.
                logger.info(
                    "Client %s probed with plaintext but encryption is "
                    "required; signaling encryption-required",
                    self._peer,
                )
                try:
                    self.writer.write(
                        encode_frame(
                            bytes([HANDSHAKE_FAILURE]) + b"Encryption required"
                        )
                    )
                    await self.writer.drain()
                except (ConnectionResetError, OSError):
                    pass
                return False
            logger.warning(
                "Client %s connected WITHOUT encryption (plaintext). "
                "Unauthenticated plaintext operation is DEPRECATED; configure "
                "an encryption key to require Noise.",
                self._peer,
            )
            self._transport = PlaintextFrameHelper(reader, self.writer)
            self._state = State.CONNECTED
            return True

        logger.warning(
            "Client %s sent unknown preamble 0x%02x", self._peer, first_byte
        )
        return False

    def _send_message(self, msg_type: int, data: bytes) -> None:
        """Send a framed message to the client over the active transport."""
        if self._closed or self._transport is None:
            return
        self._transport.write_message(msg_type, data)

    async def _handle_message(self, msg_type: int, data: bytes) -> None:
        """Dispatch a received message, gated by the connection state.

        This is the single place dispatch is gated. Each handler carries a
        minimum required state in the table; anything below it is refused.
        """
        entry = _MESSAGE_HANDLERS.get(msg_type)
        if entry is None:
            logger.debug("Unhandled message type %d", msg_type)
            return
        handler, required = entry
        if self._state.value < required.value:
            # A message arrived before the connection is authenticated. Close
            # rather than silently ignore it: a client waiting for a reply would
            # otherwise hang until its own timeout ("the proxy appears dead"),
            # and silently dropping each message lets a peer flood the log with
            # no bound. Closing gives a definitive EOF and caps this to one line
            # per connection. (The standard Home Assistant flow sends
            # ConnectRequest first and never trips this.)
            logger.warning(
                "Client %s sent message type %d before authentication "
                "(state=%s); closing the connection",
                self._peer,
                msg_type,
                self._state.name,
            )
            self._closed = True
            return
        await handler(self, data)

    # ------------------------------------------------------------------
    # Protocol handlers
    # ------------------------------------------------------------------

    async def _handle_hello(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        client_info = proto.get_field_string(fields, 1, "")
        logger.info("Hello from client: %s", client_info)

        resp = proto.encode_hello_response(
            api_version_major=1,
            api_version_minor=10,
            server_info=f"bt-proxy {self.server.name}",
            name=self.server.name,
        )
        self._send_message(proto.MSG_HELLO_RESPONSE, resp)

    async def _handle_device_info(self, _data: bytes) -> None:
        feature_flags = (
            proto.FEATURE_PASSIVE_SCAN
            | proto.FEATURE_ACTIVE_CONNECTIONS
            | proto.FEATURE_REMOTE_CACHING
            | proto.FEATURE_RAW_ADVERTISEMENTS
            | proto.FEATURE_STATE_AND_MODE
        )

        resp = proto.encode_device_info_response(
            name=self.server.name,
            mac_address=self.server.mac_address,
            esphome_version=EMULATED_ESPHOME_VERSION,
            model="Raspberry Pi BT Proxy",
            manufacturer="bt-proxy",
            friendly_name=self.server.friendly_name,
            bluetooth_proxy_feature_flags=feature_flags,
            bluetooth_mac_address=self.server.bt_mac_address,
        )
        self._send_message(proto.MSG_DEVICE_INFO_RESPONSE, resp)

    async def _handle_list_entities(self, _data: bytes) -> None:
        # No entities to list - we're just a BT proxy
        self._send_message(proto.MSG_LIST_ENTITIES_DONE_RESPONSE, b"")

    async def _handle_subscribe_states(self, _data: bytes) -> None:
        # No states to subscribe to
        pass

    async def _handle_connect(self, data: bytes) -> None:
        # ConnectResponse: field 1 = invalid_password (bool)
        # No password required, so invalid_password = false
        resp = proto.encode_field_bool(1, False)
        self._send_message(proto.MSG_CONNECT_RESPONSE, resp)
        # In plaintext mode, ConnectRequest completes authentication and opens
        # the BLE/GATT handlers. In Noise mode the connection is already
        # AUTHENTICATED; this transition is monotonic and harmless there.
        self._state = State.AUTHENTICATED

    async def _handle_ping(self, _data: bytes) -> None:
        self._send_message(proto.MSG_PING_RESPONSE, b"")

    async def _handle_disconnect(self, _data: bytes) -> None:
        self._send_message(proto.MSG_DISCONNECT_RESPONSE, b"")
        self._closed = True

    async def _handle_subscribe_ble_advertisements(self, data: bytes) -> None:
        self._subscribed_ble = True
        # Start the advertisement batch flusher
        if self._adv_flush_task is None:
            self._adv_flush_task = asyncio.create_task(self._adv_flush_loop())

        # Send current scanner state
        ble = self.server.ble_manager
        current_mode, configured_mode = self._scanner_mode_fields()
        state = (
            proto.SCANNER_STATE_RUNNING
            if ble._scanning
            else proto.SCANNER_STATE_IDLE
        )
        resp = proto.encode_ble_scanner_state_response(
            state, current_mode, configured_mode
        )
        self._send_message(proto.MSG_BLE_SCANNER_STATE_RESPONSE, resp)

    async def _handle_unsubscribe_ble_advertisements(
        self, _data: bytes
    ) -> None:
        self._subscribed_ble = False
        if self._adv_flush_task:
            self._adv_flush_task.cancel()
            self._adv_flush_task = None

    async def _handle_subscribe_connections_free(self, _data: bytes) -> None:
        self._subscribed_connections_free = True
        self._send_connections_free()

    async def _handle_ble_device_request(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        address = proto.get_field_varint(fields, 1)
        request_type = proto.get_field_varint(fields, 2)

        ble = self.server.ble_manager

        if request_type in (
            proto.BLE_REQUEST_CONNECT_V3_WITH_CACHE,
            proto.BLE_REQUEST_CONNECT_V3_WITHOUT_CACHE,
        ):
            success, mtu, error = await ble.connect_device(address)
            resp = proto.encode_ble_device_connection_response(
                address, success, mtu, error
            )
            self._send_message(proto.MSG_BLE_DEVICE_CONNECTION_RESPONSE, resp)
            if self._subscribed_connections_free:
                self._send_connections_free()

        elif request_type == proto.BLE_REQUEST_DISCONNECT:
            await ble.disconnect_device(address)
            resp = proto.encode_ble_device_connection_response(
                address, False, 0, 0
            )
            self._send_message(proto.MSG_BLE_DEVICE_CONNECTION_RESPONSE, resp)
            if self._subscribed_connections_free:
                self._send_connections_free()

        elif request_type == proto.BLE_REQUEST_PAIR:
            # Pairing not directly supported through bleak
            resp = proto.encode_ble_device_pairing_response(
                address, False, -1
            )
            self._send_message(proto.MSG_BLE_DEVICE_PAIRING_RESPONSE, resp)

        elif request_type == proto.BLE_REQUEST_UNPAIR:
            resp = proto.encode_ble_device_unpairing_response(
                address, False, -1
            )
            self._send_message(proto.MSG_BLE_DEVICE_UNPAIRING_RESPONSE, resp)

        elif request_type == proto.BLE_REQUEST_CLEAR_CACHE:
            resp = proto.encode_ble_device_clear_cache_response(
                address, True, 0
            )
            self._send_message(
                proto.MSG_BLE_DEVICE_CLEAR_CACHE_RESPONSE, resp
            )

    async def _handle_gatt_get_services(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        address = proto.get_field_varint(fields, 1)

        ble = self.server.ble_manager
        conn = ble.get_connection(address)
        if not conn:
            resp = proto.encode_ble_gatt_error_response(address, 0, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)
            return

        try:
            services = await conn.get_services()
            resp = proto.encode_ble_gatt_services_response(address, services)
            self._send_message(
                proto.MSG_BLE_GATT_GET_SERVICES_RESPONSE, resp
            )
            done_resp = proto.encode_ble_gatt_services_done_response(address)
            self._send_message(
                proto.MSG_BLE_GATT_GET_SERVICES_DONE_RESPONSE, done_resp
            )
        except Exception as e:
            logger.error("Error getting services for %016X: %s", address, e)
            resp = proto.encode_ble_gatt_error_response(address, 0, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)

    async def _handle_gatt_read(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        address = proto.get_field_varint(fields, 1)
        handle = proto.get_field_varint(fields, 2)

        conn = self.server.ble_manager.get_connection(address)
        if not conn:
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)
            return

        try:
            value = await conn.read_characteristic(handle)
            resp = proto.encode_ble_gatt_read_response(address, handle, value)
            self._send_message(proto.MSG_BLE_GATT_READ_RESPONSE, resp)
        except Exception as e:
            logger.error("GATT read error: %s", e)
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)

    async def _handle_gatt_write(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        address = proto.get_field_varint(fields, 1)
        handle = proto.get_field_varint(fields, 2)
        response = proto.get_field_bool(fields, 3)
        write_data = proto.get_field_bytes(fields, 4)

        conn = self.server.ble_manager.get_connection(address)
        if not conn:
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)
            return

        try:
            await conn.write_characteristic(handle, write_data, response)
            resp = proto.encode_ble_gatt_write_response(address, handle)
            self._send_message(proto.MSG_BLE_GATT_WRITE_RESPONSE, resp)
        except Exception as e:
            logger.error("GATT write error: %s", e)
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)

    async def _handle_gatt_read_descriptor(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        address = proto.get_field_varint(fields, 1)
        handle = proto.get_field_varint(fields, 2)

        conn = self.server.ble_manager.get_connection(address)
        if not conn:
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)
            return

        try:
            value = await conn.read_descriptor(handle)
            resp = proto.encode_ble_gatt_read_response(address, handle, value)
            self._send_message(proto.MSG_BLE_GATT_READ_RESPONSE, resp)
        except Exception as e:
            logger.error("GATT read descriptor error: %s", e)
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)

    async def _handle_gatt_write_descriptor(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        address = proto.get_field_varint(fields, 1)
        handle = proto.get_field_varint(fields, 2)
        write_data = proto.get_field_bytes(fields, 3)

        logger.debug(
            "GATT write descriptor: addr=%016X handle=%d data=%s",
            address,
            handle,
            write_data.hex() if write_data else "(empty)",
        )

        conn = self.server.ble_manager.get_connection(address)
        if not conn:
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)
            return

        try:
            await conn.write_descriptor(handle, write_data)
            resp = proto.encode_ble_gatt_write_response(address, handle)
            self._send_message(proto.MSG_BLE_GATT_WRITE_RESPONSE, resp)
        except Exception as e:
            logger.error(
                "GATT write descriptor error on handle %d: %s", handle, e
            )
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)

    async def _handle_gatt_notify(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        address = proto.get_field_varint(fields, 1)
        handle = proto.get_field_varint(fields, 2)
        enable = proto.get_field_bool(fields, 3)

        conn = self.server.ble_manager.get_connection(address)
        if not conn:
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)
            return

        try:
            if enable:
                await conn.start_notify(handle)
            else:
                await conn.stop_notify(handle)
            resp = proto.encode_ble_gatt_notify_response(address, handle)
            self._send_message(proto.MSG_BLE_GATT_NOTIFY_RESPONSE, resp)
        except Exception as e:
            logger.error("GATT notify error: %s", e)
            resp = proto.encode_ble_gatt_error_response(address, handle, -1)
            self._send_message(proto.MSG_BLE_GATT_ERROR_RESPONSE, resp)

    async def _handle_scanner_set_mode(self, data: bytes) -> None:
        fields = proto.decode_fields(data)
        mode = proto.get_field_varint(fields, 1)
        active = mode == proto.SCANNER_MODE_ACTIVE
        await self.server.ble_manager.set_scan_mode(active)

    async def _handle_subscribe_logs(self, _data: bytes) -> None:
        # We don't send logs
        pass

    async def _handle_get_time(self, _data: bytes) -> None:
        # GetTimeResponse (msg 37): field 1 = fixed32 epoch seconds
        resp = proto.encode_field_fixed32(1, int(time.time()))
        self._send_message(37, resp)

    async def _handle_noop(self, _data: bytes) -> None:
        pass

    # ------------------------------------------------------------------
    # Push methods (called by BLEManager callbacks)
    # ------------------------------------------------------------------

    def push_advertisement(
        self, address: int, rssi: int, address_type: int, data: bytes
    ) -> None:
        """Queue an advertisement for batched sending."""
        if not self._subscribed_ble:
            return
        self._adv_batch.append((address, rssi, address_type, data))

    def push_disconnect(self, address: int) -> None:
        """Notify client of a device disconnection."""
        resp = proto.encode_ble_device_connection_response(
            address, False, 0, 0
        )
        self._send_message(proto.MSG_BLE_DEVICE_CONNECTION_RESPONSE, resp)
        if self._subscribed_connections_free:
            self._send_connections_free()

    def push_notify_data(
        self, address: int, handle: int, data: bytes
    ) -> None:
        """Send GATT notification data to client."""
        resp = proto.encode_ble_gatt_notify_data_response(
            address, handle, data
        )
        self._send_message(proto.MSG_BLE_GATT_NOTIFY_DATA_RESPONSE, resp)

    def push_scanner_state(self, state: int) -> None:
        """Send scanner state update to client."""
        current_mode, configured_mode = self._scanner_mode_fields()
        resp = proto.encode_ble_scanner_state_response(
            state, current_mode, configured_mode
        )
        self._send_message(proto.MSG_BLE_SCANNER_STATE_RESPONSE, resp)

    def _scanner_mode_fields(self) -> tuple[int, int]:
        """Return (current_mode, configured_mode) for scanner state messages.

        ``current_mode`` is the mode actually in use (passive may fall back to
        active), while ``configured_mode`` is what the client requested.
        """
        ble = self.server.ble_manager
        current_mode = (
            proto.SCANNER_MODE_ACTIVE
            if ble._effective_scan_active
            else proto.SCANNER_MODE_PASSIVE
        )
        configured_mode = (
            proto.SCANNER_MODE_ACTIVE
            if ble._scan_active
            else proto.SCANNER_MODE_PASSIVE
        )
        return current_mode, configured_mode

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_connections_free(self) -> None:
        ble = self.server.ble_manager
        resp = proto.encode_ble_connections_free_response(
            ble.free_connections,
            ble.max_connections,
            ble.allocated_addresses,
        )
        self._send_message(proto.MSG_BLE_CONNECTIONS_FREE_RESPONSE, resp)

    async def _adv_flush_loop(self) -> None:
        """Periodically flush batched advertisements."""
        try:
            while not self._closed:
                await asyncio.sleep(ADV_BATCH_INTERVAL)
                if self._adv_batch:
                    batch = self._adv_batch
                    self._adv_batch = []
                    self._flush_advertisements(batch)
                    try:
                        await self.writer.drain()
                    except (ConnectionResetError, OSError):
                        break
        except asyncio.CancelledError:
            pass

    def _flush_advertisements(
        self, batch: list[tuple[int, int, int, bytes]]
    ) -> None:
        """Encode and send an advertisement batch, splitting it to fit the
        transport's frame-size limit.

        The Noise transport caps a single frame at 65535 bytes, so a dense batch
        can exceed it and ``write_message`` raises ``ValueError``. Left
        unhandled that kills the flush task and the client silently stops
        receiving *all* advertisements until it reconnects. Splitting keeps the
        task alive and drops no advertisements. Plaintext has no cap, so the
        common case sends exactly one frame.
        """
        if not batch:
            return
        resp = proto.encode_ble_raw_advertisements_response(batch)
        try:
            self._send_message(proto.MSG_BLE_RAW_ADVERTISEMENTS_RESPONSE, resp)
        except ValueError:
            if len(batch) == 1:
                # A single BLE advertisement is tens of bytes and cannot exceed
                # the frame limit; if one somehow does, drop it rather than
                # recurse forever.
                logger.warning(
                    "Dropping an advertisement that exceeds the frame size "
                    "limit (%d bytes)",
                    len(resp),
                )
                return
            mid = len(batch) // 2
            self._flush_advertisements(batch[:mid])
            self._flush_advertisements(batch[mid:])

    async def _cleanup(self) -> None:
        self._closed = True
        if self._adv_flush_task:
            self._adv_flush_task.cancel()
            self._adv_flush_task = None
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        # Remove ourselves from the server's connection list
        self.server.remove_connection(self)


# Handler dispatch table.
#
# Each entry is either ``(handler, minimum_state)`` or a bare ``handler``. A
# bare handler is normalized to require ``State.AUTHENTICATED`` -- i.e. the
# SAFE case is the default, so a handler added without an explicit state is
# gated, never accidentally exposed pre-authentication.
#
# Only the pre-authentication handshake messages (Hello, Connect, DeviceInfo,
# Ping, Disconnect) are marked ``State.CONNECTED``. Every BLE/GATT handler
# relies on the authenticated default.
_HandlerEntry = Union[Any, tuple[Any, "State"]]


def _normalize_handler(entry: _HandlerEntry) -> tuple[Any, State]:
    """Normalize a table entry to ``(handler, required_state)``.

    Bare handlers default to ``State.AUTHENTICATED`` so the safe case wins.
    """
    if isinstance(entry, tuple):
        return entry
    return (entry, State.AUTHENTICATED)


_RAW_MESSAGE_HANDLERS: dict[int, _HandlerEntry] = {
    # Pre-authentication handshake messages.
    proto.MSG_HELLO_REQUEST: (APIConnection._handle_hello, State.CONNECTED),
    proto.MSG_CONNECT_REQUEST: (APIConnection._handle_connect, State.CONNECTED),
    proto.MSG_DEVICE_INFO_REQUEST: (
        APIConnection._handle_device_info,
        State.CONNECTED,
    ),
    proto.MSG_PING_REQUEST: (APIConnection._handle_ping, State.CONNECTED),
    proto.MSG_DISCONNECT_REQUEST: (
        APIConnection._handle_disconnect,
        State.CONNECTED,
    ),
    # Everything below relies on the authenticated-by-default normalization.
    proto.MSG_LIST_ENTITIES_REQUEST: APIConnection._handle_list_entities,
    proto.MSG_SUBSCRIBE_STATES_REQUEST: APIConnection._handle_subscribe_states,
    proto.MSG_SUBSCRIBE_BLE_ADVERTISEMENTS_REQUEST: APIConnection._handle_subscribe_ble_advertisements,
    proto.MSG_UNSUBSCRIBE_BLE_ADVERTISEMENTS_REQUEST: APIConnection._handle_unsubscribe_ble_advertisements,
    proto.MSG_SUBSCRIBE_BLE_CONNECTIONS_FREE_REQUEST: APIConnection._handle_subscribe_connections_free,
    proto.MSG_BLE_DEVICE_REQUEST: APIConnection._handle_ble_device_request,
    proto.MSG_BLE_GATT_GET_SERVICES_REQUEST: APIConnection._handle_gatt_get_services,
    proto.MSG_BLE_GATT_READ_REQUEST: APIConnection._handle_gatt_read,
    proto.MSG_BLE_GATT_WRITE_REQUEST: APIConnection._handle_gatt_write,
    proto.MSG_BLE_GATT_READ_DESCRIPTOR_REQUEST: APIConnection._handle_gatt_read_descriptor,
    proto.MSG_BLE_GATT_WRITE_DESCRIPTOR_REQUEST: APIConnection._handle_gatt_write_descriptor,
    proto.MSG_BLE_GATT_NOTIFY_REQUEST: APIConnection._handle_gatt_notify,
    proto.MSG_BLE_SCANNER_SET_MODE_REQUEST: APIConnection._handle_scanner_set_mode,
    proto.MSG_SUBSCRIBE_LOGS_REQUEST: APIConnection._handle_subscribe_logs,
    proto.MSG_GET_TIME_REQUEST: APIConnection._handle_get_time,
    proto.MSG_SUBSCRIBE_HOMEASSISTANT_SERVICES_REQUEST: APIConnection._handle_noop,
    proto.MSG_SUBSCRIBE_HOMEASSISTANT_STATES_REQUEST: APIConnection._handle_noop,
}

#: The gated dispatch table: ``msg_type -> (handler, minimum_state)``.
_MESSAGE_HANDLERS: dict[int, tuple[Any, State]] = {
    msg_type: _normalize_handler(entry)
    for msg_type, entry in _RAW_MESSAGE_HANDLERS.items()
}


class APIServer:
    """ESPHome Native API TCP server."""

    def __init__(
        self,
        ble_manager: BLEManager,
        name: str = "bt-proxy",
        friendly_name: str = "Bluetooth Proxy",
        mac_address: str = "",
        bt_mac_address: str = "",
        port: int = 6053,
        encryption_key: bytes | None = None,
    ):
        self.ble_manager = ble_manager
        self.name = name
        self.friendly_name = friendly_name
        self.mac_address = mac_address
        self.bt_mac_address = bt_mac_address
        self.port = port
        #: The 32-byte Noise PSK, or None for deprecated plaintext mode.
        self.encryption_key = encryption_key
        self._connections: list[APIConnection] = []
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start the API server."""
        # Wire up BLE manager callbacks
        self.ble_manager.set_callbacks(
            on_advertisement=self._on_advertisement,
            on_disconnect=self._on_disconnect,
            on_notify=self._on_notify,
            on_scanner_state=self._on_scanner_state,
        )

        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", self.port
        )
        logger.info("API server listening on port %d", self.port)

    async def stop(self) -> None:
        """Stop the server and close all connections."""
        if self._server:
            self._server.close()
        for conn in list(self._connections):
            await conn._cleanup()
        self._connections.clear()
        if self._server:
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for API server to close")

    def remove_connection(self, conn: APIConnection) -> None:
        """Remove a connection from the active list."""
        if conn in self._connections:
            self._connections.remove(conn)
            logger.info("Connection removed, %d active", len(self._connections))

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        conn = APIConnection(reader, writer, self)
        self._connections.append(conn)
        await conn.run()

    # BLE manager callbacks - broadcast to all subscribed connections
    def _on_advertisement(
        self, address: int, rssi: int, address_type: int, data: bytes
    ) -> None:
        for conn in self._connections:
            conn.push_advertisement(address, rssi, address_type, data)

    def _on_disconnect(self, address: int) -> None:
        for conn in self._connections:
            conn.push_disconnect(address)

    def _on_notify(self, address: int, handle: int, data: bytes) -> None:
        for conn in self._connections:
            conn.push_notify_data(address, handle, data)

    def _on_scanner_state(self, state: int) -> None:
        for conn in self._connections:
            conn.push_scanner_state(state)
