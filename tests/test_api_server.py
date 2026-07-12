"""Tests for transport selection and the connection state gate.

The single most important test here is ``test_exploit_ble_request_as_first_message``:
it is the regression guard for the reviewed security finding. An unauthenticated
client must not be able to drive the BLE radio by sending a BLE/GATT request as
its very first message.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from conftest import PSK, make_ble, read_one_plaintext, start_server

from bt_proxy import api_server, proto
from bt_proxy.noise import FrameTooLargeError, NoiseFrameHelper


def ble_connect_request(address: int = 0x112233445566) -> bytes:
    """A framed BluetoothDeviceRequest (type 68) asking to CONNECT."""
    payload = proto.encode_field_varint(1, address) + proto.encode_field_varint(
        2, proto.BLE_REQUEST_CONNECT_V3_WITH_CACHE
    )
    return proto.frame_message(proto.MSG_BLE_DEVICE_REQUEST, payload)


# ---------------------------------------------------------------------------
# THE security regression test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exploit_ble_request_as_first_message(caplog):
    """A BLE request sent as the FIRST message must NOT drive the radio.

    No Hello, no Connect -- just msg type 68. BLEManager.connect_device must
    never be called. This is the vulnerability the whole plan closes.
    """
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=None)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(ble_connect_request())
        await writer.drain()
        # Give the server ample time to (wrongly) dispatch it.
        await asyncio.sleep(0.2)
        ble.connect_device.assert_not_called()
        writer.close()
    finally:
        await server.stop()


# ---------------------------------------------------------------------------
# Transport selection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_plaintext_no_regression_hello_then_device_info():
    """With no key, the v1.0.2 plaintext flow still works end to end."""
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=None)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        writer.write(proto.frame_message(proto.MSG_HELLO_REQUEST, b""))
        await writer.drain()
        msg_type, _ = await asyncio.wait_for(read_one_plaintext(reader), 2.0)
        assert msg_type == proto.MSG_HELLO_RESPONSE

        writer.write(proto.frame_message(proto.MSG_DEVICE_INFO_REQUEST, b""))
        await writer.drain()
        msg_type, _ = await asyncio.wait_for(read_one_plaintext(reader), 2.0)
        assert msg_type == proto.MSG_DEVICE_INFO_RESPONSE

        writer.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_plaintext_when_keyed_signals_encryption_required():
    """0x00 with a key configured: the server replies with the 0x01 Noise
    indicator (so a real client raises RequiresEncryptionAPIError and Home
    Assistant prompts for the key) and then closes -- no HelloResponse."""
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=PSK)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(proto.frame_message(proto.MSG_HELLO_REQUEST, b""))
        await writer.drain()
        # The reply's indicator byte is 0x01 == "encryption required", never a
        # 0x00 plaintext HelloResponse.
        first = await asyncio.wait_for(reader.readexactly(1), 2.0)
        assert first == b"\x01"
        with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError)):
            await asyncio.wait_for(reader.readexactly(4096), 2.0)
        writer.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_noise_refused_when_no_key_no_hang():
    """0x01 with no key: refused cleanly (socket closed), must not hang."""
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=None)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Client hello frame for Noise: 01 00 00
        writer.write(b"\x01\x00\x00")
        await writer.drain()
        # Server must close without hanging -> EOF within the timeout.
        with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError)):
            await asyncio.wait_for(reader.readexactly(1), 2.0)
        writer.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_unknown_preamble_closes():
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=None)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x99")
        await writer.drain()
        with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError)):
            await asyncio.wait_for(reader.readexactly(1), 2.0)
        writer.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_deprecation_warning_logged_per_connection(caplog):
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=None)
    try:
        with caplog.at_level("WARNING"):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(proto.frame_message(proto.MSG_HELLO_REQUEST, b""))
            await writer.drain()
            await asyncio.wait_for(read_one_plaintext(reader), 2.0)
            writer.close()
        assert any(
            "127.0.0.1" in r.message and "DEPRECATED" in r.message.upper()
            for r in caplog.records
        ), [r.message for r in caplog.records]
    finally:
        await server.stop()


# ---------------------------------------------------------------------------
# The state gate, exercised directly
# ---------------------------------------------------------------------------


def test_every_handler_declares_its_gate():
    """Every dispatch-table entry is an explicit (handler, State) tuple, so no
    handler can be added without declaring the state it is gated behind."""
    for msg_type, entry in api_server._MESSAGE_HANDLERS.items():
        assert isinstance(entry, tuple) and len(entry) == 2, (msg_type, entry)
        _handler, required = entry
        assert isinstance(required, api_server.State)


def test_ble_gatt_handlers_require_authentication():
    """Every BLE/GATT message type is gated behind AUTHENTICATED."""
    ble_types = [66, 68, 70, 73, 75, 76, 77, 78, 80, 87, 127]
    for t in ble_types:
        _handler, required = api_server._MESSAGE_HANDLERS[t]
        assert required is api_server.State.AUTHENTICATED, t


def test_preauth_handlers_allowed_at_connected():
    preauth = [
        proto.MSG_HELLO_REQUEST,
        proto.MSG_CONNECT_REQUEST,
        proto.MSG_DEVICE_INFO_REQUEST,
        proto.MSG_PING_REQUEST,
        proto.MSG_DISCONNECT_REQUEST,
    ]
    for t in preauth:
        _handler, required = api_server._MESSAGE_HANDLERS[t]
        assert required is api_server.State.CONNECTED, t


@pytest.mark.asyncio
async def test_plaintext_connect_authenticates_then_ble_allowed():
    """After ConnectRequest, a plaintext client may drive the radio."""
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=None)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(proto.frame_message(proto.MSG_CONNECT_REQUEST, b""))
        await writer.drain()
        msg_type, _ = await asyncio.wait_for(read_one_plaintext(reader), 2.0)
        assert msg_type == proto.MSG_CONNECT_RESPONSE

        writer.write(ble_connect_request())
        await writer.drain()
        # Now the request is authorized and reaches the radio.
        await asyncio.wait_for(read_one_plaintext(reader), 2.0)
        ble.connect_device.assert_called_once()
        writer.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_noise_client_reaches_authenticated_and_can_drive_radio():
    """A full Noise handshake authenticates; BLE request then works."""
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=PSK)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client = _NoiseClient(reader, writer, PSK)
        await asyncio.wait_for(client.handshake(), 2.0)

        payload = proto.encode_field_varint(
            1, 0x112233445566
        ) + proto.encode_field_varint(2, proto.BLE_REQUEST_CONNECT_V3_WITH_CACHE)
        await client.write_message(proto.MSG_BLE_DEVICE_REQUEST, payload)
        msg_type, _ = await asyncio.wait_for(client.read_message(), 2.0)
        assert msg_type == proto.MSG_BLE_DEVICE_CONNECTION_RESPONSE
        ble.connect_device.assert_called_once()
        writer.close()
    finally:
        await server.stop()


class _NoiseClient:
    """Minimal Noise client mirroring the one in test_noise.py."""

    def __init__(self, reader, writer, psk):
        from noise.connection import NoiseConnection

        from bt_proxy import noise as bt_noise

        self._bt_noise = bt_noise
        self.reader = reader
        self.writer = writer
        self.proto = NoiseConnection.from_name(bt_noise.NOISE_PROTOCOL_NAME)
        self.proto.set_as_initiator()
        self.proto.set_psks(psk)
        self.proto.set_prologue(bt_noise.build_prologue(b""))
        self.proto.start_handshake()

    async def _read_frame(self) -> bytes:
        header = await self.reader.readexactly(3)
        assert header[0] == 0x01
        length = (header[1] << 8) | header[2]
        return await self.reader.readexactly(length) if length else b""

    async def handshake(self):
        handshake_frame = b"\x00" + self.proto.write_message()
        self.writer.write(
            b"\x01\x00\x00" + self._bt_noise.encode_frame(handshake_frame)
        )
        await self.writer.drain()
        await self._read_frame()  # server hello
        msg = await self._read_frame()
        assert msg[0] == 0x00, msg
        self.proto.read_message(msg[1:])

    async def read_message(self):
        plaintext = self.proto.decrypt(await self._read_frame())
        return (plaintext[0] << 8) | plaintext[1], plaintext[4:]

    async def write_message(self, msg_type, data):
        inner = self._bt_noise.encode_inner(msg_type, data)
        self.writer.write(self._bt_noise.encode_frame(self.proto.encrypt(inner)))
        await self.writer.drain()


# ---------------------------------------------------------------------------
# Oversized advertisement batch must be split, not dropped or fatal.
# ---------------------------------------------------------------------------


class _CappedTransport:
    """A transport whose write_message rejects any single frame over ``cap``,
    mimicking the Noise 65535-byte frame ceiling."""

    def __init__(self, cap: int):
        self.cap = cap
        self.frames: list[tuple[int, bytes]] = []

    def write_message(self, msg_type: int, data: bytes) -> None:
        if len(data) > self.cap:
            raise FrameTooLargeError(f"frame too big: {len(data)} > {self.cap}")
        self.frames.append((msg_type, data))


@pytest.mark.asyncio
async def test_oversized_adv_batch_is_split_not_dropped():
    """A batch too large for one frame is split across frames with no losses;
    the flush must not raise (which would kill _adv_flush_loop)."""
    conn = api_server.APIConnection(MagicMock(), MagicMock(), MagicMock())
    conn._transport = _CappedTransport(cap=1000)
    conn._closed = False

    batch = [(0x1000 + i, -60, 0, bytes([i % 256]) * 30) for i in range(100)]
    conn._flush_advertisements(batch)  # must not raise

    assert len(conn._transport.frames) >= 2  # actually split
    delivered = 0
    for _msg_type, data in conn._transport.frames:
        assert len(data) <= 1000  # every frame fits
        delivered += len(proto.decode_fields(data).get(1, []))
    assert delivered == 100  # nothing dropped


@pytest.mark.asyncio
async def test_gated_message_before_auth_closes_connection():
    """A gated (AUTHENTICATED-only) message sent before ConnectRequest must
    close the connection (EOF) rather than leave the client hanging silently."""
    ble = make_ble()
    server, port = await start_server(ble, encryption_key=None)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Skip ConnectRequest; go straight to a gated subscribe.
        writer.write(
            proto.frame_message(
                proto.MSG_SUBSCRIBE_BLE_ADVERTISEMENTS_REQUEST, b""
            )
        )
        await writer.drain()
        # Server refuses and closes -> EOF within the timeout, not a hang.
        with pytest.raises((asyncio.IncompleteReadError, ConnectionResetError)):
            await asyncio.wait_for(reader.readexactly(1), 2.0)
        writer.close()
    finally:
        await server.stop()
