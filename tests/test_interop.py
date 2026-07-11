"""Interoperability tests: the REAL ``aioesphomeapi`` client vs. the real server.

This is the acceptance bar for the whole Noise-encryption plan. The client in
scenarios 1 and 2 is ``aioesphomeapi.APIClient`` -- the *exact* library Home
Assistant runs -- deliberately NOT a hand-rolled Noise client. If our server and
our own client shared the same protocol misunderstanding (say, both
little-endian) a self-vs-self test would pass while real Home Assistant still
could not connect; using foreign client code we did not write is the entire
point of this task.

The four scenarios all run against a real :class:`bt_proxy.api_server.APIServer`
on an ephemeral loopback port, with ``BLEManager`` mocked -- this exercises the
transport and the state gate, not Bluetooth.

  1. Correct key  -> Noise handshake completes, ``device_info`` returns the
                     expected name / mac_address.
  2. Wrong key    -> explicit ``InvalidEncryptionKeyAPIError``, promptly (a hang
                     or bare TCP close is a FAILURE, asserted via a timeout that
                     is NOT caught by the narrowed ``pytest.raises``).
  3. Plaintext refused when keyed -> raw ``0x00`` + HelloRequest gets no
                     HelloResponse and the socket is closed.
  4. Backwards compat (no key)   -> the v1.0.2 plaintext flow still works end to
                     end over a raw socket, and the deprecation warning is
                     logged.
"""

from __future__ import annotations

import asyncio
import base64
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from aioesphomeapi import APIClient
from aioesphomeapi.core import InvalidEncryptionKeyAPIError

from bt_proxy import api_server, proto

# Two distinct, valid-format 32-byte PSKs. WRONG_PSK is a real key the server
# was NOT configured with -- the handshake MAC must fail against it.
PSK = bytes(range(32))
WRONG_PSK = bytes((b + 7) & 0xFF for b in range(32))
PSK_B64 = base64.b64encode(PSK).decode()
WRONG_B64 = base64.b64encode(WRONG_PSK).decode()

NAME = "bt-proxy"
MAC = "AA:BB:CC:DD:EE:FF"

# A handshake/connect that hangs is the failure this suite exists to catch, so
# every wait is bounded well below any plausible real completion time.
TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def make_ble() -> MagicMock:
    """A BLEManager stand-in -- this suite tests the transport, not Bluetooth."""
    ble = MagicMock()
    ble.set_callbacks = MagicMock()
    ble.connect_device = AsyncMock(return_value=(False, 0, 0))
    ble.disconnect_device = AsyncMock()
    ble.set_scan_mode = AsyncMock()
    ble.get_connection = MagicMock(return_value=None)
    ble.free_connections = 3
    ble.max_connections = 3
    ble.allocated_addresses = []
    ble._scanning = True
    ble._effective_scan_active = True
    ble._scan_active = True
    return ble


async def start_server(encryption_key=None):
    """Start a real APIServer on an ephemeral port. Returns (server, port)."""
    server = api_server.APIServer(
        make_ble(),
        name=NAME,
        mac_address=MAC,
        bt_mac_address=MAC,
        port=0,
        encryption_key=encryption_key,
    )
    await server.start()
    port = server._server.sockets[0].getsockname()[1]
    return server, port


async def _read_varint(reader) -> int:
    result = 0
    shift = 0
    while True:
        b = (await reader.readexactly(1))[0]
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result
        shift += 7


async def read_one_plaintext(reader) -> tuple[int, bytes]:
    """Read a single 0x00-framed plaintext message from a raw socket."""
    preamble = await reader.readexactly(1)
    assert preamble == b"\x00", preamble
    data_length = await _read_varint(reader)
    msg_type = await _read_varint(reader)
    data = await reader.readexactly(data_length) if data_length else b""
    return msg_type, data


# ---------------------------------------------------------------------------
# 1. Correct key: real aioesphomeapi client completes the handshake.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_correct_key_completes_handshake_and_device_info():
    """A real Home Assistant client with the matching PSK gets device info."""
    server, port = await start_server(encryption_key=PSK)
    client = APIClient("127.0.0.1", port, None, noise_psk=PSK_B64)
    try:
        await asyncio.wait_for(client.connect(login=True), timeout=TIMEOUT)
        info = await asyncio.wait_for(client.device_info(), timeout=TIMEOUT)
        assert info.name == NAME, info.name
        assert info.mac_address == MAC, info.mac_address
    finally:
        await client.disconnect()
        await server.stop()


# ---------------------------------------------------------------------------
# 2. Wrong key: explicit rejection, promptly. THE test people get wrong.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wrong_key_is_rejected_explicitly_and_promptly():
    """A different valid-format PSK is rejected as an invalid encryption key.

    ``pytest.raises`` is narrowed to the concrete ``InvalidEncryptionKeyAPIError``
    on purpose: ``asyncio.wait_for`` raises ``TimeoutError`` on a hang, and that
    is NOT a subclass of the caught type, so a hang propagates and FAILS the
    test instead of masquerading as a pass. We additionally assert the rejection
    arrived well inside the timeout.
    """
    server, port = await start_server(encryption_key=PSK)
    client = APIClient("127.0.0.1", port, None, noise_psk=WRONG_B64)
    started = time.monotonic()
    try:
        with pytest.raises(InvalidEncryptionKeyAPIError):
            await asyncio.wait_for(
                client.connect(login=True), timeout=TIMEOUT
            )
        elapsed = time.monotonic() - started
        # The server sends an explicit rejection frame; this is near-instant.
        # If it ever crept toward the timeout it would signal a latent hang.
        assert elapsed < TIMEOUT / 2, f"rejection took {elapsed:.2f}s"
    finally:
        await client.disconnect()
        await server.stop()


# ---------------------------------------------------------------------------
# 3. Plaintext refused when a key is configured.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_plaintext_refused_when_key_configured():
    """0x00 + HelloRequest against a keyed server: no response, socket closed."""
    server, port = await start_server(encryption_key=PSK)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(proto.frame_message(proto.MSG_HELLO_REQUEST, b""))
        await writer.drain()
        # No HelloResponse must come; the server closes the socket -> EOF.
        with pytest.raises(
            (asyncio.IncompleteReadError, ConnectionResetError)
        ):
            await asyncio.wait_for(reader.readexactly(1), timeout=TIMEOUT)
        writer.close()
    finally:
        await server.stop()


# ---------------------------------------------------------------------------
# 4. Backwards compatibility: no key -> plaintext flow still works (v1.0.2).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_plaintext_backwards_compat_and_deprecation_warning(caplog):
    """With no key, plaintext Hello/DeviceInfo works and a warning is logged."""
    server, port = await start_server(encryption_key=None)
    try:
        with caplog.at_level("WARNING"):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            writer.write(proto.frame_message(proto.MSG_HELLO_REQUEST, b""))
            await writer.drain()
            msg_type, _ = await asyncio.wait_for(
                read_one_plaintext(reader), timeout=TIMEOUT
            )
            assert msg_type == proto.MSG_HELLO_RESPONSE

            writer.write(
                proto.frame_message(proto.MSG_DEVICE_INFO_REQUEST, b"")
            )
            await writer.drain()
            msg_type, _ = await asyncio.wait_for(
                read_one_plaintext(reader), timeout=TIMEOUT
            )
            assert msg_type == proto.MSG_DEVICE_INFO_RESPONSE

            writer.close()

        assert any(
            "DEPRECATED" in r.message.upper() for r in caplog.records
        ), [r.message for r in caplog.records]
    finally:
        await server.stop()
