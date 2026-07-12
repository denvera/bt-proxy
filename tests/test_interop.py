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
  3. Encryption required when keyed -> a real plaintext client is told
                     encryption is required (RequiresEncryptionAPIError), so
                     Home Assistant prompts for the key; wire reply starts 0x01.
  4. Backwards compat (no key)   -> the v1.0.2 plaintext flow still works end to
                     end over a raw socket, and the deprecation warning is
                     logged.
"""

from __future__ import annotations

import asyncio
import base64
import time

import pytest
from aioesphomeapi import APIClient
from aioesphomeapi.core import (
    InvalidEncryptionKeyAPIError,
    RequiresEncryptionAPIError,
)

from conftest import PSK, read_one_plaintext, start_server

from bt_proxy import proto

# PSK is imported from conftest. WRONG_PSK is a distinct valid-format key the
# server was NOT configured with -- the handshake MAC must fail against it.
WRONG_PSK = bytes((b + 7) & 0xFF for b in range(32))
PSK_B64 = base64.b64encode(PSK).decode()
WRONG_B64 = base64.b64encode(WRONG_PSK).decode()

NAME = "bt-proxy"
MAC = "AA:BB:CC:DD:EE:FF"

# A handshake/connect that hangs is the failure this suite exists to catch, so
# every wait is bounded well below any plausible real completion time.
TIMEOUT = 10.0


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
async def test_plaintext_client_gets_requires_encryption_when_keyed():
    """A real plaintext client (no PSK) against a keyed server must be told that
    encryption is required -- this is what makes Home Assistant prompt for the
    key rather than showing a generic connection error.

    Home Assistant always probes with plaintext first; the device signals its
    encrypted-ness by replying with a 0x01-indicator frame, which aioesphomeapi
    surfaces as RequiresEncryptionAPIError.
    """
    server, port = await start_server(encryption_key=PSK)
    try:
        client = APIClient(
            address="127.0.0.1", port=port, password="", noise_psk=None
        )
        with pytest.raises(RequiresEncryptionAPIError):
            await asyncio.wait_for(client.connect(login=True), timeout=TIMEOUT)
        try:
            await client.disconnect(force=True)
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_plaintext_probe_when_keyed_replies_with_encryption_indicator():
    """Wire-level check: the encryption-required reply starts with the 0x01
    Noise indicator byte (what the client reads as the requires-encryption
    signal), and then the socket is closed."""
    server, port = await start_server(encryption_key=PSK)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(proto.frame_message(proto.MSG_HELLO_REQUEST, b""))
        await writer.drain()
        first = await asyncio.wait_for(reader.readexactly(1), timeout=TIMEOUT)
        assert first == b"\x01"  # Noise indicator == "requires encryption"
        # ...then the server closes the connection (no plaintext session).
        with pytest.raises(
            (asyncio.IncompleteReadError, ConnectionResetError)
        ):
            await asyncio.wait_for(reader.readexactly(4096), timeout=TIMEOUT)
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
