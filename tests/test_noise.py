"""Tests for the ESPHome Noise-encrypted Native API transport (bt_proxy.noise).

The wire format is a fixed external contract, verified against
esphome/components/api/api_frame_helper_noise.cpp and
aioesphomeapi/_frame_helper/noise.py. These tests assert the bytes, not the
behaviour of the Noise library.
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from noise.connection import NoiseConnection

from bt_proxy import noise as bt_noise

PSK = bytes(range(32))
WRONG_PSK = bytes((b + 1) & 0xFF for b in range(32))


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------


def test_encode_frame_empty_payload():
    assert bt_noise.encode_frame(b"") == b"\x01\x00\x00"


def test_encode_frame_short_payload():
    assert bt_noise.encode_frame(b"hello") == b"\x01\x00\x05hello"


def test_encode_frame_length_is_big_endian():
    """A >255-byte payload catches an endianness flip."""
    payload = b"x" * 300
    frame = bt_noise.encode_frame(payload)
    assert frame[:3] == b"\x01\x01\x2c"  # 300 == 0x012c, big-endian
    assert frame[3:] == payload


def test_encode_frame_rejects_oversize_payload():
    with pytest.raises(ValueError):
        bt_noise.encode_frame(b"\x00" * (bt_noise.MAX_FRAME_LEN + 1))


# ---------------------------------------------------------------------------
# Prologue
# ---------------------------------------------------------------------------


def test_prologue_for_empty_client_hello_is_the_literal():
    assert bt_noise.build_prologue(b"") == b"NoiseAPIInit\x00\x00"


def test_prologue_general_construction():
    assert bt_noise.build_prologue(b"abc") == b"NoiseAPIInit\x00\x03abc"


# ---------------------------------------------------------------------------
# Server hello
# ---------------------------------------------------------------------------


def test_server_hello_payload_layout():
    assert (
        bt_noise.build_server_hello("bt-proxy", "AA:BB:CC:DD:EE:FF")
        == b"\x01bt-proxy\x00AA:BB:CC:DD:EE:FF\x00"
    )


# ---------------------------------------------------------------------------
# Inner (post-handshake) 4-byte header
# ---------------------------------------------------------------------------


def test_inner_header_is_big_endian_type_then_length():
    # type 0x0145 (325), payload of 300 bytes -> 0x012c
    plaintext = bt_noise.encode_inner(325, b"y" * 300)
    assert plaintext[:4] == b"\x01\x45\x01\x2c"
    assert plaintext[4:] == b"y" * 300


def test_inner_header_round_trip():
    for msg_type, data in ((1, b""), (68, b"\x01\x02"), (65535, b"z" * 1000)):
        msg_type_out, data_out = bt_noise.decode_inner(
            bt_noise.encode_inner(msg_type, data)
        )
        assert msg_type_out == msg_type
        assert data_out == data


def test_decode_inner_ignores_the_inner_length_field():
    """aioesphomeapi deliberately trusts the frame length, not the inner one."""
    plaintext = b"\x00\x09\xff\xff" + b"payload"
    msg_type, data = bt_noise.decode_inner(plaintext)
    assert msg_type == 9
    assert data == b"payload"


def test_decode_inner_rejects_short_plaintext():
    with pytest.raises(ValueError):
        bt_noise.decode_inner(b"\x00\x09\x00")


# ---------------------------------------------------------------------------
# Oversize guard on the ciphertext (plaintext + 16-byte AEAD tag)
# ---------------------------------------------------------------------------


def test_max_plaintext_accounts_for_the_aead_tag():
    assert bt_noise.MAX_FRAME_LEN == 65535
    assert bt_noise.MAX_PLAINTEXT_LEN == 65535 - 16
    assert bt_noise.MAX_MESSAGE_LEN == 65535 - 16 - 4


@pytest.mark.asyncio
async def test_write_message_rejects_oversize_message():
    helper, _client = await _handshaken_pair()
    try:
        with pytest.raises(ValueError):
            helper.write_message(42, b"\x00" * (bt_noise.MAX_MESSAGE_LEN + 1))
    finally:
        await _close(helper, _client)


# ---------------------------------------------------------------------------
# Handshake + transport, driven by a real noiseprotocol initiator
# ---------------------------------------------------------------------------


class _Client:
    """Minimal ESPHome Noise *client*, mirroring aioesphomeapi's frame helper."""

    def __init__(self, reader, writer, psk):
        self.reader = reader
        self.writer = writer
        self.proto = NoiseConnection.from_name(
            b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
        )
        self.proto.set_as_initiator()
        self.proto.set_psks(psk)
        self.proto.set_prologue(b"NoiseAPIInit\x00\x00")
        self.proto.start_handshake()
        self.server_hello = b""

    async def _read_frame(self) -> bytes:
        header = await self.reader.readexactly(3)
        assert header[0] == 0x01
        length = (header[1] << 8) | header[2]
        if not length:
            return b""
        return await self.reader.readexactly(length)

    async def handshake(self) -> bytes:
        # Client hello (empty) + handshake frame, pipelined as aioesphomeapi does.
        handshake_frame = b"\x00" + self.proto.write_message()
        self.writer.write(b"\x01\x00\x00" + bt_noise.encode_frame(handshake_frame))
        await self.writer.drain()
        self.server_hello = await self._read_frame()
        msg = await self._read_frame()
        if msg[0] != 0x00:
            raise AssertionError(msg)  # explicit reject
        self.proto.read_message(msg[1:])
        return msg

    async def read_message(self):
        plaintext = self.proto.decrypt(await self._read_frame())
        return (plaintext[0] << 8) | plaintext[1], plaintext[4:]

    async def write_message(self, msg_type: int, data: bytes) -> None:
        inner = bt_noise.encode_inner(msg_type, data)
        self.writer.write(bt_noise.encode_frame(self.proto.encrypt(inner)))
        await self.writer.drain()


async def _connected_pair(server_psk=PSK, client_psk=PSK):
    """Return (NoiseFrameHelper on the server side, _Client) over a real socket."""
    accepted: asyncio.Future = asyncio.get_running_loop().create_future()

    def on_client(reader, writer):
        accepted.set_result((reader, writer))

    server = await asyncio.start_server(on_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    c_reader, c_writer = await asyncio.open_connection("127.0.0.1", port)
    s_reader, s_writer = await accepted
    helper = bt_noise.NoiseFrameHelper(
        s_reader, s_writer, server_psk, "bt-proxy", "AA:BB:CC:DD:EE:FF"
    )
    return helper, _Client(c_reader, c_writer, client_psk), server


async def _handshaken_pair():
    helper, client, server = await _connected_pair()
    results = await asyncio.gather(helper.perform_handshake(), client.handshake())
    del results
    helper._test_server = server  # noqa: SLF001 - test bookkeeping
    return helper, client


async def _close(helper, client):
    server = getattr(helper, "_test_server", None)
    helper.close()
    client.writer.close()
    if server is not None:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_handshake_succeeds_with_matching_psk():
    helper, client = await _handshaken_pair()
    try:
        assert client.server_hello == b"\x01bt-proxy\x00AA:BB:CC:DD:EE:FF\x00"
        assert helper.handshake_complete is True
    finally:
        await _close(helper, client)


@pytest.mark.asyncio
async def test_transport_round_trip_both_directions():
    helper, client = await _handshaken_pair()
    try:
        # server -> client, with a payload larger than 255 bytes
        payload = bytes(range(256)) * 3
        helper.write_message(93, payload)
        await helper.drain()
        msg_type, data = await client.read_message()
        assert (msg_type, data) == (93, payload)

        # client -> server
        await client.write_message(68, b"\xde\xad\xbe\xef")
        assert await helper.read_message() == (68, b"\xde\xad\xbe\xef")
    finally:
        await _close(helper, client)


@pytest.mark.asyncio
async def test_wrong_psk_gets_an_explicit_rejection_frame_not_a_hang():
    helper, client, server = await _connected_pair(
        server_psk=PSK, client_psk=WRONG_PSK
    )
    try:
        server_task = asyncio.create_task(helper.perform_handshake())
        with pytest.raises(AssertionError) as excinfo:
            await asyncio.wait_for(client.handshake(), timeout=5)
        reject = excinfo.value.args[0]
        assert reject[0] == 0x01
        assert reject[1:] == b"Handshake MAC failure"

        with pytest.raises(bt_noise.NoiseHandshakeError):
            await asyncio.wait_for(server_task, timeout=5)
    finally:
        helper.close()
        client.writer.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_psk_is_never_logged(caplog):
    caplog.set_level(logging.DEBUG)
    helper, client = await _handshaken_pair()
    try:
        helper.write_message(1, b"hi")
        await helper.drain()
        await client.read_message()
    finally:
        await _close(helper, client)

    text = caplog.text
    assert PSK.hex() not in text
    assert repr(PSK) not in text
    for record in caplog.records:
        assert PSK not in str(record.args).encode("utf-8", "replace")
