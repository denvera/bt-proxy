"""Shared test helpers (previously copy-pasted across the suites)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from bt_proxy import api_server

#: A fixed 32-byte Noise PSK used across the tests.
PSK = bytes(range(32))


def make_ble() -> MagicMock:
    """A BLEManager stand-in with spies on the radio-driving methods."""
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


async def start_server(ble=None, encryption_key=None):
    """Start an APIServer on an ephemeral port; return (server, port).

    ``ble`` defaults to a fresh :func:`make_ble` mock.
    """
    ble = ble if ble is not None else make_ble()
    kwargs = {}
    if encryption_key is not None:
        kwargs["encryption_key"] = encryption_key
    server = api_server.APIServer(
        ble,
        name="bt-proxy",
        mac_address="AA:BB:CC:DD:EE:FF",
        bt_mac_address="AA:BB:CC:DD:EE:FF",
        port=0,
        **kwargs,
    )
    await server.start()
    port = server._server.sockets[0].getsockname()[1]
    return server, port


async def read_varint(reader) -> int:
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
    assert preamble == b"\x00"
    data_length = await read_varint(reader)
    msg_type = await read_varint(reader)
    data = await reader.readexactly(data_length) if data_length else b""
    return msg_type, data
