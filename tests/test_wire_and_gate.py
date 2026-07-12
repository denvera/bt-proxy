"""Gap-closing tests for Task 4.

The seven acceptance criteria for this task (byte-exact framing including the
>255-byte big-endian case, the prologue literal, the inner 4-byte header,
the oversize guard, key validation, the exploit path, and gate default-safety)
are already covered by the three existing suites:

* ``tests/test_noise.py``  -- framing, prologue, inner header, oversize.
* ``tests/test_config.py`` -- ``load_encryption_key`` validation and fallback.
* ``tests/test_api_server.py`` -- the exploit path and gate default-safety.

Rather than duplicate them, this file closes the one genuine gap: the dispatch
**gate decision itself** (``APIConnection._handle_message``) is only ever
exercised end-to-end through a real socket, or asserted statically against the
table. Nothing tests the gate's core arithmetic -- ``state.value <
required.value`` -- in isolation, and in particular nothing pins the boundary
condition where the current state exactly equals the requirement (must be
allowed, not refused). That off-by-one is invisible until exploited, which is
exactly the class of bug this task exists to guard.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from bt_proxy import api_server
from bt_proxy.api_server import State

# A message type that is not in the real dispatch table, so inserting a spy
# under it cannot collide with a production handler.
_TEST_MSG_TYPE = 0x7EEE


def _make_conn() -> api_server.APIConnection:
    """An APIConnection with no real socket -- enough to call _handle_message."""
    reader = MagicMock()
    writer = MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    server = MagicMock()
    return api_server.APIConnection(reader, writer, server)


@pytest.mark.asyncio
async def test_gate_refuses_handler_above_current_state(monkeypatch):
    """A handler requiring AUTHENTICATED is NOT called while merely CONNECTED."""
    conn = _make_conn()
    conn._state = State.CONNECTED
    spy = AsyncMock()
    monkeypatch.setitem(
        api_server._MESSAGE_HANDLERS, _TEST_MSG_TYPE, (spy, State.AUTHENTICATED)
    )

    await conn._handle_message(_TEST_MSG_TYPE, b"payload")

    spy.assert_not_called()


@pytest.mark.asyncio
async def test_gate_allows_handler_once_authenticated(monkeypatch):
    """Same handler, now AUTHENTICATED: it runs with (conn, data)."""
    conn = _make_conn()
    conn._state = State.AUTHENTICATED
    spy = AsyncMock()
    monkeypatch.setitem(
        api_server._MESSAGE_HANDLERS, _TEST_MSG_TYPE, (spy, State.AUTHENTICATED)
    )

    await conn._handle_message(_TEST_MSG_TYPE, b"payload")

    spy.assert_awaited_once_with(conn, b"payload")


@pytest.mark.asyncio
async def test_gate_allows_at_exact_state_boundary(monkeypatch):
    """state == required must pass. Guards a ``<`` that was meant to be ``<=``."""
    conn = _make_conn()
    conn._state = State.CONNECTED
    spy = AsyncMock()
    monkeypatch.setitem(
        api_server._MESSAGE_HANDLERS, _TEST_MSG_TYPE, (spy, State.CONNECTED)
    )

    await conn._handle_message(_TEST_MSG_TYPE, b"")

    spy.assert_awaited_once_with(conn, b"")


@pytest.mark.asyncio
async def test_gate_refuses_connected_handler_while_still_handshaking(monkeypatch):
    """Below the requirement (HANDSHAKE < CONNECTED) is refused."""
    conn = _make_conn()
    conn._state = State.HANDSHAKE
    spy = AsyncMock()
    monkeypatch.setitem(
        api_server._MESSAGE_HANDLERS, _TEST_MSG_TYPE, (spy, State.CONNECTED)
    )

    await conn._handle_message(_TEST_MSG_TYPE, b"")

    spy.assert_not_called()


@pytest.mark.asyncio
async def test_gate_unknown_message_type_is_a_silent_noop():
    """An unregistered type is ignored, not an error -- even pre-auth."""
    conn = _make_conn()
    conn._state = State.HANDSHAKE
    # 0xDEAD is not in the dispatch table; must return without raising.
    await conn._handle_message(0xDEAD, b"whatever")
