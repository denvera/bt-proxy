"""Tests for encryption key configuration and the startup deprecation warning.

The security-critical property under test is that a malformed or wrong-length
key is *fatal*. There must be no path by which a typo'd key silently degrades
to an unauthenticated plaintext proxy.
"""

from __future__ import annotations

import base64
import logging

import pytest

from bt_proxy.__main__ import (
    build_parser,
    load_encryption_key,
    register_mdns,
    warn_if_unencrypted,
)
from bt_proxy.noise import API_ENCRYPTION_NAME

VALID_RAW = bytes(range(32))
VALID_B64 = base64.b64encode(VALID_RAW).decode()

SHORT_RAW = bytes(range(16))
SHORT_B64 = base64.b64encode(SHORT_RAW).decode()

ENV_VAR = "BT_PROXY_ENCRYPTION_KEY"


def test_valid_key_decodes_to_32_raw_bytes(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    key = load_encryption_key(VALID_B64)
    assert key == VALID_RAW
    assert len(key) == 32


def test_malformed_base64_is_fatal(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    with pytest.raises(SystemExit) as exc:
        load_encryption_key("zzzz!!!")
    # Non-zero exit, and the message must not echo the key material back.
    assert exc.value.code != 0
    assert "openssl rand -base64 32" in str(exc.value)
    assert "zzzz!!!" not in str(exc.value)


def test_wrong_length_key_is_fatal(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    with pytest.raises(SystemExit) as exc:
        load_encryption_key(SHORT_B64)
    assert exc.value.code != 0
    message = str(exc.value)
    assert "32" in message
    assert "16" in message
    assert SHORT_B64 not in message


def test_absent_key_returns_none(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert load_encryption_key(None) is None


def test_empty_string_key_returns_none(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert load_encryption_key("") is None


def test_env_var_fallback(monkeypatch):
    monkeypatch.setenv(ENV_VAR, VALID_B64)
    assert load_encryption_key(None) == VALID_RAW


def test_cli_flag_beats_env_var(monkeypatch):
    other_raw = bytes(range(32, 64))
    monkeypatch.setenv(ENV_VAR, base64.b64encode(other_raw).decode())
    assert load_encryption_key(VALID_B64) == VALID_RAW


def test_bad_env_var_is_also_fatal(monkeypatch):
    """An env-var key gets exactly the same fail-fast treatment as the flag."""
    monkeypatch.setenv(ENV_VAR, SHORT_B64)
    with pytest.raises(SystemExit) as exc:
        load_encryption_key(None)
    assert exc.value.code != 0


def test_deprecation_warning_is_specific(caplog):
    """No key -> a WARNING that says what is actually exposed, not just 'deprecated'."""
    with caplog.at_level(logging.WARNING, logger="bt_proxy.__main__"):
        warn_if_unencrypted(None)

    records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert records, "expected a WARNING when no encryption key is configured"
    text = " ".join(r.getMessage() for r in records).lower()

    assert "without encryption" in text or "unauthenticated" in text
    assert "gatt" in text
    assert "advertisement" in text
    assert "deprecated" in text
    assert "2.0" in text
    assert "bt_proxy_encryption_key" in text


def test_no_warning_when_key_configured(caplog):
    with caplog.at_level(logging.WARNING, logger="bt_proxy.__main__"):
        warn_if_unencrypted(VALID_RAW)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


class _FakeZeroconf:
    """Stand-in for AsyncZeroconf so no real mDNS socket is opened."""

    def __init__(self, *args, **kwargs):
        pass

    async def async_register_service(self, info):
        return None


async def _mdns_properties(monkeypatch, *, encrypted: bool) -> dict:
    monkeypatch.setattr("bt_proxy.__main__.AsyncZeroconf", _FakeZeroconf)
    monkeypatch.setattr("bt_proxy.__main__.get_local_ip", lambda: "192.0.2.10")
    _zc, info = await register_mdns(
        "bt-proxy", 6053, "AA:BB:CC:DD:EE:FF", encrypted=encrypted
    )
    return info.properties


def _txt(properties: dict, key: str):
    """zeroconf stores TXT keys/values as bytes, and encodes "" as None."""
    value = properties[key.encode()]
    return value.decode() if isinstance(value, bytes) else value


@pytest.mark.asyncio
async def test_mdns_advertises_noise_when_key_configured(monkeypatch):
    properties = await _mdns_properties(monkeypatch, encrypted=True)
    assert _txt(properties, "api_encryption") == API_ENCRYPTION_NAME
    assert API_ENCRYPTION_NAME == "Noise_NNpsk0_25519_ChaChaPoly_SHA256"


@pytest.mark.asyncio
async def test_mdns_keeps_empty_api_encryption_without_key(monkeypatch):
    """Backwards compatibility: the TXT record is byte-for-byte what v1.0.2 sent.

    v1.0.2 hardcoded ``"api_encryption": ""``; zeroconf encodes that empty
    string as a valueless TXT key (``None``). Assert that exact encoding, so a
    regression to a non-empty value would be caught.
    """
    properties = await _mdns_properties(monkeypatch, encrypted=False)
    assert _txt(properties, "api_encryption") is None


def test_key_material_never_logged(caplog):
    """The key must not appear in log output at any level, including DEBUG."""
    with caplog.at_level(logging.DEBUG):
        key = load_encryption_key(VALID_B64)
        warn_if_unencrypted(key)
    text = caplog.text
    assert VALID_B64 not in text
    assert VALID_RAW.hex() not in text


# ---------------------------------------------------------------------------
# Name / friendly-name come from env vars (spaces-safe), CLI wins over env.
# ---------------------------------------------------------------------------


def test_env_vars_set_name_and_friendly_name(monkeypatch):
    """A friendly name with spaces set via BT_PROXY_FRIENDLY_NAME survives
    intact -- this is what the systemd unit relies on instead of a word-split
    argument string."""
    monkeypatch.setenv("BT_PROXY_NAME", "living-room-proxy")
    monkeypatch.setenv("BT_PROXY_FRIENDLY_NAME", "Living Room Proxy")
    args = build_parser().parse_args([])
    assert args.name == "living-room-proxy"
    assert args.friendly_name == "Living Room Proxy"


def test_cli_flag_overrides_env(monkeypatch):
    monkeypatch.setenv("BT_PROXY_FRIENDLY_NAME", "From Env")
    args = build_parser().parse_args(["--friendly-name", "From CLI"])
    assert args.friendly_name == "From CLI"


def test_defaults_when_env_unset(monkeypatch):
    monkeypatch.delenv("BT_PROXY_NAME", raising=False)
    monkeypatch.delenv("BT_PROXY_FRIENDLY_NAME", raising=False)
    args = build_parser().parse_args([])
    assert args.name == "bt-proxy"
    assert args.friendly_name == "Bluetooth Proxy"
