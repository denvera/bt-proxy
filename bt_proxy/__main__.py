"""Main entry point for the Bluetooth Proxy."""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import logging
import os
import signal
import socket
import subprocess

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from . import EMULATED_ESPHOME_VERSION
from .api_server import APIServer
from .ble_manager import BLEManager
from .noise import API_ENCRYPTION_NAME

logger = logging.getLogger(__name__)

#: Production-preferred way to supply the key: a CLI flag is visible in `ps`.
ENCRYPTION_KEY_ENV_VAR = "BT_PROXY_ENCRYPTION_KEY"

KEY_LENGTH = 32
_HOWTO = "Generate one with: openssl rand -base64 32"

UNENCRYPTED_WARNING = (
    "Running WITHOUT encryption. Any device on this network can connect to "
    "this proxy, control your Bluetooth adapter, read and write arbitrary "
    "GATT characteristics on nearby devices, and receive a live feed of every "
    "BLE advertisement in range. Set --encryption-key (or the "
    f"{ENCRYPTION_KEY_ENV_VAR} environment variable) to enable Noise "
    "encryption. Unauthenticated operation is DEPRECATED and will become "
    "opt-in / be removed in 2.0."
)


def load_encryption_key(cli_value: str | None) -> bytes | None:
    """Resolve and validate the Noise PSK.

    Returns the 32 raw key bytes, or ``None`` when no key is configured (the
    deprecated, backwards-compatible plaintext mode).

    The CLI value takes precedence over the environment variable. A malformed
    or wrong-length key raises :class:`SystemExit` -- it never degrades to
    plaintext, because an operator who fat-fingered their key would otherwise
    believe they were protected while exposing full Bluetooth control to the
    network.

    The key material is never included in any message raised or logged here.
    """
    raw_b64 = cli_value or os.environ.get(ENCRYPTION_KEY_ENV_VAR)
    if not raw_b64:
        return None

    try:
        key = base64.b64decode(raw_b64, validate=True)
    except (binascii.Error, ValueError) as err:
        # Note: neither the key nor the underlying exception text (which can
        # quote the input) is interpolated into the message.
        raise SystemExit(
            "Encryption key is not valid base64 "
            f"(--encryption-key / {ENCRYPTION_KEY_ENV_VAR}). {_HOWTO}"
        ) from err

    if len(key) != KEY_LENGTH:
        raise SystemExit(
            "Encryption key must decode to exactly "
            f"{KEY_LENGTH} bytes, got {len(key)} "
            f"(--encryption-key / {ENCRYPTION_KEY_ENV_VAR}). {_HOWTO}"
        )

    return key


def warn_if_unencrypted(key: bytes | None) -> None:
    """Emit the startup deprecation warning when running in plaintext mode."""
    if key is None:
        logger.warning(UNENCRYPTED_WARNING)


def get_local_ip() -> str:
    """Get the primary local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_bt_mac(adapter: str | None = None) -> str:
    """Get the Bluetooth adapter MAC address."""
    try:
        result = subprocess.run(
            ["bluetoothctl", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Controller") and ":" in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
    except Exception:
        pass

    # Fall back to reading from sysfs
    try:
        with open("/sys/class/bluetooth/hci0/address") as f:
            return f.read().strip().upper()
    except Exception:
        return "00:00:00:00:00:00"


async def register_mdns(
    name: str, port: int, mac: str, encrypted: bool = False
) -> tuple[AsyncZeroconf, AsyncServiceInfo]:
    """Register the service via mDNS so Home Assistant can discover it.

    When ``encrypted`` is set, the ``api_encryption`` TXT property advertises
    the Noise protocol name, which is how Home Assistant knows to ask for the
    encryption key. With no key it keeps its historical empty value.
    """
    local_ip = get_local_ip()
    logger.info("Advertising mDNS on %s:%d", local_ip, port)

    # ESPHome devices advertise as _esphomelib._tcp.local.
    info = AsyncServiceInfo(
        "_esphomelib._tcp.local.",
        f"{name}._esphomelib._tcp.local.",
        addresses=[socket.inet_aton(local_ip)],
        port=port,
        properties={
            "version": EMULATED_ESPHOME_VERSION,
            "mac": mac.replace(":", "").lower(),
            "platform": "linux",
            "network": "wifi",
            "api_encryption": API_ENCRYPTION_NAME if encrypted else "",
        },
        server=f"{name}.local.",
    )

    zc = AsyncZeroconf(ip_version=IPVersion.V4Only)
    await zc.async_register_service(info)
    return zc, info


async def async_main(args: argparse.Namespace, encryption_key: bytes | None) -> None:
    """Async main entry point."""
    bt_mac = get_bt_mac(args.adapter)
    logger.info("Bluetooth MAC: %s", bt_mac)

    ble_manager = BLEManager(
        max_connections=args.max_connections,
        adapter=args.adapter,
    )

    server = APIServer(
        ble_manager=ble_manager,
        name=args.name,
        friendly_name=args.friendly_name,
        mac_address=bt_mac,
        bt_mac_address=bt_mac,
        port=args.port,
        encryption_key=encryption_key,
    )

    # Register mDNS
    zc, service_info = await register_mdns(
        args.name, args.port, bt_mac, encrypted=encryption_key is not None
    )

    # Start BLE scanning
    await ble_manager.start_scanning()

    # Start API server
    await server.start()

    # Wait for shutdown signal
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    logger.info("Bluetooth Proxy '%s' is running", args.name)
    await stop_event.wait()

    # Cleanup
    logger.info("Shutting down...")
    await server.stop()
    await ble_manager.cleanup()
    await zc.async_unregister_service(service_info)
    await zc.async_close()
    logger.info("Shutdown complete")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ESPHome-compatible Bluetooth Proxy for Raspberry Pi"
    )
    parser.add_argument(
        "--name",
        default="bt-proxy",
        help="Device name (default: bt-proxy)",
    )
    parser.add_argument(
        "--friendly-name",
        default="Bluetooth Proxy",
        help="Friendly name (default: Bluetooth Proxy)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=6053,
        help="API server port (default: 6053)",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=3,
        help="Max concurrent BLE connections (default: 3)",
    )
    parser.add_argument(
        "--adapter",
        default=None,
        help="Bluetooth adapter (e.g. hci0). Uses default if not specified.",
    )
    parser.add_argument(
        "--encryption-key",
        default=None,
        help=(
            "Base64-encoded 32-byte Noise pre-shared key, the same value used "
            "in the Home Assistant integration. Generate one with "
            "'openssl rand -base64 32'. Falls back to the "
            f"{ENCRYPTION_KEY_ENV_VAR} environment variable, which is "
            "preferred in production because a CLI flag is visible in 'ps' "
            "output. If unset, the API is served unencrypted (DEPRECATED)."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    # Validate before anything binds a socket: a bad key is fatal, never a
    # silent downgrade to plaintext.
    encryption_key = load_encryption_key(args.encryption_key)
    if encryption_key is not None:
        logger.info("API encryption enabled (%s)", API_ENCRYPTION_NAME)
    else:
        warn_if_unencrypted(encryption_key)

    asyncio.run(async_main(args, encryption_key))


if __name__ == "__main__":
    main()
