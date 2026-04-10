"""Main entry point for the Bluetooth Proxy."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import socket
import subprocess

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from .api_server import APIServer
from .ble_manager import BLEManager

logger = logging.getLogger(__name__)


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
    name: str, port: int, mac: str
) -> tuple[AsyncZeroconf, AsyncServiceInfo]:
    """Register the service via mDNS so Home Assistant can discover it."""
    local_ip = get_local_ip()
    logger.info("Advertising mDNS on %s:%d", local_ip, port)

    # ESPHome devices advertise as _esphomelib._tcp.local.
    info = AsyncServiceInfo(
        "_esphomelib._tcp.local.",
        f"{name}._esphomelib._tcp.local.",
        addresses=[socket.inet_aton(local_ip)],
        port=port,
        properties={
            "version": "1.0",
            "mac": mac.replace(":", "").lower(),
            "platform": "linux",
            "network": "wifi",
            "api_encryption": "",
        },
        server=f"{name}.local.",
    )

    zc = AsyncZeroconf(ip_version=IPVersion.V4Only)
    await zc.async_register_service(info)
    return zc, info


async def async_main(args: argparse.Namespace) -> None:
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
    )

    # Register mDNS
    zc, service_info = await register_mdns(args.name, args.port, machine_mac)

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

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
