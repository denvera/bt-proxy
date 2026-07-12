#!/usr/bin/env python3
"""Compare CPU cost of active vs passive BLE scanning on this box.

Reports system-wide CPU% (via /proc/stat) and advert count for a scan in the
given mode. Run with bt-proxy STOPPED.

    python3 scan_cpu_test.py active 15
    python3 scan_cpu_test.py passive 15
"""
from __future__ import annotations

import asyncio
import sys

from bleak import BleakScanner
from bleak.assigned_numbers import AdvertisementDataType

try:
    from bleak.args.bluez import BlueZScannerArgs, OrPattern
except ImportError:  # older bleak layout
    from bleak.backends.bluezdbus.scanner import BlueZScannerArgs
    from bleak.backends.bluezdbus.advertisement_monitor import OrPattern

PATTERNS = [
    OrPattern(0, AdvertisementDataType.FLAGS, b"\x06"),
    OrPattern(0, AdvertisementDataType.FLAGS, b"\x1a"),
]


def cpu_sample():
    with open("/proc/stat") as f:
        v = list(map(int, f.readline().split()[1:]))
    idle = v[3] + v[4]  # idle + iowait
    return idle, sum(v)


async def main(mode: str, secs: int) -> None:
    total = 0

    def cb(dev, adv):
        nonlocal total
        total += 1

    kwargs = {"detection_callback": cb, "scanning_mode": mode}
    if mode == "passive":
        kwargs["bluez"] = BlueZScannerArgs(or_patterns=PATTERNS)

    scanner = BleakScanner(**kwargs)
    await scanner.start()
    i0, t0 = cpu_sample()
    await asyncio.sleep(secs)
    i1, t1 = cpu_sample()
    await scanner.stop()

    cpu = 100.0 * (1 - (i1 - i0) / (t1 - t0)) if t1 > t0 else 0.0
    print(f"  mode={mode}  {total} adverts in {secs}s ({total/secs:.0f}/s)  "
          f"system CPU during scan: {cpu:.0f}%")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "active"
    secs = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    try:
        asyncio.run(main(mode, secs))
    except Exception as exc:  # noqa: BLE001
        print(f"  mode={mode}: FAILED - {exc}")
        sys.exit(1)
