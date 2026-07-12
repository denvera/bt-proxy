#!/usr/bin/env python3
"""Measure the local BLE advertisement rate and how much of it is duplicate
payload -- i.e. how much an advertisement dedup/coalesce step could actually
save on this specific radio environment.

Run on the Pi with the proxy STOPPED (so they don't fight over the adapter):

    sudo systemctl stop bt-proxy
    /opt/bt-proxy/.venv/bin/python /opt/bt-proxy/measure_adverts.py [seconds]
    sudo systemctl start bt-proxy
"""
from __future__ import annotations

import asyncio
import collections
import sys

from bleak import BleakScanner


def content_key(adv) -> tuple:
    """A hashable fingerprint of an advertisement's PAYLOAD, excluding RSSI.

    Two adverts from the same device with the same content_key carry no new
    information -- exactly what a dedup step would drop.
    """
    return (
        adv.local_name,
        tuple(sorted((k, bytes(v)) for k, v in adv.manufacturer_data.items())),
        tuple(sorted((k, bytes(v)) for k, v in adv.service_data.items())),
        tuple(sorted(adv.service_uuids)),
    )


async def main(secs: int) -> None:
    per_device: collections.Counter = collections.Counter()
    total = 0
    duplicates = 0
    last_key: dict = {}

    def cb(device, adv) -> None:
        nonlocal total, duplicates
        total += 1
        addr = device.address
        per_device[addr] += 1
        key = content_key(adv)
        if last_key.get(addr) == key:
            duplicates += 1
        last_key[addr] = key

    scanner = BleakScanner(detection_callback=cb)
    print(f"Scanning for {secs}s (active scan) ...")
    await scanner.start()
    try:
        await asyncio.sleep(secs)
    finally:
        await scanner.stop()

    devices = len(per_device)
    rate = total / secs if secs else 0
    dup_pct = (100 * duplicates / total) if total else 0

    print()
    print(f"  {total} advertisements from {devices} devices in {secs}s")
    print(f"  rate:    {rate:.0f} adverts/sec")
    if devices:
        print(f"  average: {total / devices:.1f} adverts per device")
    if total:
        print(
            f"  identical-payload repeats: {duplicates} ({dup_pct:.0f}%)"
            "  <- a dedup step would drop about this share"
        )
    print()
    print("  chattiest devices:")
    for addr, n in per_device.most_common(5):
        print(f"    {addr}  {n} adverts")
    print()

    if not total:
        print("  Verdict: no advertisements seen -- is the adapter up and the")
        print("           proxy stopped? (bluetoothctl show)")
        return
    if rate < 20:
        print("  Verdict: LOW rate. Advert volume is probably not your CPU")
        print("           problem, and dedup would buy little.")
    elif dup_pct >= 50:
        print("  Verdict: HIGH rate AND mostly duplicate payloads -- dedup is")
        print("           worth doing; it would cut a large share of the work.")
    else:
        print("  Verdict: HIGH rate but payloads mostly change -- dedup helps")
        print("           less here; passive scanning is the bigger lever.")


if __name__ == "__main__":
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    try:
        asyncio.run(main(seconds))
    except Exception as exc:  # noqa: BLE001 - operator-facing diagnostic
        print(f"Error: {exc}")
        print("If this is a BlueZ/adapter error: stop the proxy first")
        print("(sudo systemctl stop bt-proxy) and check 'bluetoothctl show'.")
        sys.exit(1)
