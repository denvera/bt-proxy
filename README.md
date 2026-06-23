# bt-proxy

ESPHome-compatible Bluetooth Proxy for Raspberry Pi.

This implements the ESPHome [Bluetooth Proxy](https://esphome.io/components/bluetooth_proxy/) functionality in Python, allowing a Raspberry Pi to act as a BLE proxy for Home Assistant. It speaks the ESPHome Native API protocol so Home Assistant discovers and uses it exactly like an ESP32-based Bluetooth proxy.

WARNING: This project was coded largely with the assistance of an LLM. It works for me, but your mileage may vary.

## Features

- **BLE scanning** — passive and active scan modes, raw advertisement forwarding
- **Active connections** — GATT connect/disconnect, service discovery, read/write characteristics and descriptors, notifications
- **mDNS discovery** — automatically advertised so Home Assistant finds it
- **ESPHome Native API** — wire-compatible with `aioesphomeapi` / Home Assistant ESPHome integration

## Requirements

- Raspberry Pi (or any Linux machine) with a Bluetooth adapter
- [uv](https://docs.astral.sh/uv/) package manager
- BlueZ (installed by default on Raspberry Pi OS)

## Installation

```bash
git clone https://github.com/denvera/bt-proxy.git /opt/bt-proxy
cd /opt/bt-proxy
uv sync
```

## Usage

```bash
uv run python -m bt_proxy
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | `bt-proxy` | Device name (used in mDNS and API) |
| `--friendly-name` | `Bluetooth Proxy` | Human-readable name |
| `--port` | `6053` | API server TCP port |
| `--max-connections` | `3` | Max concurrent BLE GATT connections |
| `--adapter` | system default | Bluetooth adapter (e.g. `hci0`) |
| `--log-level` | `INFO` | Logging verbosity |

### Example

```bash
uv run python -m bt_proxy --name living-room-proxy --friendly-name "Living Room BT Proxy" --log-level DEBUG
```

## How It Works

1. Starts a BLE scanner using [bleak](https://github.com/hbldh/bleak)
2. Advertises itself via mDNS as `_esphomelib._tcp.local.`
3. Listens on TCP port 6053 for ESPHome Native API connections
4. When Home Assistant connects, it forwards BLE advertisements and handles GATT operations

> **Note:** This uses the ESPHome Native API **plaintext** variant (no encryption). The Noise-encrypted protocol is currently not supported.

## Running with Docker

Pre-built images are available for `amd64`, `arm64`, and `arm/v7` (Raspberry Pi 2+):

```bash
docker run -d \
  --name bt-proxy \
  --restart unless-stopped \
  --net=host \
  --privileged \
  -v /var/run/dbus:/var/run/dbus \
  ghcr.io/denvera/bt-proxy
```

Pass any CLI options after the image name:

```bash
docker run -d \
  --name bt-proxy \
  --restart unless-stopped \
  --net=host \
  --privileged \
  -v /var/run/dbus:/var/run/dbus \
  ghcr.io/denvera/bt-proxy \
  --name living-room-proxy --friendly-name "Living Room BT Proxy" --log-level DEBUG
```

> `--net=host` is required for mDNS discovery. `--privileged` grants access to the Bluetooth adapter — alternatively use `--cap-add=NET_ADMIN --cap-add=NET_RAW` with explicit device mounts.

## Running as a Service

Copy the unit file and enable it:

```bash
sudo cp bt-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bt-proxy
```

Check status / logs:

```bash
sudo systemctl status bt-proxy
journalctl -u bt-proxy -f
```

## Reliability on Raspberry Pi

Undervolting or brownout/undervoltage conditions on Pi's produce exactly the 
symptoms that look like flaky bluetooth, often manifested as HCI command timeouts (`dmesg`: `hci0: Opcode 0x200c failed`,
`tx timeout`), `Frame reassembly failed`, dropped connections, even an unresponsive `bluetoothd`.

**Before blaming bluetooth, check power:**

```bash
vcgencmd get_throttled      # want 0x0 (or at most 0x50000 = a brief boot-time
                            # dip); a non-zero bit 0 means under-voltage NOW
```

Use a proper **5.1 V / ≥2.5 A** supply and a short, thick cable. Undervoltage
under load (`0x...1` / `0x...5`) is the most common cause of "random" BT
failures on a Pi.

The proxy also **backs off** instead of hammering the adapter when connections
keep failing, which both protects a flaky controller and keeps the logs
readable.

### When bluetooth appears unresponsive

Two distinct failures can occur on the onboard radio, with different fixes:

- **Controller unresponsive** — `dmesg` shows `hci0: Opcode 0x200c failed: -110/-16`.
  Restarting `bluetoothd` is *not* enough; reset the adapter:
  ```bash
  sudo hciconfig hci0 reset    # or: down && up, or reboot
  ```
- **Daemon unresponsive** — the proxy logs that it looks like *"bluetoothd is wedged
  (phantom connection / no D-Bus reply)"*. Here the **daemon** needs a restart
  (an adapter reset alone won't fix it, and neither will restarting bt-proxy):
  ```bash
  sudo systemctl restart bluetooth
  ```

bt-proxy tries to detect these conditions, log a recovery hint, and back off so it
recovers once the underlying issue clears — but it wont 
reset the adapter or restart `bluetoothd` itself (those are host-level actions).

### Optional: auto-recover an unresponsive `bluetoothd` (watchdog)

If you want an automatic, albeit somewhat primitive  recovery from the unresponsive daemon
 case, add a small systemd watchdog on the **host** that restarts `bluetooth` when the proxy reports it's
frozen. For example, a timer that restarts the daemon when the marker shows up
in the proxy's logs:

```ini
# /etc/systemd/system/bt-proxy-watchdog.service
[Unit]
Description=Restart bluetoothd if unresponsive

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'journalctl -u bt-proxy --since "-3min" | grep -q "bluetoothd is wedged" && systemctl restart bluetooth || true'
```

```ini
# /etc/systemd/system/bt-proxy-watchdog.timer
[Unit]
Description=Periodically check whether bluetoothd needs restarting

[Timer]
OnUnitActiveSec=2min
AccuracySec=30s

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bt-proxy-watchdog.timer
```

> Adjust the `journalctl -u` unit name (and add `-t`/container filters) to match
> how you run the proxy. Under Docker, point it at the container logs instead,
> e.g. `docker logs --since 3m bt-proxy 2>&1 | grep -q ...`.

## Architecture

```
bt_proxy/
├── __init__.py        # Package init
├── __main__.py        # Entry point, CLI, mDNS registration
├── proto.py           # Protobuf encoding/decoding, message IDs, wire protocol
├── ble_manager.py     # BLE scanning and GATT connections (bleak)
└── api_server.py      # ESPHome Native API TCP server
```
