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
git clone https://github.com/yourusername/bt-proxy.git /opt/bt-proxy
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

## Architecture

```
bt_proxy/
├── __init__.py        # Package init
├── __main__.py        # Entry point, CLI, mDNS registration
├── proto.py           # Protobuf encoding/decoding, message IDs, wire protocol
├── ble_manager.py     # BLE scanning and GATT connections (bleak)
└── api_server.py      # ESPHome Native API TCP server
```
