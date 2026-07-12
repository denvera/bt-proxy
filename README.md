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
| `--encryption-key` | none | Base64 Noise PSK; also `BT_PROXY_ENCRYPTION_KEY` env var (see [Encryption](#encryption)) |
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

> **Note:** By default this uses the ESPHome Native API **plaintext** variant
> (no encryption). It also supports the Noise-encrypted protocol — see
> [Encryption](#encryption) below, which is the recommended way to run it.

## Encryption

The API supports ESPHome's **Noise** encryption. When a key is set, connections
are encrypted and authenticated, and plaintext connections are refused. When no
key is set, the API is served in plaintext (see the deprecation notice below).

> **Deprecation notice:** Running **without** an encryption key is **deprecated**.
> An unauthenticated proxy lets any device on your network connect, take full
> control of your Bluetooth adapter (read/write arbitrary GATT characteristics on
> nearby devices), and receive a live feed of every BLE advertisement in range.
> Unauthenticated operation becomes **opt-in in 2.0**. This is **opt-in**:
> upgrading alone changes nothing — if you upgrade and set no key you remain
> exposed. **Set a key.**

Generate a key:

```bash
openssl rand -base64 32
```

Supply it to the proxy either via the `--encryption-key` flag or the
`BT_PROXY_ENCRYPTION_KEY` environment variable:

```bash
# Preferred in production: the env var keeps the key out of `ps` output
export BT_PROXY_ENCRYPTION_KEY="<base64 key>"
uv run python -m bt_proxy

# Or via the flag (visible in `ps`, so avoid this on shared/production hosts)
uv run python -m bt_proxy --encryption-key "<base64 key>"
```

> **Prefer the environment variable in production.** A key passed as a CLI flag
> is visible to any local user in `ps` output; an environment variable is not.

Then configure the **same** key in Home Assistant's ESPHome device (or in its
YAML):

```yaml
api:
  encryption:
    key: "<same base64 key>"
```

An invalid or wrong-length key is a fatal error — the proxy will not silently
fall back to plaintext.

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

> This unit runs the app via `uv`. On a **Raspberry Pi Zero (ARMv6)** `uv` has no
> build — use [`deploy/install.sh`](deploy/README.md) instead, which sets up a
> plain venv and its own unit. Both read config from `/etc/bt-proxy/bt-proxy.env`
> (`BT_PROXY_ENCRYPTION_KEY`, `BT_PROXY_NAME`, `BT_PROXY_FRIENDLY_NAME`).

Check status / logs:

```bash
sudo systemctl status bt-proxy
journalctl -u bt-proxy -f
```

## Scanning modes: active vs passive

Home Assistant requests **passive** scanning by default. bt-proxy honours
that when BlueZ supports it, and otherwise falls back to **active** scanning
automatically — so things keep working either way. If passive isn't available
you'll see a one-off warning in the log followed by `falling back to active
scanning`; that's harmless.

Passive is generally the better default. It's lighter-weight on the proxy itself
(the radio only listens, never transmits, which also reduces RF congestion when
several proxies are around), and it can be gentler on some battery sensors:

- **Active** scanning may send a scan request to a *scannable* advertiser,
  prompting it to transmit an extra scan-response packet. **Passive** never asks
  for one.
- For non-connectable beacons (they can't be scan-requested), and for devices the proxy
  stays connected to — once connected, the connection dominates a device's power
  use, not the scan mode. It mainly matters for advertisement-only sensors that
  happen to be scannable.

### Enabling passive scanning

Passive scanning needs BlueZ's experimental features (and **BlueZ ≥ 5.56** with
**Linux kernel ≥ 5.10**, which most current systems already have). Run
`bluetoothd` with `--experimental`.

Rather than editing the packaged unit, drop in an override so updates don't
clobber it. Create `/etc/systemd/system/bluetooth.service.d/experimental.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/libexec/bluetooth/bluetoothd --experimental
```

The empty `ExecStart=` is required to clear the inherited command before
setting the new one. Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

> Match the `bluetoothd` path to your system — some distros use
> `/usr/lib/bluetooth/bluetoothd`. Check with `systemctl cat bluetooth | grep ExecStart`.

Once enabled, the proxy logs `Starting BLE scanner (configured=passive,
mode=passive)` and the active-fallback warning goes away.

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

### Adapter powered off / blocked by rfkill (common on a fresh install)

If the proxy logs `the Bluetooth adapter is powered off or blocked` /
`No powered Bluetooth adapters found ... POWERED_OFF`, the adapter simply isn't
powered — it's **not** a wedged controller. On a fresh Raspberry Pi OS install
the onboard Bluetooth is often **soft-blocked by rfkill**. Unblock it **on the
host**:

```bash
sudo rfkill unblock bluetooth
sudo hciconfig hci0 up          # only if it's still down afterwards
```

This is a host-level fix — even a `--privileged` container can't power on an
rfkill-blocked host adapter. The proxy detects this case and keeps retrying
(every 60s), so once you unblock it the scanner starts on its own without a
restart.

> `rfkill` may not be installed by default (`sudo apt install rfkill`). The
> unblock is saved across reboots (via `systemd-rfkill`), so it's usually a
> one-time fix.

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
