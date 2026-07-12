# Deploy to a Raspberry Pi Zero W

A direct guide to run bt-proxy on a Raspberry Pi Zero W (or Zero 2 W) and have it
auto-discovered by Home Assistant. No Docker.

**Needs:** a Pi Zero **W** (onboard Bluetooth + Wi-Fi — a non-W Zero has neither),
an SD card, and Home Assistant on the same LAN.

## 1. Flash the card

Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/):

- **OS:** Raspberry Pi OS Lite (32-bit).
- Click the gear / **Edit Settings** (Ctrl+Shift+X) before writing:
  - **Hostname:** `bt-proxy`
  - **Enable SSH** → *Allow public-key authentication*, paste your public key.
  - **Wi-Fi:** SSID, password, and your **Wi-Fi country** (required, or the radio stays off).
  - **Locale/timezone.**
- Write the card, put it in the Pi, power on. Give it ~1 minute to join Wi-Fi.

## 2. SSH in and install

```bash
ssh <you>@bt-proxy.local

sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/denvera/bt-proxy.git /opt/bt-proxy
sudo /opt/bt-proxy/deploy/install.sh
```

The installer sets up a Python venv, installs the `bt-proxy` systemd service, and
starts it. On a Pi Zero this can take tens of minutes (some dependencies compile
from source).

## 3. (Recommended) Turn on encryption

Generate a key and reinstall with it — or add it later by editing
`/etc/bt-proxy/bt-proxy.env` and running `sudo systemctl restart bt-proxy`:

```bash
openssl rand -base64 32          # copy this
sudo BT_PROXY_ENCRYPTION_KEY="<that key>" /opt/bt-proxy/deploy/install.sh
```

Use the **same** key in Home Assistant when you adopt the device. Without a key the
proxy still works but runs unauthenticated (deprecated).

## 4. Adopt in Home Assistant

Within a minute or two it appears under **Settings → Devices & Services** as a
discovered **ESPHome** device (it advertises itself over mDNS). Click **Add**; enter
the encryption key if you set one.

## Check / troubleshoot

```bash
systemctl status bt-proxy          # is it running?
journalctl -u bt-proxy -f          # live logs
bluetoothctl show                  # is the BT adapter up?
```

To update later: `cd /opt/bt-proxy && sudo git pull && sudo ./deploy/install.sh`.

## Performance on a Pi Zero W

A Pi Zero W (single ARMv6 core, shared WiFi/BT antenna) is marginal for BLE
proxying. The single most important thing is **passive scanning**, which the
installer enables by putting `bluetoothd` into `--experimental` mode. Without
it, when Home Assistant requests passive scanning the proxy silently falls back
to **active** scanning — roughly 5x the advertisements and 2x the CPU, and the
extra radio activity pegs NetworkManager via antenna coexistence. Confirm the
proxy is passive:

```bash
journalctl -u bt-proxy | grep "Starting BLE scanner" | tail -1
# want: configured=passive, mode=passive   (not "falling back to active")
```

The installer also disables `mpris-proxy` (a Bluetooth media bridge that wastes
CPU on a headless proxy). Even so, a busy RF environment can still load the core
heavily — if it stays pegged, the realistic fix is a Pi Zero 2 W / Pi 3+ or a
dedicated ESP32 running ESPHome, not more tuning.
