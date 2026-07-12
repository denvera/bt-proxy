#!/usr/bin/env bash
#
# Install bt-proxy as a systemd service on Raspberry Pi OS (Bookworm or Trixie).
#
# Designed for a headless Raspberry Pi Zero / Zero W (ARMv6): it uses a plain
# Python venv and prefers piwheels (the default index on Raspberry Pi OS) for
# prebuilt ARM wheels. Packages without a matching wheel (e.g. zeroconf on a
# newer Python) still compile from source, which on a Pi Zero can take tens of
# minutes. No Docker, no uv.
#
# Usage (on the Pi, after SSHing in):
#   git clone https://github.com/denvera/bt-proxy /opt/bt-proxy
#   sudo /opt/bt-proxy/deploy/install.sh
#
# Optional Noise encryption: pass a base64 32-byte key and it is written to
# the service's env file (never appears in `ps` or the unit):
#   sudo BT_PROXY_ENCRYPTION_KEY="$(openssl rand -base64 32)" /opt/bt-proxy/deploy/install.sh
#
set -euo pipefail

TARGET=/opt/bt-proxy
ENV_DIR=/etc/bt-proxy
ENV_FILE="${ENV_DIR}/bt-proxy.env"

if [ "$(id -u)" -ne 0 ]; then
    echo "This installer must run as root (use: sudo $0)" >&2
    exit 1
fi

# Resolve the repo this script was launched from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "==> Installing system packages (bluez, python venv)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends bluez python3-venv python3-pip

echo "==> Ensuring the Bluetooth stack is enabled"
systemctl enable --now bluetooth
# A fresh install often has the adapter soft-blocked (rfkill) or powered down.
rfkill unblock bluetooth 2>/dev/null || true
bluetoothctl power on 2>/dev/null || true

# Passive BLE scanning needs bluetoothd started with --experimental (BlueZ
# AdvertisementMonitor). Without it, a proxy asked for passive scanning by Home
# Assistant silently falls back to ACTIVE scanning, which on a Pi Zero W means
# ~5x the advertisements and ~2x the CPU (the shared WiFi/BT antenna also makes
# active scanning peg NetworkManager). This one flag is the single biggest CPU
# win on constrained hardware.
echo "==> Enabling BlueZ --experimental (required for passive scanning)"
BLUETOOTHD=$(systemctl show bluetooth -p ExecStart --value | grep -oE '/[^ ]*bluetoothd' | head -1)
if [ -n "$BLUETOOTHD" ]; then
    mkdir -p /etc/systemd/system/bluetooth.service.d
    printf '[Service]\nExecStart=\nExecStart=%s --experimental\n' "$BLUETOOTHD" \
        > /etc/systemd/system/bluetooth.service.d/experimental.conf
    systemctl daemon-reload
    systemctl restart bluetooth
fi

# mpris-proxy bridges Bluetooth media (AVRCP/MPRIS) to D-Bus. It is useless on a
# headless BLE proxy and gets woken by every advertisement, wasting CPU. Disable
# it globally so it does not start for any session.
systemctl --global disable mpris-proxy.service 2>/dev/null || true

# Place the code at a stable path so the unit file's paths are predictable.
if [ "$REPO_DIR" != "$TARGET" ]; then
    echo "==> Copying $REPO_DIR -> $TARGET"
    mkdir -p "$TARGET"
    # Copy the source, but never the caller's venv/VCS/test caches.
    tar -C "$REPO_DIR" --exclude=.venv --exclude=.git --exclude=__pycache__ \
        --exclude='.pytest_cache' -cf - . | tar -C "$TARGET" -xf -
fi

echo "==> Building venv and installing bt-proxy"
echo "    Any package without a prebuilt wheel compiles from source -- on a Pi"
echo "    Zero this can take tens of minutes (zeroconf especially). Grab a coffee."
python3 -m venv "$TARGET/.venv"
"$TARGET/.venv/bin/pip" install --upgrade pip
# On Raspberry Pi OS /etc/pip.conf already points at piwheels; add it explicitly
# so this also works on a vanilla Debian image.
"$TARGET/.venv/bin/pip" install \
    --extra-index-url https://www.piwheels.org/simple \
    "$TARGET"

echo "==> Writing service env file (if absent): $ENV_FILE"
mkdir -p "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
    umask 077  # may hold a secret key; keep it root-only
    cat > "$ENV_FILE" <<EOF
# bt-proxy runtime configuration.
#
# Enable Noise encryption (recommended). Generate a key with:
#   openssl rand -base64 32
# and set the identical key under Home Assistant's api: encryption: key:.
# Leaving this unset keeps the proxy unauthenticated (deprecated).
${BT_PROXY_ENCRYPTION_KEY:+BT_PROXY_ENCRYPTION_KEY=${BT_PROXY_ENCRYPTION_KEY}}

# Device name and friendly name shown in Home Assistant. Set them here (each as
# its own variable) rather than as command-line args -- a friendly name with
# spaces cannot survive systemd's word-splitting of an argument string.
# BT_PROXY_NAME=living-room-proxy
# BT_PROXY_FRIENDLY_NAME=Living Room Proxy
EOF
    chmod 600 "$ENV_FILE"
elif [ -n "${BT_PROXY_ENCRYPTION_KEY:-}" ]; then
    echo "    $ENV_FILE already exists; leaving it untouched."
    echo "    (Edit it by hand to change the encryption key.)"
fi

echo "==> Installing and starting the systemd service"
install -m 644 "$TARGET/deploy/bt-proxy.service" /etc/systemd/system/bt-proxy.service
systemctl daemon-reload
systemctl enable --now bt-proxy.service

echo
echo "==> Done. Status:"
systemctl --no-pager --full status bt-proxy.service | head -n 12 || true
echo
echo "The proxy advertises itself over mDNS as an ESPHome device."
echo "In Home Assistant it should appear under Settings -> Devices & Services"
echo "as a discovered ESPHome integration within a minute or two."
if [ -n "${BT_PROXY_ENCRYPTION_KEY:-}" ]; then
    echo "When adding it, enter the SAME base64 key you passed to this installer."
fi
