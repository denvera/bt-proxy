"""ESPHome Bluetooth Proxy implementation for Raspberry Pi."""

__version__ = "0.1.0"

# ESPHome firmware version reported to Home Assistant (in DeviceInfoResponse
# and the mDNS TXT record). HA shows a repair/warning if a bluetooth proxy
# reports an ESPHome version older than its required minimum, so keep this at
# or above that floor.
EMULATED_ESPHOME_VERSION = "2026.6.0"
