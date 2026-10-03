# Vendored WireGuard component

Source: https://github.com/trombik/esp_wireguard
Commit: `9217c5be0836e908005301ad2c2d42009e560c0e`.
The original BSD license and copyright headers are retained.

Local changes:

- Build the low-level driver directly; do not use the ESP-NETIF wrapper which
  assumes Wi-Fi and does not provide the gateway lifecycle needed here.
- Use `wireguardif_init_data.bind_netif` for both UDP binding and transport.
- Check decrypted **source** IPv4 addresses against the peer's AllowedIPs.
  Upstream checked the destination, preventing VPN-to-LAN routing and weakening
  source validation.
- Require a complete IPv4 header, strip authenticated padding, and deliver via
  `netif->input` so the gateway can enforce LAN-only destinations.
- Expose public-key derivation for the server configuration displayed in the UI.
- Do not report an expired previous/current session key as a connected peer.
- Include the ESP-IDF 5 random-number header explicitly.

ESP-IDF must keep its own metadata in netif client data rather than `netif->state`.
`CONFIG_ESP_NETIF_BRIDGE_EN=y` enables this SDK facility; it does not make this
firmware an Ethernet layer-2 bridge. A compile-time guard in `main/tunnel.c`
prevents building with an incompatible layout.
