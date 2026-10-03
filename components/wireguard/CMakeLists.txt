idf_component_register(
    SRCS "src/crypto.c" "src/wireguard.c" "src/wireguardif.c"
         "src/wireguard-platform.c" "src/crypto/refc/blake2s.c"
         "src/crypto/refc/chacha20.c" "src/crypto/refc/chacha20poly1305.c"
         "src/crypto/refc/poly1305-donna.c" "src/crypto/refc/x25519.c"
    INCLUDE_DIRS "src" "include"
    REQUIRES esp_netif lwip mbedtls esp_timer)
set_source_files_properties(src/crypto/refc/x25519.c PROPERTIES
    COMPILE_FLAGS "-Wno-error=stringop-overread")

