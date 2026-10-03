idf_component_register(SRCS "main.c" "settings.c" "network.c" "tunnel.c" "web.c" "scan.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_eth esp_netif esp_http_server nvs_flash json
             lwip mbedtls wireguard esp_timer driver bootloader_support
    EMBED_FILES "web/index.html" "web/style.css" "web/app.js")
idf_component_get_property(lwip_lib lwip COMPONENT_LIB)
target_include_directories(${lwip_lib} PRIVATE "${CMAKE_CURRENT_LIST_DIR}")
target_compile_definitions(${lwip_lib} PRIVATE ESP_IDF_LWIP_HOOK_FILENAME="gateway_hooks.h")
