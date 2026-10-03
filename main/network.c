#include "gateway.h"
#include <string.h>
#include <stdio.h>
#include "driver/gpio.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

esp_netif_t *eth_netif, *sta_netif, *ap_netif;
char setup_ssid[33];
static bool ap_active = true;
static bool ap_latched_off;
static int64_t no_clients_since;
static uint16_t ap_remaining;
static uint8_t ap_clients;

static void event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED) && config.ssid[0] && strcmp(config.mode, "eth")) esp_wifi_connect();
}

void network_start(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    sta_netif = esp_netif_create_default_wifi_sta();
    ap_netif = esp_netif_create_default_wifi_ap();
    wifi_init_config_t wifi_init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, NULL));
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(setup_ssid, sizeof(setup_ssid), "WT32-Link-%02X%02X%02X", mac[3], mac[4], mac[5]);
    if (config.ap_ssid[0]) strlcpy(setup_ssid, config.ap_ssid, sizeof(setup_ssid));
    wifi_config_t ap = {0};
    strlcpy((char *)ap.ap.ssid, setup_ssid, sizeof(ap.ap.ssid));
    strlcpy((char *)ap.ap.password, config.ap_password, sizeof(ap.ap.password));
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap.ap.max_connection = 3;
    ap.ap.channel = 1;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    wifi_config_t sta = {0};
    memcpy(sta.sta.ssid, config.ssid, strlen(config.ssid));
    memcpy(sta.sta.password, config.wifi_password, strlen(config.wifi_password));
    sta.sta.pmf_cfg.capable = true;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
    ESP_ERROR_CHECK(esp_netif_set_hostname(sta_netif, "wt32-link"));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    // WT32-ETH01 LAN8720: external 50 MHz clock on GPIO0, power/enable GPIO16.
    gpio_config_t power = { .pin_bit_mask = 1ULL << 16, .mode = GPIO_MODE_OUTPUT };
    ESP_ERROR_CHECK(gpio_config(&power));
    gpio_set_level(16, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac.smi_gpio.mdc_num = 23;
    emac.smi_gpio.mdio_num = 18;
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = 1;
    phy_config.reset_gpio_num = -1;
    esp_eth_mac_t *eth_mac = esp_eth_mac_new_esp32(&emac, &mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(eth_mac, phy);
    esp_eth_handle_t handle;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &handle));
    esp_netif_config_t netif_config = ESP_NETIF_DEFAULT_ETH();
    eth_netif = esp_netif_new(&netif_config);
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(handle)));
    ESP_ERROR_CHECK(esp_netif_set_hostname(eth_netif, "wt32-link"));
    ESP_ERROR_CHECK(esp_eth_start(handle));
}

static bool usable(esp_netif_t *n, esp_netif_ip_info_t *info) {
    return n && esp_netif_is_netif_up(n) && esp_netif_get_ip_info(n, info) == ESP_OK && info->ip.addr != 0;
}

esp_netif_t *network_select(esp_netif_ip_info_t *info) {
    if (strcmp(config.mode, "wifi") && usable(eth_netif, info)) return eth_netif;
    if (strcmp(config.mode, "eth") && usable(sta_netif, info)) return sta_netif;
    memset(info, 0, sizeof(*info));
    return NULL;
}

void network_ap_tick(bool ready) {
    (void)ready;
    if (!ap_active || ap_latched_off) return;
    int64_t now = esp_timer_get_time();
    wifi_sta_list_t clients = {0};
    if (esp_wifi_ap_get_sta_list(&clients) != ESP_OK) return;
    ap_clients = clients.num;
    if (clients.num) {
        no_clients_since = 0;
        ap_remaining = config.ap_timeout;
        return;
    }
    if (!no_clients_since) no_clients_since = now;
    int64_t left = (int64_t)config.ap_timeout * 1000000LL - (now - no_clients_since);
    ap_remaining = left > 0 ? (uint16_t)((left + 999999LL) / 1000000LL) : 0;
    if (left <= 0 && esp_wifi_set_mode(WIFI_MODE_STA) == ESP_OK) {
        ap_active = false;
        ap_latched_off = true;
    }
}

uint16_t network_ap_remaining(void) { return ap_remaining; }
uint8_t network_ap_clients(void) { return ap_clients; }
