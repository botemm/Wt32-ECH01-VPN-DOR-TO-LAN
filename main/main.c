#include "gateway.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_netif_sntp.h"
#include "nvs_flash.h"
#include "wireguard-platform.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static SemaphoreHandle_t status_lock;
static gateway_status_t shared_status;
static int64_t restart_at;

void status_get(gateway_status_t *out) {
    xSemaphoreTake(status_lock, portMAX_DELAY);
    *out = shared_status;
    xSemaphoreGive(status_lock);
}

void request_restart(void) {
    xSemaphoreTake(status_lock, portMAX_DELAY);
    restart_at = esp_timer_get_time() + 2000000;
    xSemaphoreGive(status_lock);
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(settings_load());
    status_lock = xSemaphoreCreateMutex();
    assert(status_lock);
    network_start();
    ESP_ERROR_CHECK(wireguard_platform_init());
    esp_sntp_config_t time_config = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(2, ESP_SNTP_SERVER_LIST("pool.ntp.org", "time.cloudflare.com"));
    time_config.start = false;
    ESP_ERROR_CHECK(esp_netif_sntp_init(&time_config));
    bool time_started = false;
    web_start();
    printf("\nWT32 LINK — setup\nWi-Fi: %s\nURL: http://192.168.4.1\nWi-Fi password: %s\nAdmin user: %s\nAdmin password: %s\n\n", setup_ssid, config.ap_password, config.admin_user, config.admin_password);
    for (;;) {
        gateway_status_t s = {0};
        esp_netif_ip_info_t ip, eth_ip, sta_ip;
        esp_netif_t *uplink = network_select(&ip);
        if (uplink && !time_started) {
            esp_netif_set_default_netif(uplink);
            ESP_ERROR_CHECK(esp_netif_sntp_start());
            time_started = true;
        }
        s.ethernet = esp_netif_is_netif_up(eth_netif) && esp_netif_get_ip_info(eth_netif, &eth_ip) == ESP_OK && eth_ip.ip.addr;
        s.wifi = esp_netif_is_netif_up(sta_netif) && esp_netif_get_ip_info(sta_netif, &sta_ip) == ESP_OK && sta_ip.ip.addr;
        wifi_ap_record_t record;
        if (esp_wifi_sta_get_ap_info(&record) == ESP_OK) s.rssi = record.rssi;
        strlcpy(s.uplink, uplink == eth_netif ? "Ethernet" : uplink == sta_netif ? "Wi-Fi" : "Offline", sizeof(s.uplink));
        if (uplink) {
            snprintf(s.ip, sizeof(s.ip), IPSTR, IP2STR(&ip.ip));
            esp_ip4_addr_t net = {.addr = ip.ip.addr & ip.netmask.addr};
            unsigned prefix = __builtin_popcount(ip.netmask.addr);
            snprintf(s.lan, sizeof(s.lan), IPSTR "/%u", IP2STR(&net), prefix);
        }
        tunnel_tick(uplink, &ip, &s);
        network_ap_tick(uplink != NULL);
        wifi_mode_t mode;
        esp_wifi_get_mode(&mode);
        s.ap = mode == WIFI_MODE_APSTA;
        s.ap_remaining = network_ap_remaining();
        s.ap_clients = network_ap_clients();
        xSemaphoreTake(status_lock, portMAX_DELAY);
        shared_status = s;
        bool restart = restart_at && esp_timer_get_time() >= restart_at;
        xSemaphoreGive(status_lock);
        if (restart) esp_restart();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
