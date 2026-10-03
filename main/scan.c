#include "gateway.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "lwip/etharp.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#define MAX_SCAN_HOSTS 254

typedef struct { char ip[16], mac[18]; } scan_host_t;
static SemaphoreHandle_t scan_lock;
static scan_host_t hosts[MAX_SCAN_HOSTS];
static unsigned count, progress, total;
static bool running;
static char error_text[96];

void scan_init(void) { scan_lock = xSemaphoreCreateMutex(); assert(scan_lock); }

static void scan_task(void *arg) {
    (void)arg;
    esp_netif_ip_info_t info;
    esp_netif_t *uplink = network_select(&info);
    char name[8];
    if (!uplink || esp_netif_get_netif_impl_name(uplink, name) != ESP_OK) goto offline;
    uint32_t mask = ntohl(info.netmask.addr), network = ntohl(info.ip.addr) & mask;
    unsigned host_total = ~mask - 1;
    if (host_total > MAX_SCAN_HOSTS) {
        xSemaphoreTake(scan_lock, portMAX_DELAY);
        strcpy(error_text, "Сканування підтримує підмережі до /24.");
        running = false;
        xSemaphoreGive(scan_lock);
        vTaskDelete(NULL);
    }
    xSemaphoreTake(scan_lock, portMAX_DELAY);
    total = host_total;
    xSemaphoreGive(scan_lock);
    for (unsigned i = 1; i <= host_total; i++) {
        ip4_addr_t target = { .addr = htonl(network + i) };
        if (target.addr == info.ip.addr) continue;
        struct netif *physical;
        bool usable;
        LOCK_TCPIP_CORE();
        physical = netif_find(name);
        usable = physical && netif_is_up(physical) && netif_is_link_up(physical);
        if (usable) etharp_request(physical, &target);
        UNLOCK_TCPIP_CORE();
        if (!usable) goto offline;
        vTaskDelay(pdMS_TO_TICKS(80));
        struct eth_addr *mac = NULL;
        const ip4_addr_t *cached = NULL;
        uint8_t bytes[6];
        bool found;
        LOCK_TCPIP_CORE();
        found = etharp_find_addr(physical, &target, &mac, &cached) >= 0 && mac != NULL;
        if (found) memcpy(bytes, mac->addr, sizeof(bytes));
        UNLOCK_TCPIP_CORE();
        xSemaphoreTake(scan_lock, portMAX_DELAY);
        progress = i;
        if (found && count < MAX_SCAN_HOSTS) {
            snprintf(hosts[count].ip, sizeof(hosts[count].ip), IPSTR, IP2STR(&target));
            snprintf(hosts[count].mac, sizeof(hosts[count].mac), "%02X:%02X:%02X:%02X:%02X:%02X", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
            count++;
        }
        xSemaphoreGive(scan_lock);
    }
    xSemaphoreTake(scan_lock, portMAX_DELAY);
    running = false;
    xSemaphoreGive(scan_lock);
    vTaskDelete(NULL);
offline:
    xSemaphoreTake(scan_lock, portMAX_DELAY);
    strcpy(error_text, "Підключіть WT32 до LAN перед скануванням.");
    running = false;
    xSemaphoreGive(scan_lock);
    vTaskDelete(NULL);
}

bool lan_scan_start(void) {
    xSemaphoreTake(scan_lock, portMAX_DELAY);
    if (running) { xSemaphoreGive(scan_lock); return false; }
    count = progress = total = 0;
    error_text[0] = 0;
    running = true;
    xSemaphoreGive(scan_lock);
    if (xTaskCreate(scan_task, "lan_scan", 4096, NULL, 3, NULL) == pdPASS) return true;
    xSemaphoreTake(scan_lock, portMAX_DELAY);
    running = false;
    strcpy(error_text, "Не вдалося запустити сканування.");
    xSemaphoreGive(scan_lock);
    return false;
}

void scan_add_json(cJSON *object) {
    xSemaphoreTake(scan_lock, portMAX_DELAY);
    cJSON_AddBoolToObject(object, "running", running);
    cJSON_AddNumberToObject(object, "progress", progress);
    cJSON_AddNumberToObject(object, "total", total);
    cJSON_AddStringToObject(object, "error", error_text);
    cJSON *array = cJSON_AddArrayToObject(object, "hosts");
    for (unsigned i = 0; i < count; i++) {
        cJSON *host = cJSON_CreateObject();
        cJSON_AddStringToObject(host, "ip", hosts[i].ip);
        cJSON_AddStringToObject(host, "mac", hosts[i].mac);
        cJSON_AddItemToArray(array, host);
    }
    xSemaphoreGive(scan_lock);
}
