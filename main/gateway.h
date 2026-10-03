#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_netif.h"
#include "cJSON.h"

#define CONFIG_VERSION 2
typedef struct {
    uint32_t version;
    char mode[8];
    char ssid[33], wifi_password[65];
    char admin_password[65];
    bool enabled;
    char private_key[45], public_key[45], preshared_key[45];
    char address[16], remote_cidr[19], endpoint[254];
    uint16_t port, keepalive, mtu;
    char admin_user[33], ap_ssid[33], ap_password[65], lan_cidr[19];
    uint16_t ap_timeout;
} gateway_config_t;

typedef struct {
    char uplink[12], ip[16], lan[19], state[192];
    bool ethernet, wifi, tunnel, clock_ready, ap;
    int rssi;
    uint32_t rx_bytes, tx_bytes, dropped, last_rx_age;
    uint16_t ap_remaining;
    uint8_t ap_clients;
} gateway_status_t;

extern gateway_config_t config;
extern char setup_ssid[33];
extern esp_netif_t *eth_netif, *sta_netif, *ap_netif;
esp_err_t settings_load(void);
esp_err_t settings_save(const gateway_config_t *value);
bool settings_parse(const cJSON *json, gateway_config_t *out, char *error, size_t size);
bool parse_cidr(const char *s, uint32_t *ip, uint32_t *mask, unsigned *prefix);
void network_start(void);
esp_netif_t *network_select(esp_netif_ip_info_t *info);
void network_ap_tick(bool ready);
uint16_t network_ap_remaining(void);
uint8_t network_ap_clients(void);
void tunnel_tick(esp_netif_t *uplink, const esp_netif_ip_info_t *ip, gateway_status_t *status);
void status_get(gateway_status_t *out);
void web_start(void);
void request_restart(void);
void scan_init(void);
bool lan_scan_start(void);
void scan_add_json(cJSON *object);
