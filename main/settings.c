#include "gateway.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "nvs.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "mbedtls/base64.h"

gateway_config_t config;

// Version 1 is a prefix of version 2. Keep its exact layout for NVS migration.
typedef struct {
    uint32_t version;
    char mode[8];
    char ssid[33], wifi_password[65];
    char admin_password[65];
    bool enabled;
    char private_key[45], public_key[45], preshared_key[45];
    char address[16], remote_cidr[19], endpoint[254];
    uint16_t port, keepalive, mtu;
} gateway_config_v1_t;

bool parse_cidr(const char *s, uint32_t *ip, uint32_t *mask, unsigned *prefix) {
    char buf[20];
    if (!s || strlen(s) >= sizeof(buf)) return false;
    strcpy(buf, s);
    char *slash = strchr(buf, '/'), *end;
    if (!slash || !slash[1]) return false;
    *slash++ = 0;
    if (!isdigit((unsigned char)*slash)) return false;
    unsigned long bits = strtoul(slash, &end, 10);
    struct in_addr addr;
    if (*end || bits > 32 || inet_pton(AF_INET, buf, &addr) != 1) return false;
    *ip = addr.s_addr;
    *mask = htonl(bits ? 0xffffffffu << (32 - bits) : 0);
    *prefix = bits;
    return true;
}

esp_err_t settings_save(const gateway_config_t *value) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("gateway", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(nvs, "config", value, sizeof(*value));
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t settings_load(void) {
    memset(&config, 0, sizeof(config));
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("gateway", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    size_t len = sizeof(config);
    err = nvs_get_blob(nvs, "config", &config, &len);
    nvs_close(nvs);
    if (err == ESP_OK && len == sizeof(config) && config.version == CONFIG_VERSION) return ESP_OK;
    if (err == ESP_OK && len == sizeof(gateway_config_v1_t) && config.version == 1) {
        config.version = CONFIG_VERSION;
        strcpy(config.admin_user, "admin");
        strlcpy(config.ap_password, config.admin_password, sizeof(config.ap_password));
        config.ap_timeout = 300;
        return settings_save(&config);
    }
    if (err != ESP_ERR_NVS_NOT_FOUND) return err == ESP_OK ? ESP_ERR_INVALID_VERSION : err;
    config.version = CONFIG_VERSION;
    strcpy(config.mode, "auto");
    strcpy(config.address, "10.7.0.2");
    strcpy(config.remote_cidr, "10.7.0.0/24");
    config.port = 51820;
    config.keepalive = 25;
    config.mtu = 1280;
    strcpy(config.admin_user, "admin");
    strcpy(config.admin_password, "12345678");
    strcpy(config.ap_password, "12345678");
    config.ap_timeout = 300;
    return settings_save(&config);
}

static bool key_valid(const char *s) {
    unsigned char raw[32];
    size_t len = 0;
    if (strlen(s) != 44 || mbedtls_base64_decode(raw, sizeof(raw), &len, (const unsigned char *)s, 44) || len != 32) return false;
    unsigned nonzero = 0;
    for (size_t i = 0; i < sizeof(raw); i++) nonzero |= raw[i];
    memset(raw, 0, sizeof(raw));
    return nonzero != 0;
}

static bool string_field(const cJSON *j, const char *name, char *dest, size_t cap, bool preserve_empty) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(j, name);
    if (!v) return true;
    if (!cJSON_IsString(v) || strlen(v->valuestring) >= cap) return false;
    if (!preserve_empty || v->valuestring[0]) strcpy(dest, v->valuestring);
    return true;
}

static bool number_field(const cJSON *j, const char *name, uint16_t *dest, unsigned min, unsigned max) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(j, name);
    if (!v) return true;
    if (!cJSON_IsNumber(v) || v->valuedouble < min || v->valuedouble > max || v->valuedouble != (unsigned)v->valuedouble) return false;
    *dest = v->valueint;
    return true;
}

bool settings_parse(const cJSON *j, gateway_config_t *out, char *error, size_t size) {
#define FAIL(message) do { snprintf(error, size, "%s", message); return false; } while (0)
    if (!cJSON_IsObject(j)) FAIL("Очікується JSON-об’єкт.");
    *out = config;
#define FIELD(name, member, secret) if (!string_field(j, name, out->member, sizeof(out->member), secret)) FAIL("Некоректне поле: " name)
    FIELD("mode", mode, false);
    FIELD("ssid", ssid, false);
    FIELD("wifi_password", wifi_password, true);
    FIELD("admin_password", admin_password, true);
    FIELD("admin_user", admin_user, false);
    FIELD("ap_ssid", ap_ssid, false);
    FIELD("ap_password", ap_password, true);
    FIELD("lan_cidr", lan_cidr, false);
    FIELD("private_key", private_key, true);
    FIELD("public_key", public_key, false);
    FIELD("preshared_key", preshared_key, true);
    FIELD("address", address, false);
    FIELD("remote_cidr", remote_cidr, false);
    FIELD("endpoint", endpoint, false);
#undef FIELD
    const cJSON *enabled = cJSON_GetObjectItemCaseSensitive(j, "enabled");
    if (enabled) {
        if (!cJSON_IsBool(enabled)) FAIL("Некоректний стан тунелю.");
        out->enabled = cJSON_IsTrue(enabled);
    }
    if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(j, "clear_psk"))) out->preshared_key[0] = 0;
    if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(j, "open_wifi"))) out->wifi_password[0] = 0;
    if (strcmp(out->mode, "auto") && strcmp(out->mode, "eth") && strcmp(out->mode, "wifi")) FAIL("Оберіть Auto, Ethernet або Wi-Fi.");
    if (!strcmp(out->mode, "wifi") && !out->ssid[0]) FAIL("Вкажіть назву Wi-Fi.");
    size_t wl = strlen(out->wifi_password);
    if (wl && (wl < 8 || wl > 63)) FAIL("Пароль Wi-Fi: від 8 до 63 символів.");
    if (!out->admin_user[0]) FAIL("Вкажіть логін адміністратора.");
    for (const char *p = out->admin_user; *p; p++) if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.') FAIL("Логін адміністратора: латинські літери, цифри, _, - або крапка.");
    if (strlen(out->admin_password) < 8 || strlen(out->admin_password) > 63) FAIL("Пароль адміністратора: від 8 до 63 символів.");
    for (const char *p = out->admin_password; *p; p++) if ((unsigned char)*p < 33 || (unsigned char)*p > 126) FAIL("Пароль адміністратора: латинські літери, цифри та знаки без пробілів.");
    if (strlen(out->ap_password) < 8 || strlen(out->ap_password) > 63) FAIL("Пароль точки доступу: від 8 до 63 символів.");
    if (out->ap_ssid[0]) for (const char *p = out->ap_ssid; *p; p++) if ((unsigned char)*p < 32 || (unsigned char)*p > 126) FAIL("Назва точки доступу: використайте друковані латинські символи.");
    if (!number_field(j, "port", &out->port, 1, 65535) || !number_field(j, "keepalive", &out->keepalive, 0, 120) || !number_field(j, "mtu", &out->mtu, 1280, 1420) || !number_field(j, "ap_timeout", &out->ap_timeout, 10, 3600)) FAIL("Перевірте порт, keepalive, MTU або час точки доступу.");
    if (out->lan_cidr[0]) {
        uint32_t lan, lan_mask; unsigned lan_prefix;
        if (!parse_cidr(out->lan_cidr, &lan, &lan_mask, &lan_prefix) || lan_prefix < 8 || lan_prefix > 30 || (lan & lan_mask) != lan) FAIL("LAN-підмережа має бути коректною мережею /8…/30.");
    }
    if (!out->enabled) return true;
    if (!key_valid(out->private_key) || !key_valid(out->public_key) || (out->preshared_key[0] && !key_valid(out->preshared_key))) FAIL("Ключ WireGuard має містити 32 байти у Base64 (44 символи).");
    if (!out->endpoint[0]) FAIL("Вкажіть адресу сервера WireGuard.");
    for (const char *p = out->endpoint; *p; p++) if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-') FAIL("Сервер: IPv4 або домен, без протоколу та порту.");
    uint32_t remote, mask; unsigned prefix;
    struct in_addr addr;
    if (inet_pton(AF_INET, out->address, &addr) != 1 || !parse_cidr(out->remote_cidr, &remote, &mask, &prefix) || prefix < 8 || prefix > 30) FAIL("Вкажіть IPv4 WT32 та VPN-підмережу /8…/30.");
    uint32_t host = ntohl(addr.s_addr), network = ntohl(remote);
    if ((network >> 24) == 0 || (network >> 24) == 127 || network >= 0xe0000000u || (remote & mask) != remote || (addr.s_addr & mask) != remote || host == network || host == (network | ~ntohl(mask))) FAIL("Адреса WT32 має бути адресою вузла всередині VPN-підмережі.");
    if (out->lan_cidr[0]) {
        uint32_t lan, lan_mask; unsigned lan_prefix;
        parse_cidr(out->lan_cidr, &lan, &lan_mask, &lan_prefix);
        uint32_t common = mask & lan_mask;
        if ((remote & common) == (lan & common)) FAIL("LAN і VPN-підмережі перетинаються.");
    }
    return true;
#undef FAIL
}
