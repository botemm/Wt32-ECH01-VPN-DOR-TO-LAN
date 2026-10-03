#include "gateway.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_http_server.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "mbedtls/base64.h"
#include "wireguard.h"

static bool saving;
extern const uint8_t html_start[] asm("_binary_index_html_start");
extern const uint8_t html_end[] asm("_binary_index_html_end");
extern const uint8_t css_start[] asm("_binary_style_css_start");
extern const uint8_t css_end[] asm("_binary_style_css_end");
extern const uint8_t js_start[] asm("_binary_app_js_start");
extern const uint8_t js_end[] asm("_binary_app_js_end");

static bool authorize(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    char header[192], raw[128], expected[192] = "Basic ";
    size_t len;
    snprintf(raw, sizeof(raw), "%s:%s", config.admin_user, config.admin_password);
    mbedtls_base64_encode((unsigned char *)expected + 6, sizeof(expected) - 6, &len, (unsigned char *)raw, strlen(raw));
    expected[6 + len] = 0;
    bool valid = httpd_req_get_hdr_value_str(req, "Authorization", header, sizeof(header)) == ESP_OK && strlen(header) == strlen(expected);
    unsigned diff = 0;
    if (valid) for (size_t i = 0; i < strlen(expected); i++) diff |= header[i] ^ expected[i];
    memset(raw, 0, sizeof(raw));
    memset(expected, 0, sizeof(expected));
    if (valid && !diff) return true;
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"WT32 Link\", charset=\"UTF-8\"");
    httpd_resp_sendstr(req, "Use the configured administrator login and password.");
    return false;
}

static esp_err_t json_reply(httpd_req_t *req, cJSON *j) {
    if (!j) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
    char *text = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!text) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    esp_err_t result = httpd_resp_sendstr(req, text);
    free(text);
    return result;
}

static esp_err_t asset(httpd_req_t *req) {
    if (!authorize(req)) return ESP_OK;
    const uint8_t *start = html_start, *end = html_end;
    const char *type = "text/html; charset=utf-8";
    if (!strcmp(req->uri, "/style.css")) { start = css_start; end = css_end; type = "text/css; charset=utf-8"; }
    if (!strcmp(req->uri, "/app.js")) { start = js_start; end = js_end; type = "text/javascript; charset=utf-8"; }
    httpd_resp_set_type(req, type);
    return httpd_resp_send(req, (const char *)start, end - start);
}

static esp_err_t api_status(httpd_req_t *req) {
    if (!authorize(req)) return ESP_OK;
    gateway_status_t s; status_get(&s);
    cJSON *j = cJSON_CreateObject();
#define STR(name, value) cJSON_AddStringToObject(j, name, value)
#define NUM(name, value) cJSON_AddNumberToObject(j, name, value)
#define BOOL(name, value) cJSON_AddBoolToObject(j, name, value)
    STR("uplink", s.uplink); STR("ip", s.ip); STR("lan", s.lan); STR("state", s.state);
    BOOL("ethernet", s.ethernet); BOOL("wifi", s.wifi); BOOL("tunnel", s.tunnel);
    BOOL("clock_ready", s.clock_ready); BOOL("ap", s.ap);
    NUM("ap_remaining", s.ap_remaining); NUM("ap_clients", s.ap_clients);
    NUM("rssi", s.rssi); NUM("rx_bytes", s.rx_bytes); NUM("tx_bytes", s.tx_bytes);
    NUM("dropped", s.dropped); NUM("last_rx_age", s.last_rx_age);
    NUM("uptime", esp_timer_get_time() / 1000000); NUM("heap", esp_get_free_heap_size());
    return json_reply(req, j);
}

static esp_err_t api_config(httpd_req_t *req) {
    if (!authorize(req)) return ESP_OK;
    cJSON *j = cJSON_CreateObject();
    STR("mode", config.mode); STR("ssid", config.ssid); STR("setup_ssid", setup_ssid);
    STR("ap_ssid", config.ap_ssid); STR("admin_user", config.admin_user); STR("lan_cidr", config.lan_cidr);
    STR("address", config.address); STR("remote_cidr", config.remote_cidr);
    STR("endpoint", config.endpoint); STR("public_key", config.public_key);
    BOOL("enabled", config.enabled); BOOL("has_private_key", config.private_key[0]);
    BOOL("has_wifi_password", config.wifi_password[0]); BOOL("has_psk", config.preshared_key[0]); BOOL("has_ap_password", config.ap_password[0]);
    NUM("port", config.port); NUM("keepalive", config.keepalive); NUM("mtu", config.mtu); NUM("ap_timeout", config.ap_timeout);
    // The device public key is safe to show; private key and passwords never leave NVS.
    uint8_t key[32], pub[32]; size_t key_len = sizeof(key);
    char encoded[45]; size_t encoded_len;
    if (config.private_key[0] && wireguard_base64_decode(config.private_key, key, &key_len) && key_len == 32) {
        wireguard_generate_public_key(pub, key);
        mbedtls_base64_encode((unsigned char *)encoded, sizeof(encoded), &encoded_len, pub, sizeof(pub));
        encoded[encoded_len] = 0;
        STR("device_public_key", encoded);
    }
    memset(key, 0, sizeof(key));
    return json_reply(req, j);
}

static esp_err_t api_save(httpd_req_t *req) {
    if (!authorize(req)) return ESP_OK;
    char marker[16], type[64];
    if (httpd_req_get_hdr_value_str(req, "X-WT32-Request", marker, sizeof(marker)) != ESP_OK || strcmp(marker, "1") ||
        httpd_req_get_hdr_value_str(req, "Content-Type", type, sizeof(type)) != ESP_OK || strcmp(type, "application/json"))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Invalid request origin or type");
    if (saving) { httpd_resp_set_status(req, "409 Conflict"); return httpd_resp_sendstr(req, "Restart pending"); }
    if (req->content_len < 2 || req->content_len > 6144) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body size");
    char *body = calloc(1, req->content_len + 1);
    if (!body) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
    size_t received = 0;
    while (received < req->content_len) {
        int n = httpd_req_recv(req, body + received, req->content_len - received);
        if (n <= 0) { free(body); return ESP_FAIL; }
        received += n;
    }
    cJSON *j = cJSON_ParseWithLengthOpts(body, received + 1, NULL, true);
    memset(body, 0, received); free(body);
    gateway_config_t updated;
    char error[256];
    bool valid = settings_parse(j, &updated, error, sizeof(error));
    cJSON_Delete(j);
    if (!valid) {
        httpd_resp_set_status(req, "400 Bad Request");
        cJSON *result = cJSON_CreateObject(); cJSON_AddStringToObject(result, "error", error);
        memset(&updated, 0, sizeof(updated));
        return json_reply(req, result);
    }
    esp_err_t err = settings_save(&updated);
    memset(&updated, 0, sizeof(updated));
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Could not save settings");
    saving = true;
    request_restart();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true,\"reboot\":true}");
}

static esp_err_t api_scan_get(httpd_req_t *req) {
    if (!authorize(req)) return ESP_OK;
    cJSON *j = cJSON_CreateObject();
    scan_add_json(j);
    return json_reply(req, j);
}

static esp_err_t api_scan_start(httpd_req_t *req) {
    if (!authorize(req)) return ESP_OK;
    char marker[16];
    if (httpd_req_get_hdr_value_str(req, "X-WT32-Request", marker, sizeof(marker)) != ESP_OK || strcmp(marker, "1"))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Invalid request origin");
    if (!lan_scan_start()) {
        httpd_resp_set_status(req, "409 Conflict");
        return httpd_resp_sendstr(req, "Scan is already running or could not start");
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t api_preview_key(httpd_req_t *req) {
    if (!authorize(req)) return ESP_OK;
    char marker[16];
    if (httpd_req_get_hdr_value_str(req, "X-WT32-Request", marker, sizeof(marker)) != ESP_OK || strcmp(marker, "1"))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Invalid request origin");
    if (req->content_len < 2 || req->content_len > 128) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body size");
    char body[129] = {0};
    size_t received = 0;
    while (received < req->content_len) {
        int n = httpd_req_recv(req, body + received, req->content_len - received);
        if (n <= 0) { memset(body, 0, sizeof(body)); return ESP_FAIL; }
        received += n;
    }
    cJSON *input = cJSON_Parse(body);
    memset(body, 0, sizeof(body));
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(input, "private_key");
    uint8_t key[32], pub[32]; size_t key_len = sizeof(key);
    bool valid = cJSON_IsString(value) && strlen(value->valuestring) == 44 && wireguard_base64_decode(value->valuestring, key, &key_len) && key_len == 32;
    cJSON_Delete(input);
    if (!valid) { memset(key, 0, sizeof(key)); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid private key"); }
    wireguard_generate_public_key(pub, key);
    memset(key, 0, sizeof(key));
    char encoded[45]; size_t encoded_len;
    if (mbedtls_base64_encode((unsigned char *)encoded, sizeof(encoded), &encoded_len, pub, sizeof(pub)) != 0)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Could not encode key");
    encoded[encoded_len] = 0;
    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "public_key", encoded);
    memset(encoded, 0, sizeof(encoded));
    return json_reply(req, result);
}

void web_start(void) {
    scan_init();
    httpd_config_t options = HTTPD_DEFAULT_CONFIG();
    options.stack_size = 8192;
    options.max_uri_handlers = 10;
    options.lru_purge_enable = true;
    options.recv_wait_timeout = 5;
    httpd_handle_t server;
    ESP_ERROR_CHECK(httpd_start(&server, &options));
    const httpd_uri_t routes[] = {
        { .uri = "/", .method = HTTP_GET, .handler = asset },
        { .uri = "/style.css", .method = HTTP_GET, .handler = asset },
        { .uri = "/app.js", .method = HTTP_GET, .handler = asset },
        { .uri = "/api/status", .method = HTTP_GET, .handler = api_status },
        { .uri = "/api/config", .method = HTTP_GET, .handler = api_config },
        { .uri = "/api/config", .method = HTTP_POST, .handler = api_save },
        { .uri = "/api/scan", .method = HTTP_GET, .handler = api_scan_get },
        { .uri = "/api/scan", .method = HTTP_POST, .handler = api_scan_start },
        { .uri = "/api/key", .method = HTTP_POST, .handler = api_preview_key },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) ESP_ERROR_CHECK(httpd_register_uri_handler(server, &routes[i]));
}
