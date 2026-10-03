#include "gateway.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/lwip_napt.h"
#include "lwip/netdb.h"
#include "esp_timer.h"
#include "wireguardif.h"
#include "wireguard-platform.h"
#include "mbedtls/base64.h"

#if !IP_FORWARD || !IP_NAPT || !LWIP_TCPIP_CORE_LOCKING || !LWIP_ESP_NETIF_DATA
#error "Gateway requires forwarding, NAPT, core locking and separate ESP-NETIF client data"
#endif

static struct netif wg, *physical;
static bool active;
static uint8_t peer_index;
static esp_netif_t *selected;
static esp_netif_ip_info_t selected_ip;
static ip4_addr_t vpn_network, vpn_mask;
static ip_addr_t endpoint;
static uint32_t rx_bytes, tx_bytes, dropped, last_rx;
static int64_t resolve_after;
static netif_output_fn wg_output;

// Runs in the lwIP core. Prefer the chosen LAN even if both uplinks share a subnet.
struct netif *gateway_route(const ip4_addr_t *src, const ip4_addr_t *dest) {
    if (active && (dest->addr & vpn_mask.addr) == vpn_network.addr) return &wg;
    if (physical && netif_is_up(physical) && netif_is_link_up(physical) &&
        (dest->addr & selected_ip.netmask.addr) == (selected_ip.ip.addr & selected_ip.netmask.addr)) return physical;
    return NULL;
}

static err_t gateway_input(struct pbuf *p, struct netif *n) {
    struct ip_hdr hdr;
    if (pbuf_copy_partial(p, &hdr, sizeof(hdr), 0) != sizeof(hdr) || IPH_V(&hdr) != 4 || IPH_HL(&hdr) < 5) goto drop;
    uint32_t dest = hdr.dest.addr;
    uint32_t lan = selected_ip.ip.addr & selected_ip.netmask.addr;
    bool is_lan_host = (dest & selected_ip.netmask.addr) == lan && dest != lan && dest != (lan | ~selected_ip.netmask.addr);
    // Only this LAN and the gateway's VPN address; never act as an Internet exit.
    if (!physical || (!is_lan_host && dest != netif_ip4_addr(n)->addr)) goto drop;
    rx_bytes += p->tot_len;
    last_rx = sys_now();
    return ip4_input(p, n);
drop:
    dropped++;
    pbuf_free(p);
    return ERR_OK;
}

static err_t counted_output(struct netif *n, struct pbuf *p, const ip4_addr_t *dest) {
    err_t err = wg_output(n, p, dest);
    if (err == ERR_OK) tx_bytes += p->tot_len;
    return err;
}

static void stop_locked(void) {
    if (active) {
        ip_napt_enable(netif_ip4_addr(&wg)->addr, 0);
        netif_set_down(&wg);
        wireguardif_shutdown(&wg);
        netif_remove(&wg);
        wireguardif_fini(&wg);
        memset(&wg, 0, sizeof(wg));
        active = false;
    }
    physical = NULL;
}

static bool start_locked(struct netif *uplink) {
    ip4_addr_t address, zero = {0};
    ip4addr_aton(config.address, &address);
    struct wireguardif_init_data init = { .private_key = config.private_key, .listen_port = 51820, .bind_netif = uplink };
    memset(&wg, 0, sizeof(wg));
    if (!netif_add(&wg, &address, &vpn_mask, &zero, &init, wireguardif_init, gateway_input)) return false;
    active = true;
    physical = uplink;
    wg.mtu = config.mtu;
    wg_output = wg.output;
    wg.output = counted_output;
    struct wireguardif_peer peer;
    wireguardif_peer_init(&peer);
    peer.public_key = config.public_key;
    ip_addr_copy_from_ip4(peer.allowed_ip, vpn_network);
    ip_addr_copy_from_ip4(peer.allowed_mask, vpn_mask);
    peer.endpoint_ip = endpoint;
    peer.endport_port = config.port;
    peer.keep_alive = config.keepalive;
    unsigned char psk[32] = {0}; size_t size;
    if (config.preshared_key[0]) {
        if (mbedtls_base64_decode(psk, sizeof(psk), &size, (unsigned char *)config.preshared_key, 44) != 0) { stop_locked(); return false; }
        peer.preshared_key = psk;
    }
    err_t err = wireguardif_add_peer(&wg, &peer, &peer_index);
    memset(psk, 0, sizeof(psk));
    if (err != ERR_OK) { stop_locked(); return false; }
    netif_set_up(&wg);
    ip_napt_enable(address.addr, 1);
    if (!wg.napt || wireguardif_connect(&wg, peer_index) != ERR_OK) { stop_locked(); return false; }
    return true;
}

void tunnel_tick(esp_netif_t *uplink, const esp_netif_ip_info_t *ip, gateway_status_t *status) {
    status->tunnel = false;
    status->clock_ready = time(NULL) > 1704067200;
    if (selected != uplink || memcmp(&selected_ip, ip, sizeof(*ip))) {
        LOCK_TCPIP_CORE();
        stop_locked();
        selected = uplink;
        selected_ip = *ip;
        UNLOCK_TCPIP_CORE();
        resolve_after = 0;
        ip_addr_set_zero(&endpoint);
        if (uplink) esp_netif_set_default_netif(uplink);
    }
    const char *message = "Тунель вимкнений";
    if (!config.enabled) goto done;
    message = "Очікування мережі";
    if (!uplink) goto done;
    unsigned prefix;
    uint32_t remote_addr, remote_mask;
    if (!parse_cidr(config.remote_cidr, &remote_addr, &remote_mask, &prefix)) { message = "Некоректна VPN-підмережа"; goto done; }
    uint32_t common = remote_mask & ip->netmask.addr;
    esp_netif_ip_info_t ap_info;
    esp_netif_get_ip_info(ap_netif, &ap_info);
    uint32_t ap_common = remote_mask & ap_info.netmask.addr;
    if ((remote_addr & common) == (ip->ip.addr & common) || (remote_addr & ap_common) == (ap_info.ip.addr & ap_common) ||
        (ip->ip.addr & (ip->netmask.addr & ap_info.netmask.addr)) == (ap_info.ip.addr & (ip->netmask.addr & ap_info.netmask.addr))) {
        message = "Конфлікт LAN, VPN або мережі налаштування"; goto done;
    }
    message = "Очікування синхронізації часу (NTP)";
    if (!status->clock_ready) goto done;
    int64_t now = esp_timer_get_time();
    if (now >= resolve_after) {
        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM }, *result = NULL;
        if (!getaddrinfo(config.endpoint, NULL, &hints, &result) && result) {
            ip_addr_t resolved;
            ip_addr_set_ip4_u32(&resolved, ((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr);
            freeaddrinfo(result);
            LOCK_TCPIP_CORE();
            if (active && !ip_addr_cmp(&endpoint, &resolved)) stop_locked();
            endpoint = resolved;
            UNLOCK_TCPIP_CORE();
            resolve_after = now + 300000000LL;
        } else resolve_after = now + 15000000LL;
    }
    message = "Не вдалося знайти сервер (DNS)";
    if (ip_addr_isany(&endpoint)) goto done;
    // Reject an endpoint routed into the tunnel itself or multicast/loopback.
    uint32_t ep = ntohl(ip_2_ip4(&endpoint)->addr);
    if ((ip_2_ip4(&endpoint)->addr & remote_mask) == remote_addr || ep >= 0xe0000000u || (ep >> 24) == 127 || (ep >> 24) == 0) { message = "Endpoint має бути поза VPN-підмережею"; goto done; }
    char name[8];
    if (esp_netif_get_netif_impl_name(uplink, name) != ESP_OK) { message = "Помилка мережевого інтерфейсу"; goto done; }
    LOCK_TCPIP_CORE();
    vpn_network.addr = remote_addr;
    vpn_mask.addr = remote_mask;
    struct netif *underlying = netif_find(name);
    if (underlying && (active || start_locked(underlying))) {
        status->tunnel = wireguardif_peer_is_up(&wg, peer_index, NULL, NULL) == ERR_OK;
        message = status->tunnel ? "Захищене з’єднання активне" : "Очікування WireGuard handshake";
    } else message = "Не вдалося запустити WireGuard / NAT";
    UNLOCK_TCPIP_CORE();
done:
    strlcpy(status->state, message, sizeof(status->state));
    LOCK_TCPIP_CORE();
    status->rx_bytes = rx_bytes;
    status->tx_bytes = tx_bytes;
    status->dropped = dropped;
    status->last_rx_age = last_rx ? (sys_now() - last_rx) / 1000 : UINT32_MAX;
    UNLOCK_TCPIP_CORE();
}
