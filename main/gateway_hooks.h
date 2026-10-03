#pragma once
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#undef LWIP_HOOK_IP4_ROUTE_SRC
#define LWIP_HOOK_IP4_ROUTE_SRC gateway_route
struct netif *gateway_route(const ip4_addr_t *src, const ip4_addr_t *dest);

