#pragma once

#include <string>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_ether.h>

#include "doca_log.h"
#include "doca_flow.h"

#define IF_SUCCESS(result, expr) \
	if (result == DOCA_SUCCESS) { \
		result = expr; \
		if (likely(result == DOCA_SUCCESS)) { \
			DOCA_LOG_DBG("Success: %s", #expr); \
		} else { \
			DOCA_LOG_ERR("Error: %s: %s", #expr, doca_error_get_descr(result)); \
		} \
	} else { /* skip this expr */ \
	}

#if defined(__GNUC__) || defined(__clang__)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

std::string mac_to_string(const rte_ether_addr &mac_addr);
std::string ipv4_to_string(rte_be32_t ipv4_addr);
std::string ipv6_to_string(const uint32_t ipv6_addr[]);
std::string ip_to_string(const struct doca_flow_ip_addr &ip_addr);
