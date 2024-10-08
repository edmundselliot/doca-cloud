#pragma once

#include <string>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_ether.h>

#include "doca_log.h"
#include "doca_flow.h"

#include "doca_cloud.h"

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

#define BUILD_VNI(uint24_vni) (RTE_BE32((uint32_t)uint24_vni << 8))        /* create VNI */
#define GET_BYTE(V, N) ((uint8_t)((V) >> ((N)*8) & 0xFF))

std::string mac_to_string(const rte_ether_addr &mac_addr);
std::string ipv4_to_string(rte_be32_t ipv4_addr);
std::string ipv6_to_string(const uint32_t ipv6_addr[]);
std::string ip_to_string(const struct doca_flow_ip_addr &ip_addr);
uint32_t ipv4_string_to_u32(const std::string &ipv4_str);

struct entries_status {
    bool failure;          /* will be set to true if some entry status will not be success */
    int nb_processed;     /* number of entries that was already processed */
    int entries_in_queue; /* number of entries in queue that is waiting to process */
};

doca_error_t add_single_entry(uint16_t pipe_queue,
                doca_flow_pipe *pipe,
                doca_flow_port *port,
                const doca_flow_match *match,
                const doca_flow_actions *actions,
                const doca_flow_monitor *mon,
                const doca_flow_fwd *fwd,
                doca_flow_pipe_entry **entry);
