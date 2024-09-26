#pragma once

#include <vector>
#include <string>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_arp.h>

#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dpdk.h>

#include "dpdk_utils.h"
#include "utils.h"
#include "common.h"

#define MAX_IPSEC_KEY_LEN (32)			  /* Maximal GCM key size is 256bit==32B */

struct geneve_encap_ctx_t {
    uint32_t remote_ca;
    uint32_t remote_pa;
    rte_ether_addr next_hop_mac;
    uint32_t vni;
};

struct geneve_decap_ctx_t {
    uint32_t remote_ca;
    uint32_t vni;
};

struct vlan_push_ctx_t {
    uint32_t remote_pa;
    uint16_t vlan_id;
};

struct ipsec_ctx_t {
    uint32_t remote_pa;
    uint32_t spi;
    uint8_t key[MAX_IPSEC_KEY_LEN];
    uint32_t key_len_bytes;
};


struct host_cfg_t {
    std::string hostname;
    std::string pf_pci;
    std::string vf_rep;
    rte_ether_addr vf_mac;
};

struct input_cfg_t {
    std::vector<host_cfg_t> hosts;

    std::vector<geneve_encap_ctx_t> geneve_encaps;
    std::vector<geneve_decap_ctx_t> geneve_decaps;
    std::vector<vlan_push_ctx_t> vlan_pushes;
    std::vector<ipsec_ctx_t> ipsec_encaps;
    std::vector<ipsec_ctx_t> ipsec_decaps;
};

struct cloud_app_cfg_t {
    struct application_dpdk_config dpdk_cfg; //!< Configuration details of DPDK ports and queues
	std::string core_mask; //!< EAL core mask
    uint32_t max_ipsec_sessions;
};

doca_error_t parse_input_cfg(std::string filename, struct input_cfg_t *cfg);
