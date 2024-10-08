#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <cstring>
#include <fstream>

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

#define MAX_IPSEC_KEY_LEN (32)              /* Maximal GCM key size is 256bit==32B */

struct host_cfg_t {
    std::string hostname;
    std::string pf_pci;
    std::string vf_rep;
    rte_ether_addr vf_mac;
};

// Used for input
struct geneve_tnl_ctx_t {
    std::string remote_ca;
    std::string remote_pa;
    rte_ether_addr next_hop_mac;
    uint32_t vni;
};

struct ipsec_tnl_ctx_t {
    std::string remote_pa;

    uint32_t enc_spi;
    uint8_t enc_key_data[MAX_IPSEC_KEY_LEN];
    uint32_t enc_key_len;

    uint32_t dec_spi;
    uint8_t dec_key_data[MAX_IPSEC_KEY_LEN];
    uint32_t dec_key_len;
};

struct vlan_ctx_t {
    std::string remote_pa;
    uint16_t vlan_id;
};

struct input_cfg_t {
    struct host_cfg_t host_cfg;

    std::vector<struct geneve_tnl_ctx_t> geneve_tunnels;
    std::vector<struct ipsec_tnl_ctx_t> ipsec_tunnels;
    std::vector<struct vlan_ctx_t> vlan_pushes;
};

struct cloud_app_cfg_t {
    struct input_cfg_t *input_cfg; //!< Input configuration details
    struct application_dpdk_config dpdk_cfg; //!< Configuration details of DPDK ports and queues
    std::string core_mask; //!< EAL core mask
    uint32_t max_ipsec_sessions;
};

doca_error_t parse_input_cfg(std::string filename, struct input_cfg_t *cfg);
