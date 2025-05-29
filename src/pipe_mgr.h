/*
 * Copyright (c) 2025 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#include <unistd.h>
#include <vector>
#include <set>

#include <rte_ether.h>
#include <rte_ethdev.h>

#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dpdk.h>

#include "utils.h"
#include "main.h"


/*
    High-level pipe topology


             all packets
                  │
     from VF  ┌───▼───┐ from wire
     ┌────────┤rx root├────┐
 ┌───▼───┐    └───────┘    │
 │tx root│                 │
 └───┬───┘                 │
     │                     │
 ┌───▼────────┐       ┌────▼───┐
 │geneve encap│       │vlan pop│
 └───┬────────┘       └────┬───┘
     │                     │
 ┌───▼──────┐         ┌────▼─────┐
 │ipsec encr│         │ipsec decr│
 └───┬──────┘         └────┬─────┘
     │                     │
 ┌───▼─────┐          ┌────▼─────┐
 │vlan push│          │ipsec synd│
 └───┬─────┘          └────┬─────┘
     │                     │
     ▼                ┌────▼───────┐
 fwd to wire          │geneve decap│
                      └────┬───────┘
                           │
                           ▼
                       fwd to VF

*/

struct ipsec_sa_ctx_t {
    enum doca_flow_crypto_icv_len icv_length; /* ICV length */
    enum doca_flow_crypto_key_type key_type; /* Key type */
    uint8_t key[MAX_IPSEC_KEY_LEN]; /* Policy encryption key */
    uint32_t salt; /* Key Salt */
    uint32_t lifetime_threshold; /* SA lifetime threshold */
    bool esn_en; /* If extended sn is enable*/
};

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

class PipeMgr {
private:
    struct cloud_app_cfg_t *app_cfg;

    uint32_t pf_port_id;
    struct doca_flow_port *pf_port;
    uint32_t vf_port_id;
    struct doca_flow_port *vf_port;

    uint32_t pf_pa;
    struct rte_ether_addr pf_mac;
    struct rte_ether_addr vf_mac;

    struct doca_flow_pipe *rss_pipe;
    struct doca_flow_pipe *kernel_pipe;
    struct doca_flow_pipe *tx_root_pipe;
    struct doca_flow_pipe *tx_selector_pipe;
    struct doca_flow_pipe *tx_geneve_pipe;
    struct doca_flow_pipe *tx_ipsec_pipe;
    struct doca_flow_pipe *tx_vlan_pipe;
    struct doca_flow_pipe *rx_root_pipe;
    struct doca_flow_pipe *rx_geneve_pipe;
    struct doca_flow_pipe *rx_ipsec_pipe;
    struct doca_flow_pipe *rx_ipsec_synd_pipe;
    struct doca_flow_pipe *rx_vlan_pipe;

    struct doca_flow_pipe_entry *rss_pipe_default_entry;
    struct doca_flow_pipe_entry *kernel_pipe_default_entry;
    struct doca_flow_pipe_entry *tx_root_pipe_arp_reply;
    struct doca_flow_pipe_entry *rx_root_pipe_from_vf_entry;
    struct doca_flow_pipe_entry *rx_root_pipe_arp_req;
    struct doca_flow_pipe_entry *rx_root_pipe_lacp_in;
    struct doca_flow_pipe_entry *rx_root_pipe_from_pf_entry;
    struct doca_flow_pipe_entry *rx_root_pipe_unknown;
    struct doca_flow_pipe_entry *rx_vlan_pipe_default_entry;
    const static uint8_t nb_ipsec_syndromes = 2;
    struct doca_flow_pipe_entry *rx_ipsec_syndrome_entries[nb_ipsec_syndromes];

    struct doca_flow_monitor monitor_count = {};
    struct doca_flow_fwd fwd_drop = {};
    struct doca_flow_fwd fwd_rss = {};
    struct doca_flow_actions geneve_encap_actions = {};

    struct ipsec_sa_ctx_t dummy_encap_decap_sa_ctx = {};
    uint32_t dummy_encap_crypto_id;
    uint32_t dummy_decap_crypto_id;


    std::vector<std::pair<std::string, struct doca_flow_pipe_entry*>> monitored_pipe_entries = {};
    std::vector<std::pair<std::string, struct doca_flow_pipe*>> monitored_pipe_misses = {};
    std::set<uint32_t> ipsec_sa_idxs = {};

    doca_error_t create_pipes();
    doca_error_t rss_pipe_create();
    doca_error_t kernel_pipe_create();
    doca_error_t tx_root_pipe_create();
    doca_error_t tx_selector_pipe_create();
    doca_error_t tx_geneve_pipe_create();
    doca_error_t tx_ipsec_pipe_create();
    doca_error_t tx_vlan_pipe_create();
    doca_error_t rx_root_pipe_create();
    doca_error_t rx_geneve_pipe_create();
    doca_error_t rx_ipsec_synd_pipe_create();
    doca_error_t rx_ipsec_pipe_create();
    doca_error_t rx_vlan_pipe_create();

    doca_error_t get_available_ipsec_sa_idx(uint32_t *sa_idx);
    doca_error_t create_ipsec_sa(struct ipsec_sa_ctx_t *ipsec_sa_ctx, uint32_t sa_idx, bool egress);
    doca_error_t bind_ipsec_sa_ids();
    doca_error_t tx_ipsec_pipe_entry_create(uint32_t remote_pa, uint32_t spi, uint32_t sa_idx);
    doca_error_t rx_ipsec_pipe_entry_create(uint32_t remote_pa, uint32_t spi, uint32_t sa_idx);

public:
    PipeMgr();
    ~PipeMgr();

    doca_error_t init(
        struct cloud_app_cfg_t *app_cfg,
        struct doca_flow_port *pf_port,
        struct doca_flow_port *vf_port,
        uint32_t pf_port_id,
        uint32_t vf_port_id,
        uint32_t pf_pa,
        rte_ether_addr *pf_mac,
        rte_ether_addr *vf_mac);

    doca_error_t tx_geneve_pipe_entry_create(struct geneve_encap_ctx_t *encap_ctx);
    doca_error_t rx_geneve_pipe_entry_create(struct geneve_decap_ctx_t *decap_ctx);
    doca_error_t tx_vlan_pipe_entry_create(struct vlan_push_ctx_t* vlan_ctx);
    doca_error_t tx_ipsec_session_create(struct ipsec_ctx_t* ipsec_ctx);
    doca_error_t rx_ipsec_session_create(struct ipsec_ctx_t* ipsec_ctx);

    void print_stats();
};
