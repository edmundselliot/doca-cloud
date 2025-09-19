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
#include "pipe_mgr.h"
#include <arpa/inet.h>
#include <netinet/in.h>

DOCA_LOG_REGISTER(PIPE_MGR);

PipeMgr::PipeMgr() {}
PipeMgr::~PipeMgr() {}

doca_error_t PipeMgr::init(
    struct cloud_app_cfg_t *app_cfg,
    struct doca_flow_port *pf_port,
    struct doca_flow_port *vf_port,
    uint32_t pf_port_id,
    uint32_t vf_port_id,
    uint32_t pf_pa,
    rte_ether_addr *pf_mac,
    rte_ether_addr *vf_mac)
{
    doca_error_t result = DOCA_SUCCESS;\

    this->app_cfg = app_cfg;
    this->pf_port_id = pf_port_id;
    this->vf_port_id = vf_port_id;
    this->pf_port = pf_port;
    this->vf_port = vf_port;
    this->pf_pa = pf_pa;

    rte_ether_addr_copy(pf_mac, &this->pf_mac);
    rte_ether_addr_copy(vf_mac, &this->vf_mac);

    IF_SUCCESS(result, create_pipes());

    return result;
}

doca_error_t PipeMgr::create_pipes() {
    doca_error_t result = DOCA_SUCCESS;

    IF_SUCCESS(result, create_drop_pipe());
    IF_SUCCESS(result, create_ipv6_pipe());

    return result;
}

doca_error_t PipeMgr::create_ipv6_pipe() {

    doca_error_t result = DOCA_SUCCESS;

    struct doca_flow_match match_ip_from_wire = {};
    match_ip_from_wire.outer.l3_type = DOCA_FLOW_L3_TYPE_IP6;
    match_ip_from_wire.outer.ip6.dst_ip[0] = UINT32_MAX;
    match_ip_from_wire.outer.ip6.dst_ip[1] = UINT32_MAX;
    match_ip_from_wire.outer.ip6.dst_ip[2] = UINT32_MAX;
    match_ip_from_wire.outer.ip6.dst_ip[3] = UINT32_MAX;
    match_ip_from_wire.parser_meta.port_id = pf_port_id;

    struct doca_flow_match match_ip_port_mask = {};
    match_ip_port_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP6;
    match_ip_port_mask.outer.ip6.dst_ip[0] = UINT32_MAX;
    match_ip_port_mask.outer.ip6.dst_ip[1] = UINT32_MAX;
    match_ip_port_mask.outer.ip6.dst_ip[2] = UINT32_MAX;
    match_ip_port_mask.outer.ip6.dst_ip[3] = UINT32_MAX;
    match_ip_port_mask.parser_meta.port_id = UINT16_MAX;

    struct doca_flow_monitor monitor = {};
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    // struct doca_flow_fwd fwd_drop{};
    // fwd_drop.type = DOCA_FLOW_FWD_DROP;

    struct doca_flow_fwd fwd_to_drop_pipe{};
    fwd_to_drop_pipe.type = DOCA_FLOW_FWD_PIPE;
    fwd_to_drop_pipe.next_pipe = drop_pipe;

    struct doca_flow_fwd fwd = {};
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = vf_port_id;

    struct doca_flow_pipe_cfg *pipe_cfg;
    IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "IPV6"));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_ip_from_wire, &match_ip_port_mask));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor));
    IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_to_drop_pipe, &ipv6_pipe));

    if (pipe_cfg)
        doca_flow_pipe_cfg_destroy(pipe_cfg);

    if (result == DOCA_SUCCESS)
        DOCA_LOG_INFO("Created IPv6 pipe on port %d", pf_port_id);
    else
        DOCA_LOG_ERR("Failed to create IPv6 pipe on port %d, err: %s", pf_port_id, doca_error_get_descr(result));

    return result;
}

doca_error_t PipeMgr::create_ipv6_entry(std::string ipv6_address) {
    // Parse IPv6 address
    struct in6_addr ipv6_addr;
    if (inet_pton(AF_INET6, ipv6_address.c_str(), &ipv6_addr) != 1) {
        DOCA_LOG_ERR("Invalid IPv6 address: %s", ipv6_address.c_str());
        return DOCA_ERROR_INVALID_VALUE;
    }

    struct doca_flow_match match = {};
    match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP6;
    memcpy(&match.outer.ip6.dst_ip, &ipv6_addr, sizeof(struct in6_addr));
    match.parser_meta.port_id = pf_port_id;

    doca_flow_pipe_entry *new_entry{};
    doca_error_t result = add_single_entry(0, ipv6_pipe, pf_port, &match, nullptr, nullptr, nullptr, &new_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add IPv6 entry for address: %s", ipv6_address.c_str());
        return result;
    }
    monitored_pipe_entries.emplace_back(ipv6_address, new_entry);

    DOCA_LOG_INFO("Created IPv6 entry for address: %s", ipv6_address.c_str());
    return result;
}

doca_error_t PipeMgr::create_drop_pipe() {
    doca_error_t result = DOCA_SUCCESS;

    struct doca_flow_match match = {};

    struct doca_flow_fwd fwd_drop{};
    fwd_drop.type = DOCA_FLOW_FWD_DROP;

    doca_flow_monitor monitor = {};
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    struct doca_flow_pipe_cfg *pipe_cfg;
    IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "DROP"));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, nullptr));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor));
    IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_drop, nullptr, &drop_pipe));
    if (pipe_cfg)
        doca_flow_pipe_cfg_destroy(pipe_cfg);

    doca_flow_pipe_entry *new_entry{};
    IF_SUCCESS(result, add_single_entry(0, drop_pipe, pf_port, nullptr, nullptr, &monitor, &fwd_drop, &new_entry));
    monitored_pipe_entries.emplace_back("DROP", new_entry);

    return result;
}

void PipeMgr::print_stats() {
    DOCA_LOG_INFO("=================================");
    struct doca_flow_resource_query stats;
    doca_error_t result;

    result = doca_flow_resource_query_pipe_miss(ipv6_pipe, &stats);
    if (result == DOCA_SUCCESS)
        DOCA_LOG_INFO("IPv6 pipe miss: %lu pkts", stats.counter.total_pkts);
    else
        DOCA_LOG_ERR("Failed to query IPv6 pipe: %s", doca_error_get_descr(result));

    for (auto entry : monitored_pipe_entries) {
        result = doca_flow_resource_query_entry(entry.second, &stats);
        if (result == DOCA_SUCCESS)
            DOCA_LOG_INFO("  %s hit: %lu pkts", entry.first.c_str(), stats.counter.total_pkts);
        else
            DOCA_LOG_ERR("Failed to query entry %s: %s", entry.first.c_str(), doca_error_get_descr(result));
    }
}
