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

    struct doca_flow_pipe *root_pipe;
    struct doca_flow_pipe *ipv6_pipe;
    std::vector<std::pair<std::string, doca_flow_pipe_entry *>> monitored_pipe_entries;

    doca_error_t create_pipes();
    doca_error_t create_ipv6_pipe();
    doca_error_t create_root_pipe();

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

    doca_error_t create_ipv6_entry(std::string ipv6_address);



    void print_stats();
};
