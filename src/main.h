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

struct ipv6_addr_ctx_t {
    std::string ipv6_address;
};

struct input_cfg_t {
    struct host_cfg_t host_cfg;

    std::vector<struct ipv6_addr_ctx_t> ipv6_addresses;
};

struct cloud_app_cfg_t {
    struct input_cfg_t *input_cfg{}; //!< Input configuration details
    struct application_dpdk_config dpdk_cfg{}; //!< Configuration details of DPDK ports and queues
    std::string core_mask; //!< EAL core mask
};

doca_error_t parse_input_cfg(std::string filename, struct input_cfg_t *cfg);
