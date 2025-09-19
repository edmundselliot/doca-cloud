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

#include "main.h"

DOCA_LOG_REGISTER(PARSE_CFG);

doca_error_t parse_input_cfg(std::string filename, struct input_cfg_t *cfg) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        DOCA_LOG_ERR("Failed to open file %s", filename.c_str());
        return DOCA_ERROR_IO_FAILED;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string yaml_content = buffer.str();

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        DOCA_LOG_ERR("Failed to get hostname");
        return DOCA_ERROR_IO_FAILED;
    }
    std::string current_hostname(hostname);

    YAML::Node root = YAML::Load(yaml_content);

    for (const auto& node : root["device_cfg"]) {
        if (node["hostname"].as<std::string>() == current_hostname) {
            struct host_cfg_t host_cfg;
            host_cfg.hostname = node["hostname"].as<std::string>();
            host_cfg.pf_pci = node["pci"].as<std::string>();
            host_cfg.vf_pci = node["vf_pci"].as<std::string>();
            host_cfg.vf_rep = node["vf"].as<std::string>();
            int parsed_correct = rte_ether_unformat_addr(node["vf_mac"].as<std::string>().c_str(), &host_cfg.vf_mac);
            if (parsed_correct < 0) {
                DOCA_LOG_ERR("Failed to parse MAC address %s", node["vf_mac"].as<std::string>().c_str());
                return DOCA_ERROR_INVALID_VALUE;
            }

            cfg->host_cfg = host_cfg;
        }
    }


    for (const auto& node : root["ipv6_cfg"]) {
        if (node["hostname"].as<std::string>() == current_hostname) {
            for (const auto& addr : node["addresses"]) {
                ipv6_addr_ctx_t ipv6_ctx;
                ipv6_ctx.ipv6_address = addr["ipv6_address"].as<std::string>();
                cfg->ipv6_addresses.push_back(ipv6_ctx);
            }
        }
    }

    return DOCA_SUCCESS;
}
