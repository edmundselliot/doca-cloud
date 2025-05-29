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
            host_cfg.vf_rep = node["vf"].as<std::string>();
            int parsed_correct = rte_ether_unformat_addr(node["vf_mac"].as<std::string>().c_str(), &host_cfg.vf_mac);
            if (parsed_correct < 0) {
                DOCA_LOG_ERR("Failed to parse MAC address %s", node["vf_mac"].as<std::string>().c_str());
                return DOCA_ERROR_INVALID_VALUE;
            }

            cfg->host_cfg = host_cfg;
        }
    }

    for (const auto& node : root["geneve_cfg"]) {
        if (node["hostname"].as<std::string>() == current_hostname) {
            geneve_tnl_ctx_t geneve_ctx;
            geneve_ctx.remote_ca = node["tunnels"]["ca"].as<std::string>();
            geneve_ctx.remote_pa = node["tunnels"]["pa"].as<std::string>();
            geneve_ctx.vni = node["tunnels"]["vni"].as<uint32_t>();
            int parsed_correct = rte_ether_unformat_addr(node["tunnels"]["next_hop"].as<std::string>().c_str(), &geneve_ctx.next_hop_mac);
            if (parsed_correct < 0) {
                DOCA_LOG_ERR("Failed to parse MAC address %s", node["tunnels"]["next_hop"].as<std::string>().c_str());
                return DOCA_ERROR_INVALID_VALUE;
            }

            cfg->geneve_tunnels.push_back(geneve_ctx);
        }
    }

    for (const auto& node : root["ipsec_cfg"]) {
        if (node["hostname"].as<std::string>() == current_hostname) {
            for (const auto& tunnel : node["tunnels"]) {
                ipsec_tnl_ctx_t ipsec_ctx;
                ipsec_ctx.remote_pa = tunnel["dst_pa"].as<std::string>();
                ipsec_ctx.enc_spi = tunnel["encr_spi"].as<uint32_t>();

                // Convert keys from hex string to byte array
                std::string enc_key_str = tunnel["encr_key"].as<std::string>();
                size_t enc_key_len = enc_key_str.length() / 2;  // Each byte is represented by two hex characters
                for (size_t i = 0; i < enc_key_len; ++i) {
                    sscanf(enc_key_str.substr(2 * i, 2).c_str(), "%2hhx", &ipsec_ctx.enc_key_data[i]);
                }
                ipsec_ctx.enc_key_len = enc_key_len;

                ipsec_ctx.dec_spi = tunnel["decr_spi"].as<uint32_t>();

                std::string dec_key_str = tunnel["decr_key"].as<std::string>();
                size_t dec_key_len = dec_key_str.length() / 2;  // Each byte is represented by two hex characters
                for (size_t i = 0; i < dec_key_len; ++i) {
                    sscanf(dec_key_str.substr(2 * i, 2).c_str(), "%2hhx", &ipsec_ctx.dec_key_data[i]);
                }
                ipsec_ctx.dec_key_len = dec_key_len;

                cfg->ipsec_tunnels.push_back(ipsec_ctx);
            }
        }
    }

    for (const auto& node : root["vlan_cfg"]) {
        if (node["hostname"].as<std::string>() == current_hostname) {
            for (const auto& tunnel : node["tunnels"]) {
                vlan_ctx_t vlan_ctx;
                vlan_ctx.remote_pa = tunnel["dst_pa"].as<std::string>();
                vlan_ctx.vlan_id = tunnel["vlan"].as<uint16_t>();
                cfg->vlan_pushes.push_back(vlan_ctx);
            }
        }
    }

    return DOCA_SUCCESS;
}
