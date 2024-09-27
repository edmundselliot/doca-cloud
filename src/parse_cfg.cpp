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

    // Parse device_cfg
    bool local_host_found = false;
    for (const auto& node : root["device_cfg"]) {
        host_cfg_t host_cfg;
        host_cfg.hostname = node["hostname"].as<std::string>();
        host_cfg.pf_pci = node["pci"].as<std::string>();
        host_cfg.vf_rep = node["vf"].as<std::string>();
        int parsed_correct = rte_ether_unformat_addr(node["vf_mac"].as<std::string>().c_str(), &host_cfg.vf_mac);
        if (parsed_correct < 0) {
            DOCA_LOG_ERR("Failed to parse MAC address %s", node["vf_mac"].as<std::string>().c_str());
            return DOCA_ERROR_INVALID_VALUE;
        }
        cfg->hosts.push_back(host_cfg);

        if (host_cfg.hostname == current_hostname) {
            cfg->host_cfg = host_cfg;
            DOCA_LOG_INFO("Found host configuration for %s", current_hostname.c_str());
            local_host_found = true;
        }
    }
    if (!local_host_found) {
        DOCA_LOG_ERR("No host configuration found for %s", current_hostname.c_str());
        return DOCA_ERROR_NOT_FOUND;
    }

    // Parse geneve_cfg
    for (const auto& node : root["geneve_cfg"]) {
        geneve_encap_ctx_t geneve_encap;
        geneve_encap.remote_ca = ipv4_string_to_u32(node["ca"].as<std::string>());
        geneve_encap.remote_pa = ipv4_string_to_u32(node["pa"].as<std::string>());
        // Assuming next_hop_mac is not provided in the YAML, set it to zero or a default value
        memset(geneve_encap.next_hop_mac.addr_bytes, 0, sizeof(geneve_encap.next_hop_mac.addr_bytes));
        geneve_encap.vni = node["vni"].as<uint32_t>();
        cfg->geneve_encaps.push_back(geneve_encap);

        // For decapsulation, only remote_ca and vni are needed
        geneve_decap_ctx_t geneve_decap;
        geneve_decap.remote_ca = geneve_encap.remote_ca;
        geneve_decap.vni = geneve_encap.vni;
        cfg->geneve_decaps.push_back(geneve_decap);
    }

    // Parse ipsec_cfg
    for (const auto& node : root["ipsec_cfg"]) {
        ipsec_ctx_t ipsec_encap;
        ipsec_encap.remote_pa = ipv4_string_to_u32(node["dst_pa"].as<std::string>());
        ipsec_encap.spi = node["spi"].as<uint32_t>();

        // Convert key from hex string to byte array
        std::string key_str = node["key"].as<std::string>();
        size_t key_len = key_str.length() / 2;  // Each byte is represented by two hex characters
        for (size_t i = 0; i < key_len; ++i) {
            sscanf(key_str.substr(2 * i, 2).c_str(), "%2hhx", &ipsec_encap.key[i]);
        }

        ipsec_encap.key_len_bytes = key_len;

        cfg->ipsec_encaps.push_back(ipsec_encap);

        // Assuming decapsulation context is similar, you might need to adjust based on actual requirements
        ipsec_ctx_t ipsec_decap = ipsec_encap;  // Copy encap context for decapsulation
        cfg->ipsec_decaps.push_back(ipsec_decap);
    }

    // Parse vlan_cfg
    for (const auto& node : root["vlan_cfg"]) {
        vlan_push_ctx_t vlan_push;
        vlan_push.remote_pa = ipv4_string_to_u32(node["dst_pa"].as<std::string>());
        vlan_push.vlan_id = node["vlan"].as<uint16_t>();
        cfg->vlan_pushes.push_back(vlan_push);
    }

    return DOCA_SUCCESS;
}
