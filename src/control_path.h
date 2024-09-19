#pragma once

#include <map>
#include <string>

#include "doca_log.h"

class ControlPath {
private:
    // ca <-> pa mappings for geneve pipe
    std::map<std::string, std::string> ca_to_pa_mappings;
    // pa <-> tnl mappings for ipsec pipe
    std::map<std::string, std::string> pa_to_tnl_mappings;
    // pa <-> vlan mappings for vlan pipe
    std::map<std::string, std::string> pa_to_vlan_mappings;

public:
    // get pa for a ca
    std::string get_pa_for_ca(std::string ca) {
        return ca_to_pa_mappings[ca];
    }
    // get tnl info for a pa
    std::string get_tnl_for_pa(std::string pa) {
        return pa_to_tnl_mappings[pa];
    }
    // get vlan info for a pa
    std::string get_vlan_for_pa(std::string pa) {
        return pa_to_vlan_mappings[pa];
    }

    ControlPath();
    ~ControlPath();
};