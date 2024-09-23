#include "control_path.h"

DOCA_LOG_REGISTER(CONTROL_PATH);

ControlPath::ControlPath() {
    DOCA_LOG_INFO("Initializing control path");

    // ca <-> pa mappings for geneve pipe
    ca_to_tnl_mappings["60.0.0.65"] = {
        "100.0.0.65",
        1234
    };
    ca_to_tnl_mappings["60.0.0.66"] = {
        "100.0.0.66",
        1234
    };

    // pa <-> tnl mappings for ipsec pipe
    pa_to_tnl_mappings["10.137.189.65"] = "tnl1";
    pa_to_tnl_mappings["10.137.189.66"] = "tnl2";

    // pa <-> vlan mappings for vlan pipe
    pa_to_vlan_mappings["10.137.189.65"] = "vlan1";
    pa_to_vlan_mappings["10.137.189.66"] = "vlan2";
}

ControlPath::~ControlPath() {
    DOCA_LOG_INFO("Destroying control path");
}