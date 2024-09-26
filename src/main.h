#pragma once

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

struct cloud_app_cfg_t {
    struct application_dpdk_config dpdk_cfg; //!< Configuration details of DPDK ports and queues
	std::string core_mask; //!< EAL core mask
    uint32_t max_ipsec_sessions;
};
