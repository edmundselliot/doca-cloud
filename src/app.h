#pragma once

#include <rte_ether.h>
#include <rte_ethdev.h>

#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dpdk.h>

#include "control_path.h"
#include "utils.h"
#include "common.h"

struct entries_status {
	bool failure;	      /* will be set to true if some entry status will not be success */
	int nb_processed;     /* number of entries that was already processed */
	int entries_in_queue; /* number of entries in queue that is waiting to process */
};

class OffloadApp {
private:
    std::string pf_pci;
    std::string core_mask;

    struct doca_dev *pf_dev;
    struct doca_flow_ip_addr pf_ip_addr;
    std::string pf_ip_addr_str;

    struct doca_flow_port *pf;
    struct doca_flow_port *vf;

    uint32_t pf_port_id;
    uint32_t vf_port_id;

    std::string pf_mac_str;
    std::string vf_repr_mac_str;
    rte_ether_addr pf_mac;
    rte_ether_addr vf_repr_mac;

    ControlPath control_path = ControlPath();

    // tx path
    struct doca_flow_pipe *tx_root_pipe;
    struct doca_flow_pipe *rss_pipe;
    struct doca_flow_pipe *tx_geneve_pipe;
    struct doca_flow_pipe *tx_ipsec_pipe;
    struct doca_flow_pipe *tx_vlan_pipe;

    doca_error_t init_doca_flow();
    doca_error_t init_dpdk();
    doca_error_t init_dev();
    doca_error_t start_port(uint16_t port_id, doca_dev *port_dev, doca_flow_port **port);

    static void check_for_valid_entry(doca_flow_pipe_entry *entry,
            uint16_t pipe_queue,
            enum doca_flow_entry_status status,
            enum doca_flow_entry_op op,
            void *user_ctx);

public:
    OffloadApp(std::string pf_pci, std::string core_mask);
    ~OffloadApp();

    doca_error_t init();
};
