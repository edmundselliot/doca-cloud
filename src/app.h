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

#include "control_path.h"
#include "pipe_mgr.h"
#include "main.h"

#define BURST_SZ 64

class OffloadApp {
private:
    std::string pf_pci;
    rte_ether_addr vf_mac;

    struct cloud_app_cfg_t app_cfg;
    std::string core_mask;

    struct doca_dev *pf_dev;
    struct doca_flow_ip_addr pf_ip_addr;
    std::string pf_ip_addr_str;

    struct doca_flow_port *pf_port;
    struct doca_flow_port *vf_port;

    uint32_t pf_port_id;
    uint32_t vf_port_id;

    std::string pf_mac_str;
    std::string vf_repr_mac_str;
    rte_ether_addr pf_mac;
    rte_ether_addr vf_repr_mac;

    ControlPath control_path = ControlPath();
    PipeMgr pipe_mgr = PipeMgr();

    doca_error_t init_doca_flow();
    doca_error_t init_dpdk();
    doca_error_t init_dev();
    doca_error_t init_dpdk_queues_ports();
    doca_error_t start_port(uint16_t port_id, doca_dev *port_dev, doca_flow_port **port);

    static void check_for_valid_entry(doca_flow_pipe_entry *entry,
            uint16_t pipe_queue,
            enum doca_flow_entry_status status,
            enum doca_flow_entry_op op,
            void *user_ctx);

    doca_error_t handle_arp(uint32_t port_id, uint32_t queue_id, struct rte_mbuf *arp_req_pkt);
    doca_error_t offload_static_flows();

    doca_error_t create_geneve_tunnel(std::string remote_ca, std::string remote_pa, rte_ether_addr next_hop_mac, uint32_t vni);
    doca_error_t create_vlan_mapping(std::string remote_pa, uint16_t vlan);

public:
    OffloadApp(std::string pf_pci, std::string core_mask, rte_ether_addr vf_mac);
    ~OffloadApp();

    doca_error_t init();
    doca_error_t run();
    doca_error_t handle_packet(struct rte_mbuf *pkt, uint32_t queue_id);
};

// Data that is unique to a worker thread
struct worker_params_t {
    uint32_t port_id;
    uint32_t queue_id;
    OffloadApp *app;
};
