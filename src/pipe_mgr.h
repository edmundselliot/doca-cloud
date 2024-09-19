#pragma once

#include <unistd.h>

#include <rte_ether.h>
#include <rte_ethdev.h>

#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dpdk.h>

#include "utils.h"

/*
    High-level pipe topology

       VF tx                VF rx
         │                    ▲
   ┌─────▼───────┐            │
   │tx root pipe │            │
   └─────┬───────┘            │
   ┌─────▼───────┐            │
   │tx selector  │            │
   └─────┬───────┘            │
   ┌─────▼───────┐     ┌──────┼───────┐
   │geneve egress│     │geneve ingress│
   └─────┬───────┘     └──────▲───────┘
   ┌─────▼───────┐     ┌──────┼───────┐
   │ipsec egress │     │ipsec ingress │
   └─────┬───────┘     └──────▲───────┘
   ┌─────▼───────┐     ┌──────┼───────┐
   │vlan egress  │     │vlan ingress  │
   └─────┬───────┘     └──────▲───────┘
         │             ┌──────┼───────┐
         │             │rx root pipe  │
         │             └──────▲───────┘
         ▼                    │
      wire tx             wire rx
*/

class PipeMgr {
private:
    uint32_t pf_port_id;
    struct doca_flow_port *pf_port;
    uint32_t vf_port_id;
    struct doca_flow_port *vf_port;

    struct doca_flow_pipe *rss_pipe;
    struct doca_flow_pipe *tx_root_pipe;
    struct doca_flow_pipe *tx_selector_pipe;
    struct doca_flow_pipe *tx_geneve_pipe;
    struct doca_flow_pipe *tx_ipsec_pipe;
    struct doca_flow_pipe *tx_vlan_pipe;
    struct doca_flow_pipe *rx_root_pipe;
    struct doca_flow_pipe *rx_geneve_pipe;
    struct doca_flow_pipe *rx_ipsec_pipe;
    struct doca_flow_pipe *rx_vlan_pipe;

    struct doca_flow_pipe_entry *rss_pipe_default_entry;
    struct doca_flow_pipe_entry *tx_root_pipe_default_entry;
    struct doca_flow_pipe_entry *rx_root_pipe_default_entry;

    struct doca_flow_monitor monitor_count = {};
    struct doca_flow_fwd fwd_drop = {};

    doca_error_t create_pipes();
    doca_error_t rss_pipe_create();
    doca_error_t tx_root_pipe_create(doca_flow_pipe *next_pipe);
    doca_error_t tx_selector_pipe_create();
    doca_error_t tx_geneve_pipe_create();
    doca_error_t tx_ipsec_pipe_create();
    doca_error_t tx_vlan_pipe_create();
    doca_error_t rx_root_pipe_create(doca_flow_pipe *next_pipe);
    doca_error_t rx_geneve_pipe_create();
    doca_error_t rx_ipsec_pipe_create();
    doca_error_t rx_vlan_pipe_create();

    void print_pipe_entry_stats(struct doca_flow_pipe_entry* entry, std::string entry_name);
    void print_pipe_stats(struct doca_flow_pipe* pipe, std::string pipe_name);

public:
    PipeMgr();
    ~PipeMgr();

    doca_error_t init(doca_flow_port *pf_port, doca_flow_port *vf_port, uint32_t pf_port_id, uint32_t vf_port_id) {
        this->pf_port_id = pf_port_id;
        this->vf_port_id = vf_port_id;
        this->pf_port = pf_port;
        this->vf_port = vf_port;

        return create_pipes();
    }

    void print_stats();
};