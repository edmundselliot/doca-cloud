#include "app.h"

DOCA_LOG_REGISTER(OFFLOAD_APP);

OffloadApp::OffloadApp(struct input_cfg_t *input_cfg) {
    this->app_cfg.input_cfg = input_cfg;

    DOCA_LOG_INFO("Initializing offload app");
    this->pf_pci = input_cfg->host_cfg.pf_pci;
    this->core_mask = "0x3";
    memcpy(&this->vf_mac, &input_cfg->host_cfg.vf_mac, sizeof(rte_ether_addr));

    this->pf_port_id = 0;
    this->vf_port_id = 1;

    this->app_cfg.dpdk_cfg.port_config.nb_ports = 2;
    this->app_cfg.dpdk_cfg.port_config.nb_hairpin_q = 0;
    this->app_cfg.dpdk_cfg.port_config.switch_mode = true;
    this->app_cfg.dpdk_cfg.port_config.enable_mbuf_metadata = true;
    this->app_cfg.dpdk_cfg.port_config.isolated_mode = true;
    this->app_cfg.dpdk_cfg.reserve_main_thread = true;

    // This is set after EAL init because it uses rte_lcore_count()
    this->app_cfg.dpdk_cfg.port_config.nb_queues = -1;

    // Note: 2 reserved SAs for dummy encap/decap
    this->app_cfg.max_ipsec_sessions = 4096;
}

OffloadApp::~OffloadApp() {
    DOCA_LOG_INFO("Destroying offload app");
}

doca_error_t OffloadApp::init() {
    DOCA_LOG_INFO("Initializing DOCA");

    doca_error_t result = init_doca_flow();
    IF_SUCCESS(result, init_dpdk());
    IF_SUCCESS(result, init_dev());
    IF_SUCCESS(result, init_dpdk_queues_ports());

    IF_SUCCESS(result, start_port(pf_port_id, pf_dev, &pf_port));
    IF_SUCCESS(result, start_port(vf_port_id, nullptr, &vf_port));

    pipe_mgr.init(&app_cfg, pf_port, vf_port, pf_port_id, vf_port_id, pf_ip_addr.ipv4_addr, &pf_mac, &vf_mac);

    return result;
}

doca_error_t OffloadApp::init_dpdk_queues_ports() {

    doca_error_t result = dpdk_queues_and_ports_init(&app_cfg.dpdk_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to update application ports and queues: %s", doca_error_get_descr(result));
        return result;
    }

    DOCA_LOG_INFO("DPDK ports and queues initialized");
    return result;
}

doca_error_t OffloadApp::init_dpdk() {
    const char *eal_args[] = {"", "-a", "00:00.0", "-c", core_mask.c_str()};

    int n_eal_args = sizeof(eal_args) / sizeof(eal_args[0]);
    int rc = rte_eal_init(n_eal_args, (char **)eal_args);
    if (rc < 0) {
        DOCA_LOG_ERR("EAL initialization failed: %d", rc);
        for (int i = 0; i < n_eal_args; i++) {
            DOCA_LOG_ERR("EAL arg %d: %s", i, eal_args[i]);
        }
        return DOCA_ERROR_BAD_STATE;
    }

    // This can't be set until EAL init because it uses rte_lcore_count()
    app_cfg.dpdk_cfg.port_config.nb_queues = rte_lcore_count();

    return DOCA_SUCCESS;
}

doca_error_t OffloadApp::init_dev(void)
{
    doca_error_t result = DOCA_SUCCESS;
    std::string dev_probe_str = std::string(
        "dv_flow_en=2,"     // hardware steering
        "dv_xmeta_en=4,"     // extended flow metadata support
        "fdb_def_rule_en=0," // disable default root flow table rule
        "vport_match=1,"
        "repr_matching_en=0,"
        "representor=pf0vf0");

    IF_SUCCESS(result, open_doca_device_with_pci(pf_pci.c_str(), nullptr, &pf_dev));
    IF_SUCCESS(result, doca_dpdk_port_probe(pf_dev, dev_probe_str.c_str()));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to probe device %s: %s", pf_pci.c_str(), doca_error_get_descr(result));
        return result;
    }

    rte_eth_macaddr_get(pf_port_id, &pf_mac);
    pf_mac_str = mac_to_string(pf_mac);

    rte_eth_macaddr_get(vf_port_id, &vf_repr_mac);
    vf_repr_mac_str = mac_to_string(vf_repr_mac);

    pf_ip_addr.type = DOCA_FLOW_L3_TYPE_IP4;
    result = doca_devinfo_get_ipv4_addr(
        doca_dev_as_devinfo(pf_dev),
        (uint8_t *)&pf_ip_addr.ipv4_addr,
        DOCA_DEVINFO_IPV4_ADDR_SIZE);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to find IPv4 addr for PF: %s", doca_error_get_descr(result));
        return result;
    }
    pf_ip_addr_str = ip_to_string(pf_ip_addr);

    DOCA_LOG_INFO("Probed PF %s, VF repr %s on PCI %s", pf_mac_str.c_str(), vf_repr_mac_str.c_str(), pf_pci.c_str());
    DOCA_LOG_INFO("PF IP addr: %s", pf_ip_addr_str.c_str());
    return result;
}

doca_error_t OffloadApp::start_port(uint16_t port_id, doca_dev *port_dev, doca_flow_port **port)
{
    struct doca_flow_port_cfg *port_cfg;
    std::string port_id_str = std::to_string(port_id); // note that set_devargs() clones the string contents

    doca_error_t result = doca_flow_port_cfg_create(&port_cfg);
    IF_SUCCESS(result, doca_flow_port_cfg_set_devargs(port_cfg, port_id_str.c_str()));
    IF_SUCCESS(result, doca_flow_port_cfg_set_dev(port_cfg, port_dev));
    if (port_dev) {
        IF_SUCCESS(result, doca_flow_port_cfg_set_operation_state(port_cfg, DOCA_FLOW_PORT_OPERATION_STATE_ACTIVE));
    }
    IF_SUCCESS(result, doca_flow_port_start(port_cfg, port));
    if (result == DOCA_SUCCESS)
        DOCA_LOG_INFO("Started port_id %d", port_id);

    if (port_cfg)
        doca_flow_port_cfg_destroy(port_cfg);
    return result;
}

doca_error_t OffloadApp::init_doca_flow(void)
{
    doca_error_t result = DOCA_SUCCESS;
    uint16_t nb_queues = 1;

    uint16_t rss_queues[nb_queues];
    for (int i = 0; i < nb_queues; i++)
        rss_queues[i] = i;

    struct doca_flow_resource_rss_cfg rss_config = {};
    rss_config.nr_queues = nb_queues;
    rss_config.queues_array = rss_queues;

    /* init doca flow with crypto shared resources */
    struct doca_flow_cfg *flow_cfg;
    IF_SUCCESS(result, doca_flow_cfg_create(&flow_cfg));
    IF_SUCCESS(result, doca_flow_cfg_set_pipe_queues(flow_cfg, nb_queues));
    IF_SUCCESS(result, doca_flow_cfg_set_queue_depth(flow_cfg, 128));
    IF_SUCCESS(result, doca_flow_cfg_set_nr_counters(flow_cfg, 1024));
    IF_SUCCESS(result, doca_flow_cfg_set_nr_shared_resource(
        flow_cfg, app_cfg.max_ipsec_sessions + 2, DOCA_FLOW_SHARED_RESOURCE_IPSEC_SA));
    IF_SUCCESS(result, doca_flow_cfg_set_mode_args(flow_cfg, "switch,hws"));
    IF_SUCCESS(result, doca_flow_cfg_set_cb_entry_process(flow_cfg, OffloadApp::check_for_valid_entry));
    IF_SUCCESS(result, doca_flow_cfg_set_default_rss(flow_cfg, &rss_config));
    IF_SUCCESS(result, doca_flow_init(flow_cfg));

    if (flow_cfg)
        doca_flow_cfg_destroy(flow_cfg);
    return result;
}

void OffloadApp::check_for_valid_entry(doca_flow_pipe_entry *entry,
                         uint16_t pipe_queue,
                         enum doca_flow_entry_status status,
                         enum doca_flow_entry_op op,
                         void *user_ctx)
{
    (void)entry;
    (void)op;
    (void)pipe_queue;

    auto *entry_status = (entries_status *)user_ctx;

    if (entry_status == nullptr)
        return;

    if (op != DOCA_FLOW_ENTRY_OP_ADD && op != DOCA_FLOW_ENTRY_OP_UPD)
        return;

    if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
        entry_status->failure = true; /* set failure to true if processing failed */

    entry_status->nb_processed++;
}

doca_error_t OffloadApp::handle_arp(uint32_t port_id, uint32_t queue_id, struct rte_mbuf *arp_req_pkt) {
    struct rte_ether_hdr *request_eth_hdr = rte_pktmbuf_mtod(arp_req_pkt, struct rte_ether_hdr *);
    struct rte_arp_hdr *request_arp_hdr = (rte_arp_hdr *)&request_eth_hdr[1];

    uint16_t arp_op = RTE_BE16(request_arp_hdr->arp_opcode);
    if (arp_op != RTE_ARP_OP_REQUEST) {
        DOCA_LOG_WARN("RSS ARP Handler: expected op %d, got %d", RTE_ARP_OP_REQUEST, arp_op);
        return DOCA_SUCCESS;
    }

    struct rte_mbuf *response_pkt = rte_pktmbuf_alloc(app_cfg.dpdk_cfg.mbuf_pool);
    if (!response_pkt) {
        DOCA_LOG_ERR("Out of memory for ARP response packets; exiting");
        return DOCA_ERROR_NO_MEMORY;
    }

    uint32_t pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    response_pkt->data_len = pkt_size;
    response_pkt->pkt_len = pkt_size;

    struct rte_ether_hdr *response_eth_hdr = rte_pktmbuf_mtod(response_pkt, struct rte_ether_hdr *);
    struct rte_arp_hdr *response_arp_hdr = (rte_arp_hdr *)&response_eth_hdr[1];

    rte_eth_macaddr_get(port_id, &response_eth_hdr->src_addr);
    response_eth_hdr->dst_addr = request_eth_hdr->src_addr;
    response_eth_hdr->ether_type = RTE_BE16(DOCA_FLOW_ETHER_TYPE_ARP);

    response_arp_hdr->arp_hardware = RTE_BE16(RTE_ARP_HRD_ETHER);
    response_arp_hdr->arp_protocol = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    response_arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    response_arp_hdr->arp_plen = sizeof(uint32_t);
    response_arp_hdr->arp_opcode = RTE_BE16(RTE_ARP_OP_REPLY);
    rte_eth_macaddr_get(port_id, &response_arp_hdr->arp_data.arp_sha);
    response_arp_hdr->arp_data.arp_tha = request_arp_hdr->arp_data.arp_sha;
    response_arp_hdr->arp_data.arp_sip = request_arp_hdr->arp_data.arp_tip;
    response_arp_hdr->arp_data.arp_tip = request_arp_hdr->arp_data.arp_sip;

    // This ARP reply will go to the rx_root pipe.
    rte_pktmbuf_dump(stdout, response_pkt, response_pkt->pkt_len);

    uint16_t nb_tx_packets = rte_eth_tx_burst(port_id, queue_id, &response_pkt, 1);
    if (nb_tx_packets != 1) {
        DOCA_LOG_WARN("ARP reinject: rte_eth_tx_burst returned %d", nb_tx_packets);
    }

    char ip_addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &request_arp_hdr->arp_data.arp_tip, ip_addr_str, INET_ADDRSTRLEN);
    DOCA_LOG_DBG("Port %d replied to ARP request for IP %s", port_id, ip_addr_str);

    return DOCA_SUCCESS;
}

// This function can be executed in parallel by multiple worker threads!
// Shared data access must be synchronized if needed
doca_error_t OffloadApp::handle_packet(struct rte_mbuf *pkt, uint32_t queue_id) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    uint16_t ether_type = htons(eth_hdr->ether_type);

    // Business logic for exception path packets

    // arp packets
    if (ether_type == DOCA_FLOW_ETHER_TYPE_ARP) {
        handle_arp(pf_port_id, queue_id, pkt);
    }

    // Monitoring, logging, dynamic flow creation, etc.

    rte_pktmbuf_dump(stdout, pkt, pkt->pkt_len);
    return DOCA_SUCCESS;
}

int worker_main(void *arg) {
    worker_params_t *worker_cfg = (worker_params_t *)arg;
    struct rte_mbuf *packets[BURST_SZ];

    while(1) {
        int nb_pkts = rte_eth_rx_burst(worker_cfg->port_id, worker_cfg->queue_id, packets, BURST_SZ);
        if (nb_pkts == 0)
            continue;

        for (int i = 0; i < nb_pkts; i++) {
            doca_error_t result = worker_cfg->app->handle_packet(packets[i], worker_cfg->queue_id);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to handle packet: %s", doca_error_get_descr(result));
                continue;
            }
        }
    }

    delete worker_cfg;
};

doca_error_t OffloadApp::create_geneve_tunnel(
    std::string remote_ca,
    std::string remote_pa,
    rte_ether_addr next_hop_mac,
    uint32_t vni)
{
    doca_error_t result = DOCA_SUCCESS;

    geneve_encap_ctx_t geneve_encap_data = {};
    geneve_encap_data.vni = vni;
    // geneve_encap_data.local_ca = ipv4_string_to_u32(local_ca);
    geneve_encap_data.remote_ca = ipv4_string_to_u32(remote_ca);
    geneve_encap_data.remote_pa = ipv4_string_to_u32(remote_pa);
    rte_ether_addr_copy(&next_hop_mac, &geneve_encap_data.next_hop_mac);
    result = pipe_mgr.tx_geneve_pipe_entry_create(&geneve_encap_data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create tx geneve pipe entry: %s", doca_error_get_descr(result));
        return result;
    }

    geneve_decap_ctx_t geneve_decap_data = {};
    geneve_decap_data.vni = vni;
    geneve_decap_data.remote_ca = ipv4_string_to_u32(remote_ca);
    result = pipe_mgr.rx_geneve_pipe_entry_create(&geneve_decap_data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create rx geneve pipe entry: %s", doca_error_get_descr(result));
        return result;
    }

    return result;
}


doca_error_t OffloadApp::create_vlan_mapping(std::string remote_pa, uint16_t vlan_id) {
    doca_error_t result = DOCA_SUCCESS;

    struct vlan_push_ctx_t vlan_push_data = {};
    vlan_push_data.remote_pa = ipv4_string_to_u32(remote_pa);
    vlan_push_data.vlan_id = vlan_id;
    result = pipe_mgr.tx_vlan_pipe_entry_create(&vlan_push_data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create tx vlan pipe entry: %s", doca_error_get_descr(result));
        return result;
    }

    return result;
}

doca_error_t OffloadApp::create_ipsec_tunnel(
    std::string remote_pa,
    uint32_t enc_spi, uint8_t *enc_key_data, uint32_t enc_key_len,
    uint32_t dec_spi, uint8_t *dec_key_data, uint32_t dec_key_len)
{
    struct ipsec_ctx_t egress_ipsec_ctx = {};
    egress_ipsec_ctx.remote_pa = ipv4_string_to_u32(remote_pa);
    egress_ipsec_ctx.spi = enc_spi;
    memcpy(egress_ipsec_ctx.key, enc_key_data, enc_key_len);
    egress_ipsec_ctx.key_len_bytes = enc_key_len;

    doca_error_t result = pipe_mgr.tx_ipsec_session_create(&egress_ipsec_ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create tx ipsec pipe entry: %s", doca_error_get_descr(result));
        return result;
    }

    struct ipsec_ctx_t ingress_ipsec_ctx = {};
    ingress_ipsec_ctx.remote_pa = ipv4_string_to_u32(remote_pa);
    ingress_ipsec_ctx.spi = dec_spi;
    memcpy(ingress_ipsec_ctx.key, dec_key_data, dec_key_len);
    ingress_ipsec_ctx.key_len_bytes = dec_key_len;

    result = pipe_mgr.rx_ipsec_session_create(&ingress_ipsec_ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create rx ipsec pipe entry: %s", doca_error_get_descr(result));
        return result;
    }

    return DOCA_SUCCESS;
}

doca_error_t OffloadApp::offload_static_flows() {
    doca_error_t result = DOCA_SUCCESS;

    for (auto geneve_cfg : app_cfg.input_cfg->geneve_tunnels) {
        result = create_geneve_tunnel(
            geneve_cfg.remote_ca,
            geneve_cfg.remote_pa,
            geneve_cfg.next_hop_mac,
            geneve_cfg.vni);

        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create geneve tunnel to %s: %s",
                geneve_cfg.remote_ca.c_str(), doca_error_get_descr(result));
            return result;
        }
    }

    for (auto ipsec_cfg : app_cfg.input_cfg->ipsec_tunnels) {
        result = create_ipsec_tunnel(ipsec_cfg.remote_pa,
            ipsec_cfg.enc_spi, ipsec_cfg.enc_key_data, ipsec_cfg.enc_key_len,
            ipsec_cfg.dec_spi, ipsec_cfg.dec_key_data, ipsec_cfg.dec_key_len);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create ipsec tunnel to %s: %s",
                ipsec_cfg.remote_pa.c_str(), doca_error_get_descr(result));
            return result;
        }
    }

    for (auto vlan_cfg : app_cfg.input_cfg->vlan_pushes) {
        result = create_vlan_mapping(vlan_cfg.remote_pa, vlan_cfg.vlan_id);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create vlan mapping to %s: %s",
                vlan_cfg.remote_pa.c_str(), doca_error_get_descr(result));
            return result;
        }
    }

    return result;
}

doca_error_t OffloadApp::run() {
    doca_error_t result = DOCA_SUCCESS;

    uint32_t lcore_id;
    uint32_t next_queue_id = 0;

    result = offload_static_flows();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to offload static flows: %s", doca_error_get_descr(result));
        return result;
    }

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        DOCA_LOG_INFO("Starting worker lcore %u", lcore_id);

        struct worker_params_t *worker_params = new worker_params_t();
        worker_params->port_id = pf_port_id;
        worker_params->queue_id = next_queue_id++;
        worker_params->app = this;

        rte_eal_remote_launch(worker_main, worker_params, lcore_id);
    }

    while(1) {
        pipe_mgr.print_stats();
        sleep(2);
    }

    return result;
}
