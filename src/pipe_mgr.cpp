#include "pipe_mgr.h"

DOCA_LOG_REGISTER(PIPE_MGR);

PipeMgr::PipeMgr() {
	monitor_count.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	fwd_drop.type = DOCA_FLOW_FWD_DROP;
}

PipeMgr::~PipeMgr() {}

doca_error_t PipeMgr::init(
	struct cloud_app_cfg_t *app_cfg,
	struct doca_flow_port *pf_port,
	struct doca_flow_port *vf_port,
	uint32_t pf_port_id,
	uint32_t vf_port_id,
	uint32_t pf_pa,
	rte_ether_addr *pf_mac,
	rte_ether_addr *vf_mac)
{
	this->app_cfg = app_cfg;
	this->pf_port_id = pf_port_id;
	this->vf_port_id = vf_port_id;
	this->pf_port = pf_port;
	this->vf_port = vf_port;

	this->pf_pa = pf_pa;
	rte_ether_addr_copy(pf_mac, &this->pf_mac);
	rte_ether_addr_copy(vf_mac, &this->vf_mac);

	for (uint32_t i = 0; i < app_cfg->max_ipsec_sessions; ++i) {
		ipsec_sa_idxs.insert(i);
	}

	doca_error_t result = DOCA_SUCCESS;
	dummy_encap_decap_sa_ctx.icv_length = DOCA_FLOW_CRYPTO_ICV_LENGTH_8;
	dummy_encap_decap_sa_ctx.key_type = DOCA_FLOW_CRYPTO_KEY_256;
	dummy_encap_decap_sa_ctx.key[0] = 0x01;
	dummy_encap_decap_sa_ctx.salt = 0x12345678;

	dummy_encap_crypto_id = app_cfg->max_ipsec_sessions;
	dummy_decap_crypto_id = app_cfg->max_ipsec_sessions + 1;
	IF_SUCCESS(result, bind_ipsec_sa_ids());
	IF_SUCCESS(result, create_ipsec_sa(&dummy_encap_decap_sa_ctx, dummy_encap_crypto_id, true));
	IF_SUCCESS(result, create_ipsec_sa(&dummy_encap_decap_sa_ctx, dummy_decap_crypto_id, false));

	IF_SUCCESS(result, create_pipes());

	return result;
}

doca_error_t PipeMgr::create_pipes() {
    doca_error_t result = DOCA_SUCCESS;

    IF_SUCCESS(result, rss_pipe_create());

	IF_SUCCESS(result, tx_vlan_pipe_create());
	IF_SUCCESS(result, tx_ipsec_pipe_create());
	IF_SUCCESS(result, tx_geneve_pipe_create());
    IF_SUCCESS(result, tx_root_pipe_create());

	IF_SUCCESS(result, rx_geneve_pipe_create());
	IF_SUCCESS(result, rx_ipsec_pipe_create());
	IF_SUCCESS(result, rx_vlan_pipe_create());
    IF_SUCCESS(result, rx_root_pipe_create());

    if (result == DOCA_SUCCESS)
        DOCA_LOG_INFO("Created all static pipes on port %d", pf_port_id);
    else
        DOCA_LOG_ERR("Failed to create all static pipes on port %d, err: %s", pf_port_id, doca_error_get_descr(result));

    return result;
}

void PipeMgr::print_stats() {
	DOCA_LOG_INFO("=================================");
	struct doca_flow_resource_query stats;
	doca_error_t result;

	DOCA_LOG_INFO("ENTRIES:");
	for (auto entry : monitored_pipe_entries) {
		result = doca_flow_resource_query_entry(entry.second, &stats);
        if (result == DOCA_SUCCESS)
            DOCA_LOG_INFO("  %s hit: %lu packets", entry.first.c_str(), stats.counter.total_pkts);
		else
            DOCA_LOG_ERR("Failed to query entry %s: %s", entry.first.c_str(), doca_error_get_descr(result));
	}

	DOCA_LOG_INFO("PIPES:");
	for (auto pipe : monitored_pipe_misses) {
		result = doca_flow_resource_query_pipe_miss(pipe.second, &stats);
        if (result == DOCA_SUCCESS)
            DOCA_LOG_INFO("  %s miss: %lu pkts", pipe.first.c_str(), stats.counter.total_pkts);
        else
            DOCA_LOG_ERR("Failed to query pipe %s miss: %s", pipe.first.c_str(), doca_error_get_descr(result));
	}
}


doca_error_t PipeMgr::rss_pipe_create() {
    assert(pf_port);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_all = {};

    // For now use a single RSS queue
    uint16_t rss_queues[1] = {0};
	struct doca_flow_fwd fwd_rss_q = {};
	fwd_rss_q.type = DOCA_FLOW_FWD_RSS;
	fwd_rss_q.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6;
	fwd_rss_q.num_of_queues = 1;
	fwd_rss_q.rss_queues = rss_queues;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "RSS_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_all, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_rss_q, &fwd_drop, &rss_pipe));
	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

    IF_SUCCESS(
		result,
		add_single_entry(0, rss_pipe, pf_port, nullptr, nullptr, nullptr, nullptr, &rss_pipe_default_entry));

	monitored_pipe_entries.push_back(std::make_pair("RSS_PIPE_DEFAULT_ENTRY", rss_pipe_default_entry));
	monitored_pipe_misses.push_back(std::make_pair("RSS_PIPE", rss_pipe));

	this->fwd_rss.type = DOCA_FLOW_FWD_PIPE;
	this->fwd_rss.next_pipe = rss_pipe;

	return result;
}

doca_error_t PipeMgr::tx_vlan_pipe_create() {
    assert(pf_port);

    doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_dip = {};
    match_dip.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    match_dip.outer.ip4.dst_ip = 0xffffffff;

	struct doca_flow_fwd fwd_to_wire = {};
    fwd_to_wire.type = DOCA_FLOW_FWD_PORT;
    fwd_to_wire.port_id = pf_port_id;

    struct doca_flow_actions actions = {};
    actions.has_push = true;
	actions.push.type = DOCA_FLOW_PUSH_ACTION_VLAN;
	actions.push.vlan.eth_type = rte_cpu_to_be_16(DOCA_FLOW_ETHER_TYPE_VLAN);
	actions.push.vlan.vlan_hdr.tci = rte_cpu_to_be_16(0xffff);
	struct doca_flow_actions *actions_arr[] = {&actions};

    struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "TX_VLAN_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_dip, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	// VLAN push is optional. On both hit and miss, forward to wire.
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_to_wire, &fwd_to_wire, &tx_vlan_pipe));
    if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	monitored_pipe_misses.push_back(std::make_pair("TX_VLAN_PIPE", tx_vlan_pipe));

    return result;
}

doca_error_t PipeMgr::tx_root_pipe_create() {
    assert(pf_port);
    assert(tx_geneve_pipe);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_all = {};

	struct doca_flow_fwd fwd_pipe = {};
	fwd_pipe.type = DOCA_FLOW_FWD_PIPE;
	fwd_pipe.next_pipe = tx_geneve_pipe;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "TX_ROOT"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_all, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_pipe, &fwd_drop, &tx_root_pipe));
	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	IF_SUCCESS(
		result,
		add_single_entry(0, tx_root_pipe, pf_port, nullptr, nullptr, nullptr, nullptr, &tx_root_pipe_default_entry));

	monitored_pipe_entries.push_back(std::make_pair("TX_ROOT_PIPE_DEFAULT_ENTRY", tx_root_pipe_default_entry));
	monitored_pipe_misses.push_back(std::make_pair("TX_ROOT_PIPE", tx_root_pipe));

	return result;
}

doca_error_t PipeMgr::rx_root_pipe_create() {
    assert(pf_port);
    assert(tx_root_pipe);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_rx_port = {};
	match_rx_port.parser_meta.port_meta = UINT32_MAX;

	struct doca_flow_fwd fwd_changeable = {};
	fwd_changeable.type = DOCA_FLOW_FWD_CHANGEABLE;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "RX_ROOT"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_rx_port, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_changeable, &fwd_drop, &rx_root_pipe));
	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	monitored_pipe_misses.push_back(std::make_pair("RX_ROOT_PIPE", rx_root_pipe));

	struct doca_flow_fwd fwd_tx = {};
	fwd_tx.type = DOCA_FLOW_FWD_PIPE;
	fwd_tx.next_pipe = tx_root_pipe;
	match_rx_port.parser_meta.port_meta = vf_port_id;
	IF_SUCCESS(
		result,
		add_single_entry(0, rx_root_pipe, pf_port, &match_rx_port, nullptr, nullptr, &fwd_tx, &rx_root_pipe_from_vf_entry));
	monitored_pipe_entries.push_back(std::make_pair("RX_ROOT_PIPE_FROM_VF", rx_root_pipe_from_vf_entry));

	struct doca_flow_fwd fwd_rx = {};
	fwd_rx.type = DOCA_FLOW_FWD_PIPE;
	fwd_rx.next_pipe = rx_vlan_pipe;
	match_rx_port.parser_meta.port_meta = pf_port_id;
	IF_SUCCESS(
		result,
		add_single_entry(1, rx_root_pipe, pf_port, &match_rx_port, nullptr, nullptr, &fwd_rx, &rx_root_pipe_from_pf_entry));
	monitored_pipe_entries.push_back(std::make_pair("RX_ROOT_PIPE_FROM_PF", rx_root_pipe_from_pf_entry));

	return result;
}

doca_error_t PipeMgr::tx_geneve_pipe_create()
{
	assert(pf_port);
	assert(tx_ipsec_pipe);

	struct doca_flow_match match_remote_ca = {};
	match_remote_ca.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match_remote_ca.outer.ip4.dst_ip = 0xffffffff;

	struct doca_flow_fwd fwd_hit = {};
	fwd_hit.type = DOCA_FLOW_FWD_PIPE;
	fwd_hit.next_pipe = tx_ipsec_pipe;

	struct doca_flow_actions actions = {};
	actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	actions.encap_cfg.is_l2 = false;
	actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GENEVE;
	actions.encap_cfg.encap.tun.geneve.vni = 0xffffffff;
	actions.encap_cfg.encap.tun.geneve.next_proto = RTE_BE16(DOCA_FLOW_ETHER_TYPE_IPV4);
	rte_ether_addr_copy(&pf_mac, (struct rte_ether_addr *)&actions.encap_cfg.encap.outer.eth.src_mac);
	for (int i = 0; i < 6; i++) {
		actions.encap_cfg.encap.outer.eth.dst_mac[i] = 0xff;
	}
	actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions.encap_cfg.encap.outer.ip4.src_ip = pf_pa;
	actions.encap_cfg.encap.outer.ip4.ttl = UINT8_MAX;
	actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(DOCA_FLOW_GENEVE_DEFAULT_PORT);
	actions.encap_cfg.encap.outer.ip4.dst_ip = UINT32_MAX;

	struct doca_flow_actions *actions_ptr_arr[] = { &actions };

	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "GENEVE_ENCAP_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_remote_ca, NULL));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_ptr_arr, NULL, NULL, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	// On miss, forward to RSS for monitoring/logging
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_hit, &fwd_rss, &tx_geneve_pipe));
	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	monitored_pipe_misses.push_back(std::make_pair("GENEVE_ENCAP_PIPE", tx_geneve_pipe));

	return result;
}

doca_error_t PipeMgr::tx_geneve_pipe_entry_create(geneve_encap_ctx_t *encap_ctx) {
	struct doca_flow_pipe_entry *new_entry;

	struct doca_flow_match match_remote_ca = {};
	match_remote_ca.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match_remote_ca.outer.ip4.dst_ip = encap_ctx->remote_ca;

	struct doca_flow_actions actions = {};
	actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	actions.encap_cfg.is_l2 = false;
	actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GENEVE;
	rte_ether_addr_copy(&pf_mac, (struct rte_ether_addr *)&actions.encap_cfg.encap.outer.eth.src_mac);
	actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions.encap_cfg.encap.outer.ip4.src_ip = pf_pa;
	actions.encap_cfg.encap.outer.ip4.ttl = UINT8_MAX;
	actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(DOCA_FLOW_GENEVE_DEFAULT_PORT);
	actions.encap_cfg.encap.tun.geneve.next_proto = RTE_BE16(DOCA_FLOW_ETHER_TYPE_IPV4);
	rte_ether_addr_copy(&encap_ctx->next_hop_mac, (struct rte_ether_addr *)&actions.encap_cfg.encap.outer.eth.dst_mac);
	actions.encap_cfg.encap.outer.ip4.dst_ip = encap_ctx->remote_pa;
	actions.encap_cfg.encap.tun.geneve.vni = BUILD_VNI(encap_ctx->vni);

	doca_error_t result = add_single_entry(0, tx_geneve_pipe, pf_port, &match_remote_ca, &actions, NULL, NULL, &new_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry to TX_GENEVE_PIPE: %s", doca_error_get_descr(result));
		return result;
	}

	std::string entry_name = "TX_GENEVE_PIPE_ENTRY_" + ipv4_to_string(encap_ctx->remote_ca);
	monitored_pipe_entries.push_back(std::make_pair(entry_name, new_entry));

	return DOCA_SUCCESS;
}

doca_error_t PipeMgr::rx_geneve_pipe_create() {
	assert(pf_port);

	struct doca_flow_pipe_cfg *pipe_cfg;

	struct doca_flow_match match = {};
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.parser_meta.inner_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.tun.type = DOCA_FLOW_TUN_GENEVE;
	match.tun.geneve.vni = UINT32_MAX;
	match.inner.ip4.src_ip = UINT32_MAX;
	match.outer.ip4.dst_ip = pf_pa;

	struct doca_flow_actions decap_action = {};
	decap_action.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	decap_action.decap_cfg.is_l2 = true;
	decap_action.decap_cfg.eth.type = UINT16_MAX;
	rte_ether_addr_copy(&pf_mac, (struct rte_ether_addr *)&decap_action.decap_cfg.eth.src_mac);
	rte_ether_addr_copy(&vf_mac, (struct rte_ether_addr *)&decap_action.decap_cfg.eth.dst_mac);
	struct doca_flow_actions *actions_arr[] = { &decap_action };

	struct doca_flow_fwd fwd_to_vf = {};
    fwd_to_vf.type = DOCA_FLOW_FWD_PORT;
    fwd_to_vf.port_id = vf_port_id;

	doca_error_t result = DOCA_SUCCESS;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "GENEVE_DECAP_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, actions_arr, NULL, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	// On miss, forward to RSS for monitoring/logging
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_to_vf, &fwd_rss, &rx_geneve_pipe));
	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	monitored_pipe_misses.push_back(std::make_pair("GENEVE_DECAP_PIPE", rx_geneve_pipe));

	return result;
}

doca_error_t PipeMgr::rx_geneve_pipe_entry_create(geneve_decap_ctx_t *decap_ctx) {
	struct doca_flow_pipe_entry *new_entry;

	struct doca_flow_match match_geneve = {};
	match_geneve.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match_geneve.parser_meta.inner_l3_type = DOCA_FLOW_L3_META_IPV4;
	match_geneve.tun.type = DOCA_FLOW_TUN_GENEVE;

	match_geneve.tun.geneve.vni = BUILD_VNI(decap_ctx->vni);
	match_geneve.inner.ip4.src_ip = decap_ctx->remote_ca;

	struct doca_flow_actions decap_action = {};
	decap_action.decap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	decap_action.decap_cfg.is_l2 = false;
	decap_action.decap_cfg.eth.type = UINT16_MAX;

	doca_error_t result = add_single_entry(0, rx_geneve_pipe, pf_port, &match_geneve, &decap_action, NULL, NULL, &new_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry to TX_GENEVE_PIPE: %s", doca_error_get_descr(result));
		return result;
	}

	std::string entry_name = "RX_GENEVE_PIPE_ENTRY_" + ipv4_to_string(decap_ctx->remote_ca);
	monitored_pipe_entries.push_back(std::make_pair(entry_name, new_entry));

	return DOCA_SUCCESS;
}

doca_error_t PipeMgr::rx_vlan_pipe_create() {
    assert(pf_port);
	assert(rx_ipsec_pipe);

    doca_error_t result = DOCA_SUCCESS;

	// Strip any VLAN header
	struct doca_flow_match match_vlan = {};
	match_vlan.outer.eth_vlan[0].tci = 0xffff;

    struct doca_flow_actions actions = {};
    actions.pop_vlan = true;
	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd_ipsec_pipe = {};
	fwd_ipsec_pipe.type = DOCA_FLOW_FWD_PIPE;
	fwd_ipsec_pipe.next_pipe = rx_ipsec_pipe;

    struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "RX_VLAN_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_vlan, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_ipsec_pipe, &fwd_ipsec_pipe, &rx_vlan_pipe));
    if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	monitored_pipe_misses.push_back(std::make_pair("RX_VLAN_PIPE", rx_vlan_pipe));

	IF_SUCCESS(result,
		add_single_entry(0, rx_vlan_pipe, pf_port, nullptr, nullptr, nullptr, nullptr, &rx_vlan_pipe_default_entry));

	monitored_pipe_entries.push_back(std::make_pair("RX_VLAN_PIPE_POP", rx_vlan_pipe_default_entry));

    return result;
}

doca_error_t PipeMgr::tx_vlan_pipe_entry_create(struct vlan_push_ctx_t* vlan_ctx) {
	assert(tx_vlan_pipe);

	struct doca_flow_pipe_entry *new_entry;

	struct doca_flow_match match_dip = {};
	match_dip.outer.ip4.dst_ip = vlan_ctx->remote_pa;

	struct doca_flow_actions actions = {};
	actions.has_push = true;
	actions.push.type = DOCA_FLOW_PUSH_ACTION_VLAN;
	actions.push.vlan.eth_type = rte_cpu_to_be_16(DOCA_FLOW_ETHER_TYPE_VLAN);
	actions.push.vlan.vlan_hdr.tci = rte_cpu_to_be_16(vlan_ctx->vlan_id);

	doca_error_t result = add_single_entry(0, tx_vlan_pipe, pf_port, &match_dip, &actions, NULL, NULL, &new_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry to TX_VLAN_PIPE: %s", doca_error_get_descr(result));
		return result;
	}

	std::string entry_name = "TX_VLAN_PIPE_ENTRY_" + ipv4_to_string(vlan_ctx->remote_pa);
	monitored_pipe_entries.push_back(std::make_pair(entry_name, new_entry));

	return DOCA_SUCCESS;
}

doca_error_t PipeMgr::rx_ipsec_pipe_create() {
	struct doca_flow_match match_remote_pa_esp = {};
	match_remote_pa_esp.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match_remote_pa_esp.outer.ip4.src_ip = 0xffffffff;
	match_remote_pa_esp.tun.type = DOCA_FLOW_TUN_ESP;
	match_remote_pa_esp.tun.esp_spi = 0xffffffff;

	struct doca_flow_actions actions = {};
	actions.crypto.action_type = DOCA_FLOW_CRYPTO_ACTION_DECRYPT;
	actions.crypto.resource_type = DOCA_FLOW_CRYPTO_RESOURCE_IPSEC_SA;
	actions.crypto.crypto_id = dummy_decap_crypto_id;
	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd_geneve_pipe = {};
	fwd_geneve_pipe.type = DOCA_FLOW_FWD_PIPE;
	fwd_geneve_pipe.next_pipe = rx_geneve_pipe;

	struct doca_flow_pipe_cfg *pipe_cfg;
	doca_error_t result = DOCA_SUCCESS;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "RX_IPSEC_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_enable_strict_matching(pipe_cfg, true));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_NETWORK_TO_HOST));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_remote_pa_esp, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_geneve_pipe, &fwd_geneve_pipe, &rx_ipsec_pipe));
    if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	monitored_pipe_misses.push_back(std::make_pair("RX_IPSEC_PIPE", rx_ipsec_pipe));

	assert(result == DOCA_SUCCESS);
	return result;
}

doca_error_t PipeMgr::rx_ipsec_pipe_entry_create(uint32_t remote_pa, uint32_t spi, uint32_t sa_idx) {
	struct doca_flow_pipe_entry *new_entry;

	struct doca_flow_match match_remote_pa_esp = {};
	match_remote_pa_esp.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match_remote_pa_esp.outer.ip4.src_ip = remote_pa;
	match_remote_pa_esp.tun.type = DOCA_FLOW_TUN_ESP;
	match_remote_pa_esp.tun.esp_spi = rte_cpu_to_be_32(spi);

	struct doca_flow_actions actions = {};
	actions.crypto.action_type = DOCA_FLOW_CRYPTO_ACTION_DECRYPT;
	actions.crypto.resource_type = DOCA_FLOW_CRYPTO_RESOURCE_IPSEC_SA;
	actions.crypto.crypto_id = sa_idx;

	doca_error_t result = add_single_entry(0, rx_ipsec_pipe, pf_port, &match_remote_pa_esp, &actions, NULL, NULL, &new_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry to TX_IPSEC_PIPE: %s", doca_error_get_descr(result));
		return result;
	}

	std::string entry_name = "RX_IPSEC_PIPE_ENTRY_" + ipv4_to_string(remote_pa);
	monitored_pipe_entries.push_back(std::make_pair(entry_name, new_entry));

	return DOCA_SUCCESS;
}

doca_error_t PipeMgr::tx_ipsec_pipe_create() {
	assert(pf_port);
	assert(tx_vlan_pipe);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_remote_pa = {};
	match_remote_pa.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match_remote_pa.outer.ip4.dst_ip = 0xffffffff;

	struct doca_flow_actions actions = {};
	// transport mode - no encap/decap, just ESP header below existing outer IP
	actions.crypto_encap.net_type = DOCA_FLOW_CRYPTO_HEADER_ESP_OVER_IPV4;
	memset(actions.crypto_encap.encap_data, 0xff, 16);
	actions.crypto_encap.action_type = DOCA_FLOW_CRYPTO_REFORMAT_ENCAP;
	actions.crypto.action_type = DOCA_FLOW_CRYPTO_ACTION_ENCRYPT;
	actions.crypto_encap.data_size = 16;
	actions.crypto_encap.icv_size = 8;
	actions.has_crypto_encap = true;
	actions.crypto.resource_type = DOCA_FLOW_CRYPTO_RESOURCE_IPSEC_SA;
	actions.crypto.crypto_id = dummy_encap_crypto_id;
	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd_vlan_pipe = {};
	fwd_vlan_pipe.type = DOCA_FLOW_FWD_PIPE;
	fwd_vlan_pipe.next_pipe = tx_vlan_pipe;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "TX_IPSEC_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_remote_pa, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_HOST_TO_NETWORK));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_enable_strict_matching(pipe_cfg, true));
	// On miss, forward to RSS for monitoring/logging
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_vlan_pipe, &fwd_rss, &tx_ipsec_pipe));
    if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	monitored_pipe_misses.push_back(std::make_pair("TX_IPSEC_PIPE", tx_ipsec_pipe));

	assert(result == DOCA_SUCCESS);
	return result;
}

doca_error_t PipeMgr::bind_ipsec_sa_ids()
{
	std::vector<uint32_t> sa_idx_to_bind(ipsec_sa_idxs.begin(), ipsec_sa_idxs.end());
	sa_idx_to_bind.push_back(dummy_encap_crypto_id);
	sa_idx_to_bind.push_back(dummy_decap_crypto_id);

	doca_error_t result = doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_IPSEC_SA, sa_idx_to_bind.data(), sa_idx_to_bind.size(), pf_port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to bind IPsec SA IDs: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PipeMgr::tx_ipsec_session_create(struct ipsec_ctx_t *ipsec_ctx) {
	doca_error_t result = DOCA_SUCCESS;

	// Get an available SA idx
	uint32_t sa_idx;
	IF_SUCCESS(result, get_available_ipsec_sa_idx(&sa_idx));

	// Put the key in the new SA idx
	struct ipsec_sa_ctx_t ipsec_sa_ctx = {};
	ipsec_sa_ctx.icv_length = DOCA_FLOW_CRYPTO_ICV_LENGTH_8;
	ipsec_sa_ctx.key_type = DOCA_FLOW_CRYPTO_KEY_256;
	memcpy(&ipsec_sa_ctx.key, ipsec_ctx->key, sizeof(ipsec_ctx->key));
	ipsec_sa_ctx.salt = 0x12345678;
	ipsec_sa_ctx.esn_en = false;
	IF_SUCCESS(result, create_ipsec_sa(&ipsec_sa_ctx, sa_idx, true));

	// Create the entry with the new SA idx
	IF_SUCCESS(result, tx_ipsec_pipe_entry_create(ipsec_ctx->remote_pa, ipsec_ctx->spi, sa_idx));

	return result;
}

doca_error_t PipeMgr::rx_ipsec_session_create(struct ipsec_ctx_t *ipsec_ctx) {
	doca_error_t result = DOCA_SUCCESS;

	// Get an available SA idx
	uint32_t sa_idx;
	IF_SUCCESS(result, get_available_ipsec_sa_idx(&sa_idx));

	// Put the key in the new SA idx
	struct ipsec_sa_ctx_t ipsec_sa_ctx = {};
	ipsec_sa_ctx.icv_length = DOCA_FLOW_CRYPTO_ICV_LENGTH_8;
	ipsec_sa_ctx.key_type = DOCA_FLOW_CRYPTO_KEY_256;
	memcpy(&ipsec_sa_ctx.key, ipsec_ctx->key, sizeof(ipsec_ctx->key));
	ipsec_sa_ctx.salt = 0x12345678;
	ipsec_sa_ctx.esn_en = false;
	IF_SUCCESS(result, create_ipsec_sa(&ipsec_sa_ctx, sa_idx, false));

	// Create the entry with the new SA idx
	IF_SUCCESS(result, rx_ipsec_pipe_entry_create(ipsec_ctx->remote_pa, ipsec_ctx->spi, sa_idx));

	return result;
}

doca_error_t PipeMgr::tx_ipsec_pipe_entry_create(uint32_t remote_pa, uint32_t spi, uint32_t sa_idx) {
	struct doca_flow_pipe_entry *new_entry;

	uint8_t reformat_encap_data[16] = {
		GET_BYTE(spi, 3),
		GET_BYTE(spi, 2),
		GET_BYTE(spi, 1),
		GET_BYTE(spi, 0),
		0,0,0,0,
		0,0,0,0,
		0,0,0,0
	};

	struct doca_flow_match match_remote_pa = {};
	match_remote_pa.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match_remote_pa.outer.ip4.dst_ip = remote_pa;

	struct doca_flow_actions actions = {};
	actions.has_crypto_encap = true;
	actions.crypto.crypto_id = sa_idx;
	memcpy(&actions.crypto_encap.encap_data, reformat_encap_data, sizeof(reformat_encap_data));
	actions.crypto_encap.data_size = sizeof(reformat_encap_data);
	actions.crypto_encap.icv_size = DOCA_FLOW_CRYPTO_ICV_LENGTH_8;

	doca_error_t result = add_single_entry(0, tx_ipsec_pipe, pf_port, &match_remote_pa, &actions, NULL, NULL, &new_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry to TX_IPSEC_PIPE: %s", doca_error_get_descr(result));
		return result;
	}

	std::string entry_name = "TX_IPSEC_PIPE_ENTRY_" + ipv4_to_string(remote_pa);
	monitored_pipe_entries.push_back(std::make_pair(entry_name, new_entry));

	return DOCA_SUCCESS;
}

doca_error_t PipeMgr::get_available_ipsec_sa_idx(uint32_t *sa_idx) {
	if (ipsec_sa_idxs.empty())
		return DOCA_ERROR_NO_MEMORY;

	*sa_idx = *ipsec_sa_idxs.begin();
	ipsec_sa_idxs.erase(*ipsec_sa_idxs.begin());
	return DOCA_SUCCESS;
}

doca_error_t PipeMgr::create_ipsec_sa(struct ipsec_sa_ctx_t *ipsec_sa_ctx, uint32_t crypto_id, bool egress) {
	struct doca_flow_shared_resource_cfg cfg = {};

	if (egress) {
		cfg.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS;
	} else {
		cfg.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS;
	}
	cfg.ipsec_sa_cfg.icv_len = ipsec_sa_ctx->icv_length;
	cfg.ipsec_sa_cfg.salt = ipsec_sa_ctx->salt;
	cfg.ipsec_sa_cfg.key_cfg.key_type = ipsec_sa_ctx->key_type;
	cfg.ipsec_sa_cfg.key_cfg.key = reinterpret_cast<uint32_t*>(&ipsec_sa_ctx->key);
	cfg.ipsec_sa_cfg.sn_initial = 1;
	cfg.ipsec_sa_cfg.esn_en = ipsec_sa_ctx->esn_en;
	// if (!app_cfg->sw_sn_inc_enable) {
	// 	cfg.ipsec_sa_cfg.sn_offload_type = DOCA_FLOW_CRYPTO_SN_OFFLOAD_INC;
	// 	cfg.ipsec_sa_cfg.lifetime_threshold = ipsec_sa_ctx->lifetime_threshold;
	// }

	doca_error_t result = doca_flow_shared_resource_set_cfg(DOCA_FLOW_SHARED_RESOURCE_IPSEC_SA, crypto_id, &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to cfg shared ipsec object: %s", doca_error_get_descr(result));
		return result;
	}
	memset(ipsec_sa_ctx->key, 0, sizeof(ipsec_sa_ctx->key));


	DOCA_LOG_INFO("Created ipsec sa with crypto_id %d", crypto_id);
	return DOCA_SUCCESS;
}
