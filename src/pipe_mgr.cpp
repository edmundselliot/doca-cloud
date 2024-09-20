#include "pipe_mgr.h"

DOCA_LOG_REGISTER(PIPE_MGR);

PipeMgr::PipeMgr() {
	monitor_count.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	fwd_drop.type = DOCA_FLOW_FWD_DROP;
}

PipeMgr::~PipeMgr() {}

doca_error_t PipeMgr::create_pipes() {
    doca_error_t result = DOCA_SUCCESS;

    IF_SUCCESS(result, rss_pipe_create());
    IF_SUCCESS(result, tx_vlan_pipe_create());
	IF_SUCCESS(result, tx_geneve_pipe_create());
    IF_SUCCESS(result, tx_root_pipe_create(tx_geneve_pipe));
    IF_SUCCESS(result, rx_root_pipe_create(tx_root_pipe));

    if (result == DOCA_SUCCESS)
        DOCA_LOG_INFO("Created all static pipes on port %d", pf_port_id);
    else
        DOCA_LOG_ERR("Failed to create all static pipes on port %d, err: %s", pf_port_id, doca_error_get_descr(result));

    return result;
}

void PipeMgr::print_pipe_stats(struct doca_flow_pipe* pipe, std::string pipe_name) {
    if (pipe) {
        struct doca_flow_resource_query stats = {};
		doca_error_t result = doca_flow_resource_query_pipe_miss(pipe, &stats);
        if (result == DOCA_SUCCESS)
            DOCA_LOG_INFO("%s miss: %lu pkts", pipe_name.c_str(), stats.counter.total_pkts);
        else
            DOCA_LOG_ERR("Failed to query pipe %s miss: %s", pipe_name.c_str(), doca_error_get_descr(result));
    }
}

void PipeMgr::print_pipe_entry_stats(struct doca_flow_pipe_entry* entry, std::string entry_name) {
    if (entry) {
        struct doca_flow_resource_query stats = {};
		doca_error_t result = doca_flow_resource_query_entry(entry, &stats);
        if (result == DOCA_SUCCESS)
            DOCA_LOG_INFO("%s hit: %lu packets", entry_name.c_str(), stats.counter.total_pkts);
        else
            DOCA_LOG_ERR("Failed to query entry %s: %s", entry_name.c_str(), doca_error_get_descr(result));
    }
}

void PipeMgr::print_stats() {
	DOCA_LOG_INFO("=================================");
	print_pipe_stats(rx_root_pipe, "RX_ROOT_PIPE");
	print_pipe_entry_stats(rx_root_pipe_default_entry, "RX_ROOT_DEFAULT_ENTRY");

    print_pipe_stats(tx_root_pipe, "TX_ROOT_PIPE");
    print_pipe_entry_stats(tx_root_pipe_default_entry, "TX_ROOT_DEFAULT_ENTRY");

	print_pipe_stats(rss_pipe, "RSS_PIPE");
    print_pipe_entry_stats(rss_pipe_default_entry, "RSS_PIPE_DEFAULT_ENTRY");

	print_pipe_stats(tx_geneve_pipe, "TX_GENEVE_PIPE");
    print_pipe_stats(tx_vlan_pipe, "TX_VLAN_PIPE");
}

doca_error_t PipeMgr::rss_pipe_create() {
    assert(pf_port);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_all = {};

    // For now use a single RSS queue
    uint16_t rss_queues[1] = {0};
	struct doca_flow_fwd fwd_rss = {};
	fwd_rss.type = DOCA_FLOW_FWD_RSS;
	fwd_rss.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6;
	fwd_rss.num_of_queues = 1;
	fwd_rss.rss_queues = rss_queues;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "RSS_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_all, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_rss, &fwd_drop, &rss_pipe));
	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

    IF_SUCCESS(
		result,
		add_single_entry(0, rss_pipe, pf_port, nullptr, nullptr, nullptr, nullptr, &rss_pipe_default_entry));

	return result;
}

doca_error_t PipeMgr::tx_vlan_pipe_create() {
    assert(pf_port);

    doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_dip = {};
    match_dip.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
    match_dip.outer.ip4.dst_ip = 0xffffffff;

	struct doca_flow_fwd fwd_to_wire = {};
    fwd_to_wire.type = DOCA_FLOW_FWD_PORT;
    fwd_to_wire.port_id = pf_port_id;

    struct doca_flow_actions actions = {0};
	struct doca_flow_actions *actions_arr[] = {&actions};
    actions.has_push = true;
	actions.push.type = DOCA_FLOW_PUSH_ACTION_VLAN;
	actions.push.vlan.eth_type = rte_cpu_to_be_16(DOCA_FLOW_ETHER_TYPE_VLAN);
    // TCI is defined per-entry
	actions.push.vlan.vlan_hdr.tci = rte_cpu_to_be_16(0xffff);

    struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "TX_VLAN_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_dip, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_to_wire, &fwd_drop, &tx_vlan_pipe));
    if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

    return result;
}

doca_error_t PipeMgr::tx_root_pipe_create(doca_flow_pipe *next_pipe) {
    assert(pf_port);
    assert(next_pipe);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_all = {};

	struct doca_flow_fwd fwd_pipe = {};
	fwd_pipe.type = DOCA_FLOW_FWD_PIPE;
	fwd_pipe.next_pipe = next_pipe;

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



	return result;
}

doca_error_t PipeMgr::rx_root_pipe_create(doca_flow_pipe *next_pipe) {
    assert(pf_port);
    assert(next_pipe);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_all = {};

	struct doca_flow_fwd fwd_pipe = {};
	fwd_pipe.type = DOCA_FLOW_FWD_PIPE;
	fwd_pipe.next_pipe = next_pipe;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "RX_ROOT"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_all, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_pipe, &fwd_drop, &rx_root_pipe));
	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	IF_SUCCESS(
		result,
		add_single_entry(0, rx_root_pipe, pf_port, nullptr, nullptr, nullptr, nullptr, &rx_root_pipe_default_entry));

	return result;
}

doca_error_t PipeMgr::tx_geneve_pipe_create()
{
	assert(pf_port);
	assert(tx_vlan_pipe);

	struct doca_flow_match match_ca = {};
	match_ca.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match_ca.outer.ip4.dst_ip = 0xffffffff;

	struct doca_flow_fwd fwd_hit = {};
	fwd_hit.type = DOCA_FLOW_FWD_PIPE;
	fwd_hit.next_pipe = tx_vlan_pipe;

	struct doca_flow_fwd fwd_rss = {};
	fwd_rss.type = DOCA_FLOW_FWD_PIPE;
	fwd_rss.next_pipe = rss_pipe;

	struct doca_flow_header_format encap_pipe_action_outer_ipv4 = {};

	struct doca_flow_actions actions = {};
	actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	actions.encap_cfg.is_l2 = false;
	actions.encap_cfg.encap.outer = encap_pipe_action_outer_ipv4;
	actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GENEVE;
	actions.encap_cfg.encap.tun.geneve.vni = 0xffffffff;
	actions.encap_cfg.encap.tun.geneve.next_proto = UINT16_MAX;
	for (int i = 0; i < 6; i++) {
		actions.encap_cfg.encap.outer.eth.src_mac[i] = 0xff;
		actions.encap_cfg.encap.outer.eth.dst_mac[i] = 0xff;
	}
	actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions.encap_cfg.encap.outer.ip4.src_ip = UINT32_MAX;
	actions.encap_cfg.encap.outer.ip4.dst_ip = UINT32_MAX;
	actions.encap_cfg.encap.outer.ip4.ttl = UINT8_MAX;
	actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	actions.encap_cfg.encap.outer.udp.l4_port.dst_port = RTE_BE16(DOCA_FLOW_GENEVE_DEFAULT_PORT);

	struct doca_flow_actions *actions_ptr_arr[] = { &actions };

	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "TX_GENEVE_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_ca, NULL));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_ptr_arr, NULL, NULL, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_hit, &fwd_rss, &tx_geneve_pipe));
	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	return result;
}
