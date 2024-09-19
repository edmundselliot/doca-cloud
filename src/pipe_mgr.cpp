#include "pipe_mgr.h"

DOCA_LOG_REGISTER(PIPE_MGR);

PipeMgr::PipeMgr() {
	monitor_count.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
}

PipeMgr::~PipeMgr() {}

doca_error_t PipeMgr::create_pipes() {
    doca_error_t result = DOCA_SUCCESS;

    IF_SUCCESS(result, rss_pipe_create());
    IF_SUCCESS(result, tx_vlan_pipe_create());
    IF_SUCCESS(result, tx_root_pipe_create(tx_vlan_pipe));

    if (result == DOCA_SUCCESS)
        DOCA_LOG_INFO("Created all static pipes on port %d", pf_port_id);
    else
        DOCA_LOG_ERR("Failed to create all static pipes on port %d, err: %s", pf_port_id, doca_error_get_descr(result));

    return result;
}

doca_error_t PipeMgr::rss_pipe_create() {
    assert(pf_port);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_all = {};

    // For now use a single RSS queue
    uint16_t rss_queues[1] = {0};
	struct doca_flow_fwd fwd = {};
	fwd.type = DOCA_FLOW_FWD_RSS;
	fwd.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6;
	fwd.num_of_queues = 1;
	fwd.rss_queues = rss_queues;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "RSS_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_all, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, nullptr, &rss_pipe));
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
    // TCI is defined per-entry
	actions.push.vlan.tci = rte_cpu_to_be_16(0xffff);

    struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "TX_VLAN_PIPE"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
    IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_dip, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_to_wire, nullptr, &tx_vlan_pipe));

    if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

doca_error_t PipeMgr::tx_root_pipe_create(doca_flow_pipe *next_pipe)
{
    assert(pf_port);
    assert(next_pipe);

	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_all = {};

	struct doca_flow_fwd fwd = {};
	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = next_pipe;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "TX_ROOT"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_all, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, nullptr, &tx_root_pipe));

	IF_SUCCESS(
		result,
		add_single_entry(0, tx_root_pipe, pf_port, nullptr, nullptr, nullptr, nullptr, &tx_root_pipe_default_entry));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	return result;
}
