#include "utils.h"

DOCA_LOG_REGISTER(UTILS);

std::string mac_to_string(const rte_ether_addr &mac_addr)
{
	std::string addr_str(RTE_ETHER_ADDR_FMT_SIZE, '\0');
	rte_ether_format_addr(addr_str.data(), RTE_ETHER_ADDR_FMT_SIZE, &mac_addr);
	addr_str.resize(strlen(addr_str.c_str()));
	return addr_str;
}

std::string ipv4_to_string(rte_be32_t ipv4_addr)
{
	std::string addr_str(INET_ADDRSTRLEN, '\0');
	inet_ntop(AF_INET, &ipv4_addr, addr_str.data(), INET_ADDRSTRLEN);
	addr_str.resize(strlen(addr_str.c_str()));
	return addr_str;
}

std::string ipv6_to_string(const uint32_t ipv6_addr[])
{
	std::string addr_str(INET6_ADDRSTRLEN, '\0');
	inet_ntop(AF_INET6, ipv6_addr, addr_str.data(), INET6_ADDRSTRLEN);
	addr_str.resize(strlen(addr_str.c_str()));
	return addr_str;
}

std::string ip_to_string(const struct doca_flow_ip_addr &ip_addr)
{
	if (ip_addr.type == DOCA_FLOW_L3_TYPE_IP4)
		return ipv4_to_string(ip_addr.ipv4_addr);
	else if (ip_addr.type == DOCA_FLOW_L3_TYPE_IP6)
		return ipv6_to_string(ip_addr.ipv6_addr);
	return "Invalid IP type";
}

uint32_t ipv4_string_to_u32(const std::string &ipv4_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ipv4_str.c_str(), &addr) != 1) {
		DOCA_LOG_ERR("Failed to convert string %s to IPv4 address", ipv4_str.c_str());
		assert(false);
    }
    return addr.s_addr;
}

doca_error_t add_single_entry(uint16_t pipe_queue,
						doca_flow_pipe *pipe,
						doca_flow_port *port,
						const doca_flow_match *match,
						const doca_flow_actions *actions,
						const doca_flow_monitor *mon,
						const doca_flow_fwd *fwd,
						doca_flow_pipe_entry **entry)
{
	int num_of_entries = 1;
	uint32_t flags = DOCA_FLOW_NO_WAIT;

	struct entries_status status = {};
	status.entries_in_queue = num_of_entries;

	doca_error_t result =
		doca_flow_pipe_add_entry(pipe_queue, pipe, match, actions, mon, fwd, flags, &status, entry);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entry: %s", doca_error_get_descr(result));
		return result;
	}

	if (status.nb_processed != num_of_entries || status.failure) {
		DOCA_LOG_ERR("Failed to process entry; nb_processed = %d, failure = %d",
			     status.nb_processed,
			     status.failure);
		return DOCA_ERROR_BAD_STATE;
	}

	return result;
}