#include "utils.h"


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
