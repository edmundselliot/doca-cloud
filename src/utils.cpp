/*
 * Copyright (c) 2025 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

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