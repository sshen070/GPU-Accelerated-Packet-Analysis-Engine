#ifndef ANALYTICS_H
#define ANALYTICS_H

#include "packet.h"

#include <vector>
#include <unordered_map>
#include <cstdint>
#include <string>

struct PacketFilter {
    bool filter_tcp = false;
    bool filter_udp = false;

    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    bool use_src_ip = false;
    bool use_dst_ip = false;


    uint32_t min_len = 0;
    bool min_len_enabled = false; 
};

// Filtering
bool matches(const PacketInfo& pkt, const PacketFilter& filter);

std::vector<PacketInfo> filter_packets(const std::vector<PacketInfo>& packets, const PacketFilter& filter);

// Analytics Engine
void print_protocol_counts(const std::vector<PacketInfo>& packets);

void print_top_source_ips(const std::vector<PacketInfo>& packets, size_t top_n = 10);

void print_bandwidth_stats(const std::vector<PacketInfo>& packets, double duration_seconds);

#endif
