#include "analytics.h"

#include <iostream>
#include <algorithm>
#include <arpa/inet.h>

// Return true if pkt fields match with the filter
bool matches(const PacketInfo& pkt, const PacketFilter& filter) {

    // Protocol Based
    if (filter.filter_tcp && pkt.protocol != 6)
        return false;

    if (filter.filter_udp && pkt.protocol != 17)
        return false;

    // Src & dst port
    if (filter.src_port && pkt.src_port != filter.src_port)
        return false;

    if (filter.dst_port && pkt.dst_port != filter.dst_port)
        return false;

    // Src & dest IP
    if (pkt.src_ip != filter.src_ip)
        return false;

    if (pkt.dst_ip != filter.dst_ip)
        return false;

    // Pkt Length
    if (pkt.packet_len < filter.min_len)
        return false;

    return true;
}

// Filter all packets in the vector
std::vector<PacketInfo> filter_packets(const std::vector<PacketInfo>& packets, const PacketFilter& filter) {
    std::vector<PacketInfo> filtered;
    
    // O(n) runtime ~ each packet compared with all filter conditions simultaneously
    for (const auto& pkt: packets)
    {
        if (matches(pkt, filter))
        {
            filtered.push_back(pkt);
        }
    }

    return filtered;
}
