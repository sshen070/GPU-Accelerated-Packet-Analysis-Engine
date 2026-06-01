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
    if (filter.use_src_ip && pkt.src_ip != filter.src_ip)
        return false;

    if (filter.use_dst_ip && pkt.dst_ip != filter.dst_ip)
        return false;

    // Pkt Length
    if (filter.min_len_enabled && pkt.packet_len < filter.min_len)
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

void print_protocol_counts(const std::vector<PacketInfo>& packets) {

    // Map protocols (key) to the frequency (value)
    std::unordered_map<uint8_t, uint64_t> counts;

    for (const auto& pkt : packets) {
        counts[pkt.protocol]++;
    }

    std::cout << "\n=== Protocol Counts ===\n";

    for (const auto& [proto, count] : counts) {
        std::string name = "OTHER";

        if (proto == 6)
            name = "TCP";
        else if (proto == 17)
            name = "UDP";
        else if (proto == 1)
            name = "ICMP";

        std::cout << name << " (" << (int)proto << ")" << ": " << count << "\n";
    }
}


void print_top_source_ips(const std::vector<PacketInfo>& packets, size_t top_n) {
    std::unordered_map<uint32_t, uint64_t> counts;

    for (const auto& pkt : packets)
    {
        counts[pkt.src_ip]++;
    }

    // Convert map into vector of pairs <first (key), second (value)>
    std::vector<std::pair<uint32_t, uint64_t>> sorted(counts.begin(), counts.end());

    // Sort by frequency (value)
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) {return a.second > b.second; });

    std::cout << "\n=== Top Source IPs ===\n";

    size_t limit = std::min(top_n, sorted.size());
    for (size_t i = 0; i < limit; i++)
    {
        std::cout << i + 1 << ". " << ip_to_string(sorted[i].first) << " -> " << sorted[i].second << " packets\n";
    }
}

// In production (need pkt replay to utilize)
void print_bandwidth_stats(const std::vector<PacketInfo>& packets, double duration_seconds) {
    uint64_t total_bytes = 0;

    for (const auto& pkt : packets)
    {
        total_bytes += pkt.packet_len;
    }

    double packets_per_sec = packets.size() / duration_seconds;
    double bytes_per_sec = total_bytes / duration_seconds;

    std::cout << "\n=== Traffic Stats ===\n";

    std::cout << "Packets/sec: " << packets_per_sec << "\n";
    std::cout << "Bytes/sec: " << bytes_per_sec << "\n";
}
