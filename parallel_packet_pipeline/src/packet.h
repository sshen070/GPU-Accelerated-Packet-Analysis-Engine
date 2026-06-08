#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <string>
#include <vector>

// Keep track of pkt details
struct PacketInfo {
    uint8_t protocol;

    uint16_t src_port;
    uint16_t dst_port;

    uint32_t src_ip;
    uint32_t dst_ip;

    uint32_t packet_len;
};

// Reads pcap file & loads pkts into PacketInfo objects
std::vector<PacketInfo> load_packets(const std::string& filename);

std::string ip_to_string(uint32_t ip);

#endif
