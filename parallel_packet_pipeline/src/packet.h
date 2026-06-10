#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <pcap.h>

// Keep track of pkt details
struct PacketInfo {
    uint8_t protocol;

    uint16_t src_port;
    uint16_t dst_port;

    uint32_t src_ip;
    uint32_t dst_ip;

    uint32_t packet_len;
};

pcap_t* open_file(const std::string &filename);

// Reads pcap file & loads pkts into PacketInfo objects
std::vector<PacketInfo> read_batch(pcap_t* handle, uint32_t batch_size);

std::string ip_to_string(uint32_t ip);