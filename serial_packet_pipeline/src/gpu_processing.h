#ifndef GPU_PROCESSING_H
#define GPU_PROCESSING_H

#include "packet.h"

#include <vector>
#include <cstdint>

struct PacketArrays {
    std::vector<uint32_t> src_ip;
    std::vector<uint32_t> dst_ip;

    std::vector<uint16_t> src_port;
    std::vector<uint16_t> dst_port;

    std::vector<uint8_t> protocol;

    std::vector<uint32_t> packet_len;
};


// SOA conversion (pkt vector --> SOA object)
PacketArrays convert_SOA(const std::vector<PacketInfo>& packets);

#endif