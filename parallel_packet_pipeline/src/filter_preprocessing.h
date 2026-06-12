#pragma once

#include "packet.h"

#include <vector>
#include <cstdint>

// Pkt filter arguments
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

// Locate of each of the PacketArray vectors in device memory 
struct DevicePacketArrays {
    uint8_t* protocol;

    uint16_t* src_port;
    uint16_t* dst_port;

    uint32_t* src_ip;
    uint32_t* dst_ip;

    uint32_t* packet_len;

    size_t count;
};

// SOA conversion (pkt vector --> SOA object)
PacketArrays convert_SOA(const std::vector<PacketInfo>& packets);