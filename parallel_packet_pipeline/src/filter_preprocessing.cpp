#include "filter_preprocessing.h"
#include "packet.h"

PacketArrays convert_SOA(const std:: vector<PacketInfo>& packets) {

    PacketArrays soa;

    size_t n = packets.size();

    // Preallocate memory
    soa.src_ip.reserve(n);
    soa.dst_ip.reserve(n);

    soa.src_port.reserve(n);
    soa.dst_port.reserve(n);

    soa.protocol.reserve(n);
    soa.packet_len.reserve(n);

    // Fill arrays
    for (const auto& pkt : packets)
    {
        soa.src_ip.push_back(pkt.src_ip);
        soa.dst_ip.push_back(pkt.dst_ip);

        soa.src_port.push_back(pkt.src_port);
        soa.dst_port.push_back(pkt.dst_port);

        soa.protocol.push_back(pkt.protocol);
        soa.packet_len.push_back(pkt.packet_len);
    }

    return soa;
}
