#include <iostream>
#include <algorithm>

#include "packet.h"

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: ./pkt_pipeline file.pcap\n";
        return 1;
    }

    std::vector<PacketInfo> packets = load_packets(argv[1]);

    std::cout << "Loaded packets: " << packets.size() << "\n\n";

    size_t limit = std::min((size_t)10, packets.size());

    for (size_t i = 0; i < limit; i++)
    {
        const PacketInfo& p = packets[i];

        std::cout
            << "Packet " << i << "\n"
            << "  Src IP: " << ip_to_string(p.src_ip) << "\n"
            << "  Dst IP: " << ip_to_string(p.dst_ip) << "\n"
            << "  Src Port: " << p.src_port << "\n"
            << "  Dst Port: " << p.dst_port << "\n"
            << "  Protocol: " << (int)p.protocol << "\n"
            << "  Length: " << p.packet_len << "\n\n";
    }

    return 0;
}
