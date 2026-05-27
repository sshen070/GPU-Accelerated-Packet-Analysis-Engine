#include <iostream>
#include <algorithm>
#include <arpa/inet.h>

#include "packet.h"
#include "analytics.h"

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: ./pkt_pipeline file.pcap\n";
        return 1;
    }

    std::vector<PacketInfo> packets = load_packets(argv[1]);

    std::cout << "Loaded packets: " << packets.size() << "\n\n";

    /*
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
    */
    
    PacketFilter filter;

    // filter.filter_tcp = true;
    // filter.dst_port = 443;

    filter.src_ip = inet_addr("71.126.222.64");
    filter.dst_ip = inet_addr("254.229.252.232");

    std::vector<PacketInfo> filtered = filter_packets(packets, filter);

    std::cout << "\nFiltered packets: " << filtered.size() << "\n";

    return 0;
}
