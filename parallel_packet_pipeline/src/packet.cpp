#include "packet.h"

#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>

// Converts IP address (binary) --> String
std::string ip_to_string(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

// Tracks dst & src MAC addr + protocol type (Ipv4 vs IPv6 header)
struct EthHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

// Pkt header details 
struct IPHeader {

    // ihl ~ IP header length & version ~ IP version (Ipv4 vs IPv6) 
    uint8_t ihl:4, version:4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
};

std::vector<PacketInfo> load_packets(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Track reading position & internal buffers
    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);

    if (!handle) {
        std::cerr << "PCAP open error: " << errbuf << "\n";
        return {};
    }

    // Pkt store format ~ Ethernet, Linux SLL, Raw
    int link_type = pcap_datalink(handle);

    std::vector<PacketInfo> packets;
    
    // Reduce realloc overhead ~ significant vector resize overhead otherwise
    packets.reserve(1 << 16);

    // Non-structured pkt data ~ pure bytes
    const u_char* packet;

    // Contains metadata ~ timestamp, caplen (captured length), len (orig pkt size)
    struct pcap_pkthdr* header;

    size_t total = 0;
    size_t ipv4 = 0;
    size_t skipped = 0;

    // Parse through each of the pkts (three layers)
    while (pcap_next_ex(handle, &header, &packet) >= 0)
    {
        total++;

        // Data Link Header (no header info needed ~ set parsing pointer to the beginning of IP Layer)
        const u_char* ip_layer = nullptr;
        int offset = 0;

        // Ethernet
        if (link_type == DLT_EN10MB) {

            // Uses the struct to keep track of offset values (dst, src, type)
            const EthHeader* eth = (EthHeader*)packet;
            uint16_t eth_type = ntohs(eth->type);

            offset = 14;

            // Skip VLAN tags 
            while (eth_type == 0x8100 || eth_type == 0x88A8)
            {
                eth_type = ntohs(*(uint16_t*)(packet + offset));
                offset += 4;
            }
            
            // If not IPv4 ~ skip
            if (eth_type != 0x0800)
            {
                skipped++;
                continue;
            }

            ip_layer = packet + offset;
        }

        // Linux SLL
        else if (link_type == DLT_LINUX_SLL)
        {
            // Linux cooked capture
            offset = 16;
            ip_layer = packet + offset;
        }

        // Raw IP
        else if (link_type == DLT_RAW)
        {
            ip_layer = packet;
        }

        else
        {
            skipped++;
            continue;
        }

        // IP Layer ~ check if location of IP header + offset is actually within full header
        if (header -> caplen < (uint32_t)(offset + sizeof(IPHeader)))
        {
            skipped++;
            continue;
        }

        // Map the IP layer to the struct ~ ip is pointer to the start of a byte region
        // Each field is read as a fixed offset from that base address
            // ip->src_ip	read bytes at (ip + offset_of(src_ip))
            // ip->protocol	read bytes at (ip + offset_of(protocol))
        const IPHeader* ip = (IPHeader*)ip_layer;

        PacketInfo pkt{};
        pkt.src_ip = ip -> src_ip;
        pkt.dst_ip = ip -> dst_ip;
        pkt.protocol = ip -> protocol;
        pkt.packet_len = header -> len;

        ipv4++;

        // Src & dst port info not located in IP header ~ temporarily zero until updated by TCP header info
        pkt.src_port = 0;
        pkt.dst_port = 0;

        // Find total length of ip_header to parse to transport header
        uint32_t ip_header_len = ip -> ihl * 4;

        if (header->caplen < offset + ip_header_len)
        {
            skipped++;
            continue;
        }

        const u_char* transport_layer = ip_layer + ip_header_len;

        // TCP
        if (pkt.protocol == 6)
        {
            if (header->caplen >= offset + ip_header_len + sizeof(TCPHeader))
            {
                const TCPHeader* tcp = (TCPHeader*)transport_layer;
                pkt.src_port = ntohs(tcp -> src_port);
                pkt.dst_port = ntohs(tcp -> dst_port);
            }
        }

        // UDP
        else if (pkt.protocol == 17)
        {
            if (header->caplen >= offset + ip_header_len + sizeof(UDPHeader))
            {
                const UDPHeader* udp = (UDPHeader*)transport_layer;
                pkt.src_port = ntohs(udp -> src_port);
                pkt.dst_port = ntohs(udp -> dst_port);
            }
        }

        packets.push_back(pkt);
    }

    pcap_close(handle);


    std::cout << "\n[PCAP STATS]\n";
    std::cout << "Total packets: " << total << "\n";
    std::cout << "IPv4 packets:  " << ipv4 << "\n";
    std::cout << "Skipped:       " << skipped << "\n";
    std::cout << "Parsed:        " << packets.size() << "\n\n";

    return packets;
}
