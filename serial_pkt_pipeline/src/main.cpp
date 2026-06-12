#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <arpa/inet.h>

#include "packet.h"
#include "analytics.h"

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: ./pkt_pipeline file.pcap\n";
        return 1;
    }

    std::string filename = argv[1];

    
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<PacketInfo> packets = load_packets(filename);

    std::cout << "Loaded packets: " << packets.size() << "\n";

    // Create filter
    PacketFilter filter{};

    filter.src_ip = inet_addr("71.126.222.64");
    filter.dst_ip = inet_addr("254.229.252.232");

    filter.use_src_ip = true;
    filter.use_dst_ip = true;

    auto filter_start = std::chrono::high_resolution_clock::now();

    // Return filtered packets
    std::vector<PacketInfo> filtered = filter_packets(packets, filter);

    auto filter_end = std::chrono::high_resolution_clock::now();

    double filter_ms = std::chrono::duration<double, std::milli>(
        filter_end - filter_start).count();

    // print_protocol_counts(filtered);
    // print_top_source_ips(filtered, 10);

    // double duration_seconds = 60.0;
    // print_bandwidth_stats(filtered, duration_seconds);

    auto end = std::chrono::high_resolution_clock::now();

    double total_ms = std::chrono::duration<double, std::milli>(end - start).count();

    std::cout << "\n========================================\n";
    std::cout << " Serial Pipeline Summary\n";
    std::cout << "========================================\n";

    std::cout << std::left
              << std::setw(25) << "Total Packets"
              << packets.size()
              << "\n";

    std::cout << std::left
              << std::setw(25) << "Matched Packets"
              << filtered.size()
              << "\n";

    std::cout << std::left
            << std::setw(25) << "Filter Time"
            << std::fixed
            << std::setprecision(3)
            << filter_ms
            << " ms\n";

    std::cout << std::left
              << std::setw(25) << "Pipeline Execution Time"
              << std::fixed
              << std::setprecision(3)
              << total_ms
              << " ms\n";

    std::cout << "========================================\n";

    return 0;
}