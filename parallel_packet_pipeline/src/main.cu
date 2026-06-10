#include <iostream>
#include <vector>

#include <cuda_runtime.h>
#include <arpa/inet.h>

#include "packet.h"
#include "filter_preprocessing.h"
#include "gpu_processing.h"
#include "kernel.h"


uint32_t BATCH_SIZE = 1'000'000;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./pkt_pipeline file.pcap\n";
        return 1;
    }

    std::string filename = argv[1];

    PacketArrays h_batch;
    pcap_t* handle = open_file(filename);

    bool eof = false;

    while (!eof){
        std::vector<PacketInfo> packets = read_batch(handle, BATCH_SIZE);

        // No packets left to parse --> last batch
        if (packets.size() < BATCH_SIZE) {
            eof = true;
        }

        PacketArrays h_batch = convert_SOA(packets);

        uint32_t count = packets.size();
        process_gpu_batch(h_batch, count);
    }

    pcap_close(handle);

    return 0;
}