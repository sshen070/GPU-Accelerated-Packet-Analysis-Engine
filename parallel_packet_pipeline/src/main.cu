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

    // Create two GPU data buffers for parallel execution (2x device memory allocations ~ 2 streams)
    GPUPipelineSlot pipeline_slot[2];
    
    initialize_pipeline(pipeline_slot[0], BATCH_SIZE);
    initialize_pipeline(pipeline_slot[1], BATCH_SIZE);

    // Create filter
    PacketFilter filter{};
    filter.src_ip = inet_addr("71.126.222.64");
    filter.dst_ip = inet_addr("254.229.252.232");

    // Open file to start parsing
    pcap_t* handle = open_file(filename);

    uint64_t total_matches = 0;
    uint8_t batch_id = 0;
    
    bool eof = false;

    while (!eof){
        // CPU
        std::vector<PacketInfo> packets = read_batch(handle, BATCH_SIZE);

        // No packets left to parse --> last batch
        if (packets.size() < BATCH_SIZE) {
            eof = true;
        }

        uint32_t count = packets.size();

        PacketArrays h_batch = convert_SOA(packets);

        // Determine pipeline slot used by batch ~ one batch scheduled at a time
        GPUPipelineSlot& batch = pipeline_slot[batch_id % 2];

        // Collects the results from batch run 2 iterations prior
        if(batch_id >= 2) {
            total_matches += collect_results(batch, count);
        }

        // Reuse existing GPU data buffer ~ operations are performed asynchronously (control restored to CPU)
        launch_batch(batch, h_batch, count, filter);

        batch_id++;
    }

    pcap_close(handle);

    // Free GPU data buffers
    destroy_pipeline(pipeline_slot[0]);
    destroy_pipeline(pipeline_slot[1]);

    return 0;
}