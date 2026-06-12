#include <iostream>
#include <vector>
#include <iomanip>
#include <chrono>

#include <cuda_runtime.h>
#include <arpa/inet.h>

#include "packet.h"
#include "filter_preprocessing.h"
#include "gpu_processing.h"
#include "kernel.h"

uint32_t BATCH_SIZE = 1'000'000;

void initialize_host(PacketArrays& host, uint32_t capacity) {
    host.src_ip.resize(capacity);
    host.dst_ip.resize(capacity);

    host.src_port.resize(capacity);
    host.dst_port.resize(capacity);

    host.protocol.resize(capacity);
    host.packet_len.resize(capacity);
}

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


    // No extra allocation for each sucessive batches 
    PacketArrays host_buffers[2];
    initialize_host(host_buffers[0], BATCH_SIZE);
    initialize_host(host_buffers[1], BATCH_SIZE);

    // Create filter
    PacketFilter filter{};
    filter.src_ip = inet_addr("71.126.222.64");
    filter.dst_ip = inet_addr("254.229.252.232");

    filter.use_src_ip = true;
    filter.use_dst_ip = true;

    // Time full pipeline
    auto pipeline_start = std::chrono::high_resolution_clock::now();

    // Open file to start parsing
    pcap_t* handle = open_file(filename);

    uint64_t total_packets = 0;
    uint32_t total_matches = 0;

    uint16_t batch_id = 0;
    uint16_t completed_batch;

    float total_gpu_time = 0;
    
    bool eof = false;

    while (!eof){
        // CPU
        PacketArrays h_batch = host_buffers[batch_id % 2];
        h_batch.count = 0;

        read_batch(handle, h_batch, BATCH_SIZE);
        
        // No packets left to parse --> last batch
        if (h_batch.count < BATCH_SIZE) {
            eof = true;
        }

        total_packets += h_batch.count;

        // PacketArrays h_batch = convert_SOA(packets);

        // Determine pipeline slot used by batch ~ one batch scheduled at a time
        GPUPipelineSlot& batch = pipeline_slot[batch_id % 2];

        // Collects the results from batch run 2 iterations prior ~ 
        if(batch_id >= 2) {
            total_matches += collect_results(batch, batch.d_batch.count);            
            total_gpu_time += batch.batch_time_ms;

            completed_batch = batch_id - 2;
            std::cout << "[GPU] Batch " << static_cast<uint16_t>(completed_batch) 
                << " completed in " << std::fixed << std::setprecision(3)
                << batch.batch_time_ms << " ms\n";
        }

        // Reuse existing GPU data buffer ~ operations are performed asynchronously (control restored to CPU)
        launch_batch(batch, h_batch, h_batch.count, filter);

        batch_id++;
    }

    std::cout << "All Batches Run...\n\n";

    uint32_t remaining = std::min(batch_id, static_cast<uint16_t>(2));

    // Collect results for remaining batches
    for(uint32_t i = 0; i < remaining; i++) {
        GPUPipelineSlot& batch = pipeline_slot[(batch_id + i) % 2];

        total_matches += collect_results(batch, batch.d_batch.count);

        total_gpu_time += batch.batch_time_ms;

        std::cout << "[GPU] Batch " << static_cast<uint16_t>(completed_batch + i) 
            << " completed in " << std::fixed << std::setprecision(3) 
            << batch.batch_time_ms << " ms\n";
    }

    pcap_close(handle);

    // Free GPU data buffers
    destroy_pipeline(pipeline_slot[0]);
    destroy_pipeline(pipeline_slot[1]);
    
    // Pipeline ends
    auto pipeline_end = std::chrono::high_resolution_clock::now();
    double total_pipeline_ms = std::chrono::duration<double,std::milli>(pipeline_end - pipeline_start).count();

    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << " Parallel Pipeline Summary\n";
    std::cout << "========================================\n";

    std::cout << std::left
            << std::setw(25) << "Batches Processed"
            << batch_id
            << "\n";

    std::cout << std::left
            << std::setw(25) << "Total Packets"
            << total_packets
            << "\n";


    std::cout << std::left
            << std::setw(25) << "Matched Packets"
            << total_matches
            << "\n";

    std::cout << std::left
            << std::setw(25) << "Total GPU Time"
            << std::fixed
            << std::setprecision(3)
            << total_gpu_time
            << " ms\n";

    std::cout << std::left
            << std::setw(25) << "Pipeline Execution Time"
            << std::fixed
            << std::setprecision(3)
            << total_pipeline_ms
            << " ms\n";


    std::cout << std::left
            << std::setw(25) << "Average Batch Time"
            << (batch_id ?
                    total_gpu_time / batch_id :
                    0.0f)
            << " ms\n";

    std::cout << "========================================\n";

    return 0;
}


// #include <iostream>
// #include <vector>
// #include <iomanip>
// #include <chrono>

// #include <cuda_runtime.h>
// #include <arpa/inet.h>

// #include "packet.h"
// #include "filter_preprocessing.h"
// #include "gpu_processing.h"
// #include "kernel.h"

// uint32_t BATCH_SIZE = 1'000'000;

// struct BatchProfile {
//     double read_ms = 0;
//     double soa_ms = 0;
//     double launch_ms = 0;
//     double gpu_ms = 0;
//     double collect_ms = 0;
// };

// int main(int argc, char* argv[]) {

//     if (argc < 2) {
//         std::cerr << "Usage: ./pkt_pipeline file.pcap\n";
//         return 1;
//     }

//     std::string filename = argv[1];

//     GPUPipelineSlot pipeline_slot[2];
//     initialize_pipeline(pipeline_slot[0], BATCH_SIZE);
//     initialize_pipeline(pipeline_slot[1], BATCH_SIZE);

//     PacketFilter filter{};
//     filter.src_ip = inet_addr("71.126.222.64");
//     filter.dst_ip = inet_addr("254.229.252.232");
//     filter.use_src_ip = true;
//     filter.use_dst_ip = true;

//     auto pipeline_start = std::chrono::high_resolution_clock::now();

//     pcap_t* handle = open_file(filename);

//     uint64_t total_packets = 0;
//     uint32_t total_matches = 0;
//     float total_gpu_time = 0;

//     uint16_t batch_id = 0;

//     std::vector<BatchProfile> profiles;

//     bool eof = false;

//     while (!eof) {

//         BatchProfile prof;

//         // -------------------------
//         // READ
//         // -------------------------
//         auto t0 = std::chrono::high_resolution_clock::now();
//         PacketArrays h_batch = read_batch(handle, BATCH_SIZE);
//         auto t1 = std::chrono::high_resolution_clock::now();

//         prof.read_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

//         if (h_batch.count < BATCH_SIZE) eof = true;

//         total_packets += h_batch.count;

//         // -------------------------
//         // SOA (if needed)
//         // -------------------------
//         // If read_batch already returns SOA, remove this timing.
//         auto s0 = std::chrono::high_resolution_clock::now();
//         // PacketArrays h_batch = convert_SOA(packets);
//         auto s1 = std::chrono::high_resolution_clock::now();

//         prof.soa_ms = std::chrono::duration<double, std::milli>(s1 - s0).count();

//         GPUPipelineSlot& batch = pipeline_slot[batch_id % 2];

//         // -------------------------
//         // GPU LAUNCH (enqueue only)
//         // -------------------------
//         auto l0 = std::chrono::high_resolution_clock::now();

//         if (batch_id >= 2) {
//             total_matches += collect_results(batch, batch.d_batch.count);
//             total_gpu_time += batch.batch_time_ms;
//         }

//         launch_batch(batch, h_batch, h_batch.count, filter);

//         cudaStreamSynchronize(batch.stream); // TEMP PROFILER ONLY

//         auto l1 = std::chrono::high_resolution_clock::now();
//         prof.launch_ms = std::chrono::duration<double, std::milli>(l1 - l0).count();

//         batch_id++;
//         profiles.push_back(prof);
//     }

//     // Drain remaining batches
//     for (int i = 0; i < 2; i++) {
//         GPUPipelineSlot& batch = pipeline_slot[(batch_id + i) % 2];
//         total_matches += collect_results(batch, batch.d_batch.count);
//         total_gpu_time += batch.batch_time_ms;
//     }

//     pcap_close(handle);

//     destroy_pipeline(pipeline_slot[0]);
//     destroy_pipeline(pipeline_slot[1]);

//     auto pipeline_end = std::chrono::high_resolution_clock::now();
//     double total_pipeline_ms =
//         std::chrono::duration<double, std::milli>(pipeline_end - pipeline_start).count();

//     // -------------------------
//     // PRINT PER-BATCH PROFILING
//     // -------------------------
//     std::cout << "\n========================================\n";
//     std::cout << " PER-BATCH PROFILING\n";
//     std::cout << "========================================\n";

//     for (size_t i = 0; i < profiles.size(); i++) {
//         const auto& p = profiles[i];

//         std::cout << "[BATCH " << i << "] "
//                   << "read=" << p.read_ms << " ms | "
//                   << "soa=" << p.soa_ms << " ms | "
//                   << "launch=" << p.launch_ms << " ms\n";
//     }

//     // -------------------------
//     // SUMMARY
//     // -------------------------
//     std::cout << "\n========================================\n";
//     std::cout << " PIPELINE SUMMARY\n";
//     std::cout << "========================================\n";

//     std::cout << std::left << std::setw(30) << "Total Packets"
//               << total_packets << "\n";

//     std::cout << std::left << std::setw(30) << "Matched Packets"
//               << total_matches << "\n";

//     std::cout << std::left << std::setw(30) << "Total GPU Kernel Time"
//               << total_gpu_time << " ms\n";

//     std::cout << std::left << std::setw(30) << "End-to-End Time"
//               << total_pipeline_ms << " ms\n";

//     std::cout << "========================================\n";

//     return 0;
// }