#pragma once

#include <cstdint>
#include <cuda_runtime.h>

#define IP_BUCKETS 1048576
#define TOPK 4

struct GPUPortScanState {

    cudaStream_t stream;

    // raw packet inputs (optional reuse)
    uint32_t* d_src_ip;
    uint16_t* d_dst_port;

    // GPU state
    uint32_t* d_ip_table;     // stores IPs
    uint32_t* d_port_count;   // activity counter per slot

    // intermediate buffers (for top-k stage)
    uint32_t* d_active_ips;
    uint32_t* d_active_counts;
    uint32_t* d_active_counter;

    uint32_t* d_top_ips;
    uint32_t* d_top_counts;
};

// lifecycle
void init_portscan(GPUPortScanState& state, uint32_t capacity);
void destroy_portscan(GPUPortScanState& state);

// pipeline
void launch_portscan(GPUPortScanState& state, const uint32_t* src_ip, const uint16_t* dst_port, uint32_t count);

// result extraction (TOP-K)
void collect_portscan(GPUPortScanState& state, uint32_t threshold, uint32_t* out_ips, uint32_t* out_counts);