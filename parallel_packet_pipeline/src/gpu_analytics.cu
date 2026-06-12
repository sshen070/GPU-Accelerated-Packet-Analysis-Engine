#include "gpu_analytics.h"
#include <cuda_runtime.h>
#include <cstdint>
#include <iostream>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>

#define IP_BUCKETS 1048576

// Each ip address in the batch ~ placed in a bucket (histogram implementation)
__device__ __forceinline__ uint32_t hash_ip(uint32_t ip) {
    ip ^= ip >> 16;
    ip *= 2246822519u;
    ip ^= ip >> 13;
    ip *= 3266489917u;
    ip ^= ip >> 16;
    return ip;
}

__global__ void portscan_kernel(const uint32_t* src_ip, const uint16_t* dst_port, uint32_t* ip_table, uint32_t* port_count, uint32_t n) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (i >= n) 
        return;

    uint32_t ip = src_ip[i];
    uint32_t idx = hash_ip(ip) % IP_BUCKETS;

    // Collision detection & handling (up to 4 attempts)
    for (int k = 0; k < 4; k++) {

        uint32_t pos = (idx + k) & (IP_BUCKETS - 1);

        uint32_t old = atomicCAS(&ip_table[pos], 0, ip);

        // If the slot is empty or IP already assigned previously --> increment
        if (old == 0 || old == ip) {

            ip_table[pos] = ip;
            atomicAdd(&port_count[pos], 1);

            break;
        }
    }
}

__global__ void extract_active_kernel(const uint32_t* ip_table, const uint32_t* port_count, uint32_t* out_ips, uint32_t* out_counts, uint32_t* counter, uint32_t n, uint32_t threshold) {
    
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;

    if (i >= n) 
        return;

    // Add to detection list ONLY if IP address meets threshold
    if (ip_table[i] != 0 && port_count[i] > threshold) {

        uint32_t idx = atomicAdd(counter, 1);

        out_ips[idx] = ip_table[i];
        out_counts[idx] = port_count[i];
    }
}

// Save top IPs & corresponding counts (transfer back to host later)
__global__ void topk_kernel(const uint32_t* ips, const uint32_t* counts, uint32_t n, uint32_t* top_ips, uint32_t* top_counts) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) 
        return;

    for (int k = 0; k < TOPK; k++) {

        if (counts[i] > top_counts[k]) {

            atomicExch(&top_counts[k], counts[i]);
            atomicExch(&top_ips[k], ips[i]);

            break;
        }
    }
}

void init_portscan(GPUPortScanState& state, uint32_t capacity) {
    cudaStreamCreate(&state.stream);

    cudaMalloc(&state.d_src_ip, capacity * sizeof(uint32_t));
    cudaMalloc(&state.d_dst_port, capacity * sizeof(uint16_t));

    cudaMalloc(&state.d_ip_table, IP_BUCKETS * sizeof(uint32_t));
    cudaMalloc(&state.d_port_count, IP_BUCKETS * sizeof(uint32_t));

    cudaMemset(state.d_ip_table, 0, IP_BUCKETS * sizeof(uint32_t));
    cudaMemset(state.d_port_count, 0, IP_BUCKETS * sizeof(uint32_t));

    cudaMalloc(&state.d_active_ips, IP_BUCKETS * sizeof(uint32_t));
    cudaMalloc(&state.d_active_counts, IP_BUCKETS * sizeof(uint32_t));
    cudaMalloc(&state.d_active_counter, sizeof(uint32_t));

    cudaMalloc(&state.d_top_ips, TOPK * sizeof(uint32_t));
    cudaMalloc(&state.d_top_counts, TOPK * sizeof(uint32_t));
}


void destroy_portscan(GPUPortScanState& state) {
    cudaFree(state.d_src_ip);
    cudaFree(state.d_dst_port);

    cudaFree(state.d_ip_table);
    cudaFree(state.d_port_count);

    cudaFree(state.d_active_ips);
    cudaFree(state.d_active_counts);
    cudaFree(state.d_active_counter);

    cudaFree(state.d_top_ips);
    cudaFree(state.d_top_counts);

    cudaStreamDestroy(state.stream);
}


void launch_portscan(GPUPortScanState& state, const uint32_t* src_ip, const uint16_t* dst_port, uint32_t count) {
    
    dim3 block(256);
    dim3 grid((count + 255) / 256);

    // Accumulate IP table
    portscan_kernel<<<grid, block, 0, state.stream>>>(src_ip, dst_port, state.d_ip_table, state.d_port_count, count);
}

void collect_portscan(GPUPortScanState& state, uint32_t threshold, uint32_t* out_ips, uint32_t* out_counts) {
    cudaMemset(state.d_active_counter, 0, sizeof(uint32_t));

    dim3 block(256);
    dim3 grid((IP_BUCKETS + 255) / 256);

    // Kernel launch to create detection list based on top IPs
    extract_active_kernel<<<grid, block>>>(state.d_ip_table, state.d_port_count, state.d_active_ips, state.d_active_counts, state.d_active_counter, IP_BUCKETS, threshold);

    uint32_t h_count = 0;
    cudaMemcpy(&h_count, state.d_active_counter, sizeof(uint32_t), cudaMemcpyDeviceToHost);

    dim3 grid2((h_count + 255) / 256);

    cudaMemset(state.d_top_ips, 0, TOPK * sizeof(uint32_t));
    cudaMemset(state.d_top_counts, 0, TOPK * sizeof(uint32_t));

    // Grab only the TOPK IPs on detection list
    topk_kernel<<<grid2, block>>>(state.d_active_ips, state.d_active_counts, h_count, state.d_top_ips, state.d_top_counts);

    cudaMemcpy(out_ips, state.d_top_ips, TOPK * sizeof(uint32_t), cudaMemcpyDeviceToHost);
    cudaMemcpy(out_counts, state.d_top_counts, TOPK * sizeof(uint32_t), cudaMemcpyDeviceToHost);
}