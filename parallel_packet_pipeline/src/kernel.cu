#include "packet.h"
#include "filter_preprocessing.h"

const int BLOCK_SIZE = 256;


__global__ void filter_kernel(DevicePacketArrays batch, PacketFilter filter, uint8_t* mask) {
    
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if(idx >= batch.count)
        return;

    bool match = true;

    // Protocol
    if(filter.filter_tcp) {
        match &= (batch.protocol[idx] == 6);
    }

    if(filter.filter_udp) {
        match &= (batch.protocol[idx] == 17);
    }


    // Src & Dst ports
    if(filter.src_port) {
        match &= (batch.src_port[idx] == filter.src_port);
    }

    if(filter.dst_port) {
        match &= (batch.dst_port[idx] == filter.dst_port);
    }


    // IP
    if(filter.use_src_ip) {
        match &= (batch.src_ip[idx] == filter.src_ip);
    }

    if(filter.use_dst_ip) {
        match &= (batch.dst_ip[idx] == filter.dst_ip);
    }


    // Pkt length
    if(filter.min_len_enabled) {
        match &= (batch.packet_len[idx] >= filter.min_len);
    }

    mask[idx] = match;
}

void filter_batch(DevicePacketArrays batch, PacketFilter filter, uint8_t* mask, uint32_t N, cudaStream_t stream) {

    int blocks = (N + BLOCK_SIZE - 1) / BLOCK_SIZE;
    filter_kernel<<<blocks, BLOCK_SIZE, 0, stream>>>(batch, filter, mask);
}