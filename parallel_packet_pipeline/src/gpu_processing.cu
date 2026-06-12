#include "gpu_processing.h"
#include "kernel.h"

// Create data buffer for a stream
void initialize_pipeline(GPUPipelineSlot& pipeline, uint32_t capacity) {
    pipeline.capacity = capacity;
    
    // Create stream & events (track latency)
    cudaStreamCreate(&pipeline.stream);
    cudaEventCreate(&pipeline.start);
    cudaEventCreate(&pipeline.finished);

    // Allocate memory on the host to recieve results saved in d_mask
    cudaMallocHost((void**)&pipeline.h_mask, capacity * sizeof(uint8_t));

    // Allocate memory on device
    cudaMalloc(&pipeline.d_batch.protocol, capacity * sizeof(uint8_t));

    cudaMalloc(&pipeline.d_batch.src_port, capacity * sizeof(uint16_t));
    cudaMalloc(&pipeline.d_batch.dst_port, capacity * sizeof(uint16_t));

    cudaMalloc(&pipeline.d_batch.src_ip, capacity * sizeof(uint32_t));
    cudaMalloc(&pipeline.d_batch.dst_ip, capacity * sizeof(uint32_t));

    cudaMalloc(&pipeline.d_batch.packet_len, capacity * sizeof(uint32_t));

    cudaMalloc(&pipeline.d_mask, capacity * sizeof(uint8_t));
}

// Reuse existing GPU data buffer for each batch
void launch_batch(GPUPipelineSlot& batch, const PacketArrays& h_batch, uint32_t count, const PacketFilter& filter) {
    batch.d_batch.count = count;

    // Keep track of total memcpy & kernel launch time
    cudaEventRecord(batch.start, batch.stream);

    // Copy Host --> Device
    cudaMemcpyAsync(batch.d_batch.protocol, h_batch.protocol.data(), count * sizeof(uint8_t), cudaMemcpyHostToDevice, batch.stream);

    cudaMemcpyAsync(batch.d_batch.src_port, h_batch.src_port.data(), count * sizeof(uint16_t), cudaMemcpyHostToDevice, batch.stream);
    cudaMemcpyAsync(batch.d_batch.dst_port, h_batch.dst_port.data(), count * sizeof(uint16_t), cudaMemcpyHostToDevice, batch.stream);

    cudaMemcpyAsync(batch.d_batch.src_ip, h_batch.src_ip.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice, batch.stream);
    cudaMemcpyAsync(batch.d_batch.dst_ip, h_batch.dst_ip.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice, batch.stream);

    cudaMemcpyAsync(batch.d_batch.packet_len, h_batch.packet_len.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice, batch.stream);

    // Time kernel launch ~ not yet implemented 
    filter_batch(batch.d_batch, filter, batch.d_mask, count, batch.stream);

    // Transfer data back to host
    cudaMemcpyAsync(batch.h_mask, batch.d_mask, count * sizeof(uint8_t), cudaMemcpyDeviceToHost, batch.stream);

    cudaEventRecord(batch.finished, batch.stream);
}

uint32_t collect_results(GPUPipelineSlot& batch, uint32_t count) {
    if(cudaEventQuery(batch.finished) == cudaSuccess) {
        cudaEventSynchronize(batch.finished);
    } 
    // Calculate total GPU time of batch
    float ms = 0.0f;
    cudaEventElapsedTime(&ms, batch.start, batch.finished);

    batch.batch_time_ms = ms;

    uint64_t matches = 0;
    for(uint32_t i = 0; i < count; i++) {
        matches += batch.h_mask[i];
    }

    return matches;
}

void destroy_pipeline(GPUPipelineSlot& pipeline) {
    cudaFree(pipeline.d_batch.protocol);

    cudaFree(pipeline.d_batch.src_port);
    cudaFree(pipeline.d_batch.dst_port);

    cudaFree(pipeline.d_batch.src_ip);
    cudaFree(pipeline.d_batch.dst_ip);

    cudaFree(pipeline.d_batch.packet_len);

    cudaFreeHost(pipeline.h_mask);
    cudaFree(pipeline.d_mask);

    cudaEventDestroy(pipeline.finished);
    cudaStreamDestroy(pipeline.stream);
}