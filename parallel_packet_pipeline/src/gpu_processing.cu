#include "gpu_processing.h"
#include "kernel.h"

// Create data buffer for a stream
void initialize_pipeline(GPUPipelineSlot& pipeline, uint32_t capacity) {
    pipeline.capacity = capacity;
    
    // Create stream event
    cudaStreamCreate(&pipeline.stream);
    cudaEventCreate(&pipeline.finished);

    pipeline.h_mask.resize(capacity);

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
    cudaMemcpyAsync(batch.h_mask.data(), batch.d_mask, count * sizeof(uint8_t), cudaMemcpyDeviceToHost, batch.stream);

    cudaEventRecord(batch.finished, batch.stream);
}

uint32_t collect_results(GPUPipelineSlot& batch, uint32_t count) {
    cudaEventSynchronize(batch.finished);

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

    cudaFree(pipeline.d_mask);

    cudaEventDestroy(pipeline.finished);
    cudaStreamDestroy(pipeline.stream);
}


// DevicePacketArrays& gpu_H2D(const PacketArrays& h_batch, uint32_t count, cudaStream_t stream) {
        
//     // Store pointers to each of the device vector locations 
//     DevicePacketArrays d_batch;

//     // Allocate device memory
//     cudaMallocAsync((void**)&d_batch.protocol, count * sizeof(uint8_t), stream);

//     cudaMallocAsync((void**)&d_batch.src_port, count * sizeof(uint16_t), stream);
//     cudaMallocAsync((void**)&d_batch.dst_port, count * sizeof(uint16_t), stream);

//     cudaMallocAsync((void**)&d_batch.src_ip, count * sizeof(uint32_t), stream);
//     cudaMallocAsync((void**)&d_batch.dst_ip, count * sizeof(uint32_t), stream);

//     cudaMallocAsync((void**)&d_batch.packet_len, count * sizeof(uint32_t), stream);


//     // Copy Host --> Device
//     cudaMemcpyAsync(d_batch.protocol, h_batch.protocol.data(), count * sizeof(uint8_t), cudaMemcpyHostToDevice, stream);

//     cudaMemcpyAsync(d_batch.src_port, h_batch.src_port.data(), count * sizeof(uint16_t), cudaMemcpyHostToDevice, stream);
//     cudaMemcpyAsync(d_batch.dst_port, h_batch.dst_port.data(), count * sizeof(uint16_t), cudaMemcpyHostToDevice, stream);

//     cudaMemcpyAsync(d_batch.src_ip, h_batch.src_ip.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);
//     cudaMemcpyAsync(d_batch.dst_ip, h_batch.dst_ip.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

//     cudaMemcpyAsync(d_batch.packet_len, h_batch.packet_len.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

//     return &d_batch;
// }

// uint8_t* gpu_kernel_call(const PacketArrays& d_batch, uint32_t count, cudaStream_t stream) {
//     PacketFilter filter{};

//     filter.src_ip = inet_addr("71.126.222.64");
//     filter.dst_ip = inet_addr("254.229.252.232");

//     // Keep track of the packets & if they satisfy the filter
//     uint8_t* d_mask;
//     cudaMallocAsync((void**)&d_mask, count * sizeof(uint8_t), stream);

//     // Time kernel launch ~ not yet implemented 
//     filter_batch(d_batch, filter, d_mask, count, stream);
    
//     return d_mask; 
// }


// uint32_t gpu_D2H(uint32_t& d_mask, uint32_t count, cudaStream_t stream) {
//     // Transfer filter results from device --> host
//     std::vector<uint8_t> h_mask(count);
//     cudaMemcpyAsync(h_mask.data(), d_mask, count * sizeof(uint8_t), cudaMemcpyDeviceToHost, stream);

//     size_t matches = 0;
//     for(size_t i = 0; i < count; i++) {
//         matches += h_mask[i];
//     }

//     // std::cout << "Matched packets: " << matches << "\n";
//     return matches;
// }

// void gpu_free(const PacketArrays& d_batch, uint32_t& d_mask, cudaStream_t stream) {
//     cudaFreeAsync(d_batch.protocol, stream);

//     cudaFreeAsync(d_batch.src_port, stream);
//     cudaFreeAsync(d_batch.dst_port, stream);

//     cudaFreeAsync(d_batch.src_ip, stream);
//     cudaFreeAsync(d_batch.dst_ip, stream);

//     cudaFreeAsync(d_batch.packet_len, stream);

//     cudaFreeAsync(d_mask, stream);
// }