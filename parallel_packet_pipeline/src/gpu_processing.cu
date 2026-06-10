#include "gpu_processing.h"
#include "kernel.h"


uint32_t process_gpu_batch(const PacketArrays& h_batch, uint32_t count) {
        
    // Store pointers to each of the device vector locations 
    DevicePacketArrays d_batch;

    // Allocate device memory
    cudaMalloc((void**)&d_batch.protocol, count * sizeof(uint8_t));

    cudaMalloc((void**)&d_batch.src_port, count * sizeof(uint16_t));
    cudaMalloc((void**)&d_batch.dst_port, count * sizeof(uint16_t));

    cudaMalloc((void**)&d_batch.src_ip, count * sizeof(uint32_t));
    cudaMalloc((void**)&d_batch.dst_ip, count * sizeof(uint32_t));

    cudaMalloc((void**)&d_batch.packet_len, count * sizeof(uint32_t));


    // Copy Host --> Device
    cudaMemcpy(d_batch.protocol, h_batch.protocol.data(), count * sizeof(uint8_t), cudaMemcpyHostToDevice);

    cudaMemcpy(d_batch.src_port, h_batch.src_port.data(), count * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_batch.dst_port, h_batch.dst_port.data(), count * sizeof(uint16_t), cudaMemcpyHostToDevice);

    cudaMemcpy(d_batch.src_ip, h_batch.src_ip.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_batch.dst_ip, h_batch.dst_ip.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice);

    cudaMemcpy(d_batch.packet_len, h_batch.packet_len.data(), count * sizeof(uint32_t), cudaMemcpyHostToDevice);


    PacketFilter filter{};

    filter.src_ip = inet_addr("71.126.222.64");
    filter.dst_ip = inet_addr("254.229.252.232");


    // Keep track of the packets & if they satisfy the filter
    uint8_t* d_mask;
    cudaMalloc((void**)&d_mask, count * sizeof(uint8_t));

    // Time kernel launch ~ not yet implemented 
    filter_batch(d_batch, filter, d_mask, count);

    // Transfer filter results from device --> host
    std::vector<uint8_t> h_mask(count);
    cudaMemcpy(h_mask.data(), d_mask, count * sizeof(uint8_t), cudaMemcpyDeviceToHost);

    size_t matches = 0;
    for(size_t i = 0; i < count; i++) {
        matches += h_mask[i];
    }

    // std::cout << "Matched packets: " << matches << "\n";

    cudaFree(d_batch.protocol);

    cudaFree(d_batch.src_port);
    cudaFree(d_batch.dst_port);

    cudaFree(d_batch.src_ip);
    cudaFree(d_batch.dst_ip);

    cudaFree(d_batch.packet_len);

    cudaFree(d_mask);

    return matches;
}