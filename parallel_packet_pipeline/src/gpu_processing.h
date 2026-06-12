#pragma once

#include "filter_preprocessing.h"

struct GPUPipelineSlot{
    cudaStream_t stream;

    cudaEvent_t start, finished;

    DevicePacketArrays d_batch;

    uint8_t *h_mask, *d_mask;
    uint32_t capacity;

    float batch_time_ms;
};

void initialize_pipeline(GPUPipelineSlot& pipeline, uint32_t capacity);

void launch_batch(GPUPipelineSlot& batch, const PacketArrays& h_batch, uint32_t count, const PacketFilter& filter);

uint32_t collect_results(GPUPipelineSlot& batch, uint32_t count);

void destroy_pipeline(GPUPipelineSlot& pipeline);