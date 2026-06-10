#pragma once

#include "filter_preprocessing.h"

uint32_t process_gpu_batch(const PacketArrays& h_batch, uint32_t count);
