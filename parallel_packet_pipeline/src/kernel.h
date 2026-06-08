#pragma once

#include "filter_preprocessing.h"

void filter_batch(DevicePacketArrays batch, PacketFilter filter, uint8_t* mask, uint32_t N);