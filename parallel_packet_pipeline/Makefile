NVCC        = /usr/local/cuda/bin/nvcc

NVCCFLAGS = -std=c++17
LDFLAGS = -lpcap

SRC = src/*.cpp src/*.cu
OUT = pkt_pipeline

all:
	$(NVCC) $(NVCCFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

run:
	./$(OUT) ../datasets/caida_ddos_trace.pcap

clean:
	rm -f $(OUT)