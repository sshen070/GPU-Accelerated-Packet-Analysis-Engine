CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS = -lpcap

SRC = src/main.cpp src/packet.cpp src/analytics.cpp
OUT = pkt_pipeline

all:
	$(CXX) $(CXXFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

run:
	./$(OUT) datasets/caida_ddos_trace.pcap

clean:
	rm -f $(OUT)
