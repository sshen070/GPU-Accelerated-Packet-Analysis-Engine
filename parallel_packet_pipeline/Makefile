CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS = -lpcap

SRC = src/*.cpp
OUT = pkt_pipeline

all:
	$(CXX) $(CXXFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

run:
	./$(OUT) ../datasets/caida_ddos_trace.pcap

clean:
	rm -f $(OUT)
