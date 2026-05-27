CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS = -lpcap

SRC = src/main.cpp src/packet.cpp
OUT = pkt_pipeline

all:
	$(CXX) $(CXXFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

run:
	./$(OUT) datasets/sample.pcap

clean:
	rm -f $(OUT)
