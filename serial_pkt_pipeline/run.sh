#!/bin/bash

make clean
make
./pkt_pipeline datasets/caida_ddos_trace.pcap
