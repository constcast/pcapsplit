PROJECT(tcp_rewriter)

cmake_minimum_required(VERSION 2.6)

ADD_EXECUTABLE( tcp_rewriter
	main.cpp
	pcapfile.cpp
	conntracker.cpp
)

FIND_LIBRARY(PCAP_LIBRARY NAMES pcap)
IF (NOT PCAP_LIBRARY)
    MESSAGE(FATAL_ERROR "Could not find libpcap")
ENDIF (PCAP_LIBRARY)
TARGET_LINK_LIBRARIES(tcp_rewriter ${PCAP_LIBRARY})
	
