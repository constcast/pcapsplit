#ifndef _PACKET_H_
#define _PACKET_H_

#include <pcap.h>

struct packet {
	struct pcap_pkthdr header;
	const unsigned char* data;
};

#endif
