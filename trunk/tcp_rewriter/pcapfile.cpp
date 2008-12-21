#include "pcapfile.h"
#include "flowkey.h"
#include "conntracker.h"

#include <netinet/tcp.h>

#include <stdexcept>

PcapFile::PcapFile(const std::string& filename)
{
	pcapFile = pcap_open_offline(filename.c_str(), errorBuffer);
	if (!pcapFile) {
		throw std::runtime_error(std::string("Cannot open pcap file ") + filename + ": " + errorBuffer);
	}
}

void PcapFile::readToMem(ConnTracker* connTracker)
{
	const unsigned char* pcapData;
	struct pcap_pkthdr packetHeader;
	while (NULL != (pcapData = pcap_next(pcapFile, &packetHeader))) {
		connTracker->addPacket(pcapData, &packetHeader);
	}
}

PcapFile::~PcapFile()
{
	if (pcapFile) {
		pcap_close(pcapFile);
	}
}
