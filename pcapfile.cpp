#include "pcapfile.h"
#include "flowkey.h"
#include "conntracker.h"

#include <netinet/tcp.h>

#include <stdexcept>

PcapFile::PcapFile(const std::string& infile, const std::string& outfile)
{
	pcapInFile = pcap_open_offline(infile.c_str(), errorBuffer);
	if (!pcapInFile) {
		throw std::runtime_error(std::string("Cannot open pcap file ") + infile + " for reading: " + errorBuffer);
	}
	pcapOutFile = pcap_open_dead(pcap_datalink(pcapInFile), 65535);
	dumper = pcap_dump_open(pcapOutFile, outfile.c_str());
	if (!dumper) {
		pcap_close(pcapInFile);
		pcap_close(pcapOutFile);
		throw std::runtime_error(std::string("Cannot create pcap dumper object: ") + pcap_geterr(pcapOutFile));
	}
}

void PcapFile::readToMem(ConnTracker* connTracker)
{
	const unsigned char* pcapData;
	struct pcap_pkthdr packetHeader;
	while (NULL != (pcapData = pcap_next(pcapInFile, &packetHeader))) {
		connTracker->addPacket(pcapData, &packetHeader);
	}
}

PcapFile::~PcapFile()
{
	if (pcapInFile) {
		pcap_close(pcapInFile);
	}
	if (dumper) {
		pcap_dump_close(dumper);
	}
	if (pcapOutFile) {
		pcap_close(pcapOutFile);
	}
}

void PcapFile::writeToFile(ConnTracker* connTracker)
{
}

