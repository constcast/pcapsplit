#ifndef _PCAP_FILE_H_
#define _PCAP_FILE_H_

#include <pcap.h>

#include <string>
#include <stdexcept>

class ConnTracker;

class PcapFile {
public:
	PcapFile(const std::string& filename);
	~PcapFile();

	void readToMem(ConnTracker* connTracker);
private:
	std::string filename;
	char errorBuffer[PCAP_ERRBUF_SIZE]; 
	pcap_t* pcapFile;
};

#endif
