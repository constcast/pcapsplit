#ifndef _PCAP_FILE_H_
#define _PCAP_FILE_H_

#include <pcap.h>

#include <string>
#include <stdexcept>

class ConnTracker;

class PcapFile {
public:
	PcapFile(const std::string& infile, const std::string& outFile);
	~PcapFile();

	void readToMem(ConnTracker* connTracker);
	void writeToFile(ConnTracker* connTracker);
private:
	std::string inFile;
	std::string outfile;
	char errorBuffer[PCAP_ERRBUF_SIZE]; 
	pcap_t* pcapInFile;
	pcap_t* pcapOutFile;
	pcap_dumper_t* dumper;
};

#endif
