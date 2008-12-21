#include <iostream>
#include <string>

#include "pcapfile.h"
#include "conntracker.h"

void usage(const std::string& progName);

int main(int argc, char** argv)
{
	if (argc != 3) {
		std::cerr << "Missing arguments!" << std::endl << std::endl;
		usage(argv[0]);
		return -1;
	}

	std::string inputFile = argv[1];
	std::string outputFile = argv[2];
	ConnTracker connTracker;

	try {
		PcapFile infile(inputFile);
		std::cout << "Reading data from file..." << std::endl;
		infile.readToMem(&connTracker);
		std::cout << "Found " << connTracker.count() << " tcp connections in pcap file." << std::endl;
		std::cout << "Reording connections ..." << std::endl;
		connTracker.reorder();
		std::cout << "Removing dupicates ... " << std::endl;
		connTracker.removeDuplicates();
		std::cout << "Generating output list ..." << std::endl;
		connTracker.generateOutputList();
		std::cout << "Wrinting output file ..." << std::endl;
	} catch (std::runtime_error& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

	return 0;
}

void usage(const std::string& progName)
{
	std::cout << "Usage: " << progName << " <input-file> <output-file>" << std::endl;
	std::cout << "\t" << progName << " is a tool for working with pcap files." << std::endl;
	std::cout << "\t" << "It's main purpose is to take the old pcap files, extract the tcp connections, " << std::endl;
	std::cout << "\t" << "reorder the packets, remove duplicates and write the output to another pcap file." << std::endl << std::endl;
}

