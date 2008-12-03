#include "packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>

#include <pcap.h>

#define MAX_FILENAME 65535

void usage(char* progname)
{
	fprintf(stderr, "Usage: %s <pcapfile> slicesize(in MB)\n", basename(progname));
}

int dump_to_file(pcap_t* readDev, pcap_dumper_t* dumper, size_t dump_size)
{
	struct packet p;
	size_t s = 0;
	while (NULL != (p.data = pcap_next(readDev, &p.header))) {
		pcap_dump((unsigned char*)dumper, &p.header, p.data);
		s += p.header.len;
		if (s >= dump_size) {
			// dump file reach size limit
			return 0;
		}
	}
	// end of file
	return -1;
}

int main(int argc, char** argv)
{
	char errorBuffer[PCAP_ERRBUF_SIZE];
	char outfile[MAX_FILENAME];
	unsigned filenumber = 0;
	if (argc != 3) {
		usage(argv[0]);
		return -1;
	}

	pcap_t* pfile = pcap_open_offline(argv[1], errorBuffer); 
	if (!pfile) {
		fprintf(stderr, "Cannot open %s: %s\n", argv[1], errorBuffer);
		return -1;
	}

	const unsigned slice_size = atoi(argv[2]) * 1000000;
	int ret = 0;
	do {
		sprintf(outfile, "%s.%i", argv[1], filenumber);
		pcap_t* out = pcap_open_dead(pcap_datalink(pfile), 65535);
		pcap_dumper_t* dumper = pcap_dump_open(out, outfile);
		if (!dumper) {
			fprintf(stderr, "Could not open pcapfile %s: %s", outfile, errorBuffer);
			return -1;
		}
		 ret = dump_to_file(pfile, dumper, slice_size);
		pcap_dump_flush(dumper);
		pcap_dump_close(dumper);
		filenumber++;
	} while (0 == ret);

	return 0;
}