#include "pcap-tools.h"

#include <stdlib.h>

struct dumper_tool* dumper_tool_open_file(const char* filename, int linktype)
{
	struct dumper_tool* ret = (struct dumper_tool*)malloc(sizeof(struct dumper_tool));
	ret->out_descriptor = pcap_open_dead(linktype, 65535);
	if (!ret->out_descriptor) {
		fprintf(stderr, "Error on pcap_open_dead!\n");
		goto out;
	}
	
	ret->dumper = pcap_dump_open(ret->out_descriptor, filename);
	if (!ret->dumper) {
		fprintf(stderr, "Error opening %s: %s\n", filename, pcap_geterr(ret->out_descriptor));
		goto out;
	}

	return ret;
out: 
	free(ret);
	return NULL;
}

int dumper_tool_close_file(struct dumper_tool** dumper)
{
	if (*dumper && (*dumper)->dumper) {
		pcap_dump_flush((*dumper)->dumper);
		pcap_dump_close((*dumper)->dumper);
	}

	free(*dumper);
	dumper = NULL;
	
	return 0;
}

int dumper_tool_dump(struct dumper_tool* d, struct pcap_pkthdr* header, const unsigned char* data)
{
	if (!d || !d->dumper) {
		fprintf(stderr, "Dumper is invalied. Cannot dump packet\n");
		return -1;
	}
	pcap_dump((unsigned char*)d->dumper, header, data);
	return 0;
}

