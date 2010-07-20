#include "pcap-tools.h"

#include <stdlib.h>

struct dumper_tool* dumper_tool_open_file(const char* filename, int linktype)
{
	struct dumper_tool* ret = (struct dumper_tool*)malloc(sizeof(struct dumper_tool));
	ret->out_descriptor = pcap_open_dead(linktype, 65535);
	ret->dumper = pcap_dump_open(ret->out_descriptor, filename);
	return ret;
}

int dumper_tools_close_file(struct dumper_tool** dumper)
{
	pcap_dump_flush((*dumper)->dumper);
	pcap_dump_close((*dumper)->dumper);

	free(*dumper);
	dumper = NULL;
	
	return 0;
}

