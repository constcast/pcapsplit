#include "size_dumper.h"

#include <stdlib.h>
#include <string.h>

#define MAX_FILENAME 65535

struct size_dumper_data {
	char base_filename[MAX_FILENAME];
	char dump_filename[MAX_FILENAME];
	size_t number;
};

int size_dumper_init(struct dumping_module* m, void* data)
{
	struct size_dumper_data* sdata = (struct size_dumper_data*)malloc(
		sizeof(struct size_dumper_data));
	strncpy(sdata->base_filename, (char*)data, MAX_FILENAME);
	sdata->number = 0;
	m->module_data = (void*)sdata;
	return 0;
}

int size_dumper_finish(struct dumping_module* m)
{
	free(m->module_data);
	m->module_data = NULL;
	return 0;
}

int size_dumper_run(struct dumping_module* m, struct packet* p)
{
	return 0;
}
