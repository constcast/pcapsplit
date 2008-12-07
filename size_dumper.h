#ifndef _SIZE_DUMPER_H_
#define _SIZE_DUMPER_H_

#include "dumping_module.h"

int size_dumper_init(void* data);
int size_dumper_finish();
int size_dumper_run(struct packet* p);

struct dumping_module size_dumper = {
	size_dumper_init,
	size_dumper_finish,
	size_dumper_run
};


#endif
