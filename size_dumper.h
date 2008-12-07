#ifndef _SIZE_DUMPER_H_
#define _SIZE_DUMPER_H_

#include "dumping_module.h"

int size_dumper_init(struct dumping_module* m, void* data);
int size_dumper_finish(struct dumping_module* m);
int size_dumper_run(struct dumping_module* m, struct packet* p);

struct dumping_module size_dumper = {
	size_dumper_init,
	size_dumper_finish,
	size_dumper_run
};


#endif
