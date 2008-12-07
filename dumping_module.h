#ifndef _DUMPING_MODULE_H_
#define _DUMPING_MODULE_H_

#include "packet.h"

#include <sys/types.h>

typedef int (dumper_init)(void* data);
typedef int (dumper_finish)();
typedef int (dumper_func)(struct packet* p);

struct dumping_module {
	dumper_init* dinit;
	dumper_finish* dfinish;
	dumper_func* dfunc;
};

struct dumpers {
	struct dumping_module* module;
	size_t count;
};

int dumpers_init(struct dumpers* d);
int dumpers_finish(struct dumpers* d);
int dumpers_add(struct dumpers* d, struct dumping_module* dm);

#endif
