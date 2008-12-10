#include "conf.h"
#include "iniparser.h"

struct config {
	dictionary* d;
};

struct config* config_new(const char* file)
{
	return NULL;
}


void config_free(struct config* config)
{

}

const char** config_get_module_names(struct config* config)
{
	return NULL;
}

const char* config_get_option(struct config* config, const char* module_name)
{
	return NULL;
}

