#ifndef _CONF_MODULE_H_
#define _CONF_MODULE_H_

struct config;

struct config* config_new(const char* file);
void config_free(struct config* config);

const char** config_get_module_names(struct config* config);
const char* config_get_option(struct config* config, const char* module_name);

#endif
