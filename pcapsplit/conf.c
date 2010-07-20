//  Copyright (C) 2008-2010 Lothar Braun <lothar@lobraun.de>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "conf.h"
#include "iniparser.h"
#include "dumping_module.h"

#include <stdlib.h>

struct config {
	dictionary* d;
};

struct config* config_new(const char* file)
{
	struct config* ret = (struct config*)malloc(sizeof(struct config));
	ret->d = iniparser_new(file);
	if (ret->d == NULL) {
		fprintf(stderr, "Error parsing config file!\n");
		free(ret);
		return NULL;
	}
	return ret;
}


void config_free(struct config* config)
{
	iniparser_free(config->d);
	free(config);
}

size_t config_get_module_names(struct config* config, const char** module_names)
{
	int count = iniparser_getnsec(config->d);
	int i;

	if (count < 0) {
		fprintf(stderr, "Error in config file detected!\n");
		return 0;
	}

	if (count > MAX_MODULES) {
		fprintf(stderr, "Config file does contain more modules than allowed\n");
		return 0;
	}
	for (i = 0; i != count; ++i) {
		module_names[i] = iniparser_getsecname(config->d, i);
	}
	return count;
}

const char* config_get_option(struct config* config, const char* module_name, const char* option)
{
	return iniparser_getvalue(config->d, module_name, option);
}

