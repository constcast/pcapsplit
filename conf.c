//  Copyright (C) 2008 Lothar Braun <lothar@lobraun.de>
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

#include <stdlib.h>

struct config {
	dictionary* d;
};

struct config* config_new(const char* file)
{
	struct config* ret = (struct config*)malloc(sizeof(struct config));
	ret->d = iniparser_new(file);
	return ret;
}


void config_free(struct config* config)
{
	iniparser_free(config->d);
	free(config);
}

const char** config_get_module_names(struct config* config)
{
	return NULL;
}

const char* config_get_option(struct config* config, const char* module_name)
{
	return NULL;
}

