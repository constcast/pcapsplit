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

#include "packet.h"
#include "dumping_module.h"
#include "conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>

#include <pcap.h>

#define MAX_FILENAME 65535

void usage(char* progname)
{
	fprintf(stderr, "\n%s version %s\n\n", basename(progname), VERSION);
	fprintf(stderr, "Usage: %s <pcapfile> <config-file>\n\n", basename(progname));
}

int main(int argc, char** argv)
{
	char errorBuffer[PCAP_ERRBUF_SIZE];
	if (argc != 3) {
		usage(argv[0]);
		return -1;
	}

	struct dumpers dumps;
	dumpers_init(&dumps);

	struct config* conf = config_new(argv[2]);
	if (!conf) {
		fprintf(stderr, "Invalid config. Abort!\n");
		return 0;
	}

	pcap_t* pfile = pcap_open_offline(argv[1], errorBuffer); 
	if (!pfile) {
		fprintf(stderr, "Cannot open %s: %s\n", argv[1], errorBuffer);
		return -1;
	}

	dumpers_create_all(&dumps, conf, pcap_datalink(pfile), 65535);

	struct packet p;
	int i;
	while (NULL != (p.data = pcap_next(pfile, &p.header))) {
		packet_init(&p, &p.header, p.data);
		for (i = 0; i != dumps.count; ++i) {
			dumps.modules[i]->dfunc(dumps.modules[i], &p);
		}
	}

	dumpers_finish(&dumps);
	config_free(conf);

	return 0;
}
