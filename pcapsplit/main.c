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
#include "module_list.h"
#include "conf.h"

#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>

#include <tools/msg.h>

#include <pcap.h>

#define MAX_FILENAME 65535

void usage(char* progname)
{
	fprintf(stderr, "\n%s version %s\n\n", basename(progname), VERSION);
	fprintf(stderr, "Usage: %s <config-file>\n\n", basename(progname));
}

static void print_stats(pcap_t* pcap, uint64_t packets_captured) 
{
	struct pcap_stat stat;
	if (0 > pcap_stats(pcap, &stat)) {
		msg(MSG_INFO, "Could not get pcap stats!");
		return;
	}
	double ratio = stat.ps_drop?(double)stat.ps_drop/(double)stat.ps_recv*100:0;
	msg(MSG_INFO, "%llu packets captured, %u received by filter, %u dropped by kernel, %f%% packet drop", packets_captured, stat.ps_recv, stat.ps_drop, ratio);
}

pcap_t* open_pcap(const char* name, int is_interface) 
{
	char errorBuffer[PCAP_ERRBUF_SIZE];
	pcap_t* pfile;
	if (is_interface) {
		// TODO: we might want to configure this? do we?
		pfile = pcap_open_live(name, 65535, 1, 0, errorBuffer);
	} else {
		pfile = pcap_open_offline(name, errorBuffer); 
	}
	if (!pfile) {
		msg(MSG_ERROR, "Cannot open %s: %s", name, errorBuffer);
		exit(-1);
	}
	return pfile;
}

int main(int argc, char** argv)
{
	const char* pcap_file;
	const char* capture_interface;
	int is_live = 0;
	int running = 1;

	if (argc != 2) {
		usage(argv[0]);
		return -1;
	}

	msg_setlevel(MSG_INFO);
	msg(MSG_INFO, "%s is initializing ...", argv[0]);

	struct dumpers dumps;
	dumpers_init(&dumps);

	struct config* conf = config_new(argv[1]);
	if (!conf) {
		msg(MSG_ERROR, "Invalid config. Abort!");
		return 0;
	}

	pcap_file = config_get_option(conf, MAIN_NAME, "pcapfile");
	capture_interface = config_get_option(conf, MAIN_NAME, "interface");

	if (!pcap_file && !capture_interface) {
		msg(MSG_FATAL, "main: Neither \"pcapfile\" nor \"interface\" given in config file.");
		exit(-1);
	} if (pcap_file && capture_interface) {
		msg(MSG_FATAL, "main: Got \'pcapfile\" *and* \"interface\". Please decide whether you want to work on- or offline!");
		exit(-1);
	}
	
	pcap_t* pfile;
	if (pcap_file) { 
		pfile = open_pcap(pcap_file, 0); 
		dumpers_create_all(&dumps, conf, pcap_datalink(pfile), 65535);
	} else {
		is_live = 1;
		pfile = open_pcap(capture_interface, 1);
		dumpers_create_all(&dumps, conf, pcap_datalink(pfile), 65535);
		// the dumper creating can take a significant amount of time.
		// We could not read any packets during this initialization phase and 
		// could therefore drop a significant amount of packets (depending on
		// the link speed). We therefore close and reopen the pcap descriptor
		// in order to reset the statistics and get more accurate packet
		// drop statistice (we had to open the pcap interface for retrieving the
		// interface link type which is important for module initialization
		pcap_close(pfile);
		pfile = open_pcap(capture_interface, 1);
	}
	msg(MSG_INFO, "%s is up and running. Starting to consume packets ...", argv[0]);

	struct packet p;
	int i;
	time_t last_stats = 0;
	time_t stats_interval = 10;
	uint64_t captured = 0;
	while (running) {
		if (NULL != (p.data = pcap_next(pfile, &p.header))) {
			captured++;
			if (p.header.ts.tv_sec - last_stats > stats_interval && is_live) {
				last_stats = p.header.ts.tv_sec;
				print_stats(pfile, captured);
			}
			packet_init(&p, &p.header, p.data);
			for (i = 0; i != dumps.count; ++i) {
				dumps.modules[i]->dfunc(dumps.modules[i], &p);
			}
		} else {
			if (!is_live)
				running = 0;
		}
	}

	msg(MSG_INFO, "%s finished reading packets ...", argv[0]);

	dumpers_finish(&dumps);
	config_free(conf);

	return 0;
}
