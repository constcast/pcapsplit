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

#include <tools/packet.h>
#include <modules/dumping_module.h>
#include <modules/module_list.h>
#include <tools/conf.h>

#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>

#include <tools/msg.h>

#include <pcap.h>

#include <pthread.h>

#define MAX_FILENAME 65535

static uint32_t prev_recv = 0;
static uint32_t prev_drop = 0;
static uint64_t prev_app = 0;
static volatile int running = 1;

void usage(char* progname)
{
	fprintf(stderr, "\n%s version %s\n\n", basename(progname), VERSION);
	fprintf(stderr, "Usage: %s <config-file>\n\n", basename(progname));
}

static void print_stats(pcap_t* pcap, uint64_t packets_captured, struct packet_pool* pool) 
{
	struct pcap_stat stat;
	if (0 > pcap_stats(pcap, &stat)) {
		msg(MSG_INFO, "Could not get pcap stats!");
		return;
	}
	uint32_t recv_this_interval = stat.ps_recv - prev_recv;
	uint32_t drop_this_interval = stat.ps_drop - prev_drop;

	//double ratio = stat.ps_recv?(double)stat.ps_drop/(double)stat.ps_recv*100:0;
	//msg(MSG_INFO, "%llu packets captured, %u received by filter, %u dropped by kernel, %f%% packet drop", packets_captured, stat.ps_recv, stat.ps_drop, ratio);
	double ratio = recv_this_interval?(double)drop_this_interval/(double)recv_this_interval*100:0;
	msg(MSG_INFO, "%llu packets captured, %u received by filter, %u dropped by kernel, %f%% packet drop in kernel, %llu packets lost in app", packets_captured, recv_this_interval, drop_this_interval, ratio, packet_lost(pool) - prev_app);
	
	prev_recv = stat.ps_recv;
	prev_drop = stat.ps_drop;
	prev_app = packet_lost(pool);
}

pcap_t* open_pcap(const char* name, int is_interface, int snaplen) 
{
	char errorBuffer[PCAP_ERRBUF_SIZE];
	pcap_t* pfile;
	if (is_interface) {
		// TODO: we might want to configure this? do we?
		pfile = pcap_open_live(name, snaplen, 1, 0, errorBuffer);
	} else {
		pfile = pcap_open_offline(name, errorBuffer); 
	}
	if (!pfile) {
		msg(MSG_ERROR, "Cannot open %s: %s", name, errorBuffer);
		exit(-1);
	}
	return pfile;
}

struct thread_data {
	struct packet_pool* pool;
	struct dumpers* dumpers;
};

void* worker_thread(void* d)
{
	struct thread_data* data = (struct thread_data*)d;
	uint32_t i;
	struct packet* p;

	while (running) {
		p = packet_get(data->pool);
		// we could have returned from packet_get because of an abort signal
		// check the running flag because we might have been woken for shutdown!
		if (!p || !running) {
			continue;
		}
		for (i = 0; i != data->dumpers->count; ++i) {
			data->dumpers->modules[i]->dfunc(data->dumpers->modules[i], p);
		}
		packet_free(data->pool, p);
	}

	return NULL;
}

int main(int argc, char** argv)
{
	const char* pcap_file;
	const char* capture_interface;
	const char* tmp;
	int is_live = 0;
	int snaplen = 65535;
	uint32_t packet_pool_size = 1;
	pthread_t worker_id;

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

	tmp = config_get_option(conf, MAIN_NAME, "max_packet_size");
	if (tmp) {
		snaplen = atoi(tmp);
	}

	tmp = config_get_option(conf, MAIN_NAME, "packet_pool");
	if (tmp) {
		packet_pool_size = atoi(tmp);
	}

	struct packet_pool* packet_pool = packet_pool_init(packet_pool_size, snaplen);
	struct thread_data worker_data;
	worker_data.pool = packet_pool;
	worker_data.dumpers = &dumps;

	pcap_t* pfile;
	if (pcap_file) { 
		pfile = open_pcap(pcap_file, 0, snaplen); 
		dumpers_create_all(&dumps, conf, pcap_datalink(pfile), snaplen);
		if (!dumps.count) {
			msg(MSG_FATAL, "Could not configure any modules.");
			return -1;
		}
		if (pthread_create(&worker_id, NULL, worker_thread, &worker_data)) {
			msg(MSG_FATAL, "Could not create worker thread: %s", strerror(errno));
			return -1;
		}
	} else {
		is_live = 1;
		pfile = open_pcap(capture_interface, 1, snaplen);
		dumpers_create_all(&dumps, conf, pcap_datalink(pfile), snaplen);
		if (!dumps.count) {
			msg(MSG_FATAL, "Could not configure any modules.");
			return -1;
		}
		// the dumper creating can take a significant amount of time.
		// We could not read any packets during this initialization phase and 
		// could therefore drop a significant amount of packets (depending on
		// the link speed). We therefore close and reopen the pcap descriptor
		// in order to reset the statistics and get more accurate packet
		// drop statistice (we had to open the pcap interface for retrieving the
		// interface link type which is important for module initialization
		pcap_close(pfile);
		if (pthread_create(&worker_id, NULL, worker_thread, &worker_data)) {
			msg(MSG_FATAL, "Could not create worker thread: %s", strerror(errno));
			return -1;
		}
		pfile = open_pcap(capture_interface, 1, snaplen);
	}
	msg(MSG_INFO, "%s is up and running. Starting to consume packets ...", argv[0]);

	struct pcap_pkthdr pcap_hdr;
	time_t last_stats = 0;
	time_t stats_interval = 10;
	uint64_t captured = 0;
	const unsigned char* data = NULL;
	while (running) {
		if (NULL != (data = pcap_next(pfile, &pcap_hdr))) {
			captured++;
			if (pcap_hdr.ts.tv_sec - last_stats > stats_interval && is_live) {
				last_stats = pcap_hdr.ts.tv_sec;
				print_stats(pfile, captured, packet_pool);
			}
			packet_new(packet_pool, &pcap_hdr, data);
		} else {
			if (!is_live)
				running = 0;
		}
	}

	msg(MSG_INFO, "%s finished reading packets ...", argv[0]);

	// TODO: this is a hack! we might need to wake the worker thread
	// because it might be blocked at a mutex waiting for new packets
	// we have to insert a packet in order to wake the thread from the 
	// mutex. Hence, we re-include the last packet into the pool again ...
	// FIXME: The hack can result in a segmentation fault if no packet
	// has been read from the pcap_t ...
	unsigned char* useless = malloc(snaplen);
	packet_new(packet_pool, &pcap_hdr, useless);
	free(useless);
	pthread_join(worker_id, NULL);
	dumpers_finish(&dumps);
	packet_pool_deinit(packet_pool);
	config_free(conf);

	return 0;
}

