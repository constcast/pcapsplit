#include <pcap.h>
#include <zlib.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <pthread.h>

#define MAX_PACKET_LENGTH 1550
#define MAX_THREADS 16

#define MIN(X,Y) ((X) < (Y) ? : (X) : (Y))


struct user_data {
	unsigned char copied_packet[MAX_PACKET_LENGTH];
	unsigned char out_chunk[MAX_PACKET_LENGTH];
	z_stream strm;
	unsigned have;
	int flush;
	int thread_id;
};

typedef struct thread_str{
        int thread_id;
        char *thread_name;
        struct user_data udata;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *captureDevice;
        char *interface;
        int snaplen;
		int packets_captured;
}thread_str;

static void copy_compress_packet(unsigned char* args, const struct pcap_pkthdr *header, const unsigned char* packet);
static void init_user_data(struct user_data* udata, int compression_level);
static void info(pcap_t* pd, register int verbose, int packets_captured);
static void sig_int(int sig);


int zlib_compression_level=0;
pthread_t thread[MAX_THREADS];
thread_str my_thread_str[MAX_THREADS];
int thread_ret[MAX_THREADS];
int threads = 1;

// Results
int total_filter=0;
int total_dropped=0;
int total_captured=0;

volatile int quit_flag = 0;

void * working_thread( void * str ){
	thread_str *local_str = (thread_str *)str;
        printf("Starting %s %i on device %s \n", local_str->thread_name,local_str->thread_id,local_str->interface);

        init_user_data(&local_str->udata,zlib_compression_level);
		local_str->udata.thread_id = local_str->thread_id;
        
        printf("opening device %s with snaplen %d\n", local_str->interface, local_str->snaplen);
        local_str->captureDevice = NULL;
        local_str->captureDevice = pcap_open_live(local_str->interface, local_str->snaplen, 1, 0, local_str->errbuf);
        if (!local_str->captureDevice) {
                printf("Could not open pcap device %s: %s\n", local_str->interface, local_str->errbuf);
                exit(-1);
        }
        printf("Packet compression level  %d\n", zlib_compression_level);
        
        int ret;
        do {
                ret = pcap_dispatch(local_str->captureDevice, -1, &copy_compress_packet, (u_char*)&local_str->udata);
        } while  (ret >= 0 && !quit_flag);

	printf("finished thread\n");

        if (-1 ==  ret) {
                printf("error on pcap_loop: %s\n", pcap_geterr(local_str->captureDevice));
        }
         
        if (-2 == ret) {
                printf("print statistics\n");
        }
         
        return NULL;
}

int main(int argc, char** argv)
{
	//char errbuf[PCAP_ERRBUF_SIZE];
	struct user_data udata;
	
	int i;
	
	char *interface ;
	int snaplen = 0;

	if (argc != 5) {
		printf("Usage: %s <interface> <snaplen> <zip_compression_level 1-9,0=Disable-ZIP> <thread_number>\n", argv[0]);
		exit(-1);
	}
	
	interface = argv[1];
	snaplen=atoi(argv[2]);
	zlib_compression_level = atoi(argv[3]);
	threads = atoi(argv[4]);
	
	if (zlib_compression_level <0 || zlib_compression_level >9) {
	        printf("Usage: %s <interface> <snaplen> <zip_compression_level 0-9> <thread_number> \n", argv[0]);
	        exit(-1);
        }	
	init_user_data(&udata,zlib_compression_level);
	

	if (geteuid() != 0) {
		printf("You need to be root in order to run this program. Found pid: %d\n", geteuid());
		exit(-1);
	}

	if (SIG_ERR == signal(SIGINT, sig_int)) {
		printf("Could not install signal handler!");
		exit(-1);
	}
	

	char next_interface[128];
	
	for( i=0; i<threads; i++){
	        my_thread_str[i].thread_name="Capturing Thread";
	        my_thread_str[i].thread_id=i;
			if (threads == 1){
				my_thread_str[i].interface=strdup(interface);			
			}else{
				sprintf(next_interface, "%s@%d", interface, i);		
				my_thread_str[i].interface=strdup(next_interface);	
			}
	        //sprintf(next_interface, "%s@%d", interface, i);
	        //my_thread_str[i].interface=strdup(next_interface);
        	my_thread_str[i].snaplen=snaplen;
        	thread_ret[i] = pthread_create( &thread[i], NULL, working_thread, (void*) &my_thread_str[i]);
	}
	
        printf("Started all threads...\n");

        sleep(100000);

	printf("Joining threads ...\n");

	/*
	for( i=0; i<threads; i++){
		pthread_join( thread[i], NULL);
	}
	*/
        for( i=0; i<threads; i++){
			putc('\n', stderr);
			(void)fprintf(stderr, "Results of Thread #%i:\n", i);
       		info(my_thread_str[i].captureDevice, 1, my_thread_str[i].packets_captured);
	}
	
	(void)fprintf(stderr, "\nTotal:\n");
	(void)fprintf(stderr, "%u packets captured \n", total_captured);
	(void)fprintf(stderr, "%d packets received by filter\n", total_filter);
        (void)fprintf(stderr, "%d packets dropped by kernel\n", total_dropped);
	                 
	

	exit(0);
}


static void copy_compress_packet(unsigned char* args, const struct pcap_pkthdr *header, const unsigned char* packet)
{
	struct user_data* udata = (struct user_data*)args;
	if (!packet) {
		printf("There was no data available. This should not happen as pcap has been opened without timeout\n");
		return;
	}
	
	//packets_captured++;
	my_thread_str[udata->thread_id].packets_captured++;


	if (header->len > MAX_PACKET_LENGTH) {
		printf("Packet is langer than maximum packet length. This is a bug!\n");
		return;
	}

	// Einmal kopieren. Kopiere paketlaenge aber hoehstens snaplen
	int copylen = my_thread_str[udata->thread_id].snaplen;
	if (header->len < copylen){
		copylen = header->len;
		}
	memcpy(udata->copied_packet, packet, copylen);

	// compress copied block
	udata->strm.avail_in = copylen;
	udata->strm.next_in = udata->copied_packet;

	udata->strm.next_out = udata->out_chunk;
	udata->strm.avail_out = MAX_PACKET_LENGTH;

	if (zlib_compression_level!=0){
	        deflate(&udata->strm, Z_NO_FLUSH);
	}
}

static void init_user_data(struct user_data* udata, int compression_level)
{
	udata->strm.zalloc = Z_NULL;
	udata->strm.zfree = Z_NULL;
	udata->strm.opaque = Z_NULL;
	int ret = deflateInit(&udata->strm, compression_level); // Z_DEFAULT_COMPRESSION (6) ist zu cpu lastig
	if (ret != Z_OK) {
		printf("Could not init zlib!");
		exit(-1);
	}
}

// kopiert von tcpdump
static void info(pcap_t* pd, register int verbose, int packets_captured)
{
        struct pcap_stat stat;
    
        if (pcap_stats(pd, &stat) < 0) {
                (void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
                return;
        }
    
        (void)fprintf(stderr, "%u packets captured", packets_captured);
        if (!verbose)
                fputs(", ", stderr);
        else
                putc('\n', stderr);
        (void)fprintf(stderr, "%d packets received by filter", stat.ps_recv);
        if (!verbose)
                fputs(", ", stderr);
        else
                putc('\n', stderr);
        (void)fprintf(stderr, "%d packets dropped by kernel\n", stat.ps_drop);
        
        total_filter   += stat.ps_recv;
        total_dropped  += stat.ps_drop;
        total_captured += packets_captured;
        
}

static void sig_int(int sig)
{
	if (quit_flag) {
        	int i;
		fprintf(stderr, "Received second Ctrl-C. Aborting!\n");
		
	        for( i=0; i<threads; i++){
        	        putc('\n', stderr);
			(void)fprintf(stderr, "Results of Thread #%i:\n", i);
        		info(my_thread_str[i].captureDevice, 1, my_thread_str[i].packets_captured);
		}
		exit(0);
        }
	fprintf(stderr, "Received shutdown signal\n");
	quit_flag = 1;	
}

