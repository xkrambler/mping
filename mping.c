/*

	xkrambler's Massive PING v0.3
	03/Sep/2013 Pablo Rodriguez Rey (mr -at- xkr -dot- es)
	Last update: 05/Jul/2018

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program. If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <getopt.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

//#include "debug.h"
#include "list.h"

#define MPING_VERSION "mping v0.3 Jul 05 2018 - Massive PING"

#define PING_START_SEQ 10000
#define PING_IPV4_MAXHDRSIZE 60
#define PING_PACKETSIZE 32
#define PING_TTL 255
#define PING_MAX_RECVSIZE (PING_PACKETSIZE + PING_IPV4_MAXHDRSIZE)
#define PING_TIMEOUT 1000
#define PING_MSG "PING!" // no more than (PING_PACKETSIZE - sizeof(struct icmphdr) - sizeof(IPv4address)) = 9 bytes
#define BUFFER_SIZE 1024

#define false 0
#define true 1

// host data
typedef struct {
	int seq;
	char *hostname;
	char *ip;
	pthread_t thread;
	struct hostent *he;
	struct timespec tvi;
	struct timespec tvf;
} Host;

// ICMP packet
typedef struct {
	struct icmphdr hdr;
	char msg[PING_PACKETSIZE - sizeof(struct icmphdr)];
} PacketICMP;

// 16 bit one's complement (RFC 792)
unsigned short ping_checksum(void *b, int len) {

	unsigned short *buf=b;
	unsigned int sum=0;
	unsigned short result;

	for (sum=0; len>1; len-=2)
		sum+=*buf++;

	if (len == 1)
		sum += *(unsigned char*)buf;

	sum=(sum >> 16) + (sum & 0xFFFF);
	sum+=(sum >> 16);
	result=~sum;

	return result;

}

// resolve hostname, return hostentry and IP
struct hostent * resolve(char *address, char **ip) {

	struct hostent *he;
	ip[0]=0;

	// resolve hostname
	he=gethostbyname(address);
	if (!he) return NULL;

	// return IP address
	*ip=strdup(inet_ntoa(*((struct in_addr *)he->h_addr)));

	// resolve hostname
	return he;

}

// send ICMP ECHO packet
float ping_send(int sd, Host *host) {

	struct sockaddr_in addr_ping, *addr;
	PacketICMP packet;

	// prepare address
	bzero(&addr_ping, sizeof(addr_ping));
	addr_ping.sin_family=host->he->h_addrtype;
	addr_ping.sin_port=0;
	addr_ping.sin_addr.s_addr=*(long*)host->he->h_addr;
	addr=&addr_ping;

	// prepare packet
	bzero(&packet, sizeof(packet));
	packet.hdr.type=ICMP_ECHO;
	packet.hdr.un.echo.id=getpid();
	packet.hdr.un.echo.sequence=host->seq;

	// copy message and IP address in the message
	strcpy(packet.msg, PING_MSG);
	strcat(packet.msg, host->ip);

	// update checksum
	packet.hdr.checksum=ping_checksum(&packet, sizeof(packet));

	#ifdef __DEBUG
	printf("--- PING %s %s\n", inet_ntoa(addr_ping.sin_addr), packet.msg);
	#endif

	// start timming and send PING
	clock_gettime(CLOCK_MONOTONIC, &host->tvi);
	if (sendto(sd, &packet, sizeof(packet), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0) return false;

	// all fine
	return true;

}

// receive ICMP ECHO packet
float ping_recv(int sd, PacketICMP *packet, struct sockaddr_in *addr, int timeout) {

	char *buffer=malloc(sizeof(char)*PING_MAX_RECVSIZE);

	// receive ping
	unsigned int len=sizeof(struct sockaddr_in);
	if (recvfrom(sd, buffer, PING_MAX_RECVSIZE, 0, (struct sockaddr*)addr, &len) > 0) {
		int ip_len=((buffer[0] & 0x0F)<<2); // get ip header length, we need discard it
		memcpy(packet, buffer+ip_len, sizeof(PacketICMP));
		return true;
	}

	// timeout
	return false;

}

// main program
int main(int argc, char *argv[]) {

	int i;
	int sd;
	int retry=0;
	int ping_seq=PING_START_SEQ;
	int ping_timeout=PING_TIMEOUT;
	unsigned char ping_ttl=PING_TTL;
	int show_hostnames=true;
	struct protoent *proto=NULL;
	int content_start=0;
	size_t content_size;
	char buffer[BUFFER_SIZE];
	struct timespec time_start;
	struct timespec time_recv;
	struct timespec time_end;
	int loading_hosts=true;
	pthread_mutex_t running_thread=PTHREAD_MUTEX_INITIALIZER;
	List *hosts;
	List *hosts_ok;

	// aux: search host node by sequence number
	Node *host_search(List *hosts, char *ip, int seq) {
		Node *n=hosts->first;
		while (n) {
			Host *host=(Host *)n->e;
			if (host->seq == seq && strcmp(host->ip, ip)==0)
				return n;
			n=n->sig;
		}
		return NULL;
	}

	// aux: ping a host
	Host *host_add(char *hostname) {
		Host *host=malloc(sizeof(Host));
		host->hostname=strdup(hostname);
		host->ip=NULL;
		listNodeAdd(hosts, host);
		return host;
	}

	// aux: delete host from pending list
	void host_delete(List *hosts, Node *n) {
		Host *host=(Host *)n->e;
		free(host->hostname);
		free(host->ip);
		free(host);
		listNodeDel(hosts, n);
	}

	// aux: convert timespec interval to float time difference
	float get_miliseconds(struct timespec begin, struct timespec end) {
		float s=(end.tv_sec - begin.tv_sec)*1000;
		float ms=(end.tv_nsec - begin.tv_nsec)/1000000.0;
		return s+ms;
	}

	// aux: ping to host
	int ping_host(Host *host) {
		host->he=resolve(host->hostname, &host->ip);
		host->seq=ping_seq++;
		if (host->he && ping_send(sd, host)<0) {
			perror("Failed to send ping");
			return false;
		}
		return true;
	}

	// aux: display sintax and usage options
	void show_sintax() {
		printf(MPING_VERSION);
		printf("\n\n");
		printf("Usage: %s [options] [target]\n", argv[0]);
		printf("   -t timeout   Timeout in miliseconds\n");
		printf("   -r retries   Retry down hosts extra times\n");
		printf("   -n           Do not show hostnames, only IP addresses\n");
		printf("   -v           Show version\n");
		printf("   -h           Show this help\n");
		printf("\n");
	}

	// option list and parse
	const char* const optstring="hvnr:t:";
	const struct option longopts[]={
		{"help",    0, NULL, 'h'},
		{"version", 0, NULL, 'v'},
		{"nohosts", 0, NULL, 'n'},
		{"retry",   1, NULL, 'r'},
		{"timeout", 1, NULL, 't'},
		{0,0,0,0}
	};
	while (true) {

		int r=getopt_long(argc, argv, optstring, longopts, NULL);
		if (r<0) break;

		switch (r) {
		case 'h':
			show_sintax();
			return 0;

		case 'v':
			printf(MPING_VERSION);
			printf("\n");
			return 0;

		case 'n':
			show_hostnames=false;
			break;

		case 't':
			if (!optarg) {
				printf("ERROR: -t option does not specify timeout\n");
				return 1;
			}
			ping_timeout=atoi(optarg);
			if (ping_timeout < 1) ping_timeout=1;
			break;

		case 'r':
			if (!optarg) {
				printf("ERROR: -r option does not specify retry times\n");
				return 1;
			}
			retry=atoi(optarg);
			if (retry < 0) retry=0;
			break;

		default:
			return 1;

		}

	}

	// application timming
	clock_gettime(CLOCK_MONOTONIC, &time_start);
	clock_gettime(CLOCK_MONOTONIC, &time_recv);

	// new hosts list
	hosts   =listNew();
	hosts_ok=listNew();

	// start mark
	printf("START\n");

	// make ICMP socket (requires root)
	proto=getprotobyname("ICMP");
	sd=socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sd < 0)	{
		perror("Could not create RAW socket, are you root?");
		return 4;
	}
	if (setsockopt(sd, SOL_IP, IP_TTL, &ping_ttl, sizeof(ping_ttl)) != 0) {
		perror("Could not set socket TTL");
		return 5;
	}
	if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
		perror("Could not set nonblock I/O");
		return 6;
	}

	// frame reception thread
	void *thread_recv(void *none) {

		// declarations
		PacketICMP *packet=malloc(sizeof(PacketICMP));
		struct sockaddr_in r_addr;
		struct timespec time_actual;

		// do the work!
		do {

			// while we have hosts, we ping it
			if (hosts->num) while (ping_recv(sd, packet, &r_addr, ping_timeout)) {

				#ifdef __DEBUG
				printf("--- addr=%s id=%d seq=%d msg=%s ---\n", inet_ntoa(r_addr.sin_addr), packet->hdr.un.echo.id, packet->hdr.un.echo.sequence, packet->msg);
				debug((void *)packet,sizeof(PacketICMP));
				#endif

				// search sequence correspondence
				Node *n=host_search(hosts, inet_ntoa(r_addr.sin_addr), packet->hdr.un.echo.sequence);
				if (n) {
					Host *host=(Host *)n->e;
					clock_gettime(CLOCK_MONOTONIC, &host->tvf);
					listNodeAdd(hosts_ok, host);
					listNodeDel(hosts, n);
				}

			}

			// if no more pending hosts, start count and finish loop when timeout expires
			if (!loading_hosts) {

				// no more hosts pending, finish
				if (!hosts->num) break;

				// timeout reached
				clock_gettime(CLOCK_MONOTONIC, &time_actual);
				if (get_miliseconds(time_recv, time_actual)>=ping_timeout) {
					#ifdef __DEBUG
					printf("TIMEOUT %dms\n", ping_timeout);
					#endif
					break;
				}

			}

			// wait for more hosts to be loaded
			usleep(1000);

		} while (true);

		// thread sync and finished
		pthread_mutex_unlock(&running_thread);
		return NULL;

	}

	// create receive thread
	pthread_mutex_lock(&running_thread);
	pthread_t thread;
	if (pthread_create((pthread_t *)&thread, NULL, &thread_recv, NULL)) {
		perror("Cannot create receive thread");
		return 7;
	}

	// obtain hostnames from parameters...
	int num_hosts=0;
	if (optind < argc) {

    while (optind < argc) {
    	num_hosts++;
    	ping_host(host_add(argv[optind++]));
    }

	// ...or get them from stdin
	} else {

		// allocate content
		char *content=malloc(0);
		if (content == NULL) {
			perror("Failed to allocate content");
			return 1;
		}
		//content[0]=0;
		content_size=0;

		// read from stdin
		int buffer_len;
		while ((int)(buffer_len=fread(buffer, 1, BUFFER_SIZE, stdin))) {
			if (buffer_len<0) break;

			// allocate in the buffer
			char *old=content;
			content_size+=buffer_len;
			content=realloc(content, content_size);
			if (content == NULL) {
				perror("Failed to reallocate content");
				free(old);
				return 3;
			}
			memcpy(content+content_size-buffer_len, buffer, buffer_len);

			// process buffer lines
			for (i=content_start; i<content_size; i++) {
				if (content[i]=='\r') content[i]=0;
				else if (content[i]=='\n') {
					content[i]=0;
					// line found
					if (strlen(content+content_start) > 0) {
						num_hosts++;
						ping_host(host_add(content+content_start));
					}
					content_start=i+1;
				}
			}

		}

		// free content buffer
		free(content);

		// check stdin
		if (ferror(stdin)) {
			perror("Error reading from stdin");
			return 4;
		}

	}

	// all hosts defined, start timeout counter
	clock_gettime(CLOCK_MONOTONIC, &time_recv);
	loading_hosts=false;

	// sync thread
	#ifdef __DEBUG
	printf("SYNC PENDING %d\n", hosts->num);
	#endif
	pthread_mutex_lock(&running_thread);

	// retry loop
	for (i=0; i<retry; i++) {

		// if there are pending hosts
		#ifdef __DEBUG
		printf("RETRY %d/%d PENDING %d HOSTS\n", i+1, retry, hosts->num);
		#endif
		if (hosts->num) {

			// we are going to load hosts
			loading_hosts=true;

			// start timeout counter again
			clock_gettime(CLOCK_MONOTONIC, &time_recv);

			// create receive thread
			pthread_t thread;
			if (pthread_create((pthread_t *)&thread, NULL, &thread_recv, NULL)) {
				perror("Cannot create receive thread");
				return 7;
			}

			// ping hosts
			Node *n=hosts->first;
			while (n) {
				Host *host=(Host *)n->e;
				ping_host(host);
				n=n->sig;
			}

			// sync thread
			loading_hosts=false;
			pthread_mutex_lock(&running_thread);

		}

	}

	// show OK hosts first
	int num_hosts_ok=0;
	{
		Node *n=hosts_ok->first;
		while (n) {
			num_hosts_ok++;
			Host *host=(Host *)n->e;
			float ms=get_miliseconds(host->tvi, host->tvf);
			if (show_hostnames) printf("OK %s\t%s\t%5.4fms\n", host->hostname, (host->ip?host->ip:""), ms);
			else printf("OK %s\t%5.4fms\n", (host->ip?host->ip:host->hostname), ms);
			host_delete(hosts_ok, n);
			n=n->sig;
		}
	}

	// remaining host list are timeout or host could not be resolved
	int num_hosts_ko=0;
	{
		Node *n=hosts->first;
		while (n) {
			num_hosts_ko++;
			Host *host=(Host *)n->e;
			if (host->he) {
				if (show_hostnames) printf("TIMEOUT %s\t%s\n", host->hostname, (host->ip?host->ip:""));
				else printf("TIMEOUT %s\n", (host->ip?host->ip:host->hostname));
			} else printf("UNKNOWN %s\n", host->hostname);
			host_delete(hosts, n);
			n=n->sig;
		}
	}

	// free host list
	listFree(hosts_ok);
	listFree(hosts);

	// show total timming
	clock_gettime(CLOCK_MONOTONIC, &time_end);
	printf("END %5.2fms %d hosts %d ok %d ko %d retry %dms timeout\n", get_miliseconds(time_start, time_end), num_hosts, num_hosts_ok, num_hosts_ko, retry, ping_timeout);

	// everything was fine
	return 0;

}
