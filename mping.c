/*

	xkrambler's Massive PING v0.4
	03/Sep/2013 Pablo Rodriguez Rey (mr -at- xkr -dot- es)
	Last update: 18/Jun/2025

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

//#include "debug.h" // debug
#include "list.h"

#define false 0
#define true !0

#define MPING_VERSION "mping v0.4 Jun 18 2025 by mr.xkr - Massive PING"

#define PING_START_SEQ 10000
#define PING_IPV4_MAXHDRSIZE 60
#define PING_PACKETSIZE 32
#define PING_TTL 255
#define PING_MAX_RECVSIZE (PING_PACKETSIZE + PING_IPV4_MAXHDRSIZE)
#define PING_TIMEOUT 1000
#define PING_MSG "P!NG" // no more than (PING_PACKETSIZE - sizeof(struct icmphdr) - sizeof(IPv4address)) = 9 bytes
#define BUFFER_SIZE 4096

// host data
typedef struct {
	unsigned int seq;
	char *hostname;
	char *ip;
	int ok;
	int shown;
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

	for (sum=0; len > 1; len-=2) sum+=*buf++;

	if (len == 1) sum+=*(unsigned char*)buf;

	sum=(sum >> 16) + (sum & 0xFFFF);
	sum+=(sum >> 16);
	result=~sum;

	return result;

}

// resolve hostname, return IP string and resolved sockaddr_in
int resolve(const char *address, char **ip, struct sockaddr_in *resolved_addr) {

	struct addrinfo hints, *res;
	char ipstr[INET_ADDRSTRLEN];

	// initialize hints
	memset(&hints, 0, sizeof(hints));
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_RAW;

	// resolve
	if (getaddrinfo(address, NULL, &hints, &res) != 0) return 0;

	// extract IP address
	struct sockaddr_in *addr=(struct sockaddr_in *)res->ai_addr;
	inet_ntop(AF_INET, &addr->sin_addr, ipstr, sizeof(ipstr));
	if (!(*ip)) *ip=strdup(ipstr);

	// copy resolved address
	if (resolved_addr) memcpy(resolved_addr, addr, sizeof(struct sockaddr_in));

	// free info
	freeaddrinfo(res);

	// ok
	return true;

}

// send ICMP ECHO packet
double ping_send(int sd, Host *host) {

	PacketICMP packet;
	struct sockaddr_in addr_ping;

	// resolve hostname
	if (!resolve(host->hostname, &host->ip, &addr_ping)) return false;

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
	printf("--- PING %s %s %s %s\n", host->hostname, host->ip, inet_ntoa(addr_ping.sin_addr), packet.msg);
	#endif

	// start timming and send PING
	clock_gettime(CLOCK_MONOTONIC, &host->tvi);
	if (sendto(sd, &packet, sizeof(packet), 0, (struct sockaddr*)&addr_ping, sizeof(addr_ping)) <= 0) return false;

	// all fine
	return true;

}

// receive ICMP ECHO packet
double ping_recv(int sd, PacketICMP *packet, struct sockaddr_in *addr, int timeout) {

	char *buffer=malloc(sizeof(char)*PING_MAX_RECVSIZE);

	// receive ping
	unsigned int len=sizeof(struct sockaddr_in);
	if (recvfrom(sd, buffer, PING_MAX_RECVSIZE, 0, (struct sockaddr*)addr, &len) > 0) {
		int ip_len=((buffer[0] & 0x0F)<<2); // get ip header length, we need discard it
		memcpy(packet, buffer+ip_len, sizeof(PacketICMP));
		free(buffer);
		return true;
	}

	// timeout
	free(buffer);
	return false;

}

// main program
int main(int argc, char *argv[]) {

	int i;
	int sd;
	unsigned int retry=1;
	unsigned int ping_seq=PING_START_SEQ;
	unsigned int ping_timeout=PING_TIMEOUT;
	unsigned char ping_ttl=PING_TTL;
	unsigned int show_hostnames=true;
	unsigned int only_summary=false;
	unsigned int follow=false;
	struct protoent *proto=NULL;
	unsigned int content_start=0;
	size_t content_size;
	char buffer[BUFFER_SIZE];
	unsigned int loading_hosts=true;
	struct timespec time_start, time_follow, time_recv, time_end;
	pthread_mutex_t running_thread=PTHREAD_MUTEX_INITIALIZER;
	List *hosts;

	// aux: search host node by sequence number and IP address
	Node *host_search(List *hosts, char *ip, unsigned int seq) {
		Node *n=hosts->first;
		while (n) {
			Host *host=(Host *)n->e;
			if (!host->ok && host->ip && host->seq == seq && (strcmp(host->ip, ip) == 0)) return n;
			n=n->sig;
		}
		return NULL;
	}

	// aux: add a host to the list
	Host *host_add(char *hostname) {
		Host *host=malloc(sizeof(Host));
		host->hostname=strdup(hostname);
		host->ip=NULL;
		//host->he=NULL;
		host->ok=false;
		host->shown=false;
		listNodeAdd(hosts, host);
		return host;
	}

	// aux: delete host from list
	void host_del(List *hosts, Node *n) {
		Host *host=(Host *)n->e;
		if (host) {
			if (host->hostname) free(host->hostname);
			if (host->ip) free(host->ip);
			free(host);
		}
		listNodeDel(hosts, n);
	}

	// aux: convert timespec interval to time difference (in miliseconds)
	double time_diff(struct timespec begin, struct timespec end) {
		double s=(end.tv_sec - begin.tv_sec)*1000;
		double ms=(end.tv_nsec - begin.tv_nsec)/1000000.0;
		return s+ms;
	}

	// aux: sequence w/o increment
	unsigned int sequence(int inc) {
		ping_seq=(ping_seq+inc)%65535;
		return ping_seq;
	}

	// aux: ping to host
	int ping_host(Host *host) {
		if (!host->ip) host->seq=sequence(+1);
		if (ping_send(sd, host) < 0) {
			perror("Failed to send ping");
			return false;
		}
		return true;
	}

	// aux: display syntax and usage
	void help() {
		printf(MPING_VERSION);
		printf("\n");
		printf("Usage: %s [options] [target ...]\n", argv[0]);
		printf("   target       Targets can be Hosts or IPs to be resolved. Also can be entered as input pipe.\n");
		printf("   -t timeout   Timeout in miliseconds\n");
		printf("   -r retries   Number of retries for down hosts\n");
		printf("   -f           Continue retrying pinging hosts\n");
		printf("   -n           Do not show hostnames, only IP addresses\n");
		printf("   -s           Only show summary\n");
		printf("   -v           Show version\n");
		printf("   -h           Show this help\n");
		printf("\n");
	}

	// option list and parse
	const char* const optstring="hfnsvr:t:";
	const struct option longopts[]={
		{"help",    0, NULL, 'h'},
		{"follow",  0, NULL, 'f'},
		{"version", 0, NULL, 'v'},
		{"nohosts", 0, NULL, 'n'},
		{"summary", 0, NULL, 's'},
		{"retry",   1, NULL, 'r'},
		{"timeout", 1, NULL, 't'},
		{0,0,0,0}
	};
	while (true) {

		int r=getopt_long(argc, argv, optstring, longopts, NULL);
		if (r < 0) break;

		switch (r) {
		case 'h':
			help();
			return 0;

		case 'v':
			printf(MPING_VERSION);
			printf("\n");
			return 0;

		case 'n':
			show_hostnames=false;
			break;

		case 's':
			only_summary=true;
			break;

		case 'f':
			follow=true;
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
			if (retry < 1) retry=1;
			break;

		default:
			return 1;

		}

	}

	// frame reception thread
	void *thread_recv(void *none) {

		// declarations
		PacketICMP *packet=malloc(sizeof(PacketICMP));
		struct sockaddr_in r_addr;
		struct timespec time_actual;

		// do the work!
		int hosts_ok=0;
		do {

			// while we have hosts, we search for ping
			if (hosts->num) while (ping_recv(sd, packet, &r_addr, ping_timeout)) {

				#ifdef __DEBUG
				printf("--- addr=%s id=%d seq=%d msg=%s ---\n", inet_ntoa(r_addr.sin_addr), packet->hdr.un.echo.id, packet->hdr.un.echo.sequence, packet->msg);
				debug((void *)packet, sizeof(PacketICMP));
				#endif

				// search sequence correspondence
				Node *n=host_search(hosts, inet_ntoa(r_addr.sin_addr), packet->hdr.un.echo.sequence);
				if (n) {
					Host *host=(Host *)n->e;
					clock_gettime(CLOCK_MONOTONIC, &host->tvf);
					host->ok=true;
					hosts_ok++;
				}

			}

			// no more hosts pending, finish
			if (hosts_ok >= hosts->num) break;

			// if no more pending hosts, start count and finish loop when timeout expires
			if (!loading_hosts) {

				// timeout reached
				clock_gettime(CLOCK_MONOTONIC, &time_actual);
				if (time_diff(time_recv, time_actual) >= ping_timeout) {
					#ifdef __DEBUG
					printf("TIMEOUT %dms\n", ping_timeout);
					#endif
					break;
				}

			}

			// wait for more hosts to be loaded
			usleep(1000);

		} while (true);

		// free ICMP packet
		free(packet);

		// thread sync and finished
		pthread_exit((void *)0);

	}

	// application timming
	clock_gettime(CLOCK_MONOTONIC, &time_start);
	clock_gettime(CLOCK_MONOTONIC, &time_recv);

	// set start sequence (limit 16-bits)
	sequence(time_start.tv_sec);

	// start mark
	printf("START retry=%d timeout=%dms seq=%d\n", retry, ping_timeout, ping_seq);

	// new hosts list
	hosts=listNew();

	// obtain hostnames from parameters...
	if (optind < argc) {

    while (optind < argc) {
    	host_add(argv[optind++]);
    }

	// ...or get them from stdin
	} else {

		// allocate content
		content_size=0;
		char *content=malloc(0);
		if (content == NULL) {
			perror("Failed to allocate content");
			return 1;
		}

		// read from stdin
		int buffer_len;
		while ((int)(buffer_len=fread(buffer, 1, BUFFER_SIZE, stdin))) {
			if (buffer_len < 0) break;

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
			for (i=content_start; i < content_size; i++) {
				if (content[i] == '\r') content[i]=0;
				else if (content[i] == '\n') {
					content[i]=0;
					// line found
					if (strlen(content+content_start) > 0) {
						host_add(content+content_start);
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

	// if we have hosts to ping
	if (hosts->num) {

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

		// follow
		do {

			// follow start
			clock_gettime(CLOCK_MONOTONIC, &time_follow);

			int num_hosts_ok=0;

			// retry loop
			for (i=0; i < retry; i++) {

				// if there are pending hosts
				#ifdef __DEBUG
				printf("RETRY %d/%d\n", i+1, retry);
				#endif

				// we are going to load hosts
				loading_hosts=true;
				pthread_mutex_lock(&running_thread);

				// start timeout counter again
				clock_gettime(CLOCK_MONOTONIC, &time_recv);

				// create receive thread
				pthread_t thread;
				if (pthread_create((pthread_t *)&thread, NULL, &thread_recv, NULL)) {
					perror("Cannot create receive thread");
					return 7;
				}

				// ping hosts
				{
					Node *n=hosts->first;
					while (n) {
						Host *host=(Host *)n->e;
						if (!host->ok) {
							if (!ping_host(host)) return 8;
						}
						n=n->sig;
					}
				}

				// sync thread
				loading_hosts=false;
				pthread_mutex_unlock(&running_thread);
				pthread_join(thread, NULL);

				// check OK
				num_hosts_ok=0;
				{
					Node *n=hosts->first;
					while (n) {
						Host *host=(Host *)n->e;
						if (host->ok) {
							num_hosts_ok++;
							if (!host->shown) {
								host->shown=true;
								double ms=time_diff(host->tvi, host->tvf);
								if (!only_summary) {
									if (show_hostnames) {
										printf("OK %s\t%s\t%5.4fms\n", host->hostname, (host->ip?host->ip:""), ms);
									} else {
										printf("OK %s\t%5.4fms\n", (host->ip?host->ip:host->hostname), ms);
									}
								}
							}
						}
						n=n->sig;
					}
				}

				// no more retries needed
				if (num_hosts_ok >= hosts->num) break;

			}

			// remaining host list are timeout or host could not be resolved
			int num_hosts_ko=0;
			{
				Node *n=hosts->first;
				while (n) {
					Host *host=(Host *)n->e;
					if (!host->ok) {
						num_hosts_ko++;
						if (!only_summary) {
							if (host->ip) {
								if (show_hostnames) {
									printf("TIMEOUT %s\t%s\n", host->hostname, (host->ip?host->ip:""));
								} else {
									printf("TIMEOUT %s\n", (host->ip?host->ip:host->hostname));
								}
							} else {
								printf("UNKNOWN %s\n", host->hostname);
							}
						}
					}
					host->shown=false; // reiniciar
					host->ok=false; // reiniciar
					n=n->sig;
				}
			}

			// show total timming
			clock_gettime(CLOCK_MONOTONIC, &time_end);
			printf("%s %5.2fms hosts=%d ok=%d ko=%d\n", (follow?"STATS":"END"), time_diff(time_start, time_end), hosts->num, num_hosts_ok, num_hosts_ko);

			// if follow, wait at least timeout to repeat
			if (follow) {
				struct timespec time_actual;
				clock_gettime(CLOCK_MONOTONIC, &time_actual);
				double ping_ms=time_diff(time_follow, time_actual);
				if (ping_ms < ping_timeout) usleep((ping_timeout-ping_ms)*1000);
			}

		// repeat if follow
		} while (follow);

		// close socket
		close(sd);

	}

	// free all host nodes
	{
		Node *n=hosts->first;
		while (n) {
			host_del(hosts, n);
			n=hosts->first;
		}
	}

	// free list
	listFree(hosts);

	// everything was fine
	return 0;

}
