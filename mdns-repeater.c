/*
 * mdns-repeater.c - mDNS repeater daemon
 * Copyright (C) 2011 Darell Tan
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>

#define PACKAGE "mdns-repeater"
#define MDNS_ADDR "224.0.0.251"
#define MDNS_PORT 5353

#define PIDFILE "/var/run/" PACKAGE ".pid"

#define MAX_SOCKS 16
#define MAX_SUBNETS 16

struct if_sock {
	const char *ifname;		/* interface name  */
	int sockfd;				/* socket filedesc */
	struct in_addr addr;	/* interface addr  */
	struct in_addr mask;	/* interface mask  */
	struct in_addr net;		/* interface network (computed) */
};

struct subnet {
	struct in_addr addr;    /* subnet addr */
	struct in_addr mask;    /* subnet mask */
	struct in_addr net;     /* subnet net (computed) */
};

int server_sockfd = -1;

int num_socks = 0;
struct if_sock socks[MAX_SOCKS];

int num_blacklisted_subnets = 0;
struct subnet blacklisted_subnets[MAX_SUBNETS];

int num_whitelisted_subnets = 0;
struct subnet whitelisted_subnets[MAX_SUBNETS];

#define PACKET_SIZE 65536
void *pkt_data = NULL;

int foreground = 0;
int shutdown_flag = 0;

char *pid_file = PIDFILE;

//------------------ Begin mk_unicast_repeater --------------------------------
/* MK_UNICAST_REPEATER: Author Varadhan Venkataseshan : Mimik Technology Inc */

#ifndef MK_UNICAST_REPEATER
#define MK_UNICAST_REPEATER
#endif

/******************************************************************************
A simple threaded prototype for supporting mimik mdns unicast repeater:
Code has been added under define MK_UNICAST_REPEATER. 
It basically co-exists with the current repeater and does the following.

Step1: Rapidly filters received packets containing mimik mdns
       packets with QU(Questions Requesting Unicast Responses) flags set.
- mk_ingress_mdns_unicast_pkt_filter(pkt_data, recvsize);

Step2: If Step1 succeeds, takes the ownership of repeating the matched packet to
       all given interfaces.

Step3: Waits for a maximum of 2 seconds(configurable) to receive unicast answer
       reply from mdns server to the question sent in Step2. And on receipt of
       a unicast response to the mdns packet sent in Step2, forwards the
       response pkt back to the originating source node-src_addr:port.

- mk_handle_qu_pkt_repeater(g_pmri,server_sockfd, pkt_data, recvsize, &fromaddr);

NOTE: Does not change the logic of repeating in anyway to the packets that
      fails filter checks made in Step1

*******************************************************************************/

#ifdef MK_UNICAST_REPEATER

/* mdns header

 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               id              |           flags               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               queries         |           answers             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               auth_rr         |           add_rr              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
[.......c_str 0 terminated variable Length query txt ...........]
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               type            |           class/QU            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

our mdns query signature: id=0,flags=0,queries=1,answers=0,auth_rr=0,add_rr=0,type=12(ptr),QU

*/

 #define MAX_UNICAST_IFS 5
 // #define DFT_MK_NW_INTF "docker0"
typedef struct IfsInfo {
    // Interface name
    char ifname[IFNAMSIZ];
    struct in_addr ifaddr;
    struct in_addr ifmask;
    int sd;
}IfsInfo;

#define INGRESS_PKTLIMIT 512
typedef struct MkRepeaterBlock {
   // sk_origin tuple is the key of the MkRepeaterBlock
   struct sockaddr_in sk_origin; // from address of the origin
   int ingress_sd; // socket from which to send to origin node
   int  peerdata_len;   // current "received from" or "to be sent" to peer data
   char peerdata[INGRESS_PKTLIMIT+1]; // buffer that holds ingress peer data
   // An array of interface socket to repeat multicast and receive uni-casted pkt
   int numifs;
   IfsInfo ifrsds[MAX_UNICAST_IFS];
   // void * pmri; //may be keep a reference to its parent info block
}MkRepeaterBlock;

typedef struct MkRepeaterInfo{
 #define MAX_UNICAST_REPEATERS 50
 int rpt_cnt;
 unsigned int t_in;
 pthread_mutex_t rmtx;
 int numifs;
 IfsInfo ifRefs[MAX_UNICAST_IFS];
  // TODO add an efficient data structure to manage multiple unciast repeaters
  //      for handling concurrent peers with only a single thread of control and
  //      using an efficient i/o multiplexing.
  // NOTE: the key for such a data structure will be the ip:port of the src node.
  // MkRepeaterBlock rblocks[MAX_UNICAST_REPEATERS];
}MkRepeaterInfo;

static MkRepeaterInfo *g_pmri = NULL;

MkRepeaterInfo* mk_init_unicast_repeater(void);

int mk_destroy_unicast_repeater(MkRepeaterInfo *pmri);

int mk_ingress_mdns_unicast_pkt_filter(int sockfd, void *rxpkt, size_t pktlen,
                              struct sockaddr_in *src_addr);

int mk_setup_repater_socket(IfsInfo *pifs, char *updateifname);

MkRepeaterBlock * mk_alloc_repeater_block(MkRepeaterInfo *pmri, struct sockaddr_in *src_addr);
int mk_free_repeater_block(MkRepeaterBlock * pmb);

int mk_handle_qu_pkt_repeater(MkRepeaterInfo *pmri, int rxsd, void *rxpkt, size_t pktlen,
                              struct sockaddr_in *src_addr);
void * mk_mdns_unicast_pkt_repeater_thread(void *targ);

#endif
//------------------ End mk_unicast_repeater -----------------------------------

void log_message(int loglevel, char *fmt_str, ...) {
	va_list ap;
	char buf[2048];

	va_start(ap, fmt_str);
	vsnprintf(buf, 2047, fmt_str, ap);
	va_end(ap);
	buf[2047] = 0;

	if (foreground) {
		fprintf(stderr, "%s: %s\n", PACKAGE, buf);
	} else {
		syslog(loglevel, "%s", buf);
	}
}

static int create_recv_sock() {
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "recv socket(): %s", strerror(errno));
		return sd;
	}

	int r = -1;

	int on = 1;
	if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(SO_REUSEADDR): %s", strerror(errno));
		return r;
	}

	/* bind to an address */
	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(MDNS_PORT);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);	/* receive multicast */
	if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
		log_message(LOG_ERR, "recv bind(): %s", strerror(errno));
	}

	// enable loopback in case someone else needs the data
	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		return r;
	}

#ifdef IP_PKTINFO
	if ((r = setsockopt(sd, SOL_IP, IP_PKTINFO, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_PKTINFO): %s", strerror(errno));
		return r;
	}
#endif

	return sd;
}

static int create_send_sock(int recv_sockfd, const char *ifname, struct if_sock *sockdata) {
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "send socket(): %s", strerror(errno));
		return sd;
	}

	sockdata->ifname = ifname;
	sockdata->sockfd = sd;

	int r = -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	struct in_addr *if_addr = &((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

#ifdef SO_BINDTODEVICE
	if ((r = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(struct ifreq))) < 0) {
		log_message(LOG_ERR, "send setsockopt(SO_BINDTODEVICE): %s", strerror(errno));
		return r;
	}
#endif

	// get netmask
	if (ioctl(sd, SIOCGIFNETMASK, &ifr) == 0) {
		memcpy(&sockdata->mask, if_addr, sizeof(struct in_addr));
	}

	// .. and interface address
	if (ioctl(sd, SIOCGIFADDR, &ifr) == 0) {
		memcpy(&sockdata->addr, if_addr, sizeof(struct in_addr));
	}

	// compute network (address & mask)
	sockdata->net.s_addr = sockdata->addr.s_addr & sockdata->mask.s_addr;

	int on = 1;
	if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "send setsockopt(SO_REUSEADDR): %s", strerror(errno));
		return r;
	}

	// bind to an address
	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(MDNS_PORT);
	serveraddr.sin_addr.s_addr = if_addr->s_addr;
	if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
		log_message(LOG_ERR, "send bind(): %s", strerror(errno));
	}

#if __FreeBSD__
	if((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &serveraddr.sin_addr, sizeof(serveraddr.sin_addr))) < 0) {
		log_message(LOG_ERR, "send ip_multicast_if(): errno %d: %s", errno, strerror(errno));
	}
#endif

	// add membership to receiving socket
	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(struct ip_mreq));
	mreq.imr_interface.s_addr = if_addr->s_addr;
	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
	if ((r = setsockopt(recv_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
		return r;
	}

	// enable loopback in case someone else needs the data
	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		return r;
	}

	char *addr_str = strdup(inet_ntoa(sockdata->addr));
	char *mask_str = strdup(inet_ntoa(sockdata->mask));
	char *net_str  = strdup(inet_ntoa(sockdata->net));
	log_message(LOG_INFO, "dev %s addr %s mask %s net %s", ifr.ifr_name, addr_str, mask_str, net_str);
	free(addr_str);
	free(mask_str);
	free(net_str);

	return sd;
}

static ssize_t send_packet(int fd, const void *data, size_t len) {
	static struct sockaddr_in toaddr;
	if (toaddr.sin_family != AF_INET) {
		memset(&toaddr, 0, sizeof(struct sockaddr_in));
		toaddr.sin_family = AF_INET;
		toaddr.sin_port = htons(MDNS_PORT);
		toaddr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
	}

	return sendto(fd, data, len, 0, (struct sockaddr *) &toaddr, sizeof(struct sockaddr_in));
}

static void mdns_repeater_shutdown(int sig) {
	shutdown_flag = 1;
}

static pid_t already_running() {
	FILE *f;
	int count;
	pid_t pid;

	f = fopen(pid_file, "r");
	if (f != NULL) {
		count = fscanf(f, "%d", &pid);
		fclose(f);
		if (count == 1) {
			if (kill(pid, 0) == 0)
				return pid;
		}
	}

	return -1;
}

static int write_pidfile() {
	FILE *f;
	int r;

	f = fopen(pid_file, "w");
	if (f != NULL) {
		r = fprintf(f, "%d", getpid());
		fclose(f);
		return (r > 0);
	}

	return 0;
}

static void daemonize() {
	pid_t running_pid;
	pid_t pid = fork();
	if (pid < 0) {
		log_message(LOG_ERR, "fork(): %s", strerror(errno));
		exit(1);
	}

	// exit parent process
	if (pid > 0)
		exit(0);

	// signals
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, mdns_repeater_shutdown);

	setsid();
	umask(0027);
	chdir("/");

	// close all std fd and reopen /dev/null for them
	int i;
	for (i = 0; i < 3; i++) {
		close(i);
		if (open("/dev/null", O_RDWR) != i) {
			log_message(LOG_ERR, "unable to open /dev/null for fd %d", i);
			exit(1);
		}
	}

	// check for pid file
	running_pid = already_running();
	if (running_pid != -1) {
		log_message(LOG_ERR, "already running as pid %d", running_pid);
		exit(1);
	} else if (! write_pidfile()) {
		log_message(LOG_ERR, "unable to write pid file %s", pid_file);
		exit(1);
	}
}

static void show_help(const char *progname) {
	fprintf(stderr, "mDNS repeater (version " HGVERSION ")\n");
	fprintf(stderr, "Copyright (C) 2011 Darell Tan\n\n");

	fprintf(stderr, "usage: %s [ -f ] <ifdev> ...\n", progname);
	fprintf(stderr, "\n"
					"<ifdev> specifies an interface like \"eth0\"\n"
					"packets received on an interface is repeated across all other specified interfaces\n"
					"maximum number of interfaces is 5\n"
					"\n"
					" flags:\n"
					"	-f	runs in foreground for debugging\n"
					"	-b	blacklist subnet (eg. 192.168.1.1/24)\n"
					"	-w	whitelist subnet (eg. 192.168.1.1/24)\n"
					"	-p	specifies the pid file path (default: " PIDFILE ")\n"
					"	-h	shows this help\n"
					"\n"
		);
}

int parse(char *input, struct subnet *s) {
	int delim = 0;
	int end = 0;
	while (input[end] != 0) {
		if (input[end] == '/') {
			delim = end;
		}
		end++;
	}

	if (end == 0 || delim == 0 || end == delim) {
		return -1;
	}

	char *addr = (char*) malloc(end);

	memset(addr, 0, end);
	strncpy(addr, input, delim);
	if (inet_pton(AF_INET, addr, &s->addr) != 1) {
		free(addr);
		return -2;
	}

	memset(addr, 0, end);
	strncpy(addr, input+delim+1, end-delim-1);
	int mask = atoi(addr);
	free(addr);

	if (mask < 0 || mask > 32) {
		return -3;
	}

	s->mask.s_addr = ntohl((uint32_t)0xFFFFFFFF << (32 - mask));
	s->net.s_addr = s->addr.s_addr & s->mask.s_addr;

	return 0;
}

int tostring(struct subnet *s, char* buf, int len) {
	char *addr_str = strdup(inet_ntoa(s->addr));
	char *mask_str = strdup(inet_ntoa(s->mask));
	char *net_str = strdup(inet_ntoa(s->net));
	int l = snprintf(buf, len, "addr %s mask %s net %s", addr_str, mask_str, net_str);
	free(addr_str);
	free(mask_str);
	free(net_str);

	return l;
}

static int parse_opts(int argc, char *argv[]) {
	int c, res;
	int help = 0;
	struct subnet *ss;
	char *msg;
	while ((c = getopt(argc, argv, "hfp:b:w:")) != -1) {
		switch (c) {
			case 'h': help = 1; break;
			case 'f': foreground = 1; break;
			case 'p':
				if (optarg[0] != '/')
					log_message(LOG_ERR, "pid file path must be absolute");
				else
					pid_file = optarg;
				break;

			case 'b':
				if (num_blacklisted_subnets >= MAX_SUBNETS) {
					log_message(LOG_ERR, "too many blacklisted subnets (maximum is %d)", MAX_SUBNETS);
					exit(2);
				}

				if (num_whitelisted_subnets != 0) {
					log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
					exit(2);
				}

				ss = &blacklisted_subnets[num_blacklisted_subnets];
				res = parse(optarg, ss);
				switch (res) {
					case -1:
						log_message(LOG_ERR, "invalid blacklist argument");
						exit(2);
					case -2:
						log_message(LOG_ERR, "could not parse netmask");
						exit(2);
					case -3:
						log_message(LOG_ERR, "invalid netmask");
						exit(2);
				}

				num_blacklisted_subnets++;

				msg = malloc(128);
				memset(msg, 0, 128);
				tostring(ss, msg, 128);
				log_message(LOG_INFO, "blacklist %s", msg);
				free(msg);
				break;
			case 'w':
				if (num_whitelisted_subnets >= MAX_SUBNETS) {
					log_message(LOG_ERR, "too many whitelisted subnets (maximum is %d)", MAX_SUBNETS);
					exit(2);
				}

				if (num_blacklisted_subnets != 0) {
					log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
					exit(2);
				}

				ss = &whitelisted_subnets[num_whitelisted_subnets];
				res = parse(optarg, ss);
				switch (res) {
					case -1:
						log_message(LOG_ERR, "invalid whitelist argument");
						exit(2);
					case -2:
						log_message(LOG_ERR, "could not parse netmask");
						exit(2);
					case -3:
						log_message(LOG_ERR, "invalid netmask");
						exit(2);
				}

				num_whitelisted_subnets++;

				msg = malloc(128);
				memset(msg, 0, 128);
				tostring(ss, msg, 128);
				log_message(LOG_INFO, "whitelist %s", msg);
				free(msg);
				break;
			case '?':
			case ':':
				fputs("\n", stderr);
				break;

			default:
				log_message(LOG_ERR, "unknown option %c", optopt);
				exit(2);
		}
	}

	if (help) {
		show_help(argv[0]);
		exit(0);
	}

	return optind;
}

int main(int argc, char *argv[]) {
	pid_t running_pid;
	fd_set sockfd_set;
	int r = 0;
        int rc = 0;

	parse_opts(argc, argv);

	if ((argc - optind) <= 1) {
		show_help(argv[0]);
		log_message(LOG_ERR, "error: at least 2 interfaces must be specified");
		exit(2);
	}

	openlog(PACKAGE, LOG_PID | LOG_CONS, LOG_DAEMON);
	if (! foreground)
		daemonize();
	else {
		// check for pid file when running in foreground
		running_pid = already_running();
		if (running_pid != -1) {
			log_message(LOG_ERR, "already running as pid %d", running_pid);
			exit(1);
		}
	}

	// create receiving socket
	server_sockfd = create_recv_sock();
	if (server_sockfd < 0) {
		log_message(LOG_ERR, "unable to create server socket");
		r = 1;
		goto end_main;
	}

	// create sending sockets
	int i;
	for (i = optind; i < argc; i++) {
		if (num_socks >= MAX_SOCKS) {
			log_message(LOG_ERR, "too many sockets (maximum is %d)", MAX_SOCKS);
			exit(2);
		}

		int sockfd = create_send_sock(server_sockfd, argv[i], &socks[num_socks]);
		if (sockfd < 0) {
			log_message(LOG_ERR, "unable to create socket for interface %s", argv[i]);
			r = 1;
			goto end_main;
		}
		num_socks++;
	}

	pkt_data = malloc(PACKET_SIZE);
	if (pkt_data == NULL) {
		log_message(LOG_ERR, "cannot malloc() packet buffer: %s", strerror(errno));
		r = 1;
		goto end_main;
	}

#ifdef MK_UNICAST_REPEATER
        g_pmri = mk_init_unicast_repeater();
        if (!g_pmri) {
           printf("mk_init_unicast_repeater failed \n");
        }
        else {
	  for (int i = 0; i < num_socks && i < MAX_UNICAST_IFS; i++) {
	     // For now copy the list of interface details from socks
	     // TODO get the list of all network interface details from system.
	     if (socks[i].ifname) {
		 strncpy(g_pmri->ifRefs[i].ifname, socks[i].ifname,IFNAMSIZ);
		 memcpy(&g_pmri->ifRefs[i].ifaddr, &socks[i].addr, sizeof(struct in_addr));
		 memcpy(&g_pmri->ifRefs[i].ifmask, &socks[i].mask, sizeof(struct in_addr));
		 g_pmri->numifs ++;
		 printf("%d) ifname[%s] addr[%s] mask[%s] \n",i,g_pmri->ifRefs[i].ifname,
			inet_ntoa(g_pmri->ifRefs[i].ifaddr),
			inet_ntoa(g_pmri->ifRefs[i].ifmask));
	     }
	  }
        }
#endif

	while (! shutdown_flag) {
		struct timeval tv = {
			.tv_sec = 10,
			.tv_usec = 0,
		};

		FD_ZERO(&sockfd_set);
		FD_SET(server_sockfd, &sockfd_set);
		int numfd = select(server_sockfd + 1, &sockfd_set, NULL, NULL, &tv);
		if (numfd <= 0)
			continue;

		if (FD_ISSET(server_sockfd, &sockfd_set)) {
			struct sockaddr_in fromaddr;
			socklen_t sockaddr_size = sizeof(struct sockaddr_in);

			ssize_t recvsize = recvfrom(server_sockfd, pkt_data, PACKET_SIZE, 0,
				(struct sockaddr *) &fromaddr, &sockaddr_size);
			if (recvsize < 0) {
				log_message(LOG_ERR, "recv(): %s", strerror(errno));
			}

			int j;
			char self_generated_packet = 0;
			for (j = 0; j < num_socks; j++) {
				// check for loopback
				if (fromaddr.sin_addr.s_addr == socks[j].addr.s_addr) {
					self_generated_packet = 1;
					break;
				}
			}

			if (self_generated_packet)
				continue;

			if (num_whitelisted_subnets != 0) {
				char whitelisted_packet = 0;
				for (j = 0; j < num_whitelisted_subnets; j++) {
					// check for whitelist
					if ((fromaddr.sin_addr.s_addr & whitelisted_subnets[j].mask.s_addr) == whitelisted_subnets[j].net.s_addr) {
						whitelisted_packet = 1;
						break;
					}
				}

				if (!whitelisted_packet) {
					if (foreground)
						printf("skipping packet from=%s size=%zd\n", inet_ntoa(fromaddr.sin_addr), recvsize);
					continue;
				}
			} else {
				char blacklisted_packet = 0;
				for (j = 0; j < num_blacklisted_subnets; j++) {
					// check for blacklist
					if ((fromaddr.sin_addr.s_addr & blacklisted_subnets[j].mask.s_addr) == blacklisted_subnets[j].net.s_addr) {
						blacklisted_packet = 1;
						break;
					}
				}

				if (blacklisted_packet) {
					if (foreground)
						printf("skipping packet from=%s size=%zd\n", inet_ntoa(fromaddr.sin_addr), recvsize);
					continue;
				}
			}

			if (foreground)
				printf("data from=%s size=%zd\n", inet_ntoa(fromaddr.sin_addr), recvsize);
                        
#ifdef MK_UNICAST_REPEATER
                   if (g_pmri) {
                      rc = mk_ingress_mdns_unicast_pkt_filter(server_sockfd, pkt_data, recvsize, &fromaddr);
                      if (rc == 0) {
                         printf("Success: pkt matched out filter check \n");
                         // call the ingress unicast packet repeater function here.
                         rc = mk_handle_qu_pkt_repeater(g_pmri,server_sockfd, pkt_data, recvsize, &fromaddr);
                         if (rc == 0) {
                            printf("Success: mk_handle_qu_pkt_repeater\n");
         		    continue;
                         }
                      }
                   }
#endif
			for (j = 0; j < num_socks; j++) {
				// do not repeat packet back to the same network from which it originated
				if ((fromaddr.sin_addr.s_addr & socks[j].mask.s_addr) == socks[j].net.s_addr)
					continue;

				if (foreground)
					printf("repeating data to %s\n", socks[j].ifname);

				// repeat data
				ssize_t sentsize = send_packet(socks[j].sockfd, pkt_data, (size_t) recvsize);
				if (sentsize != recvsize) {
					if (sentsize < 0)
						log_message(LOG_ERR, "send(): %s", strerror(errno));
					else
						log_message(LOG_ERR, "send_packet size differs: sent=%zd actual=%zd",
							recvsize, sentsize);
				}
			}
		}
	}

	log_message(LOG_INFO, "shutting down...");

end_main:

	if (pkt_data != NULL)
		free(pkt_data);

	if (server_sockfd >= 0)
		close(server_sockfd);

	for (i = 0; i < num_socks; i++)
		close(socks[i].sockfd);

	// remove pid file if it belongs to us
	if (already_running() == getpid())
		unlink(pid_file);

#ifdef MK_UNICAST_REPEATER
        if (g_pmri) {
          mk_destroy_unicast_repeater(g_pmri);
        }
#endif
	log_message(LOG_INFO, "exit.");

	return r;
}

#ifdef MK_UNICAST_REPEATER
//------------------ Begin mk_unicast_repeater --------------------------------

#define MDNS_FILTER_HDRSZ 12

int mk_ingress_mdns_unicast_pkt_filter(int sockfd, void *rxpkt, size_t pktlen,
                                      struct sockaddr_in *src_addr)
{
   //Step1 : Apply pre filters to quickly determine if it is a packet of interest for further processing.

   // All we want to check is: It is only a query pkt with just 1 question and no answers;
   // And should have unicast reply request bit set. The question txt has mk prefix

   // Our packet selection filters:
   // dns.flags.response == 0  // It is a query and not a response
   // dns.count.queries == 1   // It has only 1 question
   // dns.count.answers == 0   // It has Answer RRs: 0
   // dns.count.auth_rr == 0   // It has Authority RRs: 0
   // dns.count.add_rr == 0    // It has Additional RRs: 0

   // Additional filters:
   // dns.qry.name contains  "_mk" //query name contains prefix _mk
   // dns.qry.type == 12 Type: PTR (domain name PoinTeR) (12)
   // dns.qry.class == 0x0001  // Class: IN (0x0001)

   // Most important and mandatory filter
   // dns.qry.qu == 1          // It has unicast bit set : "QU" question: True

   unsigned char *pU8Cur = (unsigned char *)rxpkt;
   uint16_t *pU16 = (uint16_t *)rxpkt;
   uint16_t val16 = 0;
   uint16_t txtlen = 0;

   if ((!rxpkt)||(!src_addr)||(pktlen <= MDNS_FILTER_HDRSZ)||(pktlen > INGRESS_PKTLIMIT)) {
       printf("%s() ingress packet len = %ld not valid \n",__func__,pktlen);
       return -1;
   }

   // skip mdns Query Identifier(id): we do not need to validate pU16[0]

   // check flags for QR (Query(0)/Response(1)) Bit at (0x8000)
   val16 = ntohs(pU16[1]);
   if ((val16 & (1<<15)) == 0x8000) {
     // we are interested in only query packet and not Response
     printf("%s() mdns.flags.query is expected and not response. flags=%hu\n",__func__,val16);
     return -1;
   }

   // check for dns.count.queries == 1
   val16 = ntohs(pU16[2]);
   if (val16 != 1) {
     printf("%s() mdns.count.queries(%hu) != expected(1) \n",__func__,val16);
     return -1;
   }

   // check for dns.count.answers == 0
   val16 = ntohs(pU16[3]);
   if (val16 != 0) {
     printf("%s() mdns.count.answer(%hu) != expected(0) \n",__func__,val16);
     return -1;
   }

   // check for dns.count.auth_rr == 0
   val16 = ntohs(pU16[4]);
   if (val16 != 0) {
     printf("%s() mdns.count.auth_rr(%hu) != expected(0) \n",__func__,val16);
     return -1;
   }

   // check for dns.count.add_rr == 0    // should have Additional RRs: 0
   val16 = ntohs(pU16[3]);
   if (val16 != 0) {
     // not ours.
     printf("%s() mdns.count.add_rr(%u) != expected(0) \n",__func__,val16);
     return -1;
   }

   // point to query txt and gets the null terminated string length
   pU8Cur += MDNS_FILTER_HDRSZ; // increment by 12 bytes
   txtlen = strlen((const char *)pU8Cur);

   // check if pktlen has enough data still left for type/class/qu
   if (pktlen < (txtlen + MDNS_FILTER_HDRSZ + 5)) {
     // range check failed
     printf("%s() pktlen=%ld < txtlen(%hu) + 12 + 5 \n",__func__,pktlen,txtlen);
     return -1;
   }

   pU8Cur += (txtlen + 1); // add 1 byte for string termination 0
   // update pU16 with current position 
   pU16 = (uint16_t *)pU8Cur;
   
   // dns.qry.type == PTR
   #define MDNS_QRY_TYPE_PTR 12
   val16 = ntohs(pU16[0]);
   if (val16 != MDNS_QRY_TYPE_PTR) {
     printf("%s() mdns.qry.type(%u) != PTR(%u) \n",__func__,val16,MDNS_QRY_TYPE_PTR);
     return -1;
   }

   // mdns qry : class and qu occupy 16 bits, we need only QU test here.
   // dns.qry.class == 0x0001  // Class: IN (0x0001)

   // Most important and mandatory filter
   // dns.qry.qu == 1          // It has unicast bit set : "QU" question: True
   val16 = ntohs(pU16[1]);
   // check the Most significant bit of val16 where QU is being set
   if ((val16 & 0x8000) != 0x8000) {
      printf("%s() mdns.qry.qu=0, unicast(QU) bit not set val16=0x%X \n",__func__,val16);
      return -1;
   }

   #define QN_TXT_CHK_PREFIX "_mk"
   if (txtlen < strlen(QN_TXT_CHK_PREFIX)) {
     //range check failed
     return -1;
   }
   // Txt prefix check can be omitted if needed
   if (!strstr((char *)rxpkt + MDNS_FILTER_HDRSZ , QN_TXT_CHK_PREFIX)) {
     printf("%s() expected prefix[%s] not in qn txt[%s] \n",__func__,QN_TXT_CHK_PREFIX,pU8Cur);
     return -1;
   }

   printf("%s(!success!) pkt with QU matches => %s \n",__func__,(char *)rxpkt + MDNS_FILTER_HDRSZ);

   return 0;
}

int mk_handle_qu_pkt_repeater(MkRepeaterInfo *pmri, int rxsd, void *rxpkt, size_t pktlen, 
                                    struct sockaddr_in *src_addr)
{
   MkRepeaterBlock *pmb = NULL;
   pthread_t t;
   int i=0;
   int rc=0;

   if ((!pmri)||(!rxpkt)||(!src_addr)||(pktlen <= MDNS_FILTER_HDRSZ)||(pktlen > INGRESS_PKTLIMIT)) {
       printf("%s() ingress packet len = %ld not valid \n",__func__,pktlen);
       return -1;
   }

   pmb = mk_alloc_repeater_block(pmri,src_addr);
   if (!pmb) {
       printf("%s() mk_alloc_repeater_block failed \n",__func__);
       return -1;
   }

   memcpy(&pmb->sk_origin,src_addr,sizeof(struct sockaddr_in));
   pmb->ingress_sd = rxsd;
   memcpy(pmb->peerdata,rxpkt,pktlen);
   pmb->peerdata_len = pktlen;

   memcpy(pmb->ifrsds,pmri->ifRefs,sizeof(IfsInfo)*pmri->numifs);
   pmb->numifs = pmri->numifs;
   for (i = 0 ; (i < pmb->numifs) && (i < MAX_UNICAST_IFS) ; i++) {
      rc = mk_setup_repater_socket(&pmb->ifrsds[i],NULL);
      if ( rc < 0 ) {
        printf("%s() i=%d mk_setup_repater_socket failed for interface=%s addr=%s \n",
                __func__,i,pmb->ifrsds[i].ifname,inet_ntoa(pmb->ifrsds[i].ifaddr));
        memset(&pmb->ifrsds[i],0,sizeof(IfsInfo));
      }
   }

   //  For now spin a thread to handle this.
   //  TODO: change from n:m threads to  scalable n:1 thread, so that all the
   //  requets are handled in just one thread -- with suitable i/o wait of sds.

   rc = pthread_create(&t, NULL, mk_mdns_unicast_pkt_repeater_thread, (void *)pmb);
   if ( rc != 0 ) {
      printf("%s() pthread_create failed errno=%d %s \n",
                  __func__,errno,strerror(errno));
      return -1;
   }

   return rc;
}

void * mk_mdns_unicast_pkt_repeater_thread(void *targ)
{
  MkRepeaterBlock *pmb = (MkRepeaterBlock *)targ;
  int rc = 0;
  struct sockaddr_in src_addr;
  socklen_t addrlen = sizeof(src_addr);
  #define RX_BUFF 2048
  char recv_buff[RX_BUFF] = {0}; //more than enough for our response
  #define MK_RESPONSE_WAIT_SEC 2
  struct timeval tstart= {0,0};
  struct timeval cur_t = {0,0};
  long int elapsedms = 0;
  long int timeoutms = MK_RESPONSE_WAIT_SEC * 1000;
  ssize_t iret = 0;
  int err = 0;
  int i = 0;
  struct timeval tvsel = {0,0};
  fd_set rfds;

   if (!pmb) {
     return NULL;
   }
   pthread_detach(pthread_self());

   //Step1: repeat -- multicast the received pkts -- from a dedicated src port
   for (i = 0; (i < pmb->numifs); i++) {
       IfsInfo *p = &pmb->ifrsds[i];
       if (p->sd  <= 0) {
          continue;
       }
       // do not repeat pkt back to the same network from which it originated
       //TODO verify if this check is needed for mk_ packets.
	if ((pmb->sk_origin.sin_addr.s_addr & p->ifmask.s_addr) ==
                                (p->ifaddr.s_addr & p->ifmask.s_addr)) {
		printf("%s() NOT repeating data to itself %s sockfd=%d \n",__func__,p->ifname,p->sd); 
		continue;
        }
	// repeat data
	rc = send_packet(p->sd, pmb->peerdata, (size_t)pmb->peerdata_len);
	if (rc < 0) {
            // TODO mark the IfsInfo of this block with a flag.
	    printf("%s() send_packet error %s: \n", __func__,strerror(errno));
            continue;
	}
   } // end of for loop of if socks
  
   //Step2 : timedwait i/o wait to get response from all interfaces 


  tvsel.tv_sec = MK_RESPONSE_WAIT_SEC;
  tvsel.tv_usec = 0;

  rc = gettimeofday(&tstart, NULL);
  if (rc < 0) {
     printf("%s() gettimeofday error %s",__func__,strerror(errno));
  }

  do {
       // Add the interface sockets to i/o select wait.
       int maxsd = 0;
       err = 0;
       FD_ZERO(&rfds);
       for (i = 0; (i < pmb->numifs); i++) {
	  IfsInfo *p = &pmb->ifrsds[i];
	  if (p->sd  <= 0) {
	     continue;
	  }

	  FD_SET(p->sd, &rfds);

	  if (p->sd > maxsd) {
	    maxsd = p->sd;  //note down the max sd for use with select i/o later
	  }
       } //end of for loop of if socks

       if (maxsd <= 0) {
          err = 1;
          break ;
       }

       // wait on select and process the response
       tvsel.tv_sec = MK_RESPONSE_WAIT_SEC;
       tvsel.tv_usec = 0;
       rc = select(maxsd + 1, &rfds, NULL, NULL, &tvsel);
       if (rc > 0) {
	     for (i = 0; (i < pmb->numifs); i++) {
		IfsInfo *p = &pmb->ifrsds[i];
		if (p->sd  <= 0) {
		   continue;
		}
		if (FD_ISSET(p->sd, &rfds)) {
                     // do a recvfrom followed by send to origin using the origin socket.
		      memset(recv_buff, 0, RX_BUFF);
		      memset(&src_addr,0,sizeof(src_addr));
		      iret = (int)recvfrom(p->sd, recv_buff, RX_BUFF, 0,
					 (struct sockaddr *)&src_addr, &addrlen);
		      if (iret < 0) {
			  // May be continue with rest of the interface sockets.
			  continue;
		      }

		      if (iret > 0) {
			 //process the unciasted packet.
			 //Now send the response packet back to the originating node rightaway.
	                 rc = sendto(pmb->ingress_sd, recv_buff, iret, 0, 
                                      (struct sockaddr *)&pmb->sk_origin, sizeof(struct sockaddr_in));
                         //TODO : decide if we need to create another source socket or use p->sd
                         // We are now trying with the actual server software.
		      }
		}
	     } //end of for loop of if socks
       } else if (rc == 0) {
	 // rc == 0 select timeout occured
	 printf("%s() select receive timeout:%d sec", __func__,MK_RESPONSE_WAIT_SEC);
	 break;
       } else {
	 //(rc < 0) : select error
	 err = 1;
	 printf("%s() select() error %d %s",__func__,errno,strerror(errno) );
	 break;
       }

        if (timeoutms > 0) {
	  rc = gettimeofday(&cur_t, NULL);
	  if (rc < 0) {
             printf("%s() gettimeofday error %s",__func__,strerror(errno));
	  }

	  elapsedms = ((cur_t.tv_usec - tstart.tv_usec)/1000) +
			  (cur_t.tv_sec - tstart.tv_sec)*1000 ;
        }

     } while((err == 0) && ((timeoutms > 0)&&(elapsedms >=0)&&(elapsedms < timeoutms)));

   printf("%s() returning, err=%d timeoutms=%ld, elapsedms=%ld \n",
  	    __func__,err,timeoutms,elapsedms);

   mk_free_repeater_block(pmb);
   return NULL;
}

MkRepeaterInfo* mk_init_unicast_repeater(void)
{
   MkRepeaterInfo * pmri = malloc(sizeof(MkRepeaterInfo));
   if (!pmri) {
      return NULL;
   }
   memset(pmri,0,sizeof(MkRepeaterInfo));
   if (pthread_mutex_init(&pmri->rmtx,NULL) != 0) {
     free(pmri);
     return NULL;
   }
   return pmri;
}

int mk_destroy_unicast_repeater(MkRepeaterInfo *pmri)
{
   if (!pmri) {
      return -1;
   }
   pthread_mutex_destroy(&pmri->rmtx);
   // memset(pmri,0,sizeof(MkRepeaterInfo));
   free(pmri);
   g_pmri = NULL;
   return 0;
}

MkRepeaterBlock * mk_alloc_repeater_block(MkRepeaterInfo *pmri, struct sockaddr_in *src_addr)
{
  MkRepeaterBlock *pmb = NULL;
  if ( !pmri ) {
    return NULL;
  }

  if (pmri->rpt_cnt < MAX_UNICAST_REPEATERS) {
     // TODO avoid malloc and get it from preallocated slots.
     pmb = malloc(sizeof(MkRepeaterBlock));
  }

  //pmb will be NULL if mallco failed or (rpt_cnt >= MAX_UNICAST_REPEATERS)
  if (!pmb) {
    //unlikley but check
     return NULL;
  }

  pthread_mutex_lock(&pmri->rmtx);
    pmri->rpt_cnt++;
  pthread_mutex_unlock(&pmri->rmtx);

  pmri->t_in++;
  return pmb;
}

int mk_free_repeater_block(MkRepeaterBlock * pmb)
{
  int i=0;
  if (!pmb) {
    return -1;
  }
  for (i = 0; (i < pmb->numifs) && (i < MAX_UNICAST_IFS); i++) {
      if (pmb->ifrsds[i].sd > 0) {
         close(pmb->ifrsds[i].sd);
      }
  }
  memset(pmb,0,sizeof(MkRepeaterBlock));

  if (g_pmri) {
    pthread_mutex_lock(&g_pmri->rmtx);
      g_pmri->rpt_cnt--;
    pthread_mutex_unlock(&g_pmri->rmtx);
  }

  free(pmb);
  return 0;
}

int mk_setup_repater_socket(IfsInfo *pifs, char *updateifname)
{
	int rc = -1;
	int val = 1;
	struct ifreq ifr;
	struct in_addr *if_addr = NULL ;
	struct sockaddr_in saddr;
	struct ip_mreq mreq;

        if (!pifs) {
          return -1;
        }
        // if update of the existing or new need to be added, then replace old one
        if (updateifname && (strlen(updateifname) > 0)) {
           printf("%s() replacing old pifs->ifname(%s) with updateifname(%s) \n",
                      __func__,pifs->ifname,updateifname);
           pifs->ifaddr.s_addr = 0;
           pifs->ifmask.s_addr = 0;
           pifs->sd = 0;
           strncpy(pifs->ifname,updateifname,IFNAMSIZ);
        }

	pifs->sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (pifs->sd < 0) {
	  printf("%s() socket() failed errno=%d %s \n",__func__,errno,strerror(errno));
	  return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pifs->ifname, IFNAMSIZ);
	if_addr = &((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

#ifdef SO_BINDTODEVICE
	rc = setsockopt(pifs->sd, SOL_SOCKET, SO_BINDTODEVICE, pifs->ifname, strlen(pifs->ifname)+1);
	if (rc < 0) {
	     printf("pif->sd(%d) setsockopt(SO_BINDTODEVICE) ifname=%s: error %s \n",
                                pifs->sd,pifs->ifname,strerror(errno));
             close(pifs->sd);
             pifs->sd = 0;
	     return rc;
	}
#endif

	// get interface netmask
        if (pifs->ifmask.s_addr == 0) {
	   if (ioctl(pifs->sd, SIOCGIFNETMASK, &ifr) == 0) {
		memcpy(&pifs->ifmask, if_addr, sizeof(struct in_addr));
	   }
        }

	// get interface address
        if (pifs->ifaddr.s_addr == 0) {
	   if (ioctl(pifs->sd, SIOCGIFADDR, &ifr) == 0) {
		memcpy(&pifs->ifaddr, if_addr, sizeof(struct in_addr));
	   }
        }

        val = 1;
	rc = setsockopt(pifs->sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if (rc < 0) {
	    log_message(LOG_ERR, "send setsockopt(SO_REUSEADDR): %s \n", strerror(errno));
            close(pifs->sd);
            pifs->sd = 0;
            return rc;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = 0; // important let system choose
	saddr.sin_addr.s_addr = pifs->ifaddr.s_addr; //bind to this interface adddress
	rc = bind(pifs->sd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (rc < 0) {
	  printf("%s() bind() failed errno=%d %s \n",__func__,errno,strerror(errno));
          close(pifs->sd);
          pifs->sd = 0;
	  return rc;
	}

	rc = setsockopt(pifs->sd, IPPROTO_IP, IP_MULTICAST_IF, &saddr.sin_addr, sizeof(saddr.sin_addr));
	if (rc < 0) {
	        printf("%s() setsockpot IP_MULTICAST_IF failed errno=%d %s \n",
                      __func__,errno,strerror(errno));
                close(pifs->sd);
                pifs->sd = 0;
		return rc;
	}

	memset(&mreq, 0, sizeof(struct ip_mreq));
	mreq.imr_interface.s_addr = pifs->ifaddr.s_addr;
	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
	if ((rc = setsockopt(pifs->sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
                close(pifs->sd);
		return rc;
	}

	// enable loopback : TODO decide if we need it for this case.
        val = 1;
	if ((rc = setsockopt(pifs->sd, IPPROTO_IP, IP_MULTICAST_LOOP, &val, sizeof(val))) < 0) {
		log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		return rc;
	}

	return 0;
}

//------------------ End   mk_unicast_repeater ---------------------------------
#endif
