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
A simple module for supporting mimik mdns unicast repeater:
Code has been added under define MK_UNICAST_REPEATER. 
It basically co-exists with the current repeater and does the following.

Step1: Rapidly filters received packets containing mimik mdns
       packets with QU(Questions Requesting Unicast Responses) flags set.
- mk_ingress_mdns_unicast_pkt_filter(pkt_data, recvsize);

Step2: If Step1 succeeds, takes the ownership of repeating the matched packet to
       all given interfaces.

Step3: And on receipt of a unicast response to the mdns packet sent in Step2,
forwards the response pkt back to the originating source node-src_addr:port.

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

// Varadhan Venkataseshan : added simple hash functionality 
typedef unsigned int (*function_gen_hash) (void *key);
unsigned int mk_gen_mbyte_khash(void *key);
unsigned int multi_byte_compare(const void *key1, const void *key2);

typedef void * (*hash_alloc_t)   (int size);
typedef void   (*hash_free_t)    (void *ptr);
typedef unsigned int    (*hash_comp_t)    (const void *key1, const void *key2);
typedef void   (*hash_destroy_t) (void *data);

typedef struct HashNode {
    struct HashNode *next;
    void *key;
    void *data;
}HashNode;

typedef struct MultiByteKey {
   unsigned char *kval;
   unsigned int klen;
}MultiByteKey;

//(1 << 13)
#define HASH_MAX_NODES 8192 

typedef struct mkHashInfo
{
   unsigned int          used;
   unsigned int          numSlots;
   HashNode     **ppSlots;
   function_gen_hash     gen_key_hash;
   hash_comp_t  comp;
   hash_alloc_t alloc;
   hash_free_t  dealloc;
   hash_destroy_t  destroy_key;
   hash_destroy_t  destroy_data;
}mkHashInfo;

typedef struct HashIter {
  HashNode *node;  
  int bidx;         
  mkHashInfo *hash;       
} HashIter;

int mk_hash_init(mkHashInfo     *ctx,
              unsigned int            numSlots,
              function_gen_hash    gen_key_hash,
              hash_comp_t    comp,
              hash_alloc_t   alloc,
              hash_free_t    dealloc,
              hash_destroy_t destroy_key,
              hash_destroy_t destroy_data
);

void mk_hash_deinit(mkHashInfo *ctx);
int mk_hash_insert(mkHashInfo *ctx, void *data, void *key);
void mk_hash_remove(mkHashInfo *ctx, void *key);
void *mk_hash_find(mkHashInfo *ctx, void *key);
void mk_hash_destroy_all(mkHashInfo *ctx);
HashNode *mk_hash_iter_begin(HashIter *iter, mkHashInfo *hash);
HashNode *mk_hash_iter_next(HashIter *iter);
int mk_hash_get_used(mkHashInfo *ctx);


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
   IfsInfo *ifrsds; // pointer to onetime IfsInfo socket.
   void * pmri; // reference to its parent info block.

   MultiByteKey key; 
   #define MAX_TXT_KEY_SZ 128
   #define KEY_START_POS 1
   #define KEY_END_SZ 40
   char quKeyName[MAX_TXT_KEY_SZ+1];
   int quKeyNameLen;
   struct timeval tlast;

}MkRepeaterBlock;

typedef struct MkRepeaterInfo{
 #define MK_HASH_COUNT 997 
 // use a prime number for the has size, just in case if the hash uses %
 // would yield good index speard.
 #define MAX_UNICAST_REPEATERS MK_HASH_COUNT
 int rpt_cnt;
 unsigned int t_in;
 int ingress_sd; // socket from which to send to origin node
 int numifs;
 IfsInfo ifRefs[MAX_UNICAST_IFS];
 //MkRepeaterBlock rblocks[MAX_UNICAST_REPEATERS];

  // hash ENTER.key is MkRepeaterBlock(pmb->quKeyName)
  // hash ENTER.data is its MkRepeaterBlock instance
 mkHashInfo quHash; 

}MkRepeaterInfo;

static MkRepeaterInfo *g_pmri = NULL;

int mk_init_unicast_repeater(MkRepeaterInfo ** ppgmri,
                                      struct if_sock *ifs, int numifs, int rxsd);

int mk_destroy_unicast_repeater(MkRepeaterInfo *pmri);

int mk_ingress_mdns_unicast_pkt_filter(int sockfd, void *rxpkt, size_t pktlen,
                              struct sockaddr_in *src_addr);

int mk_setup_repater_socket(IfsInfo *pifs, char *updateifname);

MkRepeaterBlock * mk_alloc_repeater_block(MkRepeaterInfo *pmri);
void mk_free_repeater_block(void *vpmb);

int mk_handle_qu_pkt_repeater(MkRepeaterInfo *pmri, int rxsd, void *rxpkt, size_t pktlen,
                              struct sockaddr_in *src_addr);
//void * mk_mdns_unicast_ifs_sock_select_add(void *targ);
int mk_mdns_unicast_ifs_sock_select_process(MkRepeaterInfo *pmri, fd_set *prfds, int numfd);
int mk_mdns_unicast_pkt_repeater_snd(MkRepeaterBlock *pmb);

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

				msg = (char *)malloc(128);
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

				msg = (char *)malloc(128);
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
        rc = mk_init_unicast_repeater(&g_pmri, socks, num_socks, server_sockfd);
        if ((rc != 0) || (!g_pmri)) {
           printf("mk_init_unicast_repeater failed \n");
        }
#endif

	while (! shutdown_flag) {

                int maxsd = server_sockfd ;

		struct timeval tv = {
			.tv_sec = 10,
			.tv_usec = 0,
		};

		FD_ZERO(&sockfd_set);
		FD_SET(server_sockfd, &sockfd_set);
#ifdef MK_UNICAST_REPEATER
// Add interface sockets : atmost one per interface
                if (g_pmri) {
                   int i = 0;
		   for (i = 0; (i < g_pmri->numifs); i++) {
		      IfsInfo *p = &g_pmri->ifRefs[i];
		      if (p->sd  <= 0) {
			 continue;
		      }

		      FD_SET(p->sd, &sockfd_set);

		      if (p->sd > maxsd) {
			maxsd = p->sd;  //note down the max sd for use with select i/o later
		      }
		   } //end of for loop of if socks
                }
#endif
		int numfd = select(maxsd + 1, &sockfd_set, NULL, NULL, &tv);
		if (numfd <= 0)
			continue;

#ifdef MK_UNICAST_REPEATER
              
                rc = mk_mdns_unicast_ifs_sock_select_process(g_pmri, &sockfd_set, numfd);
#endif

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

			// if (foreground)
			//	printf("data from=%s size=%zd\n", inet_ntoa(fromaddr.sin_addr), recvsize);
                        
#ifdef MK_UNICAST_REPEATER
                   if (g_pmri) {
                      rc = mk_ingress_mdns_unicast_pkt_filter(server_sockfd, pkt_data, recvsize, &fromaddr);
                      if (rc == 0) {
                         // printf("%s() Success: pkt matched out filter check \n",__func__);
                         // call the ingress unicast packet repeater function here.
                        rc = mk_handle_qu_pkt_repeater(g_pmri,server_sockfd, pkt_data, recvsize, &fromaddr);
                         if (rc == 0) {
                            // printf("%s() Success: mk_handle_qu_pkt_repeater t_in=%u rpt_cnt=%d \n",
                            //                  __func__,g_pmri->t_in,g_pmri->rpt_cnt);
         		    continue;
                         }
                      }
                   }
#endif
			for (j = 0; j < num_socks; j++) {
				// do not repeat packet back to the same network from which it originated
				if ((fromaddr.sin_addr.s_addr & socks[j].mask.s_addr) == socks[j].net.s_addr)
					continue;

				// if (foreground)
				//	printf("repeating data to %s\n", socks[j].ifname);

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
       // printf("%s() ingress packet len = %ld not valid \n",__func__,pktlen);
       return -1;
   }

   // skip mdns Query Identifier(id): we do not need to validate pU16[0]

   // check flags for QR (Query(0)/Response(1)) Bit at (0x8000)
   val16 = ntohs(pU16[1]);
   if ((val16 & (1<<15)) == 0x8000) {
     // we are interested in only query packet and not Response
     // printf("%s() mdns.flags.query is expected and not response. flags=%hu\n",__func__,val16);
     return -1;
   }

   // check for dns.count.queries == 1
   val16 = ntohs(pU16[2]);
   if (val16 != 1) {
     // printf("%s() mdns.count.queries(%hu) != expected(1) \n",__func__,val16);
     return -1;
   }

   // check for dns.count.answers == 0
   val16 = ntohs(pU16[3]);
   if (val16 != 0) {
     // printf("%s() mdns.count.answer(%hu) != expected(0) \n",__func__,val16);
     return -1;
   }

   // check for dns.count.auth_rr == 0
   val16 = ntohs(pU16[4]);
   if (val16 != 0) {
     // printf("%s() mdns.count.auth_rr(%hu) != expected(0) \n",__func__,val16);
     return -1;
   }

   // check for dns.count.add_rr == 0    // should have Additional RRs: 0
   val16 = ntohs(pU16[3]);
   if (val16 != 0) {
     // not ours.
     // printf("%s() mdns.count.add_rr(%u) != expected(0) \n",__func__,val16);
     return -1;
   }

   // point to query txt and gets the null terminated string length
   pU8Cur += MDNS_FILTER_HDRSZ; // increment by 12 bytes
   txtlen = strlen((const char *)pU8Cur);

   // check if pktlen has enough data still left for type/class/qu
   if (pktlen < (txtlen + MDNS_FILTER_HDRSZ + 5)) {
     // range check failed
     // printf("%s() pktlen=%ld < txtlen(%hu) + 12 + 5 \n",__func__,pktlen,txtlen);
     return -1;
   }

   pU8Cur += (txtlen + 1); // add 1 byte for string termination 0
   // update pU16 with current position 
   pU16 = (uint16_t *)pU8Cur;
   
   // dns.qry.type == PTR
   #define MDNS_QRY_TYPE_PTR 12
   val16 = ntohs(pU16[0]);
   if (val16 != MDNS_QRY_TYPE_PTR) {
     // printf("%s() mdns.qry.type(%u) != PTR(%u) \n",__func__,val16,MDNS_QRY_TYPE_PTR);
     return -1;
   }

   // mdns qry : class and qu occupy 16 bits, we need only QU test here.
   // dns.qry.class == 0x0001  // Class: IN (0x0001)

   // Most important and mandatory filter
   // dns.qry.qu == 1          // It has unicast bit set : "QU" question: True
   val16 = ntohs(pU16[1]);
   // check the Most significant bit of val16 where QU is being set
   if ((val16 & 0x8000) != 0x8000) {
      // printf("%s() mdns.qry.qu=0, unicast(QU) bit not set val16=0x%X \n",__func__,val16);
      return -1;
   }

   #define QN_TXT_CHK_PREFIX "_mk"
   if (txtlen < strlen(QN_TXT_CHK_PREFIX)) {
     //range check failed
     return -1;
   }
   // Txt prefix check can be omitted if needed
   if (!strstr((char *)rxpkt + MDNS_FILTER_HDRSZ , QN_TXT_CHK_PREFIX)) {
     // printf("%s() expected prefix[%s] not in qn txt[%s] \n",__func__,QN_TXT_CHK_PREFIX,pU8Cur);
     return -1;
   }

   // printf("%s(!success!) pkt with QU matches => %s \n",__func__,(char *)rxpkt + MDNS_FILTER_HDRSZ);

   return 0;
}

int mk_handle_qu_pkt_repeater(MkRepeaterInfo *pmri, int rxsd, void *rxpkt, size_t pktlen, 
                                    struct sockaddr_in *src_addr)
{
  
   MkRepeaterBlock *pmb = NULL;
   int rc=0;

   if ((!pmri)||(!rxpkt)||(!src_addr)||(pktlen <= MDNS_FILTER_HDRSZ)||(pktlen > INGRESS_PKTLIMIT)) {
       // printf("%s() ingress packet len = %ld not valid \n",__func__,pktlen);
       return -1;
   }

   pmb = mk_alloc_repeater_block(pmri);
   if (!pmb) {
       printf("%s() mk_alloc_repeater_block failed \n",__func__);
       return -1;
   }

   memcpy(&pmb->sk_origin,src_addr,sizeof(struct sockaddr_in));
   pmb->ingress_sd = rxsd;
   memcpy(pmb->peerdata,rxpkt,pktlen);
   pmb->peerdata_len = pktlen;

   // copy the reference to parent info
   pmb->pmri = pmri;
   pmb->ifrsds = pmri->ifRefs;
   pmb->numifs = pmri->numifs;

   memset(pmb->quKeyName,0,sizeof(pmb->quKeyName));
   strncpy(pmb->quKeyName, (char *)pmb->peerdata + MDNS_FILTER_HDRSZ + KEY_START_POS, KEY_END_SZ);
   pmb->quKeyNameLen = strlen(pmb->quKeyName);

   pmb->key.kval = (void *)pmb->quKeyName;
   pmb->key.klen = pmb->quKeyNameLen;

   // remove old node if any as the tuple associated with old is invalid now
   // NOTE: oldpmb block will be freed via registered destroy data function
   mk_hash_remove(&pmri->quHash,(void *)&pmb->key);

   // insert the new one
   rc = mk_hash_insert(&pmri->quHash,(void *)pmb,(void *)&pmb->key);
   if (rc < 0) {
     printf("%s() hash insert failed \n",__func__);
     mk_free_repeater_block(pmb);
     return -1;
   }

   rc = mk_mdns_unicast_pkt_repeater_snd(pmb);
   if ( rc != 0 ) {
      printf("%s() mk_mdns_unicast_pkt_repeater_snd failed \n",__func__);
      mk_hash_remove(&pmri->quHash,(void *)&pmb->key);
      return -1;
   }

   return rc;
}

int mk_mdns_unicast_ifs_sock_select_process(MkRepeaterInfo * pmri, fd_set *prfds, int numfd)
{
  int rc = 0;
  int i = 0;

   if ((!pmri)||(!prfds)||(numfd <= 0)) {
     return -1;
   }

   if ( (numfd == 1) && (FD_ISSET(pmri->ingress_sd , prfds)) ) {
     // printf("%s(not ours) numfd is 1 and ingress_sd=%d is set \n",__func__,pmri->ingress_sd);
     return -1;
   }

   for (i = 0; (i < pmri->numifs); i++) {
	  // printf("%s() i=%d numfd=%d \n",__func__,i,numfd);
	  IfsInfo *p = &pmri->ifRefs[i];
	  if (p->sd  <= 0) {
	     continue;
	  }
	  if (FD_ISSET(p->sd, prfds)) {
                ssize_t iret = 0;
                struct sockaddr_in src_addr;
                socklen_t addrlen = sizeof(src_addr);
                #define RX_BUFF 2048
                char recv_buff[RX_BUFF] = {0}; //more than enough for our response
		// memset(recv_buff, 0, RX_BUFF);
		memset(&src_addr,0,sizeof(src_addr));
		iret = (int)recvfrom(p->sd, recv_buff, RX_BUFF, 0,
				   (struct sockaddr *)&src_addr, &addrlen);
		// printf("%s() recvfrom iret=%d i=%d numfd=%d \n",__func__,iret,i,numfd);
		if (iret < 0) {
		    // May be continue with rest of the interface sockets.
		    continue;
		}

		if (iret > 0) {

		   MkRepeaterBlock *pmb = NULL;
                   MultiByteKey k1;
                   char KeyName[MAX_TXT_KEY_SZ+1] = {0};
                   int KeyNameLen = 0;
                   strncpy(KeyName, (char *)recv_buff + MDNS_FILTER_HDRSZ + KEY_START_POS, KEY_END_SZ);
                   KeyNameLen = strlen(KeyName);
                   k1.kval = (void *)KeyName;
                   k1.klen = KeyNameLen;

                   pmb = (MkRepeaterBlock *)mk_hash_find(&pmri->quHash, (void *)&k1);
		   if (!pmb) {
		       printf("%s() hash find failed Name=%s len=%d \n",__func__,KeyName,KeyNameLen);
		       continue;
		   }
		   // printf("%s() hash find success... Name=%s len=%d \n",__func__,KeyName,KeyNameLen);

		   //process the unciasted packet.
		   //Now send the response packet back to the originating node rightaway.
		   rc = sendto(pmb->ingress_sd, recv_buff, iret, 0, 
				(struct sockaddr *)&pmb->sk_origin, sizeof(struct sockaddr_in));
		   //TODO : decide if we need to create another source socket or use p->sd
		   // We are now trying with the actual server software.

		   printf("%s() sent back reply rc=%d \n",__func__,rc);

                   // TODO decide about hash removal here
                   // mk_hash_remove(&pmri->quHash,(void *)&pmb->key);
		}
	  }
   } //end of for loop of if socks

   // TODO-IMP if it is due for stale pmb entries from hash table
   // and remove them.

   return 0;
}

int mk_mdns_unicast_pkt_repeater_snd(MkRepeaterBlock *pmb)
{
  int rc = 0;
  int i = 0;
  int scount = 0;

   if (!pmb) {
     return -1;
   }

   // Step1: repeat -- multicast the received pkts.
   for (i = 0; (i < pmb->numifs); i++) {
       IfsInfo *p = &pmb->ifrsds[i];
       if (p->sd  <= 0) {
          continue;
       }
       // do not repeat pkt back to the same network from which it originated
       //TODO verify if this check is needed for mk_ packets.
	if ((pmb->sk_origin.sin_addr.s_addr & p->ifmask.s_addr) ==
                                (p->ifaddr.s_addr & p->ifmask.s_addr)) {
		// printf("%s() NOT repeating data to itself %s sockfd=%d \n",__func__,p->ifname,p->sd); 
		continue;
        }
	// repeat data
	rc = send_packet(p->sd, pmb->peerdata, (size_t)pmb->peerdata_len);
	if (rc < 0) {
	    printf("%s() send_packet error %s: \n", __func__,strerror(errno));
            continue;
	}
        if(rc > 0) {
           scount++;
        }
   } // end of for loop of fixed interface sockets.
   
   if ( scount == 0 ) {
       // No send had happened.
       return -1;
   }
  
   // rc = gettimeofday(&pmb->tlast, NULL);
   // if (rc < 0) {
   //    printf("%s() gettimeofday error %s",__func__,strerror(errno));
   // }
  
   // printf("%s() returning, sendcnt=%d , quKeyNameLen=%d quKeyName=%s\n",
     //                 __func__,scount,pmb->quKeyNameLen,pmb->quKeyName);

   return 0;
}

int mk_init_unicast_repeater(MkRepeaterInfo ** ppgmri, 
                                      struct if_sock *ifs, int numifs, int rxsd)
{
   int rc=0;

   if ((!ifs) || (numifs <= 0)) {
      return -1;
   }

   MkRepeaterInfo * pmri = (MkRepeaterInfo *)malloc(sizeof(MkRepeaterInfo));
   if (!pmri) {
      return -1;
   }

   memset(pmri,0,sizeof(MkRepeaterInfo));

   // TODO need to verify if data destroy free is ok
   rc = mk_hash_init(&pmri->quHash, MK_HASH_COUNT, mk_gen_mbyte_khash,
		multi_byte_compare, (hash_alloc_t)malloc, free, NULL, mk_free_repeater_block);
   if (rc < 0) {
      printf("%s() mk_hash_init failed for quHash: MK_HASH_COUNT=%d \n",
               __func__,MK_HASH_COUNT);
      free(pmri);
      return -1;
   }
        
   pmri->ingress_sd = rxsd;

   for (int i = 0; i < numifs && i < MAX_UNICAST_IFS; i++) {
     // For now copy the list of interface details from ifs
     // TODO get the list of all network interface details from system.
     if (ifs[i].ifname) {
	 strncpy(pmri->ifRefs[i].ifname, ifs[i].ifname,IFNAMSIZ);
	 memcpy(&pmri->ifRefs[i].ifaddr, &ifs[i].addr, sizeof(struct in_addr));
	 memcpy(&pmri->ifRefs[i].ifmask, &ifs[i].mask, sizeof(struct in_addr));
	 pmri->numifs++;
	 printf("%d) ifname[%s] addr[%s] mask[%s] \n",i,pmri->ifRefs[i].ifname,
		inet_ntoa(pmri->ifRefs[i].ifaddr),
		inet_ntoa(pmri->ifRefs[i].ifmask));
	 rc = mk_setup_repater_socket(&pmri->ifRefs[i],NULL);
	 if ( rc < 0 ) {
	   printf("%s() i=%d mk_setup_repater_socket failed for interface=%s addr=%s \n",
		   __func__,i,pmri->ifRefs[i].ifname,inet_ntoa(pmri->ifRefs[i].ifaddr));
	   pmri->ifRefs[i].sd = -1;
	 }
     }
   }

   if (ppgmri) {
     *ppgmri = pmri;
   }

   return 0;
}

int mk_destroy_unicast_repeater(MkRepeaterInfo *pmri)
{
   int i=0;
   if (!pmri) {
      return -1;
   }

   mk_hash_deinit(&pmri->quHash);

   // close interface sockets
   for (i = 0; (i < pmri->numifs) && (i < MAX_UNICAST_IFS); i++) {
      if (pmri->ifRefs[i].sd > 0) {
        printf("%s() i=%d closing if sock=%d for interface=%s addr=%s \n",
                __func__,i,pmri->ifRefs[i].sd,pmri->ifRefs[i].ifname,inet_ntoa(pmri->ifRefs[i].ifaddr));
          close(pmri->ifRefs[i].sd);
          pmri->ifRefs[i].sd = -1;
      }
   }
   
   free(pmri);
   g_pmri = NULL;

   return 0;
}

MkRepeaterBlock * mk_alloc_repeater_block(MkRepeaterInfo *pmri)
{
  MkRepeaterBlock *pmb = NULL;
  if ( !pmri ) {
    return NULL;
  }

  if (pmri->rpt_cnt < MAX_UNICAST_REPEATERS) {
     // TODO avoid malloc and get it from preallocated slots.
     pmb = (MkRepeaterBlock *)malloc(sizeof(MkRepeaterBlock));
  }

  //pmb will be NULL if mallco failed or (rpt_cnt >= MAX_UNICAST_REPEATERS)
  if (!pmb) {
    //unlikley but check
     printf("%s() failed rpt_cnt=%d MAX_UNICAST_REPEATERS=%d \n",
                         __func__,pmri->rpt_cnt,MAX_UNICAST_REPEATERS);
     return NULL;
  }

    pmri->rpt_cnt++;

  pmri->t_in++;
  return pmb;
}

void mk_free_repeater_block(void * vpmb)
{
  MkRepeaterBlock *pmb = (MkRepeaterBlock *)vpmb;
  MkRepeaterInfo *pmri = NULL;

  if (!pmb) {
    return;
  }

  pmri = (MkRepeaterInfo *)pmb->pmri;
  if (pmri) {
      pmri->rpt_cnt--;
  }

  // memset(pmb,0,sizeof(MkRepeaterBlock));
  free(pmb);

  return;
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

// simple hash functionality as glibc does not a flexible one.
// glibc hcreate and hsearch does not even have a node delete and iterator functionality 
int mk_hash_init(mkHashInfo     *ctx,
              unsigned int            numSlots,
              function_gen_hash    gen_key_hash,
              hash_comp_t    comp,
              hash_alloc_t   alloc,
              hash_free_t    dealloc,
              hash_destroy_t destroy_key,
              hash_destroy_t destroy_data
)
{
   unsigned int i = 0 ;

   if ((ctx == NULL) ||
       (alloc == NULL) || (gen_key_hash == NULL) ||
       (comp == NULL) || (dealloc == NULL)) {
      return -1;
   }

   if((numSlots == 0) || (numSlots > HASH_MAX_NODES)) {
      numSlots = HASH_MAX_NODES ;
   }

   ctx->used = 0;
   ctx->gen_key_hash = gen_key_hash;
   ctx->comp = comp;
   ctx->alloc = alloc;
   ctx->dealloc = dealloc;
   ctx->numSlots = numSlots;
   ctx->destroy_key = destroy_key;
   ctx->destroy_data = destroy_data;

   ctx->ppSlots = (HashNode **) ctx->alloc(sizeof(HashNode *) * ctx->numSlots);
   if(ctx->ppSlots == NULL) {
      return -1;
   }
   for (i = 0; i < ctx->numSlots; ++i) {
      ctx->ppSlots[i] = NULL;
   }
   return 0;
}

void mk_hash_deinit(mkHashInfo *ctx)
{
    if (!ctx) { 
       return ; 
    }

    // Remove all the hash node contents.
    mk_hash_destroy_all(ctx);

    // Now remove the hash ppSlots.
    if (ctx->ppSlots) {
        ctx->dealloc(ctx->ppSlots);
        ctx->ppSlots = NULL;
    }
}

void *mk_hash_find(mkHashInfo *ctx, void *key)
{
    unsigned int bidx;
    unsigned int hskey = 0 ;
    HashNode *node;

   if ((!ctx) || (!key)) { 
     return NULL ;
   }

   if ((!ctx->numSlots) || (!ctx->gen_key_hash)) { 
      return NULL ;
   }

    hskey = ctx->gen_key_hash(key);
    bidx = hskey % ctx->numSlots;

    node = ctx->ppSlots[bidx];

    // printf("%s(%p) hskey=%u key=%p bidx=%u node=>>%p used=%d\n",
    //           __func__,ctx,hskey,key,bidx,node,ctx->used);

    // traverse all chained entries in a slot.
    while (node != NULL) {
            if(ctx->comp(node->key, key) == 0)
            return node->data;

        node = node->next;
    }
    return NULL;
}

int mk_hash_insert(mkHashInfo *ctx, void *data, void *key)
{
    unsigned int bidx = 0 ;
    unsigned int hskey = 0 ;
    HashNode *node = NULL ;

   if ((!ctx) || (!key)) { 
     return -1 ;
   }

    hskey = ctx->gen_key_hash(key) ;
    bidx = hskey % ctx->numSlots;
    node = ctx->ppSlots[bidx];

    while (node != NULL) {
        // checking to see if there is no duplicate key: Duplicate insertion
        if(ctx->comp(node->key, key) == 0)
            return -1;

        node = node->next;
    }

    node = (HashNode*) ctx->alloc(sizeof(HashNode));
    if(node == NULL) {
        return -2;
    }

    node->key = key;
    node->data = data;
    node->next = ctx->ppSlots[bidx];
    ctx->ppSlots[bidx] = node;
    ctx->used++;
    // printf("%s(%p) key=%p bidx=%u node=>>%p used=%d\n",
    //          __func__,ctx,key,bidx,node,ctx->used);

    return 0;
}

void mk_hash_remove(mkHashInfo *ctx, void *key)
{
    unsigned int bidx;
    unsigned int hskey = 0 ;
    HashNode *node, *prev;

    if ((!ctx) || (!key)) {
        return ;
    }

    hskey = ctx->gen_key_hash(key);
    bidx = hskey % ctx->numSlots;
    node = ctx->ppSlots[bidx];
    prev = NULL;

    while (node != NULL) {
        if (ctx->comp(node->key, key) == 0) {
	    if (prev != NULL) {
	        prev->next = node->next;
	    }
	    else {
	        ctx->ppSlots[bidx] = node->next;
	    }

            if(ctx->destroy_key != NULL)
                ctx->destroy_key(node->key);
            if(ctx->destroy_data != NULL)
                ctx->destroy_data(node->data);

            ctx->dealloc(node);
            ctx->used--;
            // printf("%s() , ctx=%p used=%d \n",__func__,ctx,ctx->used);

            return;
        }
        prev = node;
        node = node->next;
    }
}

void mk_hash_destroy_all(mkHashInfo *ctx)
{
    if (!ctx) { return; }

    if (ctx->used > 0) {
        unsigned int i;
        HashNode *node, *next;

        // Loop through every hash node
        for (i = 0; i < ctx->numSlots; ++i) {
            node = ctx->ppSlots[i];
            if (node != NULL) {
                while (node != NULL) {
                    next = node->next;

                    if(ctx->destroy_key != NULL)
                        ctx->destroy_key(node->key);
                    if(ctx->destroy_data != NULL)
                        ctx->destroy_data(node->data);

                    ctx->dealloc(node);
                    ctx->used--;
                    node = next;
                }
                ctx->ppSlots[i] = NULL;
            }
        }
    }
}

int mk_hash_get_used(mkHashInfo *ctx)
{
    if (!ctx) { return -1; }
    return ctx->used ;
}

HashNode *mk_hash_iter_begin(HashIter *iter, mkHashInfo *hash)
{
    unsigned int i;

    if ((iter == NULL) || (hash == NULL)) {
        return NULL;
    }

    // reset iterator
    memset(iter, 0 , sizeof(HashIter));

    if (hash->used == 0) {
        return NULL;
    }

    // return the first non empty node.
    for (i=0; i<hash->numSlots; ++i) {
        if (hash->ppSlots[i] != NULL) {
	    iter->node = hash->ppSlots[i];
	    iter->bidx = i;
	    iter->hash = hash;
	    return iter->node;
        }
    }

    hash->used = 0;
    iter->node = NULL;
    return NULL;
}

HashNode *mk_hash_iter_next(HashIter *iter)
{
    unsigned int i = 0;

    if ((iter == NULL)||(iter->node == NULL)) {
        return NULL;
    }

    // First go over current chained list if any
    if (iter->node->next != NULL) {
        //printf("iter->node=%p and iter-node->next=%p\n",
        //          iter->node,iter->node->next);

        iter->node = iter->node->next;
        return iter->node;
    }

    // find and return next non-empty slot
    for (i=iter->bidx+1; i<iter->hash->numSlots; ++i) {
        if (iter->hash->ppSlots[i] != NULL) {
	   iter->node = iter->hash->ppSlots[i];
	   iter->bidx = i;
	   return iter->node;
        }
    }

    // No more nodes were found in the ppSlots. Mark iterator has finished.
    iter->node = NULL;
    return NULL;
}

unsigned int mk_gen_mbyte_khash(void *key)
{
  int i = 0;
  MultiByteKey *mk = (MultiByteKey *)key;
  unsigned val = 0;
  if ((!mk)||(!mk->klen)||(!mk->kval)) {
    return 0;
  }

  for (i = 0; i < mk->klen; i++) {
     val = val + mk->kval[i];
  }

  return val;
}

unsigned int multi_byte_compare(const void *key1, const void *key2)
{
    MultiByteKey *k1 = (MultiByteKey *)key1 ;
    MultiByteKey *k2 = (MultiByteKey *)key2 ;
#if 0
    printf("%s() k1=%p , k2=%p , k1->kval=%p , k2->kval=%p"
           "k1->klen=%d k2->klen=%d k1->kval=%s k2->kval=%s \n",
           __func__,k1,k2,k1->kval,k2->kval,k1->klen,k2->klen,
           (char *)k1->kval,(char *)k2->kval);
#endif
    if(k1 && k2 && k1->kval && k2->kval &&
       (k1->klen == k2->klen) && (!memcmp(k1->kval,k2->kval,k1->klen))) {
       return 0 ;
    }
    return 1;
}

//------------------ End   mk_unicast_repeater ---------------------------------
#endif
