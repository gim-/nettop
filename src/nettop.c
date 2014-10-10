/* $Id: nettop.c,v 1.26 2001/11/09 03:50:03 srp Exp $ */

/*
 * Copyright (c) 2000, 2001
 *           Scott R Parish <sRp@srparish.net>, OR  97119-9201.
 *       All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Scott R Parish ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL Scott R Parish BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * TODO
 *
 * * figure ports out better
 * * show more about 802.3
 * * have a mode where you only see statistics from the last x time period
 * * allow for collapsing and expanding of sub-types (like tcp/udp/etc)
 * * move eth types out to seperate file (user defineable)
 * * remove segfaults on screen resize
 * * add support for ipv6
 * * add a quet mode which dumps percentages into a file after a given time
 * * make key strokes (such as 'q') instant instead of delayed)
 * * handle sigint better (currently segfaults sometimes)
 * * think about removing the "24" limit
 * * buetify code
 * * add packets/second
 * * remove magic numbers from code
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <slang.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#ifdef sun
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <time.h>
#include <stdlib.h>
#include <netdb.h>

#include "node.h"
#include "ent.h"

/* Colors */
#define total_c    1
#define ethernet_c 2
#define ip_c       3
#define tcp_c      4
#define udp_c      4
#define bar_c      5
#define header_c   6

#define TCP	6
#define UDP	17

/* do all the grunt work to get into permiscuious mode */
pcap_t         *pcap_start(char *filterstr);

/* print the stats out */
void            screen_update();
void            ipprint(int last[]);
void            servprint(int last[], struct node *tree, int type);

/* call functions that need to be ran every alarm, and reset the alarm */
void            alarmed();

/* tie things down before quiting */
void            dieing();

/* initialize ncurses */
void            ui_run();
void            change_screen_size();
void            ts_run();
void            sprintf_nice(char *str, unsigned long long data);
void            change_delay();
void            show_help();
void            change_sort_type();
void            pause_display();
void            clear_count();
void            usage();
void            help();
int		getport(int sport, int dport, int type);

void 		sl_print_row(char *str3, int pkt, int pktf, char *str1,
			     int tot, int totf, char *str2, int szpkt,
			     char *type, int level, int last[]);
void            sl_header();
void            sl_init();
void            sl_check_kb();

void            t_header();
void            t_print_row(char *str3, int pkt, int pktf, char *str1,
			    int tot, int totf, char *str2, int szpkt,
			    char *type, int level, int last[]);

struct node     ether;
struct node     ip;
struct node     tcp;
struct node     udp;

struct ent	*tcpent;
struct ent	*udpent;
struct ent	*ipent;

/* which network device to use */
char           *dev = 0;
char           *input_file = 0;

extern char    *optarg;
extern int      optind;

int             delay = 1000000;	/* how long to wait between
					 * screen updates */
int             runcount = 0;	/* how many times to run */

time_t          start_time, current_time;

int             y;
int             maxx, maxy;


unsigned char   sort_type = 'p';	/* either (p)acket or (s)ize */

unsigned char   ui_type = 's';	/* (s)lang, (t)ext */
int             t_print_head = 0;
int             print_lines = 1;

unsigned long long sums_h[HISTORY_SIZE] = {0};	/* history of sums for bit/s */

pcap_t         *pd;

pthread_mutex_t mutex;

int
main(int argc, char **argv)
{
	struct servent *serv = 0;
	struct protoent *proto = 0;
	struct ent *n;
	pthread_t ui;		/* user interface */
	int ch, i;
	char *filterstr = " ";

	while ((ch = getopt(argc, argv, "n:i:d:f:r:spthl")) != -1) {
		switch (ch) {
		case 'i':
			dev = optarg;
			break;
		case 'r':
			input_file = optarg;
			break;
		case 'd':
			delay = (1000000 * atof(optarg));
			break;
		case 'f':
			filterstr = optarg;
			break;
		case 'h':
			t_print_head = 1;
			break;
		case 'l':
			print_lines = !print_lines;
			break;
		case 'n':
			runcount = atoi(optarg);
			break;
		case 'p':
			sort_type = 'p';
			break;
		case 's':
			sort_type = 's';
			break;
		case 't':
			ui_type = 't';
			print_lines = !print_lines;
			break;
		case '?':
			help();
			exit(1);
		default:
			usage();
			exit(1);
		}
	}

	ether.count = ether.size = (int) ether.l = (int) ether.r = 0;
	ether.type = -1;
	for (i = 0; i < HISTORY_SIZE; i++)
		ether.size_h[i] = 0;

	ip.count = ip.size = (int) ip.l = (int) ip.r = 0;
	ip.type = -1;
	for (i = 0; i < HISTORY_SIZE; i++)
		ip.size_h[i] = 0;

	tcp.count = tcp.size = (int) tcp.l = (int) tcp.r = 0;
	tcp.type = -1;
	for (i = 0; i < HISTORY_SIZE; i++)
		tcp.size_h[i] = 0;

	udp.count = udp.size = (int) udp.l = (int) udp.r = 0;
	udp.type = -1;
	for (i = 0; i < HISTORY_SIZE; i++)
		udp.size_h[i] = 0;

	/* generate a list of services and protocols */
	setprotoent(1);
	while ((proto = getprotoent())) {
		char *s;
		s = malloc(strlen(proto->p_name) * sizeof(char) + 1);
		n = malloc(sizeof(struct ent));
		n->e_num = proto->p_proto;
		n->e_name = strcpy(s, proto->p_name);
		addent(&ipent, n);

	}
	endprotoent();

	setservent(1);
	while ((serv = getservent())) {
		char *s = malloc(strlen(serv->s_name) * sizeof(char) + 1);
		n = malloc(sizeof(struct ent));
		n->e_num = ntohs(serv->s_port);
		n->e_name = strcpy(s, serv->s_name);

		if (strcmp(serv->s_proto, "tcp")) 
			addent(&tcpent, n);
		else if (strcmp(serv->s_proto, "udp"))
			addent(&udpent, n);

	}
	endservent();

	pd = pcap_start(filterstr);

	pthread_create(&ui, NULL, (void *) &ui_run, NULL);
	signal(SIGINT, dieing);

	ts_run();

	exit(0);
}

void
ts_run()
{
	struct node *t;
	struct pcap_pkthdr hdr;
	struct ip iphdr;
	struct tcphdr tcphdr;
	struct udphdr udphdr;
	int ip_head_len, port;
	unsigned short eth_type;
	char *next_pcap(int *len), *ptr;

	while (1) {
		while ((ptr = (char *) pcap_next(pd, &hdr)) == NULL);

		/* ethernetpacket type */
		memcpy(&eth_type, &ptr[12], 2);
		eth_type = ntohs(eth_type);

		if (eth_type < 0x05dd) {	/* this is an 802.3 packet */
			unsigned short  type;
			memcpy(&type, &ptr[18], 2);
			type = ntohs(type);

			pthread_mutex_lock(&mutex);
			if ((t = get(&ether, type)));
			else
				t = new(&ether, type);
			t->count++;
			t->size += hdr.len;
			pthread_mutex_unlock(&mutex);
		} else {	/* this is a ethernet packet */

			pthread_mutex_lock(&mutex);
			if ((t = get(&ether, eth_type)));
			else
				t = new(&ether, eth_type);
			t->count++;
			t->size += hdr.len;
			pthread_mutex_unlock(&mutex);

			switch (eth_type) {
				/* IPv4 */
			case 0x0800:
				memcpy(&iphdr, ptr + 14, sizeof(struct ip));
				ip_head_len = iphdr.ip_hl * 4;

				/* which ip protocol is this */
				pthread_mutex_lock(&mutex);
				if ((t = get(&ip, iphdr.ip_p)));
				else
					t = new(&ip, iphdr.ip_p);
				t->count++;
				t->size += hdr.len;
				pthread_mutex_unlock(&mutex);

				if (iphdr.ip_p == 6) {
					memcpy(&tcphdr, ptr + 14 + ip_head_len,
					    sizeof(struct tcphdr));

					port = getport(tcphdr.th_sport,
						       tcphdr.th_dport, TCP);

					pthread_mutex_lock(&mutex);
					if ((t = get(&tcp, port)));
					else
						t = new(&tcp, port);
					t->count++;
					t->size += hdr.len;
					pthread_mutex_unlock(&mutex);
				} else if (iphdr.ip_p == 17) {
					memcpy(&udphdr, ptr + 14 + ip_head_len,
					       sizeof(struct udphdr));

					port = getport(udphdr.uh_sport,
						       udphdr.uh_dport, UDP);

					pthread_mutex_lock(&mutex);
					if ((t = get(&udp, port)));
					else
						t = new(&udp, port);
					t->count++;
					t->size += hdr.len;
					pthread_mutex_unlock(&mutex);
				}
				break;
			default:
			}
		}
	}

	pcap_close(pd);
}

int getport(int sport, int dport, int type) {
	struct ent *e;
	e = (type == TCP) ? tcpent : udpent;

	if (getentbynum(e, sport))
		return ntohs(sport);
	if (getentbynum(e, dport))
		return ntohs(dport);

	return (ntohs(sport) < ntohs(dport) ? ntohs(sport) : ntohs(dport));
}

/* this function, is called from SIGALRM, and is used to update the screen */
void
screen_update()
{
	struct node *sorted[24] = {0};
	unsigned long long sump, sums, valp, vals;
	unsigned long long xfrrate = 0;
	int i, do_ipprint, last[3] = {0};
	char str1[7], str2[7], str3[7];
	char *strtype, strtypeb[15];

	pthread_mutex_lock(&mutex);
	sump = countsump(&ether);
	sums = countsums(&ether);
	largestn(&ether, sorted, 24, sort_type);
	pthread_mutex_unlock(&mutex);

	if (current_time > start_time) {
		int             x;
		for (x = HISTORY_SIZE - 1; x > 0; x--)
			sums_h[x] = sums_h[x - 1];
		sums_h[0] = sums;
		xfrrate = (sums_h[0] - sums_h[1]);
		xfrrate = xfrrate * 8 / ((long double) delay / 1000000ULL);
		sprintf_nice(str3, xfrrate);
	}
	if (ui_type == 's')
		sl_header();
	if (ui_type == 't' && t_print_head)
		t_header();

	sprintf_nice(str1, sump);
	sprintf_nice(str2, sums);
	if (sump > 0)
		i = sums / sump;
	else
		i = 0;

	if (ui_type == 's')
		sl_print_row(str3, 100, 0, str1, 100, 0, str2, i, "total", 
			     0, last);
	if (ui_type == 't')
		t_print_row(str3, 100, 0, str1, 100, 0, str2, i, "total",
			     0, last);

	pthread_mutex_lock(&mutex);
	/* print percentages */
	for (i = 0; !last[0] && sorted[i]; i++) {
		/* the first node in our array is there as a place holder */
		/* we don't want to print it out. */
		if (sorted[i]->type == (int) 0xffffffff)
			continue;

		if (i + 1 >= 24 || !sorted[i + 2] || 
		    (ui_type == 's' && y + 1 > maxy - 1))
			last[0] = 1;


		do_ipprint = 0;
		switch (sorted[i]->type) {
		case 0x0800:
			strtype = "ipv4";
			do_ipprint = 1;
			break;
		case 0x0806:
			strtype = "arp";
			break;
		case 0x6002:
			strtype = "dec mop";
			break;
		case 0x6003:
			strtype = "dec dna-route";
			break;
		case 0x6004:
			strtype = "dec lat";
			break;
		case 0x8035:
			strtype = "rarp";
			break;
		case 0x809b:
			strtype = "appletalk DDP";
			break;
		case 0x8137:
			strtype = "novell ipx-nw";
			break;
		case 0x86dd:
			strtype = "ipv6";
			break;
		case 0x8864:
			strtype = "pppoe";
			break;
		default:
			sprintf(strtypeb, "0x%4.4x", sorted[i]->type);
			strtype = strtypeb;
		}
		valp = (sorted[i]->count * 10000) / sump;
		sprintf_nice(str1, sorted[i]->count);
		vals = (sorted[i]->size * 10000 / sums);
		sprintf_nice(str2, sorted[i]->size);

		if (current_time > start_time) {
			int             x;
			for (x = HISTORY_SIZE - 1; x > 0; x--)
				sorted[i]->size_h[x] = sorted[i]->size_h[x - 1];
			sorted[i]->size_h[0] = sorted[i]->size;
			xfrrate = (sorted[i]->size_h[0] - sorted[i]->size_h[1]);
			xfrrate = xfrrate*8 / ((long double) delay / 1000000ULL);
			sprintf_nice(str3, xfrrate);
		}
		if (ui_type == 's')
			sl_print_row(str3, valp / 100, valp % 100, str1, 
				     vals / 100, vals % 100, str2,
				     sorted[i]->size / sorted[i]->count,
				     strtype, 1, last);
		if (ui_type == 't')
			t_print_row(str3, valp / 100, valp % 100,
				    str1, vals / 100, vals % 100, str2,
				    sorted[i]->size / sorted[i]->count,
			            strtype, 1, last);

		if (do_ipprint)
			ipprint(last);
	}
	pthread_mutex_unlock(&mutex);

	if (ui_type == 's')
		SLsmg_refresh();
}

void
ipprint(int last[])
{
	struct node *sorted[24] = {0};
	struct ent *proto;
	unsigned long long valp, vals, sump, sums;
	unsigned long long xfrrate = 0;
	int j;
	char str1[7], str2[7], str3[7], *strtype, strtype2[14];

	sump = countsump(&ether);
	sums = countsums(&ether);

	largestn(&ip, sorted, 24, sort_type);

	last[1] = 0;
	for (j = 0; !last[1] && sorted[j]; j++) {
		if (sorted[j]->type == -1)
			continue;

		if (j + 1 >= 24 || !sorted[j + 2] ||
		    (ui_type == 's' && y + 1 > maxy - 1))
			last[1] = 1;

		if ((proto = getentbynum(ipent, sorted[j]->type)))
			strtype = proto->e_name;
		else {
			sprintf(strtype2, "%d", sorted[j]->type);
			strtype = strtype2;
		}

		valp = (sorted[j]->count * 10000) / sump;
		sprintf_nice(str1, sorted[j]->count);
		vals = (sorted[j]->size * 10000) / sums;
		sprintf_nice(str2, sorted[j]->size);

		if (current_time > start_time) {
			int x;
			for (x = HISTORY_SIZE - 1; x > 0; x--)
				sorted[j]->size_h[x] = sorted[j]->size_h[x - 1];
			sorted[j]->size_h[0] = sorted[j]->size;
			xfrrate = (sorted[j]->size_h[0] - sorted[j]->size_h[1]);
			xfrrate = xfrrate*8 / ((long double)delay / 1000000ULL);
			sprintf_nice(str3, xfrrate);
		}
		if (ui_type == 's')
			sl_print_row(str3, valp / 100, valp % 100, str1,
				     vals / 100, vals % 100, str2,
				     sorted[j]->size / sorted[j]->count,
				      strtype, 2, last);
		if (ui_type == 't')
			t_print_row(str3, valp / 100, valp % 100, str1,
				    vals / 100, vals % 100, str2,
				    sorted[j]->size / sorted[j]->count,
				    strtype, 2, last);

		if (sorted[j]->type == 6)
			servprint(last, &tcp, TCP);
		if (sorted[j]->type == 17)
			servprint(last, &udp, UDP);
	}
}

void
servprint(int last[], struct node *tree, int type)
{
	struct node *sorted[24] = {0};
	struct ent *e;
	struct ent *service;
	unsigned long long vals, valp, sums, sump;
	unsigned long long xfrrate = 0;
	int j;
	char str1[7], str2[7], str3[7], *strtype, strtype2[14];

	e = (type == TCP) ? tcpent : udpent;

	sump = countsump(&ether);
	sums = countsums(&ether);

	largestn(tree, sorted, 24, sort_type);

	last[2] = 0;
	for (j = 0; !last[2] && sorted[j]; j++) {
		if (sorted[j]->type == -1)
			continue;

		if (j + 1 >= 24 || !sorted[j + 2] ||
		    (ui_type == 's' && y + 1 > maxy - 1))
			last[2] = 1;

		if ((service = getentbynum(e, sorted[j]->type))) {
			strtype = service->e_name;
		} else {
			sprintf(strtype2, "%d", sorted[j]->type);
			strtype = strtype2;
		}

		valp = (sorted[j]->count * 10000) / sump;
		sprintf_nice(str1, sorted[j]->count);
		vals = (sorted[j]->size * 10000) / sums;
		sprintf_nice(str2, sorted[j]->size);

		if (current_time > start_time) {
			int             x;
			for (x = HISTORY_SIZE - 1; x > 0; x--)
				sorted[j]->size_h[x] = sorted[j]->size_h[x - 1];
			sorted[j]->size_h[0] = sorted[j]->size;
			xfrrate = (sorted[j]->size_h[0] - sorted[j]->size_h[1]);
			xfrrate = xfrrate*8 / ((long double)delay / 1000000ULL);
			sprintf_nice(str3, xfrrate);
		}
		if (ui_type == 's')
			sl_print_row(str3, valp / 100, valp % 100, str1,
				     vals / 100, vals % 100, str2,
				     sorted[j]->size / sorted[j]->count,
				     strtype, 3, last);
		if (ui_type == 't')
			t_print_row(str3, valp / 100, valp % 100, str1,
				    vals / 100, vals % 100, str2,
				    sorted[j]->size / sorted[j]->count,
				    strtype, 3, last);
	}
}

void
dieing()
{
	if (ui_type == 's') {
		SLsmg_reset_smg();
		SLang_reset_tty();
	}
	pcap_close(pd);
	exit(0);
}

void
ui_run()
{
	int i;

	current_time = start_time = time(0);

	if (ui_type == 's') {
		sl_init();
		screen_update();
	}
	for (i = 0; !runcount || i < runcount; i++) {
		if (ui_type == 's')
			sl_check_kb();

		usleep(delay);
		current_time = time(0);
		screen_update();
	}

	dieing();
}


void
change_screen_size()
{
	SLtt_get_screen_size();
	SLang_init_tty(-1, 0, 0);
	SLsmg_reset_smg();
	SLsmg_init_smg();

	SLsmg_cls();
	screen_update();

	signal(SIGWINCH, change_screen_size);
}

pcap_t *
pcap_start(char *filterstr)
{
	struct bpf_program fcode;
	pcap_t *pd;
	int datalink, snaplen = 200;
	unsigned int localnet, netmask;
	char *device;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (input_file != 0) {
		if ((pd = pcap_open_offline(input_file, errbuf)) == NULL) {
			fprintf(stderr, "Can not open file: %s\n", errbuf);
			exit(1);
		}
	} else {
		if (dev == 0) {
			if ((device = pcap_lookupdev(errbuf)) == NULL) {
				fprintf(stderr, "Can not open device: %s\n",
				        errbuf);
				exit(1);
			}
		} else
			device = dev;

		pd = pcap_open_live(device, snaplen, 1, 500, errbuf);
		if (pd == NULL) {
			fprintf(stderr, "Can not open device: %s\n", errbuf);
			if (getuid() != 0) {
				fprintf(stderr, "You may not have permissions to open this device\n");
			}
			exit(1);
		}
		if (pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0) {
			fprintf(stderr, "pcap_open_live: %s\n", errbuf);
			exit(1);
		}
	}

	if (pcap_compile(pd, &fcode, filterstr, 1, netmask) < 0) {
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(pd));
		exit(1);
	}
	if (pcap_setfilter(pd, &fcode) < 0) {
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(pd));
		exit(1);
	}
	if ((datalink = pcap_datalink(pd)) < 0) {
		fprintf(stderr, "pcap_datalink: %s\n", pcap_geterr(pd));
		exit(1);
	}
	return pd;
}

void
sprintf_nice(char *str, unsigned long long data)
{
	if (data / 1000 == 0)
		sprintf(str, "%6.1f ", (double) data);
	else if (data / 1024 < 1024)
		sprintf(str, "%6.1fk", (double) data / 1024.0);
	else if (data / 1048576 < 1024)
		sprintf(str, "%6.1fm", (double) data / 1048576.0);
	else if (data / 1073741824 < 1024)
		sprintf(str, "%6.1fg", (double) data / 1073741824.0);
	else
		sprintf(str, "%6.1ft", (double) data / 1099511627776.0);
}

void
change_delay()
{
	unsigned int i;
	int x;
	char str[10];

	SLsmg_set_color(0);
	SLsmg_gotorc(0, 0);
	SLsmg_printf("Please enter a new delay time in seconds:");
	for (x = 41; x < SLtt_Screen_Cols; x++)
		SLsmg_printf(" ");
	SLsmg_refresh();
	i = 0;
	while (i < 10 && SLang_input_pending(25)) {
		x = SLang_getkey();
		switch (x) {
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
		case '.':
			str[i++] = x;
			SLsmg_gotorc(0, 41 + i);
			SLsmg_write_char(x);
			SLsmg_refresh();
			break;
		case 127:	/* backspace */
			SLsmg_gotorc(0, 41 + i);
			SLsmg_write_char(' ');
			SLsmg_refresh();
			str[--i] = 0;
			break;
		case '\r':
			str[i] = 0;
			delay = (1000000 * atof(str));
			return;
		}
	}
}


void
change_sort_type()
{
	unsigned int i;
	int x;

	SLsmg_set_color(0);
	SLsmg_gotorc(0, 0);
	SLsmg_printf("Change sorting to [p]ackets or [s]ize:");
	for (x = 41; x < SLtt_Screen_Cols; x++)
		SLsmg_printf(" ");
	SLsmg_refresh();
	i = 0;
	while (i < 10 && SLang_input_pending(25)) {
		x = SLang_getkey();
		switch (x) {
		case 'p':
			sort_type = 'p';
			return;
		case 's':
			sort_type = 's';
			return;
		}
	}
}

void
show_help()
{
	int y = 0;

	SLsmg_cls();
	SLsmg_gotorc(y++, 0);

	SLsmg_set_color(header_c);

	SLsmg_printf("Nettop: %s", VERSION);
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("Written by Scott Parish, copyright 2001, BSD");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("Compiled at %s, %s", __TIME__, __DATE__);
	y += 2;
	SLsmg_gotorc(y++, 0);

	SLsmg_printf("  Key     Effect");
	SLsmg_set_color(0);
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("   c      clear the data, and start all counting over");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("   l      toggle drawing tree lines");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("   o      change the order of sort (by [p]ackets or [s]ize)");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("   s      change update delay time (default 1 sec)");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("q or x    exit nettop");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("? or h    this screen");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf("<space>   pause display from updating (but keep sniffing)");
	SLsmg_gotorc(y++, 0);

	SLsmg_gotorc(y++, 0);
	SLsmg_printf(" %%pkts    what fraction of total packets are from this type");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf(" total    total number of packets from this type");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf(" %%size    what fraction by size of all packets are type");
	SLsmg_gotorc(y++, 0);
	SLsmg_printf(" sz/pkt   What is the average size of each packet");
	SLsmg_gotorc(y++, 0);

	SLsmg_gotorc(SLtt_Screen_Rows - 2, 0);
	SLsmg_printf("Press any key to return to program");
	SLsmg_refresh();

	SLang_getkey();
	SLsmg_cls();
}

void
pause_display()
{
	int x, center;

	SLsmg_gotorc(0, 0);
	SLsmg_set_color(header_c);
	center = SLtt_Screen_Cols / 2 - 8;
	for (x = 0; x < center; x++)
		SLsmg_printf(" ");
	SLsmg_printf("--== paused ==--");
	for (; x < SLtt_Screen_Cols; x++)
		SLsmg_printf(" ");
	SLsmg_refresh();
	SLang_getkey();
}

void
clear_count()
{
	pthread_mutex_lock(&mutex);
	ndelete(&ether);
	ndelete(&ip);
	ndelete(&tcp);
	ndelete(&udp);
	pthread_mutex_unlock(&mutex);
	current_time = start_time = time(0);
	SLsmg_cls();
}

/*
 * Slang output
 */

void
sl_init()
{
	SLtt_get_terminfo();
	SLang_init_tty(-1, 0, 0);
	SLsmg_init_smg();

	SLtt_set_color(0, "normal", "lightgray", "default");
	SLtt_set_color(total_c, "total", "yellow", "default");
	SLtt_set_color(ethernet_c, "level1", "brightcyan", "default");
	SLtt_set_color(ip_c, "level2", "brightgreen", "default");
	SLtt_set_color(tcp_c, "level3", "brightmagenta", "default");
	SLtt_set_color(udp_c, "level3", "brightmagenta", "default");
	SLtt_set_color(bar_c, "bar", "blue", "lightgray");
	SLtt_set_color(header_c, "total", "white", "default");
	SLtt_set_color(50, "total", "gray", "default");
	SLtt_set_color(51, "total", "lightgray", "default");
	SLtt_set_color(52, "total", "white", "default");
	signal(SIGWINCH, change_screen_size);
}

void
sl_check_kb()
{
	while (SLang_input_pending(0)) {
		switch (SLang_getkey()) {
			case 's':change_delay();
			break;
		case 'c':
			clear_count();
			break;
		case 'x':
		case 'q':
			dieing();
			break;
		case '?':
		case 'h':
			show_help();
			break;
		case 'l':
			print_lines = !print_lines;
			break;
		case 'o':
			change_sort_type();
			break;
		case ' ':
			pause_display();
			break;
		case '':
			SLsmg_cls();
			break;
		}
	}
}

/* header is printed at the top of every update */
void
sl_header()
{
	time_t t;
	int x = 0, a, b, c, i;
	int time_diff;

	SLsmg_gotorc(0, 0);

	x = 0;
	y = 1;

	/* print clock */
	SLsmg_set_color(header_c);
	t = time(0);
	SLsmg_printf("%s", ctime(&t));
	x = 24;

	/* print counter */
	for (; x < SLtt_Screen_Cols - 10; x++)
		SLsmg_printf(" ");
	time_diff = current_time - start_time;
	a = time_diff / 3600;
	b = time_diff % 3600 / 60;
	c = (time_diff % 3600) % 60;
	SLsmg_set_color(header_c);
	SLsmg_printf("%4d:%2.2d:%2.2d", a, b, c);
	x = 0;

	SLsmg_gotorc(y++, x);

	x = 11;
	maxy = SLtt_Screen_Rows;
	maxx = SLtt_Screen_Cols;

	/* print bar */
	SLsmg_set_color(bar_c);
	SLsmg_printf("  %%pkts  total    %%size   total   sz/pkt    bit/s");
	for (i = x; i < maxx - 43; i++)
		SLsmg_printf(" ");
	SLsmg_printf("type");
	for (i = (x += 4); i < maxx; i++)
		SLsmg_printf(" ");
	SLsmg_gotorc(y++, 0);
}

void
sl_print_row(char *str3, int pkt, int pktf, char *str1, int tot, int totf,
	     char *str2, int szpkt, char *type, int level, int last[])
{
	int             i;
	SLsmg_set_color(level + 1);
	SLsmg_printf("%3d.%2.2d%% %5s", pkt, pktf, str1);
	SLsmg_printf("  %3d.%2.2d%% %5s", tot, totf, str2);
	SLsmg_printf("  %6d", szpkt);
	SLsmg_printf("  %5s", str3);
	SLsmg_gotorc(y - 1, maxx - 20);

	if (print_lines) {
		SLsmg_set_color(51);
		for (i = 0; i < level - 1; i++) {
			if (last[i])
				SLsmg_printf("  ");
			else
				SLsmg_printf("| ");
		}
		if (level) {
			if (last[level - 1])
				SLsmg_printf("`-");
			else
				SLsmg_printf("|-");
		}
	}
	SLsmg_set_color(level + 1);
	SLsmg_printf("%-13s", type);
	SLsmg_gotorc(y++, 0);
}



/*
 * text interface
 */
void
t_header()
{
	printf("\n  %%pkts  total    %%size   total   sz/pkt  type\n");
	printf("-------------------------------------------------\n");
}

void
t_print_row(char *str3, int pkt, int pktf, char *str1, int tot, int totf,
	    char *str2, int szpkt, char *type, int level, int last[])
{
	int i;

	printf("%3d.%2.2d%% %5s  %3d.%2.2d%% %5s  %5s  %6d  ",
	       pkt, pktf, str1, tot, totf, str2, str3, szpkt);

	if (print_lines) {
		for (i = 0; i < level - 1; i++) {
			if (last[i])
				printf("  ");
			else
				printf("| ");
		}
		if (level) {
			if (last[level - 1])
				printf("`-");
			else
				printf("|-");
		}
	}
	printf("%-13s\n", type);
}



/*
 * usage - print the command line args options
 */
void
usage()
{
	fprintf(stderr, "Usage: nettop [-s|-p] [-l] [-t [-h]] [-i dev] [-d delay] [-n num] [-f filter] [-?]\n");
}

void
help()
{
	usage();
	fprintf(stderr,
		"-s                               Sort by size\n"
		"-p                               Sort by number of packets\n"
		"-l                               Hide tree lines\n"
		"-t                               Output plain text\n"
		"-h                               Show header\n"
		"-i device                        Select interface\n"
		"-r file                          Read input from a file\n"
		"-d delay                         Delay in seconds between updates\n"
		"-n number                        Number of updates to run before stopping\n"
		"-f filter                        Specify filter rules\n"
		"-?                               This screen\n"
		);
}
