#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define IPV4_PROTOCOL_TCP 6
#define HTTP_PORT 80

#pragma pack(push, 1)

typedef struct {
	uint8_t  vhl;
	uint8_t  tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	uint8_t  ip_src[4];
	uint8_t  ip_dst[4];
} ipv4_hdr;

typedef struct {
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack;
	uint8_t  off_reserved;
	uint8_t  flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
} tcp_hdr;

#pragma pack(pop)

char *host;
int host_len;

void usage(void) {
	printf("syntax : netfilter-test <host>\n");
	printf("sample : netfilter-test neverssl.com\n");
}

bool host_match(const char *packet_host, int packet_host_len) {
	if (packet_host_len == host_len &&
		strncasecmp(packet_host, host, host_len) == 0)
		return true;

	if (packet_host_len == host_len + 3 &&
		strncasecmp(packet_host, host, host_len) == 0 &&
		strncmp(packet_host + host_len, ":80", 3) == 0)
		return true;

	return false;
}

bool find_and_match_host(unsigned char *http, int http_len) {
	char *host_line = memmem(http, http_len, "Host: ", 6);
	if (host_line == NULL)
		return false;

	char *host_start = host_line + 6;
	int remain = http_len - (host_start - (char *)http);

	char *host_end = memchr(host_start, '\r', remain);
	if (host_end == NULL)
		host_end = memchr(host_start, '\n', remain);
	if (host_end == NULL)
		return false;

	return host_match(host_start, host_end - host_start);
}

bool should_drop(unsigned char *data, int len) {
	if (len < (int)sizeof(ipv4_hdr))
		return false;

	ipv4_hdr *ip = (ipv4_hdr *)data;

	uint8_t ip_version = ip->vhl >> 4;
	uint8_t ip_len = (ip->vhl & 0x0F) * 4;
	uint16_t ip_total_len = ntohs(ip->total_len);
	int cap_len = len < ip_total_len ? len : ip_total_len;

	if (ip_version != 4 || ip_len < 20 ||
		cap_len < ip_len + (int)sizeof(tcp_hdr) ||
		ip->protocol != IPV4_PROTOCOL_TCP)
		return false;

	tcp_hdr *tcp = (tcp_hdr *)(data + ip_len);
	uint8_t tcp_len = ((tcp->off_reserved >> 4) & 0x0F) * 4;

	if (tcp_len < 20 || cap_len < ip_len + tcp_len ||
		ntohs(tcp->dport) != HTTP_PORT)
		return false;

	unsigned char *http = data + ip_len + tcp_len;
	int http_len = cap_len - ip_len - tcp_len;

	if (http_len < 10)
		return false;

	if (!(memcmp(http, "GET ", 4) == 0 ||
		  memcmp(http, "POST ", 5) == 0 ||
		  memcmp(http, "HEAD ", 5) == 0))
		return false;

	return find_and_match_host(http, http_len);
}

static u_int32_t print_pkt(struct nfq_data *tb, int *blocked)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);

	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d\n", ret);

		if (should_drop(data, ret)) {
			printf("[DROP] blocked host: %s\n", host);
			*blocked = 1;
		}
	}

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int blocked = 0;
	u_int32_t id = print_pkt(nfa, &blocked);

	(void)nfmsg;
	(void)data;

	printf("entering callback\n");

	if (blocked)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		usage();
		exit(1);
	}

	host = argv[1];
	host_len = strlen(host);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}

		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
