#include "FreeRTOS.h"
#include "lwip.h"
#include "lwip/icmp.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/timeouts.h"
#include "lwip/mem.h"
#include "lwip/icmp.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip.h"
#include "ping.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>


struct icmp_ra_addr
{
  uint32_t ira_addr;
  uint32_t ira_preference;
};


struct icmp
{
  uint8_t  icmp_type;	/* type of message, see below */
  uint8_t  icmp_code;	/* type sub code */
  uint16_t icmp_cksum;	/* ones complement checksum of struct */
  union
  {
    uint8_t ih_pptr;		/* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;	/* gateway address */
    struct ih_idseq		/* echo datagram */
    {
      uint16_t icd_id;
      uint16_t icd_seq;
    } ih_idseq;
    uint32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      uint16_t ipm_void;
      uint16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      uint8_t irt_num_addrs;
      uint8_t irt_wpa;
      uint16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      uint32_t its_otime;
      uint32_t its_rtime;
      uint32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip_hdr idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    uint32_t   id_mask;
    uint8_t    id_data[1];
  } icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_radv	icmp_dun.id_radv
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
};

static const int DEFDATALEN = 56;
static const int MAXIPLEN = 60;
static const int MAXICMPLEN = 76;
#define	MAX_DUP_CHK	(8 * 128)
static const int PINGINTERVAL = 1;		/* second */
static const int MAXWAIT = 10;

#define O_QUIET         (1 << 0)

#define	A(bit)		rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	SET(bit)	(A(bit) |= B(bit))
#define	CLR(bit)	(A(bit) &= (~B(bit)))
#define	TST(bit)	(A(bit) & B(bit))

#define PING_ID        0xAFAF

void ping(const char *host);

/* common routines */
static int in_cksum(unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ans) = *(unsigned char *) w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return (ans);
}


/* full(er) version */
static char *hostname = NULL;
static struct sockaddr_in pingaddr;
static int pingsock = -1;
static int datalen; /* intentionally uninitialized to work around gcc bug */

static long ntransmitted = 0, nreceived = 0, nrepeats = 0, pingcount = 0;
static int myid = PING_ID, options = 0;
static unsigned long tmin = 0xFFFF, tmax = 0, tsum = 0;
static char rcvd_tbl[MAX_DUP_CHK / 8];

static void sendping(int);
static void pingstats(int);
static void unpack(char *, int, struct sockaddr_in *);

void perror_msg_and_die(const char *s, ...)
{
}

void perror_msg(const char *s, ...)
{
}

void error_msg(const char *s, ...)
{
}

void error_msg_and_die(const char *s, ...)
{
}
/**************************************************************************/

static void pingstats(int junk)
{
	int status;
	UNUSED(status);
	//signal(SIGINT, SIG_IGN);

	printf("\r\n--- %s ping statistics ---\r\n", hostname);
	printf("%ld packets transmitted, ", ntransmitted);
	printf("%ld packets received, ", nreceived);
	if (nrepeats)
		printf("%ld duplicates, ", nrepeats);
	if (ntransmitted)
		printf("%ld%% packet loss\r\n",
			   (ntransmitted - nreceived) * 100 / ntransmitted);
	if (nreceived)
		printf("round-trip min/avg/max = %lu.%lu/%lu.%lu/%lu.%lu ms\r\n",
			   tmin / 10, tmin % 10,
			   (tsum / (nreceived + nrepeats)) / 10,
			   (tsum / (nreceived + nrepeats)) % 10, tmax / 10, tmax % 10);
	if (nreceived != 0)
		status = EXIT_SUCCESS;
	else
		status = EXIT_FAILURE;
}

#include "task.h"
struct  timezone{
	int tz_minuteswest;
	int tz_dsttime;
};

int gettimeofday(struct  timeval*tv,struct  timezone *tz )
{
		unsigned long long uptime_msec =  xTaskGetTickCount();
		tv->tv_sec = uptime_msec / 1000;
		tv->tv_usec = (uptime_msec%1000)*1000;
		return 0;
}

TimerHandle_t xTimer; 

void sendping_wrapper( TimerHandle_t xTimer )
{
	sendping(0);
}
void pingstats_wrapper( TimerHandle_t xTimer )
{
	pingstats(0);
}
static void sendping(int junk)
{
	struct icmp *pkt;
	int i;
	char packet[datalen + 8];

	pkt = (struct icmp *) packet;

	pkt->icmp_type = ICMP_ECHO;
	pkt->icmp_code = 0;
	pkt->icmp_cksum = 0;
	pkt->icmp_seq = ++ntransmitted;
	pkt->icmp_id = myid;
	CLR(pkt->icmp_seq % MAX_DUP_CHK);

	gettimeofday((struct timeval *) &packet[8], NULL);
	//pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));

	i = sendto(pingsock, packet, sizeof(packet), 0,
			   (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in));

	if (i < 0)
		perror_msg_and_die("sendto");
	else if ((size_t)i != sizeof(packet))
		error_msg_and_die("ping wrote %d chars; %d expected", i,
			   (int)sizeof(packet));

	//signal(SIGALRM, sendping);
	if (pingcount == 0 || ntransmitted < pingcount) {	/* schedule next in 1s */
		//alarm(PINGINTERVAL);
		//sys_timeout(PINGINTERVAL*1000, sendping_wrapper, NULL);
    if( xTimerIsTimerActive( xTimer ) == pdFALSE )
		{
			xTimerStart( xTimer, 0 );
		}
	} else {					/* done, wait for the last ping to come back */
		/* todo, don't necessarily need to wait so long... */
		//signal(SIGALRM, pingstats);
		//alarm(MAXWAIT);
		//sys_timeout(MAXWAIT*1000, pingstats_wrapper, NULL);
		//xTimerStop(xTimer,5000);
		xTimerDelete(xTimer,5000);
		xTimer = NULL;
	}
}

static char *icmp_type_name (int id)
{
	switch (id) {
	case ICMP_ECHOREPLY: 		return "Echo Reply";
	case ICMP_DEST_UNREACH: 	return "Destination Unreachable";
	case ICMP_SOURCE_QUENCH: 	return "Source Quench";
	case ICMP_REDIRECT: 		return "Redirect (change route)";
	case ICMP_ECHO: 			return "Echo Request";
	case ICMP_TIME_EXCEEDED: 	return "Time Exceeded";
	case ICMP_PARAMETERPROB: 	return "Parameter Problem";
	case ICMP_TIMESTAMP: 		return "Timestamp Request";
	case ICMP_TIMESTAMPREPLY: 	return "Timestamp Reply";
	case ICMP_INFO_REQUEST: 	return "Information Request";
	case ICMP_INFO_REPLY: 		return "Information Reply";
	case ICMP_ADDRESS: 			return "Address Mask Request";
	case ICMP_ADDRESSREPLY: 	return "Address Mask Reply";
	default: 					return "unknown ICMP type";
	}
}

static void unpack(char *buf, int sz, struct sockaddr_in *from)
{
	struct icmp *icmppkt;
	struct ip_hdr *iphdr;
	struct timeval tv, *tp;
	int hlen, dupflag;
	unsigned long triptime;

	gettimeofday(&tv, NULL);

	/* check IP header */
	iphdr = (struct ip_hdr *) buf;
	hlen = (iphdr->_v_hl&0x0F) << 2;
	/* discard if too short */
	if (sz < (datalen + ICMP_MINLEN))
		return;

	sz -= hlen;
	icmppkt = (struct icmp *) (buf + hlen);

	if (icmppkt->icmp_id != myid)
	    return;				/* not our ping */

	if (icmppkt->icmp_type == ICMP_ECHOREPLY) {
	    ++nreceived;
		tp = (struct timeval *) icmppkt->icmp_data;

		if ((tv.tv_usec -= tp->tv_usec) < 0) {
			--tv.tv_sec;
			tv.tv_usec += 1000000;
		}
		tv.tv_sec -= tp->tv_sec;

		triptime = tv.tv_sec * 10000 + (tv.tv_usec / 100);
		tsum += triptime;
		if (triptime < tmin)
			tmin = triptime;
		if (triptime > tmax)
			tmax = triptime;

		if (TST(icmppkt->icmp_seq % MAX_DUP_CHK)) {
			++nrepeats;
			--nreceived;
			dupflag = 1;
		} else {
			SET(icmppkt->icmp_seq % MAX_DUP_CHK);
			dupflag = 0;
		}

		if (options & O_QUIET)
			return;

		printf("%d bytes from %s: icmp_seq=%u", sz,
			   inet_ntoa(*(struct in_addr *) &from->sin_addr.s_addr),
			   icmppkt->icmp_seq);
		printf(" ttl=%d", iphdr->_ttl);
		printf(" time=%lu.%lu ms", triptime / 10, triptime % 10);
		if (dupflag)
			printf(" (DUP!)");
		printf("\r\n");
	} else 
		if (icmppkt->icmp_type != ICMP_ECHO)
			error_msg("Warning: Got ICMP %d (%s)",
					icmppkt->icmp_type, icmp_type_name (icmppkt->icmp_type));
}

int create_icmp_socket(void)
{
	struct protoent *proto;
	UNUSED(proto);
	int sock;
	struct timeval timeout = {0};
	timeout.tv_sec = 5;
	/* if getprotobyname failed, just silently force
	 * proto->p_proto to have the correct value for "icmp" */
	if ((sock = socket(AF_INET, SOCK_RAW, IP_PROTO_ICMP)) < 0) {        /* 1 == ICMP */
		if (errno == EPERM)
			error_msg_and_die("permission denied. (are you root?)");
		else
			perror_msg_and_die("can't create socket");
	}

  lwip_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	/* drop root privs if running setuid */
	//setuid(getuid());

	return sock;
}


void ping(const char *host)
{
	struct hostent *h;
	char buf[MAXHOSTNAMELEN];
	char packet[datalen + MAXIPLEN + MAXICMPLEN];
	int sockopt;

	pingsock = create_icmp_socket();

	memset(&pingaddr, 0, sizeof(struct sockaddr_in));

	pingaddr.sin_family = AF_INET;
	h = gethostbyname(host);
	if (h->h_addrtype != AF_INET)
	{
		error_msg_and_die("unknown address type; only AF_INET is currently supported.");
		return ;
	}

	memcpy(&pingaddr.sin_addr, h->h_addr, sizeof(pingaddr.sin_addr));
	strncpy(buf, h->h_name, sizeof(buf) - 1);
	hostname = buf;

	/* enable broadcast pings */
	sockopt = 1;
	setsockopt(pingsock, SOL_SOCKET, SO_BROADCAST, (char *) &sockopt,
			   sizeof(sockopt));

	/* set recv buf for broadcast pings */
	sockopt = 48 * 1024;
	setsockopt(pingsock, SOL_SOCKET, SO_RCVBUF, (char *) &sockopt,
			   sizeof(sockopt));

	printf("PING %s (%s): %d data bytes\r\n",
		   hostname,
		   inet_ntoa(*(struct in_addr *) &pingaddr.sin_addr.s_addr),
		   datalen);

	//signal(SIGINT, pingstats);

	/* start the ping's going ... */
	sendping(0);

	/* listen for replies */
	while (1) {
		struct sockaddr_in from;
		socklen_t fromlen = (socklen_t) sizeof(from);
		int c;

		if ((c = recvfrom(pingsock, packet, sizeof(packet), 0,
						  (struct sockaddr *) &from, &fromlen)) < 0) {
			if (errno == EINTR)
				continue;
			perror_msg("recvfrom");
			if(ntransmitted < pingcount)
				continue;
			else
				break;
		}
		unpack(packet, c, &from);
		if (pingcount > 0 && nreceived >= pingcount)
			break;
	}
	pingstats(0);
}

void ping_main(const char *host)
{
	datalen = DEFDATALEN; /* initialized here rather than in global scope to work around gcc bug */
	pingcount = 4;
	ntransmitted = 0;
	nreceived = 0;
	nrepeats = 0;	
	tmin = 0xFFFF;
	tmax = 0;
	tsum = 0;

	xTimer = xTimerCreate("alarm",2*1000,pdFAIL,( void * ) 0,sendping_wrapper);
	ping(host);
	lwip_close(pingsock);
	if(xTimer != NULL)
		xTimerDelete(xTimer,5000);		
 }
