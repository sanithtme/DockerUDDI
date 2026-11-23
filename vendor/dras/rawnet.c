#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>


#define         UDP_HDR_LEN  8
#define         IP_HDR_LEN  20
#define         HSIZE (UDP_HDR_LEN + IP_HDR_LEN)
#define         ETH_HDR_LEN 14
#define         ip_cksum_carry(x) \
            (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

static int		     tx_sock,rx_sock;
static u_char	     packbuf[1500];
struct sockaddr_in	 sa;
static struct ip	 *ip = (struct ip *) packbuf;
static struct udphdr *udp = (struct udphdr *) ( packbuf + IP_HDR_LEN);
static u_char		 *payload = packbuf + IP_HDR_LEN + UDP_HDR_LEN;
static u_short		 src_port;
static u_short		 dst_port;


int init_rawnet( char *, uint32_t, uint32_t);
int send_raw( u_char *, size_t, uint32_t, uint32_t );
int recv_raw( u_char *, size_t);
inline int ip_cksum_add(const void *, size_t, int);
int getmac(char *, uint8_t  *);
int add_filter(int,  uint8_t *, uint16_t);

int init_rawnet( char *ifname, uint32_t sport, uint32_t dport)
{
    uint8_t		mac[6];
    int           	sockbufsiz=4*1024*1024;
    int                 ifindex;
    struct sockaddr_ll  ll;

    src_port = htons(sport);
    dst_port = htons(dport);

    memset(ip, 0, sizeof(struct ip));
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    if (getmac(ifname, mac) < 0 ){
	fprintf(stderr, "Could not find MAC for %s\n", ifname);
	return(-1);
    }
    if ((tx_sock=socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        printf("Tx socket open failed\n");
        return(-1);
    }
    if (setsockopt(tx_sock, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0){
         printf("setsockopt %d HDRINCL failed\n", tx_sock);
        return(-1);
    }
    if (setsockopt(tx_sock, SOL_SOCKET, SO_SNDBUF, &sockbufsiz, sizeof(sockbufsiz)) < 0){
         printf("setsockopt %d SO_SNDBUF failed\n", tx_sock);
    }

    if ((rx_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
        printf("Rx socket open failed\n");
        return(-1);
    }

    if (setsockopt(rx_sock, SOL_SOCKET, SO_RCVBUF, &sockbufsiz, sizeof(sockbufsiz)) < 0){
         printf("setsockopt %d SO_RCVBUF failed\n", rx_sock);
    }

    //if (setsockopt(rx_sock, SOL_SOCKET, SO_TIMESTAMPING, &(int){1}, sizeof(int)) < 0){
         //printf("setsockopt %d SO_TIMESTAMPING failed\n", rx_sock);
    //}
    
    ifindex = if_nametoindex(ifname);

    memset(&ll,0,sizeof(ll));
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = ifindex;

    if (bind(rx_sock, (struct sockaddr *)&ll, sizeof(ll)) <0){
        perror("rx bind");
        return(-1);
    }

    //printf("Iface: %s Index: %d\n", ifname, ifindex);
    struct packet_mreq      sock_params;
    memset(&sock_params, 0, sizeof(sock_params));
    sock_params.mr_type = PACKET_MR_PROMISC;
    sock_params.mr_ifindex = ifindex;
    if (setsockopt(rx_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&sock_params,
                                    sizeof(sock_params)) < 0){
        perror("setsockopt add_membership");
        return -1;
    }

    if (add_filter(rx_sock, mac, sport) < 0){
        fprintf(stderr,"Filter attach failed\n");
        return(-1);
    }

    ip->ip_v   = 4;
    ip->ip_hl  = 5;
    ip->ip_ttl = 255;
    ip->ip_tos = 0;
    ip->ip_p = IPPROTO_UDP;
    //printf("rxsock = %d txsock=%d\n", rx_sock, tx_sock);
    return(rx_sock);
}	
int send_raw( u_char *data, size_t len, uint32_t ip_src, uint32_t ip_dest)
{
	int sum=0;

	sa.sin_addr.s_addr = ip_dest;
	ip->ip_src.s_addr =  ip_src;
	ip->ip_dst.s_addr =  ip_dest;
	ip->ip_sum = 0;
	ip->ip_id += 3;
	ip->ip_len = htons(len + HSIZE);
	udp->source = src_port;
	udp->dest =   dst_port;
	udp->len = htons(UDP_HDR_LEN + len);
	udp->check = 0;
	memcpy(payload, data, len);
	sum = ip_cksum_add(ip, IP_HDR_LEN, 0);
        ip->ip_sum = ip_cksum_carry(sum);

	if ((len=sendto(tx_sock, packbuf, len + HSIZE,0,
		(struct sockaddr *)&sa, sizeof(sa))) <= 0){
		perror("sendto");
		return(-1);
	}
	return(len);
}
/* User responsible for providing a large enough buffer */
int recv_raw( u_char *buf, size_t bufsiz)
{
    uint8_t headers[HSIZE+ETH_HDR_LEN]; // Basically a throwaway
    struct msghdr   msg;
    struct iovec    iov[2];
    int             len;
    //struct timeval  ts;
    //memset(&ts,0,sizeof(ts));
    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    //msg.msg_name=&ts;
    //msg.msg_namelen = sizeof(ts);

    iov[0].iov_base = headers;
    iov[0].iov_len = sizeof(headers);

    iov[1].iov_base = buf;
    iov[1].iov_len = bufsiz;

    msg.msg_iov = iov;
    msg.msg_iovlen = 2;


    if ((len=recvmsg(rx_sock, &msg, 0)) < 0){
        perror("rev_raw: recvmsg");
    }
    else {
        len -= sizeof(headers);
    }
    //printf("timestamp: %lu : %lu x\n", ts.tv_sec, ts.tv_usec);
    return(len);
}
int ip_cksum_add(const void *buf, size_t len, int cksum)
{               
        uint16_t *sp = (uint16_t *)buf;
        int n, sn;
        
        sn = len / 2; 
        n = (sn + 15) / 16;
        
        switch (sn % 16) {
        case 0: do {
                cksum += *sp++;
        case 15:
                cksum += *sp++;
        case 14:
                cksum += *sp++;
        case 13:
                cksum += *sp++;
        case 12:
                cksum += *sp++;
        case 11:
                cksum += *sp++;
        case 10:
                cksum += *sp++;
        case 9:
                cksum += *sp++;
        case 8:
                cksum += *sp++;
        case 7:
                cksum += *sp++;
        case 6:
                cksum += *sp++;
        case 5:
                cksum += *sp++;
        case 4:
                cksum += *sp++;
        case 3:
                cksum += *sp++;
        case 2:
                cksum += *sp++;
        case 1:
                cksum += *sp++;
                } while (--n > 0);
        }
        if (len & 1)
                cksum += htons(*(u_char *)sp << 8);

        return (cksum);
}
int getmac(char *ifname, uint8_t  *buf)
{
	struct ifreq ifr;
	int sock;

	if ( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ){
		perror("socket");
		return(-1);
	}

 	ifr.ifr_addr.sa_family = AF_INET;
	memcpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

 	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
		perror("ioctl");
		return(-1);
	}
 	close(sock);
	memcpy(buf, ifr.ifr_hwaddr.sa_data,6);	
	return(0);
}

int add_filter(int socket,  uint8_t *mac, uint16_t src_port)
{

    //printf("addfilter: MAC %02x:%02x:%02x:%02x:%02x:%02x Port: %u\n",
		//mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],src_port);
    static struct sock_filter reply_filter[]= {
        //udp and src port 0x2233  and  ether dst aa:bb:cc:dd:ee:ff
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 4, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 0, 15, 0x00000011 },
        { 0x28, 0, 0, 0x00000036 },
        { 0x15, 8, 13, 0x00002233 },
        { 0x15, 0, 12, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 10, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 8, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 0, 5, 0x00002233 },
        { 0x20, 0, 0, 0x00000002 },
        { 0x15, 0, 3, 0xccddeeff },
        { 0x28, 0, 0, 0x00000000 },
        { 0x15, 0, 1, 0x0000aabb },
        { 0x6, 0, 0, 0x000005b2 },
        { 0x6, 0, 0, 0x00000000 },
    };

    struct sock_fprog f = { sizeof(reply_filter)/sizeof(reply_filter[0]), reply_filter };
    reply_filter[5].k = src_port;
    reply_filter[13].k = src_port;
    reply_filter[15].k = htonl(*((uint32_t *)(mac + 2)));
    reply_filter[17].k = htons(*((uint16_t *)(mac)));
    if (setsockopt(socket, SOL_SOCKET, SO_ATTACH_FILTER, &f, sizeof(f)) < 0) {
        perror("Add filter");
        return(-1);
    }


    return(0);
}
	
