/*
 * $Id: wdse.c,v 1.2 2005/07/31 21:09:12 roberts Exp $
 *
 * wds (Worst DHCP Server)
 * Very simple program to validate a DHCP client
 *
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dhcp.h"

#define		MAX_OPTS 32;

int mkresponse( uint8_t *buffy, int *len, struct in_addr *);

int main(int argc, char **argv)
{

	int		sock;
	struct		sockaddr_in sa, ca;
	uint32_t	socket_bufsize = 128 * 1024;
	uint8_t		buff[1024];
	int		opt =1;
	int		err;
	ssize_t		len;
	socklen_t	calen = sizeof(ca);
	

	if (argc < 2){
		fprintf(stderr,"\n\nUsage: wds  IP Delay(ms)\n");
		exit(1);
	}
	if ((sock=socket(AF_INET, SOCK_DGRAM, 0)) < 0 ){
		perror("socket:");
		exit(1);
	}
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		(char *) &socket_bufsize, sizeof(socket_bufsize));
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
		(char *) &socket_bufsize, sizeof(socket_bufsize));
	memset(&sa, '\0', sizeof(struct sockaddr_in));
	memset(&ca, '\0', sizeof(struct sockaddr_in));
	ca.sin_port = htons(67);
	ca.sin_family = AF_INET;
	sa.sin_port = htons(67);
	sa.sin_family = AF_INET;
	if ( argv[1] && inet_aton(argv[1], &sa.sin_addr) == 0){
		perror("bind:");
		exit(1);
	}

	if (bind(sock, (struct sockaddr *) &sa, sizeof(sa)) < 0 ){
		perror("bind:");
		return(1);
	}

	for (;;){
		if ( (len=recvfrom(sock, buff, sizeof(buff), 0,
			(struct sockaddr *) &ca, &calen)) < 0 ){
			perror("read:");
			exit(1);
		}
		if ( (len = mkresponse(buff, &len, &sa.sin_addr)) == 0)
			continue;
		if ( len < 0 )
			continue;
		ca.sin_port = htons(67);
		if ( sendto(sock, buff, len, 0, (struct sockaddr *) &ca, calen) < 0 ){
			exit(1);
		}
		

	}
}

int mkresponse( uint8_t *buffy, int *length, struct in_addr *addr)
{
	uint32_t		offset = 4;
	int			nopts=0, dhcp_type=4242;
/*
	struct {
		uint8_t			optid;
		uint8_t			length;
		uint8_t			value[62];	
	} opts[MAX_OPTS];
*/
	struct dhcp_packet	*packet =(struct dhcp_packet *)buffy;
	uint8_t			*options = packet->options;
	uint8_t			*mac = packet->chaddr;	

	/*
		Pull the DHCP packet type, and craft response
		Create really simple response 
	*/
	if ( memcmp(options, DHCP_OPTIONS_COOKIE, 4) != 0){
                fprintf(stderr,"Bad DHCP magic cookie\n");
		*length = -1;
                return(-1);
	}
	while ( offset + DHCP_FIXED_NON_UDP < *length && options[offset] != DHO_END){
                if (options[offset] == DHO_DHCP_MESSAGE_TYPE){
                        dhcp_type = options[offset+2]; 
                        if ( dhcp_type == DHCPDISCOVER )
                                options[offset + 2] = DHCPOFFER;
                        else if ( dhcp_type == DHCPREQUEST )
                                options[offset + 2] = DHCPACK;
                        else 
				return(-1);
			offset+=3;
			options[offset++] = 0xFF;
			options[offset++] = 0;
			break;
			
                }
                else if (options[offset] == DHO_PAD) {
                        offset++;
                        continue;
                }
                offset +=  options[offset+1] + 2;
        }
	*length = DHCP_FIXED_NON_UDP + offset;
	memset(packet->chaddr,'\0',0);
	packet->yiaddr.s_addr = 0xdeadbeef;
	packet->op = BOOTREPLY;
	packet->siaddr.s_addr  = addr->s_addr;
	return(DHCP_FIXED_NON_UDP+offset);
}
