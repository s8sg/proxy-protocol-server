#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "proxy_proto_c/proxy_ptc.h"


/*
 * error - wrapper for perror
 */
void error(char *msg) {
  perror(msg);
  exit(1);
}

struct sockaddr_storage from; /* already filled by accept() */
struct sockaddr_storage to;   /* already filled by getsockname() */


const char *reply_format = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"> "
                           "<html> "
				"<head> "
				   "<title>Proxy Protocol Report</title> "
				"</head> "
				"<body> "
				      "<h1>Proxy Protocol Report</h1> "
				         "<p> protocol version: %s </p> "
					 "<p> address family: %s </p> "
					 "<p>From: %d.%d.%d.%d:%d -> To: %d.%d.%d.%d:%d </p> "
				"</body> "
			   "</html>";

#define REPLY_LENGTH (strlen(reply_format) + 60)

int generate_reply(char *buf, int ppver) {
	int len;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	unsigned char *ip1, *ip2;
	int port1, port2;
	char *ver;
	char *family;

 	if (ppver == PPROXY_V1) { 
		printf("proxy protocol v1\n"); 
		ver = "v1";
	}else {
		printf("proxy protocol v2\n"); 
		ver = "v2";
	}

	sin = (struct sockaddr_in *)&from;
	if(sin->sin_family == AF_INET) {
		printf("\n Family: IPV4\n");
		family = "IPv4";
		ip1 = (unsigned char *)&sin->sin_addr.s_addr;
		port1 = sin->sin_port;
		printf("\nFrom: %d.%d.%d.%d:%d  -> ", ip1[0], ip1[1], ip1[2], ip1[3], port1); 
		sin = (struct sockaddr_in *)&to;
		ip2 = (unsigned char *)&sin->sin_addr.s_addr;
		port2 = sin->sin_port;
		printf("To: %d.%d.%d.%d:%d \n", ip2[0], ip2[1], ip2[2], ip2[3], port2);
	
		len = sprintf(buf, reply_format, ver, family, 
		              ip1[0], ip1[1], ip1[2], ip1[3], port1,
			      ip2[0], ip2[1], ip2[2], ip2[3], port2);
	}
	sin6 = (struct sockaddr_in6 *)&from;
	if(sin6->sin6_family == AF_INET6) {
		printf("\n Family: IPV6\n");
		family = "IPv6";
		printf("From: :%d  -> ", sin6->sin6_port);
		sin6 = (struct sockaddr_in6 *)&to;
		printf("To: :%d \n", sin6->sin6_port);

		len = sprintf(buf, reply_format, ver, family, 
		              0, 0, 0, 0, sin->sin_port,
			      0, 0, 0, 0, sin->sin_port);
	}
	return len;
}

#if 0
/* returns 0 if needs to poll, <0 upon error or >0 if it did the job */
int read_evt(int fd)
{
    union {
        struct {
            char line[108];
        } v1;
        struct {
            uint8_t sig[12];
            uint8_t ver_cmd;
            uint8_t fam;
            uint16_t len;
            union {
                struct {  /* for TCP/UDP over IPv4, len = 12 */
                    uint32_t src_addr;
                    uint32_t dst_addr;
                    uint16_t src_port;
                    uint16_t dst_port;
                } ip4;
                struct {  /* for TCP/UDP over IPv6, len = 36 */
                     uint8_t  src_addr[16];
                     uint8_t  dst_addr[16];
                     uint16_t src_port;
                     uint16_t dst_port;
                } ip6;
                struct {  /* for AF_UNIX sockets, len = 216 */
                     uint8_t src_addr[108];
                     uint8_t dst_addr[108];
                } unx;
            } addr;
        } v2;
    } hdr;

    int size, ret;
    int type = 0;

    do {
        ret = recv(fd, &hdr, sizeof(hdr), MSG_PEEK);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1)
        return (errno == EAGAIN) ? 0 : -1;

    memset(&from, 0, sizeof(struct sockaddr_storage));
    memset(&to, 0, sizeof(struct sockaddr_storage));
    memset(buf, 0, 108);

    if (ret >= 16 && memcmp(&hdr.v2, v2sig, 12) == 0 &&
        (hdr.v2.ver_cmd & 0xF0) == 0x20) {
        printf("V2 signature match\n");
        size = 16 + ntohs(hdr.v2.len);
        printf("size: %d len: %d\n", size, ntohs(hdr.v2.len));
        if (ret < size)
            return -1; /* truncated or too large header */
        type = 2;

        switch (hdr.v2.ver_cmd & 0xF) {
        case 0x01: /* PROXY command */
            switch (hdr.v2.fam) {
            case 0x11:  /* TCPv4 */
                ((struct sockaddr_in *)&from)->sin_family = AF_INET;
                ((struct sockaddr_in *)&from)->sin_addr.s_addr =
                    hdr.v2.addr.ip4.src_addr;
                ((struct sockaddr_in *)&from)->sin_port =
                    hdr.v2.addr.ip4.src_port;
                ((struct sockaddr_in *)&to)->sin_family = AF_INET;
                ((struct sockaddr_in *)&to)->sin_addr.s_addr =
                    hdr.v2.addr.ip4.dst_addr;
                ((struct sockaddr_in *)&to)->sin_port =
                    hdr.v2.addr.ip4.dst_port;
                goto done;
            case 0x21:  /* TCPv6 */
                ((struct sockaddr_in6 *)&from)->sin6_family = AF_INET6;
                memcpy(&((struct sockaddr_in6 *)&from)->sin6_addr,
                    hdr.v2.addr.ip6.src_addr, 16);
                ((struct sockaddr_in6 *)&from)->sin6_port =
                    hdr.v2.addr.ip6.src_port;
                ((struct sockaddr_in6 *)&to)->sin6_family = AF_INET6;
                memcpy(&((struct sockaddr_in6 *)&to)->sin6_addr,
                    hdr.v2.addr.ip6.dst_addr, 16);
                ((struct sockaddr_in6 *)&to)->sin6_port =
                    hdr.v2.addr.ip6.dst_port;
                goto done;
             default:
                printf("Invalid family: %x\n", hdr.v2.fam);
                return -1;
            }
            /* unsupported protocol, keep local connection address */
            break;
        case 0x00: /* LOCAL command */
            /* keep local connection address for LOCAL */
            break;
        default:
            printf("Invalid command: %x -> %x\n", hdr.v2.ver_cmd, hdr.v2.ver_cmd & 0xF);
            return -1; /* not a supported command */
        }
    }
    else if (ret >= 8 && memcmp(hdr.v1.line, "PROXY", 5) == 0) {
        char *end = memchr(hdr.v1.line, '\r', ret - 1);
        if (!end || end[1] != '\n')
            return -1; /* partial or invalid header */
        *end = '\0'; /* terminate the string to ease parsing */
        size = end + 2 - hdr.v1.line; /* skip header + CRLF */
        type = 1;
	strcpy(buf, hdr.v1.line);
    }
    else {
        /* Wrong protocol */
        return -1;
    }

  done:
      /* we need to consume the appropriate amount of data from the socket */
      do {
          ret = recv(fd, &hdr, size, 0);
      } while (ret == -1 && errno == EINTR);
      return (ret >= 0) ? type : -1;
  }
#endif

int main(int argc, char **argv) {
	int parentfd; /* parent socket */
	int childfd; /* child socket */
	int portno; /* port to listen on */
	socklen_t clientlen; /* byte size of client's address */
	struct sockaddr_in serveraddr; /* server's addr */
	struct sockaddr_in clientaddr; /* client addr */
	struct hostent *hostp; /* client host info */
	char replybuf[REPLY_LENGTH]; /* message buffer */
	char *hostaddrp; /* dotted decimal host addr string */
	int optval; /* flag value for setsockopt */
	pp_ret_t ppret; /* proxy protoocl return */
	pproxy_ver_t ppver; /* version of protocol proxy */
	int n;

	/* 
	 * check command line arguments 
	 */
	if (argc != 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}
	portno = atoi(argv[1]);

	/* 
	 * socket: create the parent socket 
	 */
	parentfd = socket(AF_INET, SOCK_STREAM, 0);
	if (parentfd < 0) 
		error("ERROR opening socket");

	/* setsockopt: Handy debugging trick that lets 
	 * us rerun the server immediately after we kill it; 
	 * otherwise we have to wait about 20 secs. 
	 * Eliminates "ERROR on binding: Address already in use" error. 
	 */
	optval = 1;
	setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR, 
		   (const void *)&optval , sizeof(int));

	/*
	 * build the server's Internet address
	 */
	bzero((char *) &serveraddr, sizeof(serveraddr));

	/* this is an Internet address */
	serveraddr.sin_family = AF_INET;

	/* let the system figure out our IP address */
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* this is the port we will listen on */
	serveraddr.sin_port = htons((unsigned short)portno);

	/* 
	 * bind: associate the parent socket with a port 
	 */
	if (bind(parentfd, (struct sockaddr *) &serveraddr, 
		 sizeof(serveraddr)) < 0) 
		error("ERROR on binding");

	/* 
	 * listen: make this socket ready to accept connection requests 
	 */
	if (listen(parentfd, 5) < 0) /* allow 5 requests to queue up */ 
		error("ERROR on listen");

	/* 
	 * main loop: wait for a connection request, echo input line, 
	 * then close connection.
	 */
	clientlen = sizeof(clientaddr);
	while (1) {

		/* 
		 * accept: wait for a connection request 
		 */
		childfd = accept(parentfd, (struct sockaddr *) &clientaddr, &clientlen);
		if (childfd < 0) 
			error("ERROR on accept");

		/* 
		 * gethostbyaddr: determine who sent the message 
		 */
		hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, 
			  sizeof(clientaddr.sin_addr.s_addr), AF_INET);
		if (hostp == NULL)
			error("ERROR on gethostbyaddr");
		hostaddrp = inet_ntoa(clientaddr.sin_addr);
		if (hostaddrp == NULL)
			error("ERROR on inet_ntoa\n");

		printf("server established connection with %s (%s)\n", 
		       hostp->h_name, hostaddrp);


		memset(&from, 0, sizeof(struct sockaddr_storage));
		memset(&to, 0, sizeof(struct sockaddr_storage));

		/* 
		 * read: read input string from the client
		 */
		ppret = proxy_ptc_read(childfd, &ppver, &from, &to);
		if (ppret < 0) {
			printf("Failed to parse proxy protocol: %d\n", ppret);
			close(childfd);
			continue;
		} 

		/* generate output */
		bzero(replybuf, REPLY_LENGTH);
                n = generate_reply(replybuf, ppver);

		/* 
		* write: echo the input string back to the client 
		*/
		n = write(childfd, replybuf, n);
		if (n < 0) 
			error("ERROR writing to socket");

		close(childfd);
	}
}
