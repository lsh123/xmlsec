/** 
 * XML Security Library example: simple XKMS server
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xkms.h>
#include <xmlsec/crypto.h>

#ifdef UNIX_SOCKETS
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/tcp.h> 
#include <netdb.h> 
#include <fcntl.h>
#else  /* UNIX_SOCKETS */
#ifdef WIN32_SOCKETS
#include <windows.h>
#include <winsock.h> 
#else  /* WIN32_SOCKETS */
#error "Your operating system is not supported"
#endif /* WIN32_SOCKETS */ 
#endif /* UNIX_SOCKETS */

#define DEFAULT_PORT 			1234
#define PENDING_QUEUE_SIZE		100

static int sockfd = - 1; 
static int  InitServer(unsigned short port);
static void ShutdownServer();
static void ProcessRequest(int fd, const char* in_ip);
static int  ReadRequest(int fd, const char* in_ip, xmlSecBufferPtr buffer);
static void SendResponse(int fd, const char* in_ip, int resp_code, 
			const char* body, int body_size);

static char http_header[] = 
    "HTTP/1.0 %d\n"
    "Server: XML Security Library: Simple XKMS Server/1.0\n"
    "Content-length: %d\n"
    "\n";

static char http_503[] = 
    "Error 503 - Service Unavailable\n";

int main(int argc, char* argv) {
    struct sockaddr_in saddr;
    int saddr_size;
    int fd;

    if(InitServer(DEFAULT_PORT) < 0) {
	fprintf(stderr, "Error: server initialization failed\n");
	goto done;
    }
    assert(sockfd != -1);
    
    while(1) {
	saddr_size = sizeof(struct sockaddr_in);
        if((fd = accept(sockfd, (struct sockaddr *)&saddr, &saddr_size)) == -1) {
	    fprintf(stderr, "Error: accept() failed\n");
	    continue;
	}
	fprintf(stdout, "Log: got connection from %s\n", inet_ntoa(saddr.sin_addr));
#ifdef UNIX_SOCKETS
	if(!fork()) {
	    /* child process */
	    close(sockfd); /* we don't need listening socket */
	    ProcessRequest(fd, inet_ntoa(saddr.sin_addr));
	    shutdown(fd, SHUT_RDWR);
	    close(fd);
	    exit(0);
	}
#endif /* UNIX_SOCKETS */

#ifdef WIN32_SOCKETS
	/* todo */
	close(fd);
#endif /* WIN32_SOCKETS */	
    }
    
done:    
    ShutdownServer();
    return(0);
}


static int  
InitServer(unsigned short port) {
#ifdef WIN32_SOCKETS
    WSADATA data;         
#endif /* WIN32_SOCKETS */
    struct sockaddr_in saddr;
    int flag;
    
#ifdef WIN32_SOCKETS
    if(WSAStartup(MAKEWORD(1,1), &data)) {
	fprintf(stderr, "Error: WSAStartup() failed\n");
	return(-1);
    }
#endif /* WIN32_SOCKETS */

    /* create socket */
    if((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	fprintf(stderr, "Error: socket() failed\n");
	return(-1);
    }

    /* enable reuse of address */
    flag = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) != 0) {
	fprintf(stderr, "Error: setsockopt(SO_REUSEADDR) failed\n");
	return(-1);
    }

    /* preset socket structure for socket binding */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family 		= AF_INET;
    saddr.sin_port 		= htons(port);
    saddr.sin_addr.s_addr	= INADDR_ANY;
    if(bind(sockfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr)) != 0) {
	fprintf(stderr, "Error: bind() failed\n");
	return(-1);
    }
    
    /* prepare for listening */
    if(listen(sockfd, PENDING_QUEUE_SIZE) != 0) {
	fprintf(stderr, "Error: listen() failed\n");
	return(-1);	
    }

    fprintf(stdout, "Log: server is ready and listening on port %d\n", port);
    return(0);
}

static void 
ShutdownServer() {
#ifdef UNIX_SOCKETS
    if(sockfd != -1) {
        shutdown(sockfd, SHUT_RDWR);
	close(sockfd);
	sockfd = -1;
    }
#endif /* UNIX_SOCKETS */ 

#ifdef WIN32_SOCKETS
    if(sockfd != -1) {
        shutdown(sockfd, SHUT_RDWR);
	closesocket(sockfd);
	sockfd = -1;
    }
#endif /* WIN32_SOCKETS */ 
    fprintf(stdout, "Log: server is shutted down\n");
}

static void  
ProcessRequest(int fd, const char* in_ip) {
    int resp_ready = 0;
    xmlSecBuffer buffer;
    int ret;
    
    assert(fd != -1);
    assert(in_ip != NULL);
    
    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
	fprintf(stderr, "Error: xmlSecBufferInitialize() failed\n");
	goto done;	
    }

    /* read input request */
    ret = ReadRequest(fd, in_ip, &buffer);
    if(ret < 0) {
	fprintf(stderr, "Error: ReadRequest() failed\n");
	goto done;	
    }

done:
    if((resp_ready == 1) && (xmlSecBufferGetData(&buffer) != NULL)) {
	SendResponse(fd, in_ip, 200, xmlSecBufferGetData(&buffer), xmlSecBufferGetSize(&buffer));
	fprintf(stdout, "Log: processed request from %s\n", in_ip);
    } else {
	SendResponse(fd, in_ip, 503, http_503, strlen(http_503));
	fprintf(stdout, "Log: failed to process request from %s\n", in_ip);
    }
    
    xmlSecBufferFinalize(&buffer);
}

static int  
ReadRequest(int fd, const char* in_ip, xmlSecBufferPtr buffer) {
    char buf[1024];
    int nread;
    int ret;
    
    assert(fd != -1);
    assert(in_ip != NULL);
    assert(buffer);

    do {
	nread = read(fd, buf, sizeof(buf));
	if(nread < 0) {
	    fprintf(stderr, "Error: read() failed\n");
	    return(-1);
	} else if(nread == 0) {
	    break;
	}
	assert(nread > 0);

	ret = xmlSecBufferAppend(buffer, buf, nread);
	if(ret < 0) {
	    fprintf(stderr, "Error: xmlSecBufferAppend() failed\n");
	    return(-1);
	}
    } while(nread >= sizeof(buf));
    fprintf(stdout, "Log: read %d bytes from %s\n", xmlSecBufferGetSize(buffer), in_ip);
    
    return(0);
}

static void 
SendResponse(int fd, const char* in_ip, int resp_code, const char* body, int body_size) {
    char header[sizeof(http_header) + 100];
    
    assert(fd != -1);
    assert(in_ip != NULL);
    assert(resp_code > 0);
    assert(body != NULL);
    
    /* prepare and send http header */
    snprintf(header, sizeof(header), http_header, resp_code, body_size);
    if(send(fd, header, strlen(header), 0) == -1) {
	fprintf(stderr, "Error: send(header) failed\n");
	return;
    }

    /* send body */
    if(send(fd, body, body_size, 0) == -1) {
	fprintf(stderr, "Error: send(body) failed\n");
	return;
    }
}
