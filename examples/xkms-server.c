/**
 * XML Security Library example: simple XKMS server
 *
 * Starts XKMS server on specified port.
 * 
 * Usage:
 * 	./xkms-server [--port <port>] [--format plain|soap-1.1|soap-1.2] <keys-file>
 *
 * Example:
 *	./xkms-server --port 8080 --format soap-1.1 keys.xml
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
#include <xmlsec/app.h>
#include <xmlsec/crypto.h>

#ifdef UNIX_SOCKETS
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/tcp.h> 
#include <netdb.h> 
#include <fcntl.h>
#include <signal.h>
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

#define LOG_LEVEL_SILENT		0
#define LOG_LEVEL_INFO			1
#define LOG_LEVEL_DATA			2
#define LOG_LEVEL_DEBUG			3

static int  sockfd    = -1; 
static int  finished  = 0;
static int  log_level = LOG_LEVEL_INFO;

static int  init_server(unsigned short port);
static void stop_server();
static void int_signal_handler(int sig_num);

static int  handle_connection(int fd, xmlSecXkmsServerCtxPtr xkmsCtx, xmlSecXkmsServerFormat format);
static int  read_request(int fd, const char* in_ip, xmlSecBufferPtr buffer);
static int  send_response(int fd, const char* in_ip, int resp_code, 
			const char* body, int body_size);

static char usage[] = "[--port <port>] [--format plain|soap-1.1|soap-1.2] <keys-file>";
static char http_header[] = 
    "HTTP/1.0 %d\n"
    "Server: XML Security Library: Simple XKMS Server/1.0\n"
    "Content-length: %d\n"
    "\n";
static char http_503[] = 
    "Error 503 - Service Unavailable\n";

int main(int argc, char** argv) {
    int argpos;
    int port = DEFAULT_PORT;
    xmlSecKeysMngrPtr mngr = NULL;
    xmlSecXkmsServerCtxPtr xkmsCtx = NULL;
    xmlSecXkmsServerFormat format = xmlSecXkmsServerFormatPlain;
    int ret;

    fprintf(stdout, "Log: server is starting up\n");
    
    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */
        	
    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
	fprintf(stderr, "Error: xmlsec initialization failed.\n");
	return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
	fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
	return(-1);
    }

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
	fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
			"that you have it installed and check shared libraries path\n"
			"(LD_LIBRARY_PATH) envornment variable.\n");
	return(-1);	
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
	fprintf(stderr, "Error: crypto initialization failed.\n");
	return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
	fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
	return(-1);
    }
    
    /* Create and initialize keys manager */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
	fprintf(stderr, "Error: failed to create keys manager.\n");
	goto done;
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
	fprintf(stderr, "Error: failed to initialize keys manager.\n");
	goto done;
    }    

    /* Create XKMS server context */
    xkmsCtx = xmlSecXkmsServerCtxCreate(mngr);
    if(xkmsCtx == NULL) {
	fprintf(stderr, "Error: XKMS server context initialization failed\n");
	goto done;
    }

    /* Process input parameters */
    for(argpos = 1; (argpos < argc) && (argv[argpos][0] == '-'); argpos++) {
	if((strcmp(argv[argpos], "--port") == 0) || (strcmp(argv[argpos], "-p") == 0)) {
	    argpos++;
	    port = atoi(argv[argpos]);
	    if(port == 0) {
		fprintf(stderr, "Error: invalid port number \"%s\".\nUsage: %s %s\n", argv[argpos], argv[0], usage);
		goto done;
	    }
	} else if((strcmp(argv[argpos], "--format") == 0) || (strcmp(argv[argpos], "-f") == 0)) {
	    argpos++;
	    format = xmlSecXkmsServerFormatFromString(BAD_CAST argv[argpos]);
	    if(format == xmlSecXkmsServerFormatUnknown) {
		fprintf(stderr, "Error: invalid format \"%s\".\nUsage: %s %s\n", argv[argpos], argv[0], usage);
		goto done;
	    }
	} else if((strcmp(argv[argpos], "--log-level") == 0) || (strcmp(argv[argpos], "-l") == 0)) {
	    argpos++;
	    log_level = atoi(argv[argpos]);
	} else {
	    fprintf(stderr, "Error: unknown parameter \"%s\".\nUsage: %s %s\n", argv[argpos], argv[0], usage);
	    goto done;
	}
    }
    if(argpos >= argc) {
	fprintf(stderr, "Error: keys file is not specified.\nUsage: %s %s\n", argv[0], usage);
	goto done;
    }
    
    /* Load keys */
    for(; argpos < argc; argpos++) {
        if(xmlSecCryptoAppDefaultKeysMngrLoad(mngr, argv[argpos]) < 0) {
	    fprintf(stderr, "Error: failed to load xml keys file \"%s\".\nUsage: %s %s\n", argv[argpos], argv[0], usage);
	    goto done;
	}   
	if(log_level >= LOG_LEVEL_INFO) {
	    fprintf(stdout, "Log: loaded keys from \"%s\"\n", argv[argpos]); 
	}
    }
    
    /* Startup TCP server */
    if(init_server(port) < 0) {
	fprintf(stderr, "Error: server initialization failed\n");
	goto done;
    }
    assert(sockfd != -1);
    
    /* main loop: accept connections and process requests */
    while(finished == 0) {
	fd_set fds;
        struct timeval timeout;
	
	/* Set up polling using select() */
	FD_ZERO(&fds);
	FD_SET(sockfd, &fds);
	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_sec = 1;
	ret = select(sockfd + 1, &fds, NULL, NULL, &timeout);
	if((ret <= 0) || !FD_ISSET(sockfd, &fds)) {
	    /* error, timed out or not our socket: try again */
	    continue;
	}

	if(handle_connection(sockfd, xkmsCtx, format) < 0) {
	    fprintf(stderr, "Error: unable to accept incomming connection\n");
	    goto done;
	}
    }
        
done:
    if(log_level >= LOG_LEVEL_INFO) {
	fprintf(stdout, "Log: server is shutting down\n");
    }
    
    /* Shutdown TCP server */
    stop_server();

    /* Destroy xkms server context */
    if(xkmsCtx != NULL) {
	xmlSecXkmsServerCtxDestroy(xkmsCtx);
	xkmsCtx = NULL;
    }
    
    /* Destroy keys manager */
    if(mngr != NULL) {
        xmlSecKeysMngrDestroy(mngr);
	mngr = NULL;
    }
    
    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();
    
    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();
    
    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    fprintf(stdout, "Log: server is down, bye!\n");
    return(0);
}

/**
 * init_server:
 * @port:		the server's TCP port number.
 *
 * Starts up a TCP server listening on given @port.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
static int  
init_server(unsigned short port) {
#ifdef WIN32_SOCKETS
    WSADATA data;         
#endif /* WIN32_SOCKETS */
    struct sockaddr_in saddr;
    int flags;
    
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
    flags = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flags, sizeof(flags)) != 0) {
	fprintf(stderr, "Error: setsockopt(SO_REUSEADDR) failed\n");
	return(-1);
    }

    /* set non-blocking */
    flags = fcntl(sockfd, F_GETFL);
    if(flags < 0) {
	fprintf(stderr, "Error: fcntl(F_GETFL) failed\n");
	return(-1);
    }
    if(fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
	fprintf(stderr, "Error: fcntl(F_SETFL) failed\n");
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

#ifdef UNIX_SOCKETS
    /* setup SIGINT handler that will stop the server */
    signal(SIGINT, int_signal_handler);
#endif /* UNIX_SOCKETS */

    if(log_level >= LOG_LEVEL_INFO) {
        fprintf(stdout, "Log: server is ready and listening on port %d\n", port);
    }
    return(0);
}

/**
 * stop_server:
 * 
 * Shuts down TCP server.
 */
static void 
stop_server() {
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
    if(log_level >= LOG_LEVEL_INFO) {
        fprintf(stdout, "Log: server is shutted down\n");
    }
}

/**
 * int_signal_handler:
 * @sig_num:		the signal number.
 *
 * Unix's Ctrl-C signal handler that stops the server.
 */
static void 
int_signal_handler(int sig_num) {
    if(log_level >= LOG_LEVEL_INFO) {
        fprintf(stdout, "Log: server is asked to shutdown\n");
    }
    finished = 1;    
}

/**
 * handle_connection:
 * @sockfd:		the server's socket.
 * @xkmsCtx:		the template XKMS server context.
 * @format:		the expected format of XKMS requests.
 *
 * Establishs a connection, forks a child process (onUnix), reads the request, 
 * processes it and writes back the response.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
static int
handle_connection(int sockfd, xmlSecXkmsServerCtxPtr xkmsCtx, xmlSecXkmsServerFormat format) {
    int in_child_process = 0;
    int fd = -1;
    struct sockaddr_in saddr;
    int saddr_size;
    xmlSecXkmsServerCtxPtr xkmsCtx2 = NULL;
    xmlSecBufferPtr buffer = NULL;
    xmlDocPtr inDoc = NULL;
    xmlDocPtr outDoc = NULL;
    xmlNodePtr result = NULL;
    xmlOutputBufferPtr output = NULL;
    int resp_ready = 0;
    int ret;
    
    assert(sockfd != -1);
    assert(xkmsCtx != NULL);

    /* Get the socket connection */
    saddr_size = sizeof(struct sockaddr_in);
    if((fd = accept(sockfd, (struct sockaddr *)&saddr, &saddr_size)) == -1) {
	fprintf(stderr, "Error: accept() failed\n");
	return(-1);
    }
    if(log_level >= LOG_LEVEL_INFO) {
        fprintf(stdout, "Log [%s]: got connection\n", inet_ntoa(saddr.sin_addr));
    }
    
    /* Create a copy of XKMS server context */
    xkmsCtx2 = xmlSecXkmsServerCtxCreate(NULL);
    if(xkmsCtx2 == NULL) {
	fprintf(stderr, "Error [%s]: a copy of XKMS server context initialization failed\n", inet_ntoa(saddr.sin_addr));
	goto done;
    }
    if(xmlSecXkmsServerCtxCopyUserPref(xkmsCtx2, xkmsCtx) < 0) {
	fprintf(stderr, "Error [%s]: XKMS server context copy failed\n", inet_ntoa(saddr.sin_addr));
	goto done;
    }

#ifdef UNIX_SOCKETS
    /* on Unix we use child process to process requests */
    if(fork()) {
	/* parent process */
	return(0);
    }
    
    /* child process */
    in_child_process = 1;
    close(sockfd); /* we don't need listening socket */
#endif /* UNIX_SOCKETS */

    buffer = xmlSecBufferCreate(0);
    if(buffer == NULL) {
	fprintf(stderr, "Error [%s]: xmlSecBufferCreate() failed\n", inet_ntoa(saddr.sin_addr));
	goto done;	
    }

    /* read input request */
    ret = read_request(fd, inet_ntoa(saddr.sin_addr), buffer);
    if(ret < 0) {
	fprintf(stderr, "Error [%s]: read_request() failed\n", inet_ntoa(saddr.sin_addr));
	goto done;	
    }

    /* parse request */
    inDoc = xmlParseMemory(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer) );
    if((inDoc == NULL) || (xmlDocGetRootElement(inDoc) == NULL)) {
	fprintf(stderr, "Error [%s]: failed to parse request\n", inet_ntoa(saddr.sin_addr));
	goto done;	
    }
    xmlSecBufferEmpty(buffer);
    
    /* prepare result document */
    outDoc = xmlNewDoc(BAD_CAST "1.0");
    if(outDoc == NULL) {
	fprintf(stderr, "Error [%s]: failed to create result doc\n", inet_ntoa(saddr.sin_addr));
	goto done;
    }
    
    result = xmlSecXkmsServerCtxProcess(xkmsCtx2, xmlDocGetRootElement(inDoc), format, outDoc);
    if(result == NULL) {
	fprintf(stderr, "Error [%s]: failed to process xkms server request\n", inet_ntoa(saddr.sin_addr));
	goto done;
    }

    /* apppend returned result node to the output document */
    xmlDocSetRootElement(outDoc, result);

    /* create LibXML2 output buffer */    
    output = xmlSecBufferCreateOutputBuffer(buffer);
    if(output == NULL) {
	fprintf(stderr, "Error [%s]: xmlSecBufferCreateOutputBuffer() failed\n", inet_ntoa(saddr.sin_addr));
	goto done;
    }
    xmlNodeDumpOutput(output, result->doc, result, 0, 0, NULL);
    
    xmlOutputBufferClose(output); output = NULL;
    resp_ready = 1;
done:
    /* send back response */
    if((resp_ready == 1) && (xmlSecBufferGetData(buffer) != NULL)) {
	ret = send_response(fd, inet_ntoa(saddr.sin_addr), 200, xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer));
	if(log_level >= LOG_LEVEL_INFO) {
	    fprintf(stdout, "Log [%s]: processed request\n", inet_ntoa(saddr.sin_addr));
	}
    } else if(fd >= 0) {
    	ret = send_response(fd, inet_ntoa(saddr.sin_addr), 503, http_503, strlen(http_503));
        if(log_level >= LOG_LEVEL_INFO) {
	    fprintf(stdout, "Log [%s]: failed to process request\n", inet_ntoa(saddr.sin_addr));
	}
    } else {
	ret = -1;
    }
    if(ret < 0) {
	fprintf(stderr, "Error [%s]: send_response() failed\n", inet_ntoa(saddr.sin_addr));
    }
    
    /* cleanup */
    if(output != NULL) {
	xmlOutputBufferClose(output);
	output = NULL;
    }
    
    if(outDoc != NULL) {
	xmlFreeDoc(outDoc);
	outDoc = NULL;
    }
    
    if(inDoc != NULL) {
	xmlFreeDoc(inDoc);
	inDoc = NULL;
    }

    if(buffer != NULL) {
	xmlSecBufferDestroy(buffer);
	buffer = NULL;
    }

    if(xkmsCtx2 != NULL) {
	xmlSecXkmsServerCtxDestroy(xkmsCtx2);
	xkmsCtx2 = NULL;
    }
    
    if(fd >= 0) {
	shutdown(fd, SHUT_RDWR);
	close(fd);
	fd = -1;
    }

    if(in_child_process) {
	exit(0);
    }    
    return(0);
}

/**
 * read_request:
 * @fd:			the request's socket.
 * @in_ip:		the request's IP address (for logging).
 * @buffer:		the output buffer.
 *
 * Reads the request from socket @fd and stores it in the @buffer.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
static int  
read_request(int fd, const char* in_ip, xmlSecBufferPtr buffer) {
    char buf[1024];
    const xmlChar* s;
    const xmlChar* p;
    int nread;
    int length = 0;
    int found = 0;
    
    assert(fd != -1);
    assert(in_ip != NULL);
    assert(buffer);

    /* first read as much data from socket as possible and this should give us all the http headers */
    do {
	nread = read(fd, buf, sizeof(buf));
	if(nread < 0) {
	    fprintf(stderr, "Error [%s]: read() failed\n", in_ip);
	    return(-1);
	} else if(nread == 0) {
	    break;
	}
	assert(nread > 0);

	if(xmlSecBufferAppend(buffer, buf, nread) < 0) {
	    fprintf(stderr, "Error [%s]: xmlSecBufferAppend(%d) failed\n", in_ip, nread);
	    return(-1);
	}
    } while(nread >= sizeof(buf));
    
    /* to simplify the request processing, add \0 at the end */
    xmlSecBufferAppend(buffer, BAD_CAST "\0", 1);
    assert(xmlSecBufferGetData(buffer) != NULL);
    if(log_level >= LOG_LEVEL_DEBUG) {
        fprintf(stdout, "Debug [%s]: request headers:\n%s\n", in_ip, xmlSecBufferGetData(buffer));
    }
    
    /* Parse the request and extract the body. We expect the request to look
     * like this:
     *    POST <path> HTTP/1.x\r\n
     *    <header1>\r\n
     *    <header2>\r\n
     *	  ...
     *    <headerN>\r\n
     * 	  \r\n
     *	  <body>
     */
     
    /* analyze the first line */
    s = xmlSecBufferGetData(buffer);
    p = xmlStrstr(s, "\r\n");
    if(p == NULL) {
	fprintf(stderr, "Error [%s]: there is no HTTP header\n", in_ip);
	return(-1);
    }
    if(xmlStrncasecmp(s, BAD_CAST "POST ", 5) != 0) {
	fprintf(stderr, "Error [%s]: not a POST request\n", in_ip);
	return(-1);
    }
    /* "POST " + " HTTP/1.x" == 14 */
    if(p - s <= 14) {
	fprintf(stderr, "Error [%s]: first line has bad length\n", in_ip);
	return(-1);
    }
    if((xmlStrncasecmp(p - 9, BAD_CAST " HTTP/1.0", 9) != 0) && 
       (xmlStrncasecmp(p - 9, BAD_CAST " HTTP/1.1", 9) != 0)) {
	fprintf(stderr, "Error [%s]: first line does not end with \" HTTP/1.x\"\n", in_ip);
	return(-1);
    }
    if(xmlSecBufferRemoveHead(buffer, p - s + 2) < 0) {
	fprintf(stderr, "Error [%s]: failed to skip first line\n", in_ip);
	return(-1);
    }
    
    /* now skip all the headers (i.e. everything until empty line) */
    found = 0;
    while(!found) {
	s = s;
	p = xmlStrstr(s, "\r\n");
        if(p == NULL) {
    	    fprintf(stderr, "Error [%s]: there is no HTTP body\n", in_ip);
	    return(-1);
	}
	
	if(s == p) {
	    found = 1;
	} else if(xmlStrncasecmp(s, BAD_CAST "Content-length: ", 16) == 0) {
	    length = atoi(s + 16);
	}
	
	if(xmlSecBufferRemoveHead(buffer, p - s + 2) < 0) {
	    fprintf(stderr, "Error [%s]: failed to skip header line\n", in_ip);
	    return(-1);
	}
    }
    
    /* remove the trailing \0 we added */
    xmlSecBufferRemoveTail(buffer, 1);
    
    /* now read the body */
    while(xmlSecBufferGetSize(buffer) < length) {
	nread = read(fd, buf, sizeof(buf));
	if(nread < 0) {
	    fprintf(stderr, "Error [%s]: read() failed\n", in_ip);
	    return(-1);
	} else if(nread == 0) {
	    break;
	}
	assert(nread > 0);

	if(xmlSecBufferAppend(buffer, buf, nread) < 0) {
	    fprintf(stderr, "Error [%s]: xmlSecBufferAppend(%d) failed\n", nread, in_ip, nread);
	    return(-1);
	}
    }
    if(log_level >= LOG_LEVEL_INFO) {
	fprintf(stdout, "Log [%s]: body size is %d bytes\n", in_ip, xmlSecBufferGetSize(buffer));
    }
    if(log_level >= LOG_LEVEL_DATA) {
	xmlSecBufferAppend(buffer, BAD_CAST "\0", 1);
        fprintf(stdout, "Log [%s]: request body:\n%s\n", in_ip, xmlSecBufferGetData(buffer));
	xmlSecBufferRemoveTail(buffer, 1);
    }
    return(0);
}

/**
 * send_response:
 * @fd:			the request's socket.
 * @in_ip:		the request's IP address (for logging).
 * @resp_code:		the HTTP response code.
 * @body:		the response body.
 * @body_len:		the response body length.
 *
 * Writes HTTP response headers and @body to the @socket.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
static int
send_response(int fd, const char* in_ip, int resp_code, const char* body, int body_size) {
    char header[sizeof(http_header) + 100];
    
    assert(fd != -1);
    assert(in_ip != NULL);
    assert(resp_code > 0);
    assert(body != NULL);
    
    /* prepare and send http header */
    snprintf(header, sizeof(header), http_header, resp_code, body_size);
    if(send(fd, header, strlen(header), 0) == -1) {
	fprintf(stderr, "Error [%s]: send(header) failed\n", in_ip);
	return(-1);
    }

    if(log_level >= LOG_LEVEL_DATA) {
	xmlChar* tmp = xmlStrndup(body, body_size);
        fprintf(stdout, "Log [%s]: response is\n%s\n", in_ip, tmp);
	xmlFree(tmp);
    }

    /* send body */
    if(send(fd, body, body_size, 0) == -1) {
	fprintf(stderr, "Error [%s]: send(body) failed\n", in_ip);
	return(-1);
    }
    
    return(0);
}
