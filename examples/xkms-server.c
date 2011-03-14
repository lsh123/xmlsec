/**
 * XML Security Library example: simple XKMS server
 *
 * Starts XKMS server on specified port.
 * 
 * Usage:
 *      ./xkms-server [--port <port>] [--format plain|soap-1.1|soap-1.2] <keys-file>
 *
 * Example:
 *      ./xkms-server --port 8080 --format soap-1.1 keys.xml
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#ifdef XMLSEC_NO_XKMS

int main(int argc, char** argv) {
        fprintf(stderr, "ERROR: XKMS is disabled.\n");
        return 1;
}

#else /* XMLSEC_NO_XKMS */

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xkms.h>
#include <xmlsec/crypto.h>

#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
#include <xmlsec/app.h>
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

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

#define DEFAULT_PORT                    1234
#define PENDING_QUEUE_SIZE              100

#define LOG_LEVEL_SILENT                0
#define LOG_LEVEL_INFO                  1
#define LOG_LEVEL_DATA                  2
#define LOG_LEVEL_DEBUG                 3

#ifdef UNIX_SOCKETS
static int  sockfd    = -1; 
#endif /* UNIX_SOCKETS */

#ifdef WIN32_SOCKETS
static SOCKET sockfd  = -1; 
#endif /* WIN32_SOCKETS */ 

static int  finished  = 0;
static int  log_level = LOG_LEVEL_INFO;

static int  init_server(unsigned short port);
static void stop_server();
static void int_signal_handler(int sig_num);
static const xmlChar* my_strnstr(const xmlChar* str, xmlSecSize strLen, const xmlChar* tmpl, xmlSecSize tmplLen);

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
    unsigned short port = DEFAULT_PORT;
#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */
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

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs(); 
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs); 
#endif /* XMLSEC_NO_XSLT */
                
    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error %d: xmlsec initialization failed.\n", errno);
        return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error %d: loaded xmlsec library version is not compatible.\n", errno);
        return(-1);
    }

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
        fprintf(stderr, "Error %d: unable to load default xmlsec-crypto library. Make sure\n"
                        "that you have it installed and check shared libraries path\n"
                        "(LD_LIBRARY_PATH) envornment variable.\n", errno);
        return(-1);     
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error %d: crypto initialization failed.\n", errno);
        return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error %d: xmlsec-crypto initialization failed.\n", errno);
        return(-1);
    }
    
    /* Create and initialize keys manager */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
        fprintf(stderr, "Error %d: failed to create keys manager.\n", errno);
        goto done;
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        fprintf(stderr, "Error %d: failed to initialize keys manager.\n", errno);
        goto done;
    }    

    /* Create XKMS server context */
    xkmsCtx = xmlSecXkmsServerCtxCreate(mngr);
    if(xkmsCtx == NULL) {
        fprintf(stderr, "Error %d: XKMS server context initialization failed\n", errno);
        goto done;
    }

    /* Process input parameters */
    for(argpos = 1; (argpos < argc) && (argv[argpos][0] == '-'); argpos++) {
        if((strcmp(argv[argpos], "--port") == 0) || (strcmp(argv[argpos], "-p") == 0)) {
            argpos++;
            port = atoi(argv[argpos]);
            if(port == 0) {
                fprintf(stderr, "Error %d: invalid port number \"%s\".\nUsage: %s %s\n", errno, argv[argpos], argv[0], usage);
                goto done;
            }
        } else if((strcmp(argv[argpos], "--format") == 0) || (strcmp(argv[argpos], "-f") == 0)) {
            argpos++;
            format = xmlSecXkmsServerFormatFromString(BAD_CAST argv[argpos]);
            if(format == xmlSecXkmsServerFormatUnknown) {
                fprintf(stderr, "Error %d: invalid format \"%s\".\nUsage: %s %s\n", errno, argv[argpos], argv[0], usage);
                goto done;
            }
        } else if((strcmp(argv[argpos], "--log-level") == 0) || (strcmp(argv[argpos], "-l") == 0)) {
            argpos++;
            log_level = atoi(argv[argpos]);
        } else {
            fprintf(stderr, "Error %d: unknown parameter \"%s\".\nUsage: %s %s\n", errno, argv[argpos], argv[0], usage);
            goto done;
        }
    }
    if(argpos >= argc) {
        fprintf(stderr, "Error %d: keys file is not specified.\nUsage: %s %s\n", errno, argv[0], usage);
        goto done;
    }
    
    /* Load keys */
    for(; argpos < argc; argpos++) {
        if(xmlSecCryptoAppDefaultKeysMngrLoad(mngr, argv[argpos]) < 0) {
            fprintf(stderr, "Error %d: failed to load xml keys file \"%s\".\nUsage: %s %s\n", errno, argv[argpos], argv[0], usage);
            goto done;
        }   
        if(log_level >= LOG_LEVEL_INFO) {
            fprintf(stdout, "Log: loaded keys from \"%s\"\n", argv[argpos]); 
        }
    }
    
    /* Startup TCP server */
    if(init_server(port) < 0) {
        fprintf(stderr, "Error, errno: server initialization failed\n", errno);
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
            fprintf(stderr, "Error %d: unable to accept incomming connection\n");
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
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    fprintf(stdout, "Log: server is down, bye!\n");
    return(0);
}

/**
 * init_server:
 * @port:               the server'xmlSecBufferGetData(buffer) TCP port number.
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
        fprintf(stderr, "Error %d: WSAStartup() failed\n", errno);
        return(-1);
    }
#endif /* WIN32_SOCKETS */

    /* create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef UNIX_SOCKETS
    if(sockfd == -1) {
#endif /* UNIX_SOCKETS */

#ifdef WIN32_SOCKETS
    if(sockfd == INVALID_SOCKET) {
#endif /* WIN32_SOCKETS */

        fprintf(stderr, "Error %d: socket() failed\n", errno);
        return(-1);
    }

    /* enable reuse of address */
    flags = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flags, sizeof(flags)) != 0) {
        fprintf(stderr, "Error %d: setsockopt(SO_REUSEADDR) failed\n", errno);
        return(-1);
    }

#ifdef UNIX_SOCKETS
    /* set non-blocking */
    flags = fcntl(sockfd, F_GETFL);
    if(flags < 0) {
        fprintf(stderr, "Error %d: fcntl(F_GETFL) failed\n", errno);
        return(-1);
    }
    if(fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "Error %d: fcntl(F_SETFL) failed\n", errno);
        return(-1);
    }
#endif /* UNIX_SOCKETS */
    
    /* preset socket structure for socket binding */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family            = AF_INET;
    saddr.sin_port              = htons(port);
    saddr.sin_addr.s_addr       = INADDR_ANY;
    if(bind(sockfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr)) != 0) {
        fprintf(stderr, "Error %d: bind() failed\n", errno);
        return(-1);
    }
    
    /* prepare for listening */
    if(listen(sockfd, PENDING_QUEUE_SIZE) != 0) {
        fprintf(stderr, "Error %d: listen() failed\n", errno);
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
        close(sockfd);
        sockfd = -1;
    }
#endif /* WIN32_SOCKETS */ 
    if(log_level >= LOG_LEVEL_INFO) {
        fprintf(stdout, "Log: server is shutted down\n");
    }
}

/**
 * int_signal_handler:
 * @sig_num:            the signal number.
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
 * @sockfd:             the server's socket.
 * @xkmsCtx:            the template XKMS server context.
 * @format:             the expected format of XKMS requests.
 *
 * Establishs a connection, forks a child process (onUnix), reads the request, 
 * processes it and writes back the response.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
static int
handle_connection(int sockfd, xmlSecXkmsServerCtxPtr xkmsCtx, xmlSecXkmsServerFormat format) {
#ifdef UNIX_SOCKETS
    int fd = -1; 
#endif /* UNIX_SOCKETS */

#ifdef WIN32_SOCKETS
    SOCKET fd = -1; 
#endif /* WIN32_SOCKETS */ 

    int in_child_process = 0;
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
    fd = accept(sockfd, (struct sockaddr *)&saddr, &saddr_size);

#ifdef UNIX_SOCKETS
    if(sockfd == -1) {
#endif /* UNIX_SOCKETS */

#ifdef WIN32_SOCKETS
    if(sockfd == INVALID_SOCKET) {
#endif /* WIN32_SOCKETS */

        fprintf(stderr, "Error %d: accept() failed\n", errno);
        return(-1);
    }
    if(log_level >= LOG_LEVEL_INFO) {
        fprintf(stdout, "Log [%s]: got connection\n", inet_ntoa(saddr.sin_addr));
    }
    
    /* Create a copy of XKMS server context */
    xkmsCtx2 = xmlSecXkmsServerCtxCreate(NULL);
    if(xkmsCtx2 == NULL) {
        fprintf(stderr, "Error %d [%s]: a copy of XKMS server context initialization failed\n", errno, inet_ntoa(saddr.sin_addr));
        goto done;
    }
    if(xmlSecXkmsServerCtxCopyUserPref(xkmsCtx2, xkmsCtx) < 0) {
        fprintf(stderr, "Error %d [%s]: XKMS server context copy failed\n", errno, inet_ntoa(saddr.sin_addr));
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
        fprintf(stderr, "Error %d [%s]: xmlSecBufferCreate() failed\n", errno, inet_ntoa(saddr.sin_addr));
        goto done;      
    }

    /* read input request */
    ret = read_request(fd, inet_ntoa(saddr.sin_addr), buffer);
    if(ret < 0) {
        fprintf(stderr, "Error %d [%s]: read_request() failed\n", errno, inet_ntoa(saddr.sin_addr));
        goto done;      
    }

    /* parse request */
    inDoc = xmlParseMemory(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer) );
    if((inDoc == NULL) || (xmlDocGetRootElement(inDoc) == NULL)) {
        fprintf(stderr, "Error %d [%s]: failed to parse request\n", errno, inet_ntoa(saddr.sin_addr));
        goto done;      
    }
    xmlSecBufferEmpty(buffer);
    
    /* prepare result document */
    outDoc = xmlNewDoc(BAD_CAST "1.0");
    if(outDoc == NULL) {
        fprintf(stderr, "Error %d [%s]: failed to create result doc\n", errno, inet_ntoa(saddr.sin_addr));
        goto done;
    }
    
    result = xmlSecXkmsServerCtxProcess(xkmsCtx2, xmlDocGetRootElement(inDoc), format, outDoc);
    if(result == NULL) {
        fprintf(stderr, "Error %d [%s]: failed to process xkms server request\n", errno, inet_ntoa(saddr.sin_addr));
        goto done;
    }

    /* apppend returned result node to the output document */
    xmlDocSetRootElement(outDoc, result);

    /* create LibXML2 output buffer */    
    output = xmlSecBufferCreateOutputBuffer(buffer);
    if(output == NULL) {
        fprintf(stderr, "Error %d [%s]: xmlSecBufferCreateOutputBuffer() failed\n", errno, inet_ntoa(saddr.sin_addr));
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
        fprintf(stderr, "Error %d [%s]: send_response() failed\n", errno, inet_ntoa(saddr.sin_addr));
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
#ifdef UNIX_SOCKETS
        shutdown(fd, SHUT_RDWR);
        close(fd);
#endif /* UNIX_SCOKETS */

#ifdef WIN32_SOCKETS
        close(fd);
#endif /* WIN32_SCOKETS */

        fd = -1;
    }

    if(in_child_process) {
        exit(0);
    }    
    return(0);
}

/**
 * read_request:
 * @fd:                 the request's socket.
 * @in_ip:              the request's IP address (for logging).
 * @buffer:             the output buffer.
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
    int counter;
    
    assert(fd != -1);
    assert(in_ip != NULL);
    assert(buffer);

    /* first read the http headers */
    counter = 5;
    while(my_strnstr(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer), BAD_CAST "\r\n\r\n", 4) == NULL) {
            nread = recv(fd, buf, sizeof(buf), 0);
            if(nread < 0) {
                fprintf(stderr, "Error %d [%s]: read() failed\n", errno, in_ip);
                return(-1);
            }

            if((nread > 0) && (xmlSecBufferAppend(buffer, buf, nread) < 0)) {
                fprintf(stderr, "Error %d [%s]: xmlSecBufferAppend(%d) failed\n", errno, in_ip, nread);
                return(-1);
            }

        if(nread < sizeof(buffer)) {
            counter--;
            if(counter <= 0) {
                break;
            }
        }
    }    
    
    if(xmlSecBufferGetData(buffer) == NULL) {
        fprintf(stderr, "Error %d [%s]: no bytes read\n", errno, in_ip);
            return(-1);
    }

    if(log_level >= LOG_LEVEL_DEBUG) {
            xmlSecBufferAppend(buffer, BAD_CAST "\0", 1);
        fprintf(stdout, "Debug [%s]: request headers:\n%s\n", in_ip, xmlSecBufferGetData(buffer));
            xmlSecBufferRemoveTail(buffer, 1);
    }
    
    /* Parse the request and extract the body. We expect the request to look
     * like this:
     *    POST <path> HTTP/1.x\r\n
     *    <header1>\r\n
     *    <header2>\r\n
     *    ...
     *    <headerN>\r\n
     *    \r\n
     *    <body>
     */
     
    /* analyze the first line */
    p = my_strnstr(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer), BAD_CAST "\r\n", 2);
    if(p == NULL) {
            fprintf(stderr, "Error %d [%s]: there is no HTTP header\n", errno, in_ip);
            return(-1);
    }
    if(xmlStrncasecmp(xmlSecBufferGetData(buffer), BAD_CAST "POST ", 5) != 0) {
            fprintf(stderr, "Error %d [%s]: not a POST request\n", errno, in_ip);
            return(-1);
    }
    /* "POST " + " HTTP/1.x" == 14 */
    s = xmlSecBufferGetData(buffer);
    if(p - s <= 14) {
            fprintf(stderr, "Error %d [%s]: first line has bad length\n", errno, in_ip);
            return(-1);
    }
    if((xmlStrncasecmp(p - 9, BAD_CAST " HTTP/1.0", 9) != 0) && 
       (xmlStrncasecmp(p - 9, BAD_CAST " HTTP/1.1", 9) != 0)) {
            
        fprintf(stderr, "Error %d [%s]: first line does not end with \" HTTP/1.x\"\n", errno, in_ip);
            return(-1);
    }
    if(xmlSecBufferRemoveHead(buffer, p - xmlSecBufferGetData(buffer) + 2) < 0) {
            fprintf(stderr, "Error %d [%s]: failed to skip first line\n", errno, in_ip);
            return(-1);
    }
    
    /* now skip all the headers (i.e. everything until empty line) */
    found = 0;
    while(!found) {
        p = my_strnstr(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer), BAD_CAST "\r\n", 2);
        if(p == NULL) {
            fprintf(stderr, "Error %d [%s]: there is no HTTP body\n", errno, in_ip);
                return(-1);
            }
        
            if(p == xmlSecBufferGetData(buffer)) {
                found = 1;
            } else if(xmlStrncasecmp(xmlSecBufferGetData(buffer), BAD_CAST "Content-length: ", 16) == 0) {
                length = atoi(xmlSecBufferGetData(buffer) + 16);
            }
        
            if(xmlSecBufferRemoveHead(buffer, p - xmlSecBufferGetData(buffer) + 2) < 0) {
                fprintf(stderr, "Error %d [%s]: failed to skip header line\n", errno, in_ip);
                return(-1);
            }
    }
    
    /* remove the trailing \0 we added */
    xmlSecBufferRemoveTail(buffer, 1);
    
    /* now read the body */
    counter = 5;
    while(xmlSecBufferGetSize(buffer) < length) {
            nread = recv(fd, buf, sizeof(buf), 0);
            if(nread < 0) {
                fprintf(stderr, "Error %d [%s]: read() failed\n", errno, in_ip);
                return(-1);
            }

            if((nread > 0) && (xmlSecBufferAppend(buffer, buf, nread) < 0)) {
                fprintf(stderr, "Error %d [%s]: xmlSecBufferAppend(%d) failed\n", errno, in_ip, nread);
                return(-1);
            }
        if(nread < sizeof(buffer)) {
            counter--;
            if(counter <= 0) {
                break;
            }
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
 * @fd:                 the request's socket.
 * @in_ip:              the request's IP address (for logging).
 * @resp_code:          the HTTP response code.
 * @body:               the response body.
 * @body_len:           the response body length.
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
    sprintf(header, http_header, resp_code, body_size);
    if(send(fd, header, strlen(header), 0) == -1) {
        fprintf(stderr, "Error %d [%s]: send(header) failed\n", errno, in_ip);
        return(-1);
    }

    if(log_level >= LOG_LEVEL_DATA) {
        xmlChar* tmp = xmlStrndup(body, body_size);
        fprintf(stdout, "Log [%s]: response is\n%s\n", in_ip, tmp);
        xmlFree(tmp);
    }

    /* send body */
    if(send(fd, body, body_size, 0) == -1) {
        fprintf(stderr, "Error %d [%s]: send(body) failed\n", errno, in_ip);
        return(-1);
    }
    
    return(0);
}

/**
 * my_strnstr:
 * @str:            the soruce string.
 * @strLen:         the source string length.
 * @tmpl:           the template string.
 * @tmplLen:        the template string length.
 *
 * Searches for the first occurence of @tmpl in @str.
 * 
 * Returns pointer to the first occurence of @tmpl in @str or NULL if it is not found.
 */
static const xmlChar* 
my_strnstr(const xmlChar* str, xmlSecSize strLen, const xmlChar* tmpl, xmlSecSize tmplLen) {
    xmlSecSize pos;

    if((str == NULL) || (tmpl == NULL)) {
        return(NULL);
    }
    for(pos = 0; pos + tmplLen <= strLen; pos++) {
        if(xmlStrncmp(str + pos, tmpl, tmplLen) == 0) {
            return(str + pos);
        }
    }

    return(NULL);
}

#endif /* XMLSEC_NO_XKMS */

