/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/crypto.h>
#include <xmlsec/openssl/errors.h>

static ERR_STRING_DATA xmlSecStrReasons[]= {
  { XMLSEC_ERRORS_R_MALLOC_FAILED,		"failed to allocate memory" },
  { XMLSEC_ERRORS_R_XMLSEC_FAILED,		"xmlsec operation failed" },
  { XMLSEC_ERRORS_R_CRYPTO_FAILED,		"crypto operation failed" },
  { XMLSEC_ERRORS_R_XML_FAILED,			"xml operation failed" },
  { XMLSEC_ERRORS_R_XSLT_FAILED,		"xslt operation failed" },
  { XMLSEC_ERRORS_R_IO_FAILED,			"io operation failed" },
  { XMLSEC_ERRORS_R_INVALID_TRANSFORM,		"invlaid transform" },
  { XMLSEC_ERRORS_R_INVALID_TRANSFORM_DATA,	"invlaid transform data	" },
  { XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY,	"invalid transform or key" },
  { XMLSEC_ERRORS_R_INVALID_KEY,		"key is invalid" },
  { XMLSEC_ERRORS_R_INVALID_KEY_DATA,		"key data is invalid" },
  { XMLSEC_ERRORS_R_INVALID_KEY_SIZE,		"invalid key size" },
  { XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,		"invalid key origin" },
  { XMLSEC_ERRORS_R_KEY_NOT_FOUND,		"key not found" },
  { XMLSEC_ERRORS_R_INVALID_SIZE,		"invalid size" },
  { XMLSEC_ERRORS_R_INVALID_DATA,		"invalid data" },
  { XMLSEC_ERRORS_R_INVALID_TYPE,		"invalid type" },
  { XMLSEC_ERRORS_R_INVALID_USAGE,		"invalid usage" },
  { XMLSEC_ERRORS_R_INVALID_NODE,		"invalid node" },
  { XMLSEC_ERRORS_R_INVALID_NODESET,		"invalid nodes set" },
  { XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,	"invalid node content" },
  { XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,	"invalid node attribute" },
  { XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,	"node already present" },
  { XMLSEC_ERRORS_R_SAME_DOCUMENT_REQUIRED,	"same document required" },
  { XMLSEC_ERRORS_R_NODE_NOT_FOUND,		"node not found" },
  { XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL,	"max retrievals level reached" },
  { XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,		"cert verification failed" },
  { XMLSEC_ERRORS_R_CERT_NOT_FOUND,		"cert not found" },
  { XMLSEC_ERRORS_R_CERT_REVOKED,		"cert revoked" },
  { XMLSEC_ERRORS_R_CERT_ISSUER_FAILED,		"failed to get cert issuer" },
  { XMLSEC_ERRORS_R_CERT_NOT_YET_VALID,		"cert is not valid yet" },
  { XMLSEC_ERRORS_R_CERT_HAS_EXPIRED,		"cert has expired" },
  { XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE,	"invalid reference" },
  { XMLSEC_ERRORS_R_ASSERTION,			"assertion" },
  { XMLSEC_ERRORS_R_DISABLED,			"disabled" },
  { 0,						NULL}
};

static ERR_STRING_DATA xmlSecStrLib[]= {
  { ERR_PACK(XMLSEC_ERRORS_LIB,0,0),		"xmlsec routines"},
  { 0,     					NULL}
};
 
static ERR_STRING_DATA xmlSecStrDefReason[]= {
  { XMLSEC_ERRORS_LIB,				"xmlsec lib"},
  { 0,						NULL}
};

static void xmlSecOpenSSLErrorsDefaultCallback	(const char* file, int line, 
						 const char* func,
						 int reason, const char* msg);	
static int  xmlSecOpenSSLLoadRandFile		(const char *file);
static int  xmlSecOpenSSLSaveRandFile		(const char *file);


/**
 * xmlSecCryptoInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 * This is an internal function called by @xmlSecInit function.
 * The application must call @xmlSecAppCryptoInit before
 * calling @xmlSecInit function or do general crypto engine
 * initialization by itself.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int	
xmlSecCryptoInit(void) {
    ERR_load_crypto_strings();
    ERR_load_strings(XMLSEC_ERRORS_LIB, xmlSecStrLib); /* define xmlsec lib name */
    ERR_load_strings(XMLSEC_ERRORS_LIB, xmlSecStrDefReason); /* define default reason */
    ERR_load_strings(XMLSEC_ERRORS_LIB, xmlSecStrReasons); 

    xmlSecErrorsSetCallback(xmlSecOpenSSLErrorsDefaultCallback);
    return(0);
}

/**
 * xmlSecCryptoShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 * This is an internal function called by @xmlSecShutdown function.
 * The application must call @xmlSecShutdown function
 * before calling @xmlSecAppCryptoInit or doing general 
 * crypto engine shutdown by itself.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecCryptoShutdown(void) {
    ERR_remove_state(0);
    ERR_free_strings();
    return(0);
}

/**
 * xmlSecAppCryptoInit:
 * 
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecAppCryptoInit(void) {
    int ret;
    
    OpenSSL_add_all_algorithms();
    if(RAND_status() != 1) {
        ret = xmlSecOpenSSLLoadRandFile(NULL);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecOpenSSLLoadRandFile - %d", ret);	
	    return(-1);
	}
    }
    return(0);
}

/**
 * xmlSecAppCryptoShutdown:
 * 
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecAppCryptoShutdown(void) {
    xmlSecOpenSSLSaveRandFile(NULL);
    RAND_cleanup();
    EVP_cleanup();    
#ifndef XMLSEC_NO_X509
    X509_TRUST_cleanup();
#endif /* XMLSEC_NO_X509 */    
#ifndef XMLSEC_OPENSSL096
    CRYPTO_cleanup_all_ex_data();
#endif /* XMLSEC_OPENSSL096 */     
    return(0);
}

void 
xmlSecOpenSSLErrorsDefaultCallback(const char* file, int line, const char* func,
			    int reason, const char* msg) {
    const char* error_msg = NULL;
    unsigned long error = ERR_PACK(XMLSEC_ERRORS_LIB, XMLSEC_ERRORS_FUNCTION, reason);
    unsigned int i;

    /* in the OpenSSL case we want to put error in the stack */
    ERR_put_error(XMLSEC_ERRORS_LIB, XMLSEC_ERRORS_FUNCTION, reason, file, line);

    /* search for printable error name */
    for(i = 0; i < sizeof(xmlSecStrReasons)/sizeof(xmlSecStrReasons[0]); ++i) {
        if(xmlSecStrReasons[i].error == error) {
    	    error_msg = xmlSecStrReasons[i].string;
	    break;
	}
    }
    if(error_msg != NULL) {
	char buf[XMLSEC_ERRORS_BUFFER_SIZE];
	
	/* todo: snprintf is not ansi C function */
	snprintf(buf, sizeof(buf), "%s : %s", (msg != NULL) ? msg : "", error_msg);
	buf[sizeof(buf) - 1] = '\0';
	xmlSecErrorsDefaultCallback(file, line, func, reason, buf);	
    } else {
	xmlSecErrorsDefaultCallback(file, line, func, reason, msg);
    }
}

/**
 * Random numbers initialization from openssl (apps/app_rand.c)
 */
static int seeded = 0;
static int egdsocket = 0;
		    
int 
xmlSecOpenSSLLoadRandFile(const char *file) {
    char buffer[1024];
    	
    if(file == NULL) {
	file = RAND_file_name(buffer, sizeof(buffer));
    }else if(RAND_egd(file) > 0) {
	/* we try if the given filename is an EGD socket.
	 * if it is, we don't write anything back to the file. */
	egdsocket = 1;
	return(0);
    }

    if((file == NULL) || !RAND_load_file(file, -1)) {
	if(RAND_status() == 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_load_file");
	    return(-1);
	}
    }
    seeded = 1;
    return(0);
}

int 
xmlSecOpenSSLSaveRandFile(const char *file) {
    char buffer[1024];
	
    if(egdsocket || !seeded) {
	/* If we did not manage to read the seed file,
	 * we should not write a low-entropy seed file back --
	 * it would suppress a crucial warning the next time
	 * we want to use it. */
	return(-1);
    }
    
    if(file == NULL) {
	file = RAND_file_name(buffer, sizeof(buffer));
    }
    if((file == NULL) || !RAND_write_file(file)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    "RAND_write_file");
	return(-1);
    }
    return(0);
}


