/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <libxml/tree.h>
#include <openssl/err.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>

#define XMLSEC_ERRORS_BUFFER_SIZE	1024

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
  { XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE,	"invalid reference" },
  { XMLSEC_ERRORS_R_ASSERTION,			"assertion" },
  { XMLSEC_ERRORS_R_DISABLED,			"disabled" },
  { 0,						NULL}
};

static void xmlSecErrorsDefaultCallback		(const char* file, int line, 
				    		 const char* func,
						 int reason, const char* msg);

static xmlSecErrorsCallback xmlSecErrorsClbk = xmlSecErrorsDefaultCallback;
int  xmlSecPrintErrorMessages = 1;	/* whether the error messages will be printed immidiatelly */

/** 
 * xmlSecErrorsInit:
 *
 * Initializes the errors reporting. It is called from xmlSecInit() function.
 * and applications must not call this function directly.
 */
void 
xmlSecErrorsInit(void) {
    ERR_load_crypto_strings();
    ERR_load_strings(XMLSEC_ERRORS_LIB, xmlSecStrReasons);
}

/** 
 * xmlSecErrorsShutdown:
 *
 * Cleanups the errors reporting. It is called from xmlSecShutdown() function.
 * and applications must not call this function directly.
 */
void 
xmlSecErrorsShutdown(void) {
    ERR_remove_state(0);
    ERR_free_strings();
}

/**
 * xmlSecErrorsSetCallback:
 * @callback: the errors callback function.
 *
 * Sets the errors callback function @callback that will be called 
 * every time an error occurs.
 */
void 
xmlSecErrorsSetCallback(xmlSecErrorsCallback callback) {
    xmlSecErrorsClbk = callback;
}

/**
 * xmlSecError:
 * @file: the error origin filename (__FILE__).
 * @line: the error origin line number (__LINE__).
 * @func: the error origin function (__FUNCTIION__).
 * @reason: the error code.
 * @msg: the error message in printf format.
 * @...: the parameters for the @msg.
 *
 * Reports an error.
 */
void	
xmlSecError(const char* file, int line, const char* func, 
  	    int reason, const char* msg, ...) {
	    
    if(xmlSecErrorsClbk != NULL) {
	char error_msg[XMLSEC_ERRORS_BUFFER_SIZE];
	
	if(msg != NULL) {
	    va_list va;

	    va_start(va, msg);
#if defined(WIN32) && !defined(__CYGWIN__)
  	    _vsnprintf(error_msg, sizeof(error_msg), msg, va);
#else  /* WIN32 */
  	    vsnprintf(error_msg, sizeof(error_msg), msg, va);
#endif /* WIN32 */
	    error_msg[sizeof(error_msg) - 1] = '\0';
	    va_end(va);	
	}
	xmlSecErrorsClbk(file, line, func, reason, 
			(msg != NULL) ? error_msg : NULL);
    }	
}
 
/**
 * xmlSecErrorsDefaultCallback:
 */
static void 
xmlSecErrorsDefaultCallback(const char* file, int line, const char* func,
			    int reason, const char* msg) {

    ERR_put_error(XMLSEC_ERRORS_LIB, XMLSEC_ERRORS_FUNCTION, reason, file, line);

    if(xmlSecPrintErrorMessages) {    
	const char* error_msg = NULL;
	unsigned long error = ERR_PACK(XMLSEC_ERRORS_LIB, XMLSEC_ERRORS_FUNCTION, reason);
	unsigned int i;

	for(i = 0; i < sizeof(xmlSecStrReasons)/sizeof(xmlSecStrReasons[0]); ++i) {
	    if(xmlSecStrReasons[i].error == error) {
		error_msg = xmlSecStrReasons[i].string;
		break;
	    }
	}
	xmlGenericError(xmlGenericErrorContext,
	    "%s (%s:%d): error %d: %s : %s \n",
	    (func != NULL) ? func : "unknown",
	    (file != NULL) ? file : "unknown",
	    line,
	    reason,
	    (error_msg != NULL) ? error_msg : "",
	    (msg != NULL) ? msg : "");
    }
}




