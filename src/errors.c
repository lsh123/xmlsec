/** 
 * XMLSec library
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>

#define XMLSEC_ERRORS_BUFFER_SIZE	1024

typedef struct _xmlSecErrorDescription			xmlSecErrorDescription, *xmlSecErrorDescriptionPtr;
struct _xmlSecErrorDescription {
    int 		errorCode;
    const char*		errorMsg;
};

static xmlSecErrorDescription xmlSecErrorsTable[XMLSEC_ERRORS_MAX_NUMBER + 1] = {
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
  { XMLSEC_ERRORS_R_INVALID_STATUS,		"invalid status" },
  { XMLSEC_ERRORS_R_DATA_NOT_MATCH,		"data not match" },
  { XMLSEC_ERRORS_R_ASSERTION,			"assertion" },
  { XMLSEC_ERRORS_R_DISABLED,			"disabled" },
  { 0,						NULL}
};

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
}

/** 
 * xmlSecErrorsShutdown:
 *
 * Cleanups the errors reporting. It is called from xmlSecShutdown() function.
 * and applications must not call this function directly.
 */
void 
xmlSecErrorsShutdown(void) {
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
 * xmlSecErrorsDefaultCallback:
 */
void 
xmlSecErrorsDefaultCallback(const char* file, int line, const char* func,
			    const char* errorObject, const char* errorSubject,
			    int reason, const char* msg) {
    if(xmlSecPrintErrorMessages) {    
	const char* error_msg = NULL;
	size_t i;

	for(i = 0; (i < XMLSEC_ERRORS_MAX_NUMBER) && (xmlSecErrorsGetMsg(i) != NULL); ++i) {
	    if(xmlSecErrorsGetCode(i) == reason) {
		error_msg = xmlSecErrorsGetMsg(i);
		break;
	    }
	}
	xmlGenericError(xmlGenericErrorContext,
	    "func=%s:file=%s:line=%d:obj=%s:subj=%s:error=%d:%s:%s\n",
	    (func != NULL) ? func : "unknown",
	    (file != NULL) ? file : "unknown",
	    line,
	    (errorObject != NULL) ? errorObject : "unknown",
	    (errorSubject != NULL) ? errorSubject : "unknown",
	    reason,
	    (error_msg != NULL) ? error_msg : "",
	    (msg != NULL) ? msg : "");
    }
}

int 
xmlSecErrorsGetCode(size_t pos) {
    /* could not use asserts here! */
    if(pos < sizeof(xmlSecErrorsTable) / sizeof(xmlSecErrorsTable[0])) {
	return(xmlSecErrorsTable[pos].errorCode);
    }
    return(0);
}

const char* 
xmlSecErrorsGetMsg(size_t pos) {
    /* could not use asserts here! */
    if(pos < sizeof(xmlSecErrorsTable) / sizeof(xmlSecErrorsTable[0])) {
	return(xmlSecErrorsTable[pos].errorMsg);
    }
    return(NULL);
}

const char* 
xmlSecErrorGetEmptyMessage(void) {
    static const char emptyMessage[] = " ";
    return(emptyMessage);
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
	    const char* errorObject, const char* errorSubject,
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
	} else {
	    error_msg[0] = '\0';	    
	}
	xmlSecErrorsClbk(file, line, func, errorObject, errorSubject, reason, error_msg);
    }	
}
 
