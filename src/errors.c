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
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>

static xmlSecErrorsCallback xmlSecErrorsClbk = xmlSecErrorsDefaultCallback;
int  xmlSecPrintErrorMessages = 1;	/* whether the error messages will be printed immidiatelly */

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
void 
xmlSecErrorsDefaultCallback(const char* file, int line, const char* func,
			    int reason, const char* msg) {

    if(xmlSecPrintErrorMessages) {    
    	xmlGenericError(xmlGenericErrorContext,
	    "%s (%s:%d): error %d: %s\n",
	    (func != NULL) ? func : "unknown",
	    (file != NULL) ? file : "unknown",
	    line,
	    reason,
	    (msg != NULL) ? msg : "");
    }
}

