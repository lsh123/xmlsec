/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include <libxml/tree.h>
#include <openssl/err.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>

#define XMLSEC_ERRORS_BUFFER_SIZE	1024

void	
xmlSecError(const char* file, int line, const char* func, 
  	    int reason, const char* msg, ...) {
    char error_msg[XMLSEC_ERRORS_BUFFER_SIZE];

    ERR_put_error(XMLSEC_ERRORS_LIB, XMLSEC_ERRORS_FUNCTION, reason, file, line);
    
#ifdef XMLSEC_DEBUG
    if(msg != NULL) {
	va_list va;
	
	va_start(va, msg);
  	vsnprintf(error_msg, sizeof(error_msg), msg, va);	
	error_msg[sizeof(error_msg) - 1] = '\0';
	va_end(va);	
    }
    xmlGenericError(xmlGenericErrorContext,
	    "%s (%s:%d) - %d - %s \n",
	    (func != NULL) ? func : "unknown",
	    (file != NULL) ? file : "unknown",
	    line,
	    reason,
	    (msg != NULL) ? error_msg : "");
#endif /* XMLSEC_DEBUG */	        
}
