/** 
 * XMLSec library Error codes
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_ERRORS_H__
#define __XMLSEC_ERRORS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <openssl/err.h>

#define XMLSEC_ERRORS_LIB				(ERR_LIB_USER + 57)
#define XMLSEC_ERRORS_FUNCTION				0

/** 
 * Error codes
 */
#define XMLSEC_ERRORS_R_MALLOC_FAILED		 -1001  /* "failed to allocate memory" */
#define XMLSEC_ERRORS_R_XMLSEC_FAILED		 -1002	/* "xmlsec operation failed" */
#define XMLSEC_ERRORS_R_CRYPTO_FAILED		 -1003	/* "crypto operation failed" */
#define XMLSEC_ERRORS_R_XML_FAILED		 -1004	/* "xml operation failed" */

#define XMLSEC_ERRORS_R_INVALID_TRANSFORM	 -2001	/* "invlaid transform" */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_DATA	 -2007	/* "invlaid transform data	" */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY -2002	/* "invalid transform or key" */
#define XMLSEC_ERRORS_R_INVALID_KEY		 -2003	/* "key is invalid" */
#define XMLSEC_ERRORS_R_INVALID_KEY_DATA	 -2004	/* "key data is invalid" */
#define XMLSEC_ERRORS_R_INVALID_KEY_SIZE	 -2005	/* "invalid key size" */

#define XMLSEC_ERRORS_R_INVALID_SIZE		 -3001	/* "invalid size" */
#define XMLSEC_ERRORS_R_INVALID_DATA		 -3002	/* "invalid data" */
#define XMLSEC_ERRORS_R_INVALID_NODE_CONTENT	 -3003	/* "invalid node content" */

#define XMLSEC_ERRORS_R_ASSERTION		 -4001	/* "assertion" */

/*
#define XMLSEC_ERRORS_R_
#define XMLSEC_ERRORS_R_
#define XMLSEC_ERRORS_R_
#define XMLSEC_ERRORS_R_
#define XMLSEC_ERRORS_R_
#define XMLSEC_ERRORS_R_
*/


/**
 * Error function
 */ 
/* __FUNCTION_ may not be defined */
#ifndef __GNUC__
#define __FUNCTION__   ""
#endif /* __GNUC__ */

#define XMLSEC_ERRORS_HERE	__FILE__,__LINE__,__FUNCTION__


void	xmlSecError		(const char* file, int line, const char* func,
				 int reason, const char* msg, ...);

/**
 * Assertions
 */
#define xmlSecAssert( p ) \
	if(!( p ) ) { \
	    xmlSecError(XMLSEC_ERRORS_HERE, \
			XMLSEC_ERRORS_R_ASSERTION, \
			"%s", #p); \
	    return; \
	} 

#define xmlSecAssert2( p, ret ) \
	if(!( p ) ) { \
	    xmlSecError(XMLSEC_ERRORS_HERE, \
			XMLSEC_ERRORS_R_ASSERTION, \
			"%s", #p); \
	    return(ret); \
	} 

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_ERRORS_H__ */


