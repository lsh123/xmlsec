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
#define XMLSEC_ERRORS_R_MALLOC_FAILED		 1  	/* "failed to allocate memory" */
#define XMLSEC_ERRORS_R_XMLSEC_FAILED		 2	/* "xmlsec operation failed" */
#define XMLSEC_ERRORS_R_CRYPTO_FAILED		 3	/* "crypto operation failed" */
#define XMLSEC_ERRORS_R_XML_FAILED		 4	/* "xml operation failed" */
#define XMLSEC_ERRORS_R_XSLT_FAILED		 5	/* "xslt operation failed" */
#define XMLSEC_ERRORS_R_IO_FAILED		 6	/* "io operation failed" */

#define XMLSEC_ERRORS_R_INVALID_TRANSFORM	 11	/* "invlaid transform" */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_DATA	 12	/* "invlaid transform data	" */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY 13	/* "invalid transform or key" */
#define XMLSEC_ERRORS_R_INVALID_KEY		 14	/* "key is invalid" */
#define XMLSEC_ERRORS_R_INVALID_KEY_DATA	 15	/* "key data is invalid" */
#define XMLSEC_ERRORS_R_INVALID_KEY_SIZE	 16	/* "invalid key size" */
#define XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN	 17	/* "invalid key origin" */

#define XMLSEC_ERRORS_R_INVALID_SIZE		 21	/* "invalid size" */
#define XMLSEC_ERRORS_R_INVALID_DATA		 22	/* "invalid data" */
#define XMLSEC_ERRORS_R_INVALID_TYPE		 22	/* "invalid type" */
#define XMLSEC_ERRORS_R_INVALID_NODE	 	 26	/* "invalid node" */
#define XMLSEC_ERRORS_R_INVALID_NODE_CONTENT	 23	/* "invalid node content" */
#define XMLSEC_ERRORS_R_INVLAID_NODE_ATTRIBUTE	 24	/* "invalid node attribute" */
#define XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT	 25	/* "node already present" */
#define XMLSEC_ERRORS_R_SAME_DOCUMENT_REQUIRED	 27	/* "same document required" */
#define XMLSEC_ERRORS_R_NODE_NOT_FOUND 	 	 28	/* "node not found" */


#define XMLSEC_ERRORS_R_ASSERTION		 31	/* "assertion" */
#define XMLSEC_ERRORS_R_DISABLED		 32	/* "disabled" */

#define XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL	 41	/* "max retrievals level reached" */
#define XMLSEC_ERRORS_R_CERT_VERIFY_FAILED	 42	/* "cert verification failed" */
#define XMLSEC_ERRORS_R_CERT_NOT_FOUND		 43	/* "cert not found" */
#define XMLSEC_ERRORS_R_KEY_NOT_FOUND		 44	/* "key not found" */

/**
 * Error function
 */ 
/* __FUNCTION_ may not be defined */
#ifndef __GNUC__
#define __FUNCTION__   ""
#endif /* __GNUC__ */

#define XMLSEC_ERRORS_HERE	__FILE__,__LINE__,__FUNCTION__


XMLSEC_EXPORT void xmlSecError	(const char* file, int line, const char* func,
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


