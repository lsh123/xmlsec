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

/**
 * Error constants for OpenSSL 
 */
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

#define XMLSEC_ERRORS_R_INVALID_TRANSFORM	 10	/* "invlaid transform" */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_DATA	 11	/* "invlaid transform data	" */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY 12	/* "invalid transform or key" */
#define XMLSEC_ERRORS_R_INVALID_KEY		 13	/* "key is invalid" */
#define XMLSEC_ERRORS_R_INVALID_KEY_DATA	 14	/* "key data is invalid" */
#define XMLSEC_ERRORS_R_INVALID_KEY_SIZE	 15	/* "invalid key size" */
#define XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN	 16	/* "invalid key origin" */
#define XMLSEC_ERRORS_R_KEY_NOT_FOUND		 17	/* "key not found" */
#define XMLSEC_ERRORS_R_INVALID_SIZE		 18	/* "invalid size" */
#define XMLSEC_ERRORS_R_INVALID_DATA		 19	/* "invalid data" */
#define XMLSEC_ERRORS_R_INVALID_TYPE		 21	/* "invalid type" */
#define XMLSEC_ERRORS_R_INVALID_USAGE		 22	/* "invalid usage" */
#define XMLSEC_ERRORS_R_INVALID_NODE	 	 23	/* "invalid node" */
#define XMLSEC_ERRORS_R_INVALID_NODESET	 	 24	/* "invalid nodes set" */
#define XMLSEC_ERRORS_R_INVALID_NODE_CONTENT	 25	/* "invalid node content" */
#define XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE	 26	/* "invalid node attribute" */
#define XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT	 27	/* "node already present" */
#define XMLSEC_ERRORS_R_SAME_DOCUMENT_REQUIRED	 28	/* "same document required" */
#define XMLSEC_ERRORS_R_NODE_NOT_FOUND 	 	 29	/* "node not found" */
#define XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL	 30	/* "max retrievals level reached" */
#define XMLSEC_ERRORS_R_CERT_VERIFY_FAILED	 31	/* "cert verification failed" */
#define XMLSEC_ERRORS_R_CERT_NOT_FOUND		 32	/* "cert not found" */
#define XMLSEC_ERRORS_R_CERT_REVOKED		 33	/* "cert revoked" */
#define XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE 	 34	/* "invalid reference" */

#define XMLSEC_ERRORS_R_ASSERTION		 100	/* "assertion" */
#define XMLSEC_ERRORS_R_DISABLED		 101	/* "disabled" */


/**
 * Error functions
 */ 
typedef void (*xmlSecErrorsCallback) 		(const char* file, int line, 
				    		 const char* func,
						 int reason, const char* msg);

XMLSEC_EXPORT void xmlSecErrorsInit		(void);
XMLSEC_EXPORT void xmlSecErrorsShutdown		(void);
XMLSEC_EXPORT void xmlSecErrorsSetCallback	(xmlSecErrorsCallback callback);
 
XMLSEC_EXPORT_VAR int xmlSecPrintErrorMessages;	/* whether the error messages will be printed immidiatelly */

#define XMLSEC_ERRORS_HERE			__FILE__,__LINE__,__FUNCTION__
#ifdef __GNUC__
XMLSEC_EXPORT void xmlSecError			(const char* file, int line, 
						 const char* func,
						 int reason, const char* msg, 
						 ...)
						__attribute__ ((format (printf, 5, 6)));
#else /* __GNUC__ */
XMLSEC_EXPORT void xmlSecError			(const char* file, int line, 
						 const char* func,
						 int reason, const char* msg, 
						 ...);
#endif /* __GNUC__ */

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


/* __FUNCTION_ may not be defined */
#ifndef __GNUC__
#define __FUNCTION__   ""
#endif /* __GNUC__ */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_ERRORS_H__ */


