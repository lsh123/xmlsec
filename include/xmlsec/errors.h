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

/***************************************************************
 *
 * Error codes
 *
 **************************************************************/
/**
 * XMLSEC_ERRORS_R_MALLOC_FAILED:
 *
 * Failed to allocate memory error.
 */
#define XMLSEC_ERRORS_R_MALLOC_FAILED		 1 	
/**
 * XMLSEC_ERRORS_R_XMLSEC_FAILED:
 *
 * An XMLSec function failed.
 */
#define XMLSEC_ERRORS_R_XMLSEC_FAILED		 2
/**
 * XMLSEC_ERRORS_R_CRYPTO_FAILED:
 *
 * Crypto (OpenSSL) function failed. 
 */
#define XMLSEC_ERRORS_R_CRYPTO_FAILED		 3
/**
 * XMLSEC_ERRORS_R_XML_FAILED:
 *
 * LibXML function failed.
 */
#define XMLSEC_ERRORS_R_XML_FAILED		 4
/**
 * XMLSEC_ERRORS_R_XSLT_FAILED:
 * 
 * LibXSLT function failed.
 */
#define XMLSEC_ERRORS_R_XSLT_FAILED		 5
/**
 * XMLSEC_ERRORS_R_IO_FAILED:
 *
 * IO operation failed.
 */
#define XMLSEC_ERRORS_R_IO_FAILED		 6
/**
 * XMLSEC_ERRORS_R_INVALID_TRANSFORM:
 * 
 * Invlaid transform.
 */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM	 10
/**
 * XMLSEC_ERRORS_R_INVALID_TRANSFORM_DATA:
 *
 * Invlaid transform data.
 */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_DATA	 11
/**
 * XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY:
 *
 * Invalid transform or key.
 */
#define XMLSEC_ERRORS_R_INVALID_TRANSFORM_OR_KEY 12
/**
 * XMLSEC_ERRORS_R_INVALID_KEY:
 * 
 * Key is invalid.
 */
#define XMLSEC_ERRORS_R_INVALID_KEY		 13
/**
 * XMLSEC_ERRORS_R_INVALID_KEY_DATA:
 *
 * Key data is invalid.
 */
#define XMLSEC_ERRORS_R_INVALID_KEY_DATA	 14
/**
 * XMLSEC_ERRORS_R_INVALID_KEY_SIZE:
 *
 * Invalid key size.
 */
#define XMLSEC_ERRORS_R_INVALID_KEY_SIZE	 15
/**
 * XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN:
 *
 * Invalid key origin.
 */
#define XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN	 16
/**
 * XMLSEC_ERRORS_R_KEY_NOT_FOUND:
 * 
 * Key not found.
 */
#define XMLSEC_ERRORS_R_KEY_NOT_FOUND		 17
/**
 * XMLSEC_ERRORS_R_INVALID_SIZE:
 *
 * Invalid size.
 */
#define XMLSEC_ERRORS_R_INVALID_SIZE		 18
/**
 * XMLSEC_ERRORS_R_INVALID_DATA:
 *
 * Invalid data.
 */
#define XMLSEC_ERRORS_R_INVALID_DATA		 19
/**
 * XMLSEC_ERRORS_R_INVALID_TYPE:
 * 
 * Invalid type.
 */
#define XMLSEC_ERRORS_R_INVALID_TYPE		 21
/**
 * XMLSEC_ERRORS_R_INVALID_USAGE:
 * 
 * Invalid usage.
 */
#define XMLSEC_ERRORS_R_INVALID_USAGE		 22
/**
 * XMLSEC_ERRORS_R_INVALID_NODE:
 * 
 * Invalid node,
 */
#define XMLSEC_ERRORS_R_INVALID_NODE	 	 23
/**
 * XMLSEC_ERRORS_R_INVALID_NODESET:
 *
 * Invalid nodes set,
 */
#define XMLSEC_ERRORS_R_INVALID_NODESET	 	 24
/**
 * XMLSEC_ERRORS_R_INVALID_NODE_CONTENT:
 *
 * Invalid node content.
 */
#define XMLSEC_ERRORS_R_INVALID_NODE_CONTENT	 25
/**
 * XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE:
 *
 * Invalid node attribute.
 */
#define XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE	 26
/**
 * XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT:
 *
 * Node already present,
 */
#define XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT	 27
/**
 * XMLSEC_ERRORS_R_SAME_DOCUMENT_REQUIRED:
 *
 * The transform requires the same document.
 */
#define XMLSEC_ERRORS_R_SAME_DOCUMENT_REQUIRED	 28
/**
 * XMLSEC_ERRORS_R_NODE_NOT_FOUND:
 *
 * Node not found.
 */
#define XMLSEC_ERRORS_R_NODE_NOT_FOUND 	 	 29
/**
 * XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL:
 *
 * Max allowed retrievals level reached.
 */
#define XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL	 30
/**
 * XMLSEC_ERRORS_R_CERT_VERIFY_FAILED:
 *
 * Certificate verification failed.
 */
#define XMLSEC_ERRORS_R_CERT_VERIFY_FAILED	 41
/**
 * XMLSEC_ERRORS_R_CERT_NOT_FOUND:
 *
 * Requested certificate is not found.
 */
#define XMLSEC_ERRORS_R_CERT_NOT_FOUND		 42
/**
 * XMLSEC_ERRORS_R_CERT_REVOKED:
 * 
 * The certificate is revoked.
 */
#define XMLSEC_ERRORS_R_CERT_REVOKED		 43
/**
 * XMLSEC_ERRORS_R_CERT_ISSUER_FAILED:
 *
 * Failed to get certificate issuer.
 */
#define XMLSEC_ERRORS_R_CERT_ISSUER_FAILED	 44
/**
 * XMLSEC_ERRORS_R_CERT_NOT_YET_VALID:
 *
 * "Not valid before" verification failed.
 */
#define XMLSEC_ERRORS_R_CERT_NOT_YET_VALID	 45
/**
 * XMLSEC_ERRORS_R_CERT_HAS_EXPIRED:
 *
 * "Not valid after" verification failed.
 */
#define XMLSEC_ERRORS_R_CERT_HAS_EXPIRED	 46

/**
 * XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE:
 *
 * The <dsig:Reference> validation failed.
 */
#define XMLSEC_ERRORS_R_DSIG_INVALID_REFERENCE 	 51
/**
 * XMLSEC_ERRORS_R_ASSERTION:
 *
 * Invalid assertion.
 */
#define XMLSEC_ERRORS_R_ASSERTION		 100
/**
 * XMLSEC_ERRORS_R_DISABLED:
 *
 * The feature is disabled during compilation.
 * Check './configure --help' for details on how to
 * enable it.
 */
#define XMLSEC_ERRORS_R_DISABLED		 101



#define XMLSEC_ERRORS_MAX_NUMBER		256



/*******************************************************************
 *
 * Error functions
 *
 *******************************************************************/ 
/**
 * xmlSecErrorsCallback:
 * @file: the error origin filename (__FILE__).
 * @line: the error origin line number (__LINE__).
 * @func: the error origin function (__FUNCTIION__).
 * @reason: the error code.
 * @msg: the error message.
 *
 * The errors reporting callback function typedef.
 */
typedef void (*xmlSecErrorsCallback) 		(const char* file, int line, 
				    		 const char* func,
						 int reason, const char* msg);


XMLSEC_EXPORT void xmlSecErrorsInit			(void);
XMLSEC_EXPORT void xmlSecErrorsShutdown			(void);
XMLSEC_EXPORT void xmlSecErrorsSetCallback		(xmlSecErrorsCallback callback);
XMLSEC_EXPORT void xmlSecErrorsDefaultCallback		(const char* file, 
							 int line, 
				    			 const char* func,
							 int reason, 
							 const char* msg);
XMLSEC_EXPORT int xmlSecErrorsGetCode			(size_t pos);
XMLSEC_EXPORT const char* xmlSecErrorsGetMsg		(size_t pos);


 
/**
 * xmlSecPrintErrorMessages:
 *
 * The flag that determines whether the error message will be printed
 * out immidiatelly. For default errors reporting callback, this flag
 * determines whether the error is reported to LibXML library or not.
 */
XMLSEC_EXPORT_VAR int xmlSecPrintErrorMessages;

/** 
 * XMLSEC_ERRORS_HERE:
 *
 * The macro that specifies the location (file, line and function)
 * for the xmlSecError() function.
 */
#define XMLSEC_ERRORS_HERE			__FILE__,__LINE__,__FUNCTION__
#ifdef __GNUC__
#define XMLSEC_ERRORS_PRINTF_ATTRIBUTE 		__attribute__ ((format (printf, 5, 6)))
#else /* __GNUC__ */
#define XMLSEC_ERRORS_PRINTF_ATTRIBUTE 		
#endif /* __GNUC__ */

XMLSEC_EXPORT void xmlSecError			(const char* file, int line, 
						 const char* func,
						 int reason, const char* msg, 
						 ...) XMLSEC_ERRORS_PRINTF_ATTRIBUTE;
						 
						

/**********************************************************************
 *
 * Assertions
 *
 **********************************************************************/
/**
 * xmlSecAssert:
 * @p: the expression.
 *
 * Macro. Verifies that @p is true and calls return() otherwise.
 */
#define xmlSecAssert( p ) \
	if(!( p ) ) { \
	    xmlSecError(XMLSEC_ERRORS_HERE, \
			XMLSEC_ERRORS_R_ASSERTION, \
			"%s", #p); \
	    return; \
	} 

/**
 * xmlSecAssert2:
 * @p: the expression.
 * @ret: the return value.
 *
 * Macro. Verifies that @p is true and calls return(@ret) otherwise.
 */
#define xmlSecAssert2( p, ret ) \
	if(!( p ) ) { \
	    xmlSecError(XMLSEC_ERRORS_HERE, \
			XMLSEC_ERRORS_R_ASSERTION, \
			"%s", #p); \
	    return(ret); \
	} 


/* __FUNCTION__ may not be defined */
#if defined(_MSC_VER) && (_MSC_VER < 1300) 
#define __FUNCTION__  ""
#endif /* _MSC_VER */

#if defined(__SUNPRO_C) && (__SUNPRO_C <= 0x530)
#define __FUNCTION__  ""
#endif /* __SUNPRO_C */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_ERRORS_H__ */


