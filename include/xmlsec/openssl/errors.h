/** 
 * XMLSec library Error codes
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_ERRORS_H__
#define __XMLSEC_OPENSSL_ERRORS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <openssl/err.h>

/**************************************************************
 *
 * Error constants for OpenSSL 
 *
 *************************************************************/

/**
 * XMLSEC_ERRORS_LIB:
 *
 * Macro. The XMLSec library id for OpenSSL errors reporting functions.
 */
#define XMLSEC_ERRORS_LIB			(ERR_LIB_USER + 57)
/**
 * XMLSEC_ERRORS_FUNCTION:
 *
 * Macro. The XMLSec library functions OpenSSL errors reporting functions.
 */
#define XMLSEC_ERRORS_FUNCTION			0

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_ERRORS_H__ */


