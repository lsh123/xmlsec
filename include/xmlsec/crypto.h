/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_CRYPTO_H__
#define __XMLSEC_CRYPTO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>

/**
 * xmlSecCryptoInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 * This is an internal function called by @xmlSecInit function.
 * The application must call @xmlSecCryptoAppInit before
 * calling @xmlSecInit function or do general crypto engine
 * initialization by itself.
 *
 * Returns 0 on success or a negative value otherwise.
 */
XMLSEC_EXPORT int		xmlSecCryptoInit		(void);

/**
 * xmlSecCryptoShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 * This is an internal function called by @xmlSecShutdown function.
 * The application must call @xmlSecShutdown function
 * before calling @xmlSecCryptoAppInit or doing general 
 * crypto engine shutdown by itself.
 *
 * Returns 0 on success or a negative value otherwise.
 */
XMLSEC_EXPORT int		xmlSecCryptoShutdown		(void);

/**
 * xmlSecCryptoAppInit:
 * 
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before 
 * @xmlSecInit function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
XMLSEC_EXPORT int		xmlSecCryptoAppInit		(void);

/**
 * xmlSecCryptoAppShutdown:
 * 
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after 
 * @xmlSecShutdown function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
XMLSEC_EXPORT int		xmlSecCryptoAppShutdown		(void);

XMLSEC_EXPORT xmlSecKeyValuePtr 	xmlSecCryptoAppLoadPemKey	(const xmlChar* keyName,
								 const char* filename,
								 const char* pwd,
								 xmlSecKeyValueType type);
XMLSEC_EXPORT xmlSecX509Data 	xmlSecCryptoAppLoadPemCert	(const char* filename,
								 const char* pwd,
								 xmlSecX509DataType type);
XMLSEC_EXPORT xmlSecKeyValuePtr	xmlSecCryptoAppLoadPkcs12	(const xmlChar* keyName,
								 const char* filename,
								 const char* pwd);
								
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_CRYPTO_H__ */


