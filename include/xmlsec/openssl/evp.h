/** 
 * XMLSec library
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_EVP_H__
#define __XMLSEC_OPENSSL_EVP_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <openssl/evp.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

#include <xmlsec/openssl/crypto.h>



/******************************************************************************
 *
 * EVP Block Cipher transforms
 *
 *****************************************************************************/
XMLSEC_EXPORT int	xmlSecOpenSSLEvpBlockCipherInitialize	(xmlSecTransformPtr transform,
								 const EVP_CIPHER *type);
XMLSEC_EXPORT void	xmlSecOpenSSLEvpBlockCipherFinalize	(xmlSecTransformPtr transform);
XMLSEC_EXPORT int	xmlSecOpenSSLEvpBlockCipherSetKey	(xmlSecTransformPtr transform,
								 const unsigned char* key,
								 size_t keySize);								 
XMLSEC_EXPORT int	xmlSecOpenSSLEvpBlockCipherExecuteBin	(xmlSecTransformPtr transform,
								 const unsigned char* in,
								 size_t inSize,
								 size_t* inRes,
								 unsigned char* out,
								 size_t outSize,
								 size_t* outRes);

/******************************************************************************
 *
 * EVP helper functions
 *
 *****************************************************************************/
XMLSEC_EXPORT xmlSecKeyDataPtr 	xmlSecOpenSSLEvpParseKey	(EVP_PKEY *pKey);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_EVP_H__ */


