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



/******************************************************************************
 *
 * EVP Signature transforms
 *
 *****************************************************************************/
#define XMLSEC_OPENSSL_DSA_SIGNATURE_SIZE			40

XMLSEC_EXPORT int	xmlSecOpenSSLEvpSignatureInitialize	(xmlSecTransformPtr transform,
								 const EVP_MD* digest);
XMLSEC_EXPORT void	xmlSecOpenSSLEvpSignatureFinalize	(xmlSecTransformPtr transform);
XMLSEC_EXPORT int	xmlSecOpenSSLEvpSignatureSetKey		(xmlSecTransformPtr transform,
								 EVP_PKEY* pKey);
XMLSEC_EXPORT int  	xmlSecOpenSSLEvpSignatureVerify		(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int	xmlSecOpenSSLEvpSignatureExecute	(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
#define xmlSecOpenSSLEvpSignatureSize	\
	(sizeof(xmlSecTransform) + sizeof(EVP_MD))


/******************************************************************************
 *
 * EVP helper functions
 *
 *****************************************************************************/
XMLSEC_EXPORT EVP_PKEY*	xmlSecOpenSSLEvpKeyDup			(EVP_PKEY* pKey);
XMLSEC_EXPORT xmlSecKeyDataPtr 	xmlSecOpenSSLEvpKeyAdopt	(EVP_PKEY *pKey);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_EVP_H__ */


