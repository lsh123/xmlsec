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
								 const EVP_CIPHER *cipher);
XMLSEC_EXPORT void	xmlSecOpenSSLEvpBlockCipherFinalize	(xmlSecTransformPtr transform);
XMLSEC_EXPORT int	xmlSecOpenSSLEvpBlockCipherSetKey	(xmlSecTransformPtr transform,
								 const unsigned char* key,
								 size_t keySize);								 
XMLSEC_EXPORT int	xmlSecOpenSSLEvpBlockCipherExecute	(xmlSecTransformPtr transform,
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
#define xmlSecOpenSSLEvpBlockCipherSize	\
	(sizeof(xmlSecTransform) + sizeof(EVP_CIPHER_CTX))


/******************************************************************************
 *
 * EVP Digest transforms
 *
 *****************************************************************************/
XMLSEC_EXPORT int	xmlSecOpenSSLEvpDigestInitialize	(xmlSecTransformPtr transform,
								 const EVP_MD* digest);
XMLSEC_EXPORT void	xmlSecOpenSSLEvpDigestFinalize		(xmlSecTransformPtr transform);
XMLSEC_EXPORT int  	xmlSecOpenSSLEvpDigestVerify		(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int	xmlSecOpenSSLEvpDigestExecute		(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
#define xmlSecOpenSSLEvpDigestSize	\
	(sizeof(xmlSecTransform) + sizeof(EVP_MD))

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


