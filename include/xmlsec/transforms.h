/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TRANSFORMS_H__
#define __XMLSEC_TRANSFORMS_H__    



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>


typedef struct _xmlSecTransform 	*xmlSecTransformPtr; 
typedef const struct _xmlSecTransformId *xmlSecTransformId;
/* invalid/unknown */
#define xmlSecTransformUnknown			NULL

typedef enum _xmlSecTransformStatus {
    xmlSecTransformStatusNone = 0,
    xmlSecTransformStatusOk,
    xmlSecTransformStatusFail
} xmlSecTransformStatus;


/**
 * AES transforms
 */
#ifndef XMLSEC_NO_AES
extern xmlSecTransformId 	xmlSecEncAes128Cbc;
extern xmlSecTransformId 	xmlSecEncAes192Cbc;
extern xmlSecTransformId 	xmlSecEncAes256Cbc;
extern xmlSecKeyId 	 	xmlSecAesKey;

int	xmlSecAesKeyGenerate			(xmlSecKeyPtr key,
						 const unsigned char *buf, 
						 size_t size);
#endif /* XMLSEC_NO_AES */

/** 
 * Base64 Transform
 */
#define XMLSEC_BASE64_LINESIZE		64
extern xmlSecTransformId xmlSecEncBase64Encode;
extern xmlSecTransformId xmlSecEncBase64Decode;

void   	xmlSecBase64EncodeSetLineSize		(xmlSecTransformPtr transform,
						 size_t lineSize);


/**
 * C14N transforms 
 */
extern xmlSecTransformId 	xmlSecC14NInclusive;
extern xmlSecTransformId 	xmlSecC14NInclusiveWithComments;
extern xmlSecTransformId 	xmlSecC14NExclusive;
extern xmlSecTransformId 	xmlSecC14NExclusiveWithComments;

int	xmlSecC14NExclAddInclNamespaces		(xmlNodePtr transformNode,
						 const xmlChar *prefixList);

/**
 * DES transform
 */
#ifndef XMLSEC_NO_DES
extern xmlSecTransformId 	xmlSecEncDes3Cbc;
extern xmlSecKeyId 		xmlSecDesKey;
 
int	xmlSecDesKeyGenerate			(xmlSecKeyPtr key,
						 const unsigned char *buf, 
						 size_t size);
#endif /* XMLSEC_NO_DES */

/**
 * DSA transform
 */
#ifndef XMLSEC_NO_DSA
#include <openssl/dsa.h>

extern xmlSecTransformId 	xmlSecSignDsaSha1;
extern xmlSecKeyId 		xmlSecDsaKey;

int	xmlSecDsaKeyGenerate			(xmlSecKeyPtr key,
						 DSA *dsa);
#endif /* XMLSEC_NO_DSA */

/**
 * Enveloped transform 
 */
extern xmlSecTransformId 	xmlSecTransformEnveloped;


/**
 * HMAC transforms
 */
#ifndef XMLSEC_NO_HMAC
extern xmlSecTransformId 	xmlSecMacHmacSha1;
extern xmlSecTransformId 	xmlSecMacHmacRipeMd160;
extern xmlSecTransformId 	xmlSecMacHmacMd5;
extern xmlSecKeyId 		xmlSecHmacKey;

int	xmlSecHmacKeyGenerate			(xmlSecKeyPtr key,
						 const unsigned char *buf, 
						 size_t size);
int	xmlSecHmacAddOutputLength		(xmlNodePtr transformNode,
						 size_t bitsLen);
#endif /* XMLSEC_NO_HMAC */


/**
 * RSA transforms
 */
#ifndef XMLSEC_NO_RSA
extern xmlSecTransformId 	xmlSecSignRsaSha1;
extern xmlSecTransformId 	xmlSecEncRsaPkcs1;
extern xmlSecTransformId 	xmlSecEncRsaOaep;
extern xmlSecKeyId 		xmlSecRsaKey;

int	xmlSecRsaKeyGenerate			(xmlSecKeyPtr key,
						 RSA *rsa);
int  	xmlSecEncRsaOaepAddParam		(xmlNodePtr transformNode,
						 const unsigned char *buf,
						 size_t size);
#endif /* XMLSEC_NO_RSA */


/**
 * SHA1 transform
 */
#ifndef XMLSEC_NO_SHA1
extern xmlSecTransformId 	xmlSecDigestSha1;
#endif /* XMLSEC_NO_SHA1 */

/**
 * XPath transform */
extern xmlSecTransformId 	xmlSecTransformXPath;
int 	xmlSecTransformXPathAdd			(xmlNodePtr transformNode, 
						 const xmlChar *expression,
						 const xmlChar **namespaces);

/**
 * XSLT transform 
 */
#ifndef XMLSEC_NO_XSLT
extern xmlSecTransformId 	xmlSecTransformXslt;
int 	xmlSecTransformXsltAdd			(xmlNodePtr transformNode, 
						 const xmlChar *xslt);
#endif /* XMLSEC_NO_XSLT */




#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_H__ */

