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
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecEncAes128Cbc;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecEncAes192Cbc;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecEncAes256Cbc;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecKWAes128;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecKWAes192;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecKWAes256;
XMLSEC_EXPORT_VAR xmlSecKeyId 	 	xmlSecAesKey;

XMLSEC_EXPORT int	xmlSecAesKeyGenerate	(xmlSecKeyPtr key,
						 const unsigned char *buf, 
						 size_t size);
#endif /* XMLSEC_NO_AES */

/** 
 * Base64 Transform
 */
#define XMLSEC_BASE64_LINESIZE		64
XMLSEC_EXPORT_VAR xmlSecTransformId xmlSecEncBase64Encode;
XMLSEC_EXPORT_VAR xmlSecTransformId xmlSecEncBase64Decode;

XMLSEC_EXPORT void   	xmlSecBase64EncodeSetLineSize(xmlSecTransformPtr transform,
						 size_t lineSize);


/**
 * C14N transforms 
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecC14NInclusive;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecC14NInclusiveWithComments;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecC14NExclusive;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecC14NExclusiveWithComments;

XMLSEC_EXPORT int	xmlSecC14NExclAddInclNamespaces		
						(xmlNodePtr transformNode,
						 const xmlChar *prefixList);

/**
 * DES transform
 */
#ifndef XMLSEC_NO_DES
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecEncDes3Cbc;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecKWDes3Cbc;
XMLSEC_EXPORT_VAR xmlSecKeyId 		xmlSecDesKey;
 
XMLSEC_EXPORT int	xmlSecDesKeyGenerate	(xmlSecKeyPtr key,
						 const unsigned char *buf, 
						 size_t size);
#endif /* XMLSEC_NO_DES */

/**
 * DSA transform
 */
#ifndef XMLSEC_NO_DSA
#include <openssl/dsa.h>

XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecSignDsaSha1;
XMLSEC_EXPORT_VAR xmlSecKeyId 		xmlSecDsaKey;

XMLSEC_EXPORT int	xmlSecDsaKeyGenerate	(xmlSecKeyPtr key,
						 DSA *dsa);
#endif /* XMLSEC_NO_DSA */

/**
 * Enveloped transform 
 */
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecTransformEnveloped;


/**
 * HMAC transforms
 */
#ifndef XMLSEC_NO_HMAC
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecMacHmacSha1;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecMacHmacRipeMd160;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecMacHmacMd5;
XMLSEC_EXPORT_VAR xmlSecKeyId 		xmlSecHmacKey;

XMLSEC_EXPORT int	xmlSecHmacKeyGenerate	(xmlSecKeyPtr key,
						 const unsigned char *buf, 
						 size_t size);
XMLSEC_EXPORT int	xmlSecHmacAddOutputLength(xmlNodePtr transformNode,
						 size_t bitsLen);
#endif /* XMLSEC_NO_HMAC */

#ifndef XMLSEC_NO_RIPEMD160
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecDigestRipemd160;
#endif /* XMLSEC_NO_RIPEMD160 */

/**
 * RSA transforms
 */
#ifndef XMLSEC_NO_RSA
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecSignRsaSha1;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecEncRsaPkcs1;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecEncRsaOaep;
XMLSEC_EXPORT_VAR xmlSecKeyId 		xmlSecRsaKey;

XMLSEC_EXPORT int	xmlSecRsaKeyGenerate	(xmlSecKeyPtr key,
						 RSA *rsa);
XMLSEC_EXPORT int  	xmlSecEncRsaOaepAddParam(xmlNodePtr transformNode,
						 const unsigned char *buf,
						 size_t size);
#endif /* XMLSEC_NO_RSA */


/**
 * SHA1 transform
 */
#ifndef XMLSEC_NO_SHA1
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecDigestSha1;
#endif /* XMLSEC_NO_SHA1 */

/**
 * XPath transform 
 */
typedef enum _xmlSecXPath2TransformType {
    xmlSecXPathTransformUnknown = 0,
    xmlSecXPathTransformIntersect,
    xmlSecXPathTransformSubtract,
    xmlSecXPathTransformUnion
} xmlSecXPath2TransformType;
 
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecTransformXPath;
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecTransformXPath2;
#ifndef XMLSEC_NO_XPATHALT  
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecXPathAlt;
#endif /* XMLSEC_NO_XPATHALT */

XMLSEC_EXPORT int 	xmlSecTransformXPathAdd	(xmlNodePtr transformNode, 
						 const xmlChar *expression,
						 const xmlChar **namespaces);
XMLSEC_EXPORT int 	xmlSecTransformXPath2Add(xmlNodePtr transformNode, 
						 xmlSecXPath2TransformType type,
						 const xmlChar *expression,
						 const xmlChar **namespaces);

/**
 * XSLT transform 
 */
#ifndef XMLSEC_NO_XSLT
XMLSEC_EXPORT_VAR xmlSecTransformId 	xmlSecTransformXslt;
XMLSEC_EXPORT int 	xmlSecTransformXsltAdd	(xmlNodePtr transformNode, 
						 const xmlChar *xslt);
#endif /* XMLSEC_NO_XSLT */




#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_H__ */

