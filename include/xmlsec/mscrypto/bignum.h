/** 
 * XMLSec library
 * 
 * Reading/writing BIGNUM values
 * 
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef __XMLSEC_MSCRYPTO_BIGNUM_H__
#define __XMLSEC_MSCRYPTO_BIGNUM_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h> 

#include <xmlsec/xmlsec.h>

XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoNodeGetBigNumValue(xmlNodePtr cur, xmlSecBufferPtr retval);
XMLSEC_CRYPTO_EXPORT int 	xmlSecMSCryptoNodeSetBigNumValue(xmlNodePtr cur, xmlSecByte* buf, xmlSecSize bufLen, int addLineBreaks);
XMLSEC_CRYPTO_EXPORT xmlChar*	xmlSecMSCryptoHexToDec(const xmlChar *hex);
XMLSEC_CRYPTO_EXPORT xmlChar*	xmlSecMSCryptoDecToHex(const xmlChar *dec);
XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoWordbaseSwap(xmlChar *s);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCRYPTO_BIGNUM_H__ */

