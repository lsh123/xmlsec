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

XMLSEC_CRYPTO_EXPORT int	xmlSecMSCryptoNodeGetBigNumValue(const xmlNodePtr cur, xmlSecBufferPtr retval);
XMLSEC_CRYPTO_EXPORT int 	xmlSecMSCryptoNodeSetBigNumValue(xmlNodePtr cur, const xmlSecBufferPtr a, int addLineBreaks);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCRYPTO_BIGNUM_H__ */

