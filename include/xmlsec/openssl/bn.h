/** 
 * XMLSec library
 * 
 * Reading/writing BIGNUM values
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_BN_H__
#define __XMLSEC_BN_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <openssl/bn.h>

#include <libxml/tree.h> 

#include <xmlsec/xmlsec.h>

XMLSEC_CRYPTO_EXPORT BIGNUM*	xmlSecOpenSSLNodeGetBNValue	(const xmlNodePtr cur,
							 BIGNUM **a);
XMLSEC_CRYPTO_EXPORT int	xmlSecOpenSSLNodeSetBNValue	(xmlNodePtr cur, 
							 const BIGNUM *a,
							 int addLineBreaks);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_BN_H__ */

