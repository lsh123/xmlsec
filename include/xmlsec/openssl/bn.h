/** 
 * XMLSec library
 * 
 * Reading/writing BIGNUM values
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_BN_H__
#define __XMLSEC_OPENSSL_BN_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <openssl/bn.h>
#include <xmlsec/xmlsec.h>



XMLSEC_EXPORT int	xmlSecBnToCryptoBinary		(const BIGNUM *a, 
							 unsigned char** value, 
							 size_t* valueSize);
XMLSEC_EXPORT BIGNUM*	xmlSecBnFromCryptoBinary	(const unsigned char* value, 
							 size_t valueSize, 
							 BIGNUM **a);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_BN_H__ */

