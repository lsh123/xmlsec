/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef __XMLSEC_MSCRYPTO_CERTKEYS_H__
#define __XMLSEC_MSCRYPTO_CERTKEYS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT 	xmlSecMSCryptoKeyDataGetCert	(xmlSecKeyDataPtr data);
HCRYPTKEY xmlSecMSCryptoKeyDataGetKey					(xmlSecKeyDataPtr data, 
									 xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT int 		xmlSecMSCryptoKeyDataDuplicate	(xmlSecKeyDataPtr dst, 
									 xmlSecKeyDataPtr src);
XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT 	xmlSecMSCryptoCertDup		(PCCERT_CONTEXT pCert);
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataPtr 	xmlSecMSCryptoCertAdopt		(PCCERT_CONTEXT pCert, xmlSecKeyDataType type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCRYPTO_PCCERT_CONTEXT_H__ */


