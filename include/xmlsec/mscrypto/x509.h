/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef __XMLSEC_MSCRYPTO_X509_H__
#define __XMLSEC_MSCRYPTO_X509_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#ifndef XMLSEC_NO_X509

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

/**
 * xmlSecMSCryptoKeyDataX509Id:
 * 
 * The MSCrypto X509 data klass.
 */
#define xmlSecMSCryptoKeyDataX509Id \
	xmlSecMSCryptoKeyDataX509GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecMSCryptoKeyDataX509GetKlass(void);

XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT	xmlSecMSCryptoKeyDataX509GetKeyCert(xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT int		xmlSecMSCryptoKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, 
									      PCCERT_CONTEXT pCertContext);

XMLSEC_CRYPTO_EXPORT int 		xmlSecMSCryptoKeyDataX509AdoptCert(xmlSecKeyDataPtr data,
									   PCCERT_CONTEXT pCertContext);
XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT	xmlSecMSCryptoKeyDataX509GetCert    (xmlSecKeyDataPtr data,
									     xmlSecSize pos);
XMLSEC_CRYPTO_EXPORT xmlSecSize		xmlSecMSCryptoKeyDataX509GetCertsSize(xmlSecKeyDataPtr data);

XMLSEC_CRYPTO_EXPORT int 		xmlSecMSCryptoKeyDataX509AdoptCrl(xmlSecKeyDataPtr data,
									 PCCRL_CONTEXT crl);
XMLSEC_CRYPTO_EXPORT PCCRL_CONTEXT	xmlSecMSCryptoKeyDataX509GetCrl	(xmlSecKeyDataPtr data,
									 xmlSecSize pos);
XMLSEC_CRYPTO_EXPORT xmlSecSize		xmlSecMSCryptoKeyDataX509GetCrlsSize(xmlSecKeyDataPtr data);


/**
 * xmlSecMSCryptoKeyDataRawX509CertId:
 * 
 * The MSCrypto raw X509 certificate klass.
 */
#define xmlSecMSCryptoKeyDataRawX509CertId \
	xmlSecMSCryptoKeyDataRawX509CertGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecMSCryptoKeyDataRawX509CertGetKlass(void);

/**
 * xmlSecMSCryptoX509StoreId:
 * 
 * The MSCrypto X509 store klass.
 */
#define xmlSecMSCryptoX509StoreId \
	xmlSecMSCryptoX509StoreGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataStoreId xmlSecMSCryptoX509StoreGetKlass(void);

XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT 	xmlSecMSCryptoX509StoreFindCert		(xmlSecKeyDataStorePtr store,
									 	 xmlChar *subjectName,
									 	 xmlChar *issuerName, 
									 	 xmlChar *issuerSerial,
									 	 xmlChar *ski,
									 	 xmlSecKeyInfoCtx* keyInfoCtx);


XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT 	xmlSecMSCryptoX509StoreVerify		(xmlSecKeyDataStorePtr store,
									 	 HCERTSTORE certs,
									 	 xmlSecKeyInfoCtx* keyInfoCtx);
XMLSEC_CRYPTO_EXPORT int		xmlSecMSCryptoX509StoreAdoptCert 	(xmlSecKeyDataStorePtr store,
																			  PCCERT_CONTEXT pCertContext,
																			  xmlSecKeyDataType type);


#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCRYPTO_X509_H__ */
