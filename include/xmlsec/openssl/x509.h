/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_X509_H__
#define __XMLSEC_OPENSSL_X509_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#ifndef XMLSEC_NO_X509

#include <openssl/x509.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

/**
 * xmlSecOpenSSLKeyDataX509Id:
 * 
 * The OpenSSL X509 data klass.
 */
#define xmlSecOpenSSLKeyDataX509Id \
	xmlSecOpenSSLKeyDataX509GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecOpenSSLKeyDataX509GetKlass(void);

XMLSEC_CRYPTO_EXPORT X509* 		xmlSecOpenSSLKeyDataX509GetKeyCert(xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, 
									 X509* cert);

XMLSEC_CRYPTO_EXPORT int 		xmlSecOpenSSLKeyDataX509AdoptCert(xmlSecKeyDataPtr data,
									 X509* cert);
XMLSEC_CRYPTO_EXPORT X509* 		xmlSecOpenSSLKeyDataX509GetCert	(xmlSecKeyDataPtr data,
									 xmlSecSize pos);
XMLSEC_CRYPTO_EXPORT xmlSecSize		xmlSecOpenSSLKeyDataX509GetCertsSize(xmlSecKeyDataPtr data);

XMLSEC_CRYPTO_EXPORT int 		xmlSecOpenSSLKeyDataX509AdoptCrl(xmlSecKeyDataPtr data,
									 X509_CRL* crl);
XMLSEC_CRYPTO_EXPORT X509_CRL*		xmlSecOpenSSLKeyDataX509GetCrl	(xmlSecKeyDataPtr data,
									 xmlSecSize pos);
XMLSEC_CRYPTO_EXPORT xmlSecSize		xmlSecOpenSSLKeyDataX509GetCrlsSize(xmlSecKeyDataPtr data);


/**
 * xmlSecOpenSSLKeyDataRawX509CertId:
 * 
 * The OpenSSL raw X509 certificate klass.
 */
#define xmlSecOpenSSLKeyDataRawX509CertId \
	xmlSecOpenSSLKeyDataRawX509CertGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId 	xmlSecOpenSSLKeyDataRawX509CertGetKlass(void);

/**
 * xmlSecOpenSSLX509StoreId:
 * 
 * The OpenSSL X509 store klass.
 */
#define xmlSecOpenSSLX509StoreId \
	xmlSecOpenSSLX509StoreGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataStoreId xmlSecOpenSSLX509StoreGetKlass(void);
XMLSEC_CRYPTO_EXPORT X509* 		xmlSecOpenSSLX509StoreFindCert	(xmlSecKeyDataStorePtr store,
									 xmlChar *subjectName,
									 xmlChar *issuerName, 
									 xmlChar *issuerSerial,
									 xmlChar *ski,
									 xmlSecKeyInfoCtx* keyInfoCtx);
XMLSEC_CRYPTO_EXPORT X509* 		xmlSecOpenSSLX509StoreVerify	(xmlSecKeyDataStorePtr store,
									 STACK_OF(X509)* certs,
									 STACK_OF(X509_CRL)* crls,
									 xmlSecKeyInfoCtx* keyInfoCtx);
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLX509StoreAdoptCert	(xmlSecKeyDataStorePtr store,
									 X509* cert,
									 xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT int		xmlSecOpenSSLX509StoreAddCertsPath(xmlSecKeyDataStorePtr store,
									 const char* path);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_X509_H__ */
