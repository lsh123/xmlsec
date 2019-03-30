/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_X509_H__
#define __XMLSEC_MSCNG_X509_H__

#ifndef XMLSEC_NO_X509

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * xmlSecMSCngKeyDataX509Id:
 *
 * The MSCng X509 data klass.
 */
#define xmlSecMSCngKeyDataX509Id \
        xmlSecMSCngKeyDataX509GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataX509GetKlass(void);

/**
 * xmlSecMSCngKeyDataRawX509CertId:
 *
 * The MSCng raw X509 certificate klass.
 */
#define xmlSecMSCngKeyDataRawX509CertId \
        xmlSecMSCngKeyDataRawX509CertGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataRawX509CertGetKlass(void);

/**
 * xmlSecMSCngX509StoreId:
 *
 * The MSCng X509 store klass.
 */
#define xmlSecMSCngX509StoreId \
        xmlSecMSCngX509StoreGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataStoreId xmlSecMSCngX509StoreGetKlass(void);

XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeyDataX509AdoptKeyCert   (xmlSecKeyDataPtr data,
                                                                              PCCERT_CONTEXT cert);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeyDataX509AdoptCert      (xmlSecKeyDataPtr data,
                                                                              PCCERT_CONTEXT cert);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptCert        (xmlSecKeyDataStorePtr store,
                                                                              PCCERT_CONTEXT cert,
                                                                              xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptKeyStore    (xmlSecKeyDataStorePtr store,
                                                                              HCERTSTORE keyStore);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptTrustedStore(xmlSecKeyDataStorePtr store,
                                                                              HCERTSTORE trustedStore);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptUntrustedStore(xmlSecKeyDataStorePtr store,
                                                                                HCERTSTORE untrustedStore);
XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT     xmlSecMSCngX509StoreVerify           (xmlSecKeyDataStorePtr store,
									      HCERTSTORE certs,
									      xmlSecKeyInfoCtx* keyInfoCtx);
PCCERT_CONTEXT                          xmlSecMSCngX509StoreFindCert         (xmlSecKeyDataStorePtr store,
                                                                              xmlChar *subjectName,
                                                                              xmlChar *issuerName,
                                                                              xmlChar *issuerSerial,
                                                                              xmlChar *ski,
                                                                              xmlSecKeyInfoCtx* keyInfoCtx);
PCCERT_CONTEXT                          xmlSecMSCngX509FindCertBySubject     (HCERTSTORE store,
                                                                              LPTSTR wcSubject,
                                                                              DWORD dwCertEncodingType);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_X509 */

#endif /* __XMLSEC_MSCNG_X509_H__ */
