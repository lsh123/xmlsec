/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef XMLSEC_MSCNG_X509_H
#define XMLSEC_MSCNG_X509_H

/**
 * @defgroup xmlsec_mscng_x509 MsCng X.509 Support
 * @ingroup xmlsec_mscng
 * @brief X.509 certificate handling for the MsCng back-end.
 * @{
 */

#ifndef XMLSEC_NO_X509

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>

#include <windows.h>
#include <wincrypt.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief The MSCng X509 data klass.
 */
#define xmlSecMSCngKeyDataX509Id \
        xmlSecMSCngKeyDataX509GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataX509GetKlass(void);

/**
 * @brief The MSCng raw X509 certificate klass.
 */
#define xmlSecMSCngKeyDataRawX509CertId \
        xmlSecMSCngKeyDataRawX509CertGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataRawX509CertGetKlass(void);

/**
 * @brief The MSCng X509 store klass.
 */
#define xmlSecMSCngX509StoreId \
        xmlSecMSCngX509StoreGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataStoreId xmlSecMSCngX509StoreGetKlass(void);

XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT     xmlSecMSCngKeyDataX509GetKeyCert     (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeyDataX509AdoptKeyCert   (xmlSecKeyDataPtr data,
                                                                              PCCERT_CONTEXT cert);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeyDataX509AdoptCert      (xmlSecKeyDataPtr data,
                                                                              PCCERT_CONTEXT cert);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeyDataX509AdoptCrl       (xmlSecKeyDataPtr data,
                                                                              PCCRL_CONTEXT crl);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptCert        (xmlSecKeyDataStorePtr store,
                                                                              PCCERT_CONTEXT cert,
                                                                              xmlSecKeyDataType type);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptCrl         (xmlSecKeyDataStorePtr store,
                                                                              PCCRL_CONTEXT crl);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreVerifyCrl        (xmlSecKeyDataStorePtr store,
                                                                              PCCRL_CONTEXT crl,
                                                                              xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptKeyStore    (xmlSecKeyDataStorePtr store,
                                                                              HCERTSTORE keyStore);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptTrustedStore (xmlSecKeyDataStorePtr store,
                                                                               HCERTSTORE trustedStore);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngX509StoreAdoptUntrustedStore (xmlSecKeyDataStorePtr store,
                                                                                 HCERTSTORE untrustedStore);
XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT     xmlSecMSCngX509StoreVerify           (xmlSecKeyDataStorePtr store,
                                                                              HCERTSTORE certs,
                                                                              xmlSecKeyInfoCtxPtr keyInfoCtx);

/******************************************************************************
 *
 * DEPRECATED
 *
  *****************************************************************************/
XMLSEC_CRYPTO_EXPORT XMLSEC_DEPRECATED PCCERT_CONTEXT xmlSecMSCngX509StoreFindCert     (xmlSecKeyDataStorePtr store,
                                                                                        xmlChar *subjectName,
                                                                                        xmlChar *issuerName,
                                                                                        xmlChar *issuerSerial,
                                                                                        xmlChar *ski,
                                                                                        xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_CRYPTO_EXPORT XMLSEC_DEPRECATED PCCERT_CONTEXT xmlSecMSCngX509StoreFindCert_ex  (xmlSecKeyDataStorePtr store,
                                                                                        xmlChar* subjectName,
                                                                                        xmlChar* issuerName,
                                                                                        xmlChar* issuerSerial,
                                                                                        xmlSecByte* ski,
                                                                                        xmlSecSize skiSize,
                                                                                        xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_CRYPTO_EXPORT XMLSEC_DEPRECATED PCCERT_CONTEXT xmlSecMSCngX509FindCertBySubject (HCERTSTORE store,
                                                                                         LPTSTR wcSubject,
                                                                                         DWORD dwCertEncodingType);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_X509 */

/** @} */ /* xmlsec_mscng_x509 */

#endif /* XMLSEC_MSCNG_X509_H */
