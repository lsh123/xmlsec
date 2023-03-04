/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_OPENSSL_PRIVATE_H__
#define __XMLSEC_OPENSSL_PRIVATE_H__

#ifndef XMLSEC_PRIVATE
#error "openssl/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */


#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#include "../keysdata_helpers.h"

#ifndef XMLSEC_NO_X509
#include <openssl/x509_vfy.h>
#include <openssl/x509.h>
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * X509 Util functions
 *
 ******************************************************************************/
#ifndef XMLSEC_NO_X509

typedef struct _xmlSecOpenSSLX509FindCertCtx {
    X509_NAME *subjectName;
    X509_NAME * issuerName;
    ASN1_INTEGER * issuerSerial;
    const xmlSecByte * ski; /* NOT OWNED */
    int skiLen;

    const xmlSecByte * digestValue; /* NOT OWNED */
    unsigned int digestLen;
    const EVP_MD* digestMd;
} xmlSecOpenSSLX509FindCertCtx, *xmlSecOpenSSLX509FindCertCtxPtr;

XMLSEC_CRYPTO_EXPORT int        xmlSecOpenSSLX509FindCertCtxInitialize      (xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                             const xmlChar *subjectName,
                                                                             const xmlChar *issuerName,
                                                                             const xmlChar *issuerSerial,
                                                                             const xmlSecByte * ski,
                                                                             xmlSecSize skiSize);
XMLSEC_CRYPTO_EXPORT int        xmlSecOpenSSLX509FindCertCtxInitializeFromValue(xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                             xmlSecKeyX509DataValuePtr x509Value);
XMLSEC_CRYPTO_EXPORT void       xmlSecOpenSSLX509FindCertCtxFinalize        (xmlSecOpenSSLX509FindCertCtxPtr ctx);

XMLSEC_CRYPTO_EXPORT int        xmlSecOpenSSLX509FindCertCtxMatch          (xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                            X509* cert);



XMLSEC_CRYPTO_EXPORT X509*      xmlSecOpenSSLX509StoreFindCertByValue       (xmlSecKeyDataStorePtr store,
                                                                             xmlSecKeyX509DataValuePtr x509Value);


XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecOpenSSLX509FindKeyByValue           (xmlSecPtrListPtr keysList,
                                                                             xmlSecKeyX509DataValuePtr x509Value);

XMLSEC_CRYPTO_EXPORT const EVP_MD* xmlSecOpenSSLX509GetDigestFromAlgorithm  (const xmlChar* href);



XMLSEC_CRYPTO_EXPORT X509*       xmlSecOpenSSLX509CertLoadBIO               (BIO* bio,
                                                                             xmlSecKeyDataFormat format);
XMLSEC_CRYPTO_EXPORT X509_CRL*   xmlSecOpenSSLX509CrlLoadBIO                (BIO* bio,
                                                                             xmlSecKeyDataFormat format);

XMLSEC_CRYPTO_EXPORT time_t      xmlSecOpenSSLX509Asn1TimeToTime            (const ASN1_TIME * t);

#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_PRIVATE_H__ */
