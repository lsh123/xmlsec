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


#ifndef XMLSEC_NO_X509
#include <openssl/x509.h>
#endif /* XMLSEC_NO_X509 */

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#include "../keysdata_helpers.h"

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
} xmlSecOpenSSLX509FindCertCtx, *xmlSecOpenSSLX509FindCertCtxPtr;

XMLSEC_CRYPTO_EXPORT int        xmlSecOpenSSLX509FindCertCtxInitialize      (xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                             const xmlChar *subjectName,
                                                                             const xmlChar *issuerName,
                                                                             xmlChar *issuerSerial,
                                                                             const xmlSecByte * ski,
                                                                             xmlSecSize skiSize);
XMLSEC_CRYPTO_EXPORT int        xmlSecOpenSSLX509FindCertCtxInitializeFromValue(xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                             xmlSecKeyValueX509Ptr x509Value);
XMLSEC_CRYPTO_EXPORT void       xmlSecOpenSSLX509FindCertCtxFinalize        (xmlSecOpenSSLX509FindCertCtxPtr ctx);

XMLSEC_CRYPTO_EXPORT int        xmlSecOpenSSLX509FindCertCtxMatch          (xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                            X509* cert);



XMLSEC_CRYPTO_EXPORT X509*              xmlSecOpenSSLX509StoreFindCertByValue(xmlSecKeyDataStorePtr store,
                                                                              xmlSecKeyValueX509Ptr x509Value);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_PRIVATE_H__ */
