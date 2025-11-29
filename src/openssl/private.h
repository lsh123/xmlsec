/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_OPENSSL_PRIVATE_H__
#define __XMLSEC_OPENSSL_PRIVATE_H__

#ifndef XMLSEC_PRIVATE
#error "openssl/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */


#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#include "../keysdata_helpers.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/******************************************************************************
 *
 * RSA Util functions
 *
 ******************************************************************************/
#ifndef XMLSEC_NO_RSA

int             xmlSecOpenSSLKeyValueRsaCheckKeyType            (EVP_PKEY* pKey);

#endif /* XMLSEC_NO_RSA */

/******************************************************************************
 *
 * X509 Util functions
 *
 ******************************************************************************/
#ifndef XMLSEC_NO_X509

typedef struct _xmlSecOpenSSLX509FindCertCtx {
    X509_NAME * subjectName;
    X509_NAME * issuerName;
    ASN1_INTEGER * issuerSerial;
    const xmlSecByte * ski; /* NOT OWNED */
    int skiLen;

    const xmlSecByte * digestValue; /* NOT OWNED */
    unsigned int digestLen;
    const EVP_MD* digestMd;
} xmlSecOpenSSLX509FindCertCtx, *xmlSecOpenSSLX509FindCertCtxPtr;

int             xmlSecOpenSSLX509FindCertCtxInitialize          (xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                 const xmlChar *subjectName,
                                                                 const xmlChar *issuerName,
                                                                 const xmlChar *issuerSerial,
                                                                 const xmlSecByte * ski,
                                                                 xmlSecSize skiSize);
int             xmlSecOpenSSLX509FindCertCtxInitializeFromValue (xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                 xmlSecKeyX509DataValuePtr x509Value);
void            xmlSecOpenSSLX509FindCertCtxFinalize            (xmlSecOpenSSLX509FindCertCtxPtr ctx);

int             xmlSecOpenSSLX509FindCertCtxMatch               (xmlSecOpenSSLX509FindCertCtxPtr ctx,
                                                                 X509* cert);



X509*           xmlSecOpenSSLX509StoreFindCertByValue           (xmlSecKeyDataStorePtr store,
                                                                 xmlSecKeyX509DataValuePtr x509Value);


xmlSecKeyPtr    xmlSecOpenSSLX509FindKeyByValue                 (xmlSecPtrListPtr keysList,
                                                                 xmlSecKeyX509DataValuePtr x509Value);

const EVP_MD*   xmlSecOpenSSLX509GetDigestFromAlgorithm         (const xmlChar* href);



X509*           xmlSecOpenSSLX509CertLoadBIO                    (BIO* bio,
                                                                 xmlSecKeyDataFormat format);
X509_CRL*       xmlSecOpenSSLX509CrlLoadBIO                     (BIO* bio,
                                                                 xmlSecKeyDataFormat format);

int             xmlSecOpenSSLX509Asn1TimeToTime                 (const ASN1_TIME * t, time_t * res);


STACK_OF(X509)*        xmlSecOpenSSLKeyDataX509GetCerts         (xmlSecKeyDataPtr data);
STACK_OF(X509_CRL)*    xmlSecOpenSSLKeyDataX509GetCrls          (xmlSecKeyDataPtr data);

#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_PRIVATE_H__ */
