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
#error "mscng/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

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

typedef struct _xmlSecMSCngX509FindCertCtx {
    LPTSTR wcSubjectName;

    LPTSTR wcIssuerName;
    xmlSecBnPtr issuerSerialBn;

    const xmlSecByte * ski; /* NOT OWNED */
    DWORD skiLen;

    const xmlSecByte * digestValue; /* NOT OWNED */
    DWORD digestLen;
} xmlSecMSCngX509FindCertCtx, *xmlSecMSCngX509FindCertCtxPtr;

XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngX509FindCertCtxInitialize        (xmlSecMSCngX509FindCertCtxPtr ctx,
                                                                             const xmlChar *subjectName,
                                                                             const xmlChar *issuerName,
                                                                             const xmlChar *issuerSerial,
                                                                             const xmlSecByte * ski,
                                                                             xmlSecSize skiSize);
XMLSEC_CRYPTO_EXPORT int        xmlSecMSCngX509FindCertCtxInitializeFromValue(xmlSecMSCngX509FindCertCtxPtr ctx,
                                                                             xmlSecKeyX509DataValuePtr x509Value);
XMLSEC_CRYPTO_EXPORT void       xmlSecMSCngX509FindCertCtxFinalize           (xmlSecMSCngX509FindCertCtxPtr ctx);


XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT xmlSecMSCngX509StoreFindCertByValue     (xmlSecKeyDataStorePtr store,
                                                                             xmlSecKeyX509DataValuePtr x509Value);
XMLSEC_CRYPTO_EXPORT PCCERT_CONTEXT xmlSecMSCngX509FindCert                 (HCERTSTORE store, 
                                                                             xmlSecMSCngX509FindCertCtxPtr findCertCtx);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_PRIVATE_H__ */
