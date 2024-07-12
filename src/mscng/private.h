/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_OPENSSL_PRIVATE_H__
#define __XMLSEC_OPENSSL_PRIVATE_H__

#ifndef XMLSEC_PRIVATE
#error "mscng/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#include <xmlsec/exports.h>
#include <xmlsec/bn.h>
#include <xmlsec/xmlsec.h>

#include "../keysdata_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


 /******************************************************************************
 *
 * Key data functions
 *
 ******************************************************************************/
 xmlSecSize         xmlSecMSCngKeyDataGetSize                       (xmlSecKeyDataPtr data);

/******************************************************************************
 *
 * X509 Util functions
 *
 ******************************************************************************/
#ifndef XMLSEC_NO_X509

int                 xmlSecMSCngX509StoreVerifyKey                    (xmlSecKeyDataStorePtr store,
                                                                     xmlSecKeyPtr key,
                                                                     xmlSecKeyInfoCtxPtr keyInfoCtx);

HCERTSTORE          xmlSecMSCngKeyDataX509GetCertStore              (xmlSecKeyDataPtr data);

typedef struct _xmlSecMSCngX509FindCertCtx {
    LPTSTR wcSubjectName;

    LPTSTR wcIssuerName;
    xmlSecBnPtr issuerSerialBn;

    const xmlSecByte * ski; /* NOT OWNED */
    DWORD skiLen;

    const xmlSecByte * digestValue; /* NOT OWNED */
    DWORD digestLen;
} xmlSecMSCngX509FindCertCtx, *xmlSecMSCngX509FindCertCtxPtr;

int                 xmlSecMSCngX509FindCertCtxInitialize            (xmlSecMSCngX509FindCertCtxPtr ctx,
                                                                     const xmlChar *subjectName,
                                                                     const xmlChar *issuerName,
                                                                     const xmlChar *issuerSerial,
                                                                     const xmlSecByte * ski,
                                                                     xmlSecSize skiSize);
int                 xmlSecMSCngX509FindCertCtxInitializeFromValue   (xmlSecMSCngX509FindCertCtxPtr ctx,
                                                                     xmlSecKeyX509DataValuePtr x509Value);
void                xmlSecMSCngX509FindCertCtxFinalize              (xmlSecMSCngX509FindCertCtxPtr ctx);

PCCERT_CONTEXT      xmlSecMSCngX509StoreFindCertByValue             (xmlSecKeyDataStorePtr store,
                                                                     xmlSecKeyX509DataValuePtr x509Value);
PCCERT_CONTEXT      xmlSecMSCngX509FindCert                         (HCERTSTORE store,
                                                                     xmlSecMSCngX509FindCertCtxPtr findCertCtx);

xmlChar*            xmlSecMSCngX509GetFriendlyNameUtf8              (PCCERT_CONTEXT cert);
LPCWSTR             xmlSecMSCngX509GetFriendlyNameUnicode           (PCCERT_CONTEXT cert);


#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_PRIVATE_H__ */
