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
#ifndef __XMLSEC_NSS_PRIVATE_H__
#define __XMLSEC_NSS_PRIVATE_H__

#ifndef XMLSEC_PRIVATE
#error "nss/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */


#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifndef XMLSEC_NO_X509
#include <xmlsec/x509.h>
#endif /* XMLSEC_NO_X509 */

#include "../keysdata_helpers.h"
#include "private.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Maximum digest output size in bytes
 */
#define XMLSEC_NSS_MAX_DIGEST_SIZE              128


/******************************************************************************
 *
 * X509 Util functions
 *
 ******************************************************************************/
#ifndef XMLSEC_NO_X509


typedef struct _xmlSecNssX509FindCertCtx {
    PRArenaPool *arena;

    CERTName* subjectName;
    SECItem* subjectNameItem;

    CERTName* issuerName;
    SECItem* issuerNameItem;
    PRUint64 issuerSN;
    CERTIssuerAndSN issuerAndSN;
    int issuerAndSNInitialized;

    SECItem skiItem; /* NOT OWNED */

    const xmlSecByte * digestValue; /* NOT OWNED */
    unsigned int digestLen;
    SECOidTag digestAlg;
} xmlSecNssX509FindCertCtx, *xmlSecNssX509FindCertCtxPtr;

XMLSEC_CRYPTO_EXPORT int        xmlSecNssX509FindCertCtxInitialize          (xmlSecNssX509FindCertCtxPtr ctx,
                                                                             const xmlChar *subjectName,
                                                                             const xmlChar *issuerName,
                                                                             const xmlChar *issuerSerial,
                                                                             xmlSecByte * ski,
                                                                             xmlSecSize skiSize);
XMLSEC_CRYPTO_EXPORT int        xmlSecNssX509FindCertCtxInitializeFromValue(xmlSecNssX509FindCertCtxPtr ctx,
                                                                             xmlSecKeyX509DataValuePtr x509Value);
XMLSEC_CRYPTO_EXPORT void       xmlSecNssX509FindCertCtxFinalize            (xmlSecNssX509FindCertCtxPtr ctx);

XMLSEC_CRYPTO_EXPORT int        xmlSecNssX509FindCertCtxMatch               (xmlSecNssX509FindCertCtxPtr ctx,
                                                                             CERTCertificate* cert);

XMLSEC_CRYPTO_EXPORT CERTCertificate * xmlSecNssX509StoreFindCertByValue    (xmlSecKeyDataStorePtr store,
                                                                             xmlSecKeyX509DataValuePtr x509Value);
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr xmlSecNssX509FindKeyByValue               (xmlSecPtrListPtr keysList,
                                                                             xmlSecKeyX509DataValuePtr x509Value);

XMLSEC_CRYPTO_EXPORT SECOidTag  xmlSecNssX509GetDigestFromAlgorithm         (const xmlChar* href);


/* NSS has a list for Certs but not Crls so we have to do it ourselves */
typedef struct _xmlSecNssX509CrlNode xmlSecNssX509CrlNode, *xmlSecNssX509CrlNodePtr;
struct _xmlSecNssX509CrlNode {
    xmlSecNssX509CrlNodePtr  next;
    CERTSignedCrl           *crl;
};

XMLSEC_CRYPTO_EXPORT xmlSecNssX509CrlNodePtr xmlSecNssX509CrlListDuplicate  (xmlSecNssX509CrlNodePtr head);
XMLSEC_CRYPTO_EXPORT void       xmlSecNssX509CrlListDestroy                 (xmlSecNssX509CrlNodePtr head);
XMLSEC_CRYPTO_EXPORT int        xmlSecNssX509CrlListAdoptCrl                (xmlSecNssX509CrlNodePtr * head,
                                                                             CERTSignedCrl* crl);

XMLSEC_CRYPTO_EXPORT CERTCertificate* xmlSecNssX509CertDerRead               (CERTCertDBHandle *handle,
                                                                              xmlSecByte* buf,
                                                                              xmlSecSize size);
XMLSEC_CRYPTO_EXPORT CERTSignedCrl*   xmlSecNssX509CrlDerRead                (xmlSecByte* buf,
                                                                              xmlSecSize size,
                                                                              unsigned int flags);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_PRIVATE_H__ */
