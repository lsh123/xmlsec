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

int        xmlSecNssX509FindCertCtxInitialize           (xmlSecNssX509FindCertCtxPtr ctx,
                                                         const xmlChar *subjectName,
                                                         const xmlChar *issuerName,
                                                         const xmlChar *issuerSerial,
                                                         xmlSecByte * ski,
                                                         xmlSecSize skiSize);
int        xmlSecNssX509FindCertCtxInitializeFromValue  (xmlSecNssX509FindCertCtxPtr ctx,
                                                         xmlSecKeyX509DataValuePtr x509Value);
void       xmlSecNssX509FindCertCtxFinalize             (xmlSecNssX509FindCertCtxPtr ctx);

int        xmlSecNssX509FindCertCtxMatch                (xmlSecNssX509FindCertCtxPtr ctx,
                                                         CERTCertificate* cert);

CERTCertificate * xmlSecNssX509StoreFindCertByValue     (xmlSecKeyDataStorePtr store,
                                                         xmlSecKeyX509DataValuePtr x509Value);
xmlSecKeyPtr xmlSecNssX509FindKeyByValue                (xmlSecPtrListPtr keysList,
                                                         xmlSecKeyX509DataValuePtr x509Value);

SECOidTag   xmlSecNssX509GetDigestFromAlgorithm          (const xmlChar* href);

int         xmlSecNssX509StoreVerifyKey                 (xmlSecKeyDataStorePtr store,
                                                         xmlSecKeyPtr key,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);


/* NSS has a list for Certs but not Crls so we have to do it ourselves */
typedef struct _xmlSecNssX509CrlNode xmlSecNssX509CrlNode, *xmlSecNssX509CrlNodePtr;
struct _xmlSecNssX509CrlNode {
    xmlSecNssX509CrlNodePtr  next;
    CERTSignedCrl           *crl;
};

xmlSecNssX509CrlNodePtr xmlSecNssX509CrlListDuplicate  (xmlSecNssX509CrlNodePtr head);
void       xmlSecNssX509CrlListDestroy                 (xmlSecNssX509CrlNodePtr head);
int        xmlSecNssX509CrlListAdoptCrl                (xmlSecNssX509CrlNodePtr * head,
                                                        CERTSignedCrl* crl);

CERTCertificate* xmlSecNssX509CertDerRead               (CERTCertDBHandle *handle,
                                                         xmlSecByte* buf,
                                                         xmlSecSize size);
CERTCertificate* xmlSecNssX509CertPemRead               (CERTCertDBHandle *handle,
                                                         xmlSecByte* buf,
                                                         xmlSecSize size);
CERTSignedCrl*   xmlSecNssX509CrlDerRead                (xmlSecByte* buf,
                                                         xmlSecSize size,
                                                         unsigned int flags);

int              xmlSecNssX509CertGetTime               (PRTime* t,
                                                         time_t* res);

CERTCertList* xmlSecNssKeyDataX509GetCerts              (xmlSecKeyDataPtr data);
xmlSecNssX509CrlNodePtr xmlSecNssKeyDataX509GetCrls     (xmlSecKeyDataPtr data);

#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_PRIVATE_H__ */
