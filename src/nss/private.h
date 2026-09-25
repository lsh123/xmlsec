/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal private header for NSS.
 */
#ifndef XMLSEC_NSS_PRIVATE_H
#define XMLSEC_NSS_PRIVATE_H

#ifndef XMLSEC_PRIVATE
#error "nss/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-nss libraries"
#endif /* XMLSEC_PRIVATE */


#include <time.h>

#include <nspr.h>
#include <cert.h>
#include <nss.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>

#ifndef XMLSEC_NO_X509
#include <xmlsec/x509.h>
#endif /* XMLSEC_NO_X509 */

#include "../keysdata_helpers.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Maximum digest output size in bytes
 */
#define XMLSEC_NSS_MAX_DIGEST_SIZE              128

SECOidTag   xmlSecNssGetDigestFromHref                  (const xmlChar* href);


/******************************************************************************
 *
 * X509 Util functions
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_X509


typedef struct _xmlSecNssX509FindCertCtx {
    CERTCertDBHandle *certDb;
    PLArenaPool *arena;

    CERTName* subjectName;
    SECItem* subjectNameItem;

    CERTName* issuerName;
    SECItem* issuerNameItem;
    CERTIssuerAndSN issuerAndSN;
    int issuerAndSNInitialized;

    SECItem skiItem; /* NOT OWNED */

    const xmlSecByte * digestValue; /* NOT OWNED */
    unsigned int digestLen;
    SECOidTag digestAlg;
} xmlSecNssX509FindCertCtx, *xmlSecNssX509FindCertCtxPtr;

int        xmlSecNssX509FindCertCtxInitialize           (xmlSecNssX509FindCertCtxPtr ctx,
                                                         CERTCertDBHandle *certDb,
                                                         const xmlChar *subjectName,
                                                         const xmlChar *issuerName,
                                                         const xmlChar *issuerSerial,
                                                         xmlSecByte * ski,
                                                         xmlSecSize skiSize);
int        xmlSecNssX509FindCertCtxInitializeFromValue  (xmlSecNssX509FindCertCtxPtr ctx,
                                                         CERTCertDBHandle *certDb,
                                                         xmlSecKeyX509DataValuePtr x509Value);
void       xmlSecNssX509FindCertCtxFinalize             (xmlSecNssX509FindCertCtxPtr ctx);

int        xmlSecNssX509FindCertCtxMatch                (xmlSecNssX509FindCertCtxPtr ctx,
                                                         CERTCertificate* cert);

CERTCertificate * xmlSecNssX509StoreFindCertByValue     (xmlSecKeyDataStorePtr store,
                                                         xmlSecKeyX509DataValuePtr x509Value);
xmlSecKeyPtr xmlSecNssX509FindKeyByValue                (CERTCertDBHandle *certDb,
                                                         xmlSecPtrListPtr keysList,
                                                         xmlSecKeyX509DataValuePtr x509Value);

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

int              xmlSecNssX509StoreVerifyCrl            (xmlSecKeyDataStorePtr store,
                                                         CERTSignedCrl* crl,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);

int              xmlSecNssX509CertGetTime               (PRTime* t,
                                                         time_t* res);

CERTCertList* xmlSecNssKeyDataX509GetCerts              (xmlSecKeyDataPtr data);
xmlSecNssX509CrlNodePtr xmlSecNssKeyDataX509GetCrls     (xmlSecKeyDataPtr data);

#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NSS_PRIVATE_H */
