/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * X509 certificates implementation for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:x509
 * @Short_description: X509 certificates implementation for NSS.
 * @Stability: Stable
 *
 * X509 certificates implementation for NSS.
 */

#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include <prmem.h>
#include <pratom.h>
#include <keyhi.h>
#include <cert.h>
#include <certdb.h>
#include <pk11func.h>
#include <sechash.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/x509.h>
#include <xmlsec/nss/pkikeys.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "private.h"

/* workaround - NSS exports this but doesn't declare it */
extern CERTCertificate * __CERT_NewTempCertificate(CERTCertDBHandle *handle,
                                                   SECItem *derCert,
                                                   char *nickname,
                                                   PRBool isperm,
                                                   PRBool copyDER);

/*************************************************************************
 *
 * X509 utility functions
 *
 ************************************************************************/
static int              xmlSecNssVerifyAndAdoptX509KeyData     (xmlSecKeyPtr key,
                                                                xmlSecKeyDataPtr data,
                                                                xmlSecKeyInfoCtxPtr keyInfoCtx);

static int              xmlSecNssX509SECItemWrite               (SECItem * secItem,
                                                                 xmlSecBufferPtr buf);
static xmlChar*         xmlSecNssX509NameWrite                  (CERTName* nm);
static xmlChar*         xmlSecNssASN1IntegerWrite               (SECItem *num);
static int              xmlSecNssX509DigestWrite                (CERTCertificate* cert,
                                                                 const xmlChar* algorithm,
                                                                 xmlSecBufferPtr buf);
static void             xmlSecNssX509CertDebugDump              (CERTCertificate* cert,
                                                                 FILE* output);
static void             xmlSecNssX509CertDebugXmlDump           (CERTCertificate* cert,
                                                                 FILE* output);


/*************************************************************************
 *
 * Internal NSS X509 data CTX
 *
 ************************************************************************/
typedef struct _xmlSecNssX509DataCtx {
    CERTCertificate*  keyCert;  /* OWNED BY certsList */

    CERTCertList*    certsList;
    unsigned int     numCerts;

    xmlSecNssX509CrlNodePtr crlsList;
    unsigned int     numCrls;
} xmlSecNssX509DataCtx, *xmlSecNssX509DataCtxPtr;

/**************************************************************************
 *
 * &lt;dsig:X509Data/&gt; processing (http://www.w3.org/TR/xmldsig-core/#sec-X509Data)
 *
 *************************************************************************/
XMLSEC_KEY_DATA_DECLARE(NssX509Data, xmlSecNssX509DataCtx)
#define xmlSecNssX509DataSize XMLSEC_KEY_DATA_SIZE(NssX509Data)

static int              xmlSecNssKeyDataX509Initialize  (xmlSecKeyDataPtr data);
static int              xmlSecNssKeyDataX509Duplicate   (xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecNssKeyDataX509Finalize    (xmlSecKeyDataPtr data);
static int              xmlSecNssKeyDataX509XmlRead     (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecNssKeyDataX509XmlWrite    (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyDataType xmlSecNssKeyDataX509GetType    (xmlSecKeyDataPtr data);
static const xmlChar* xmlSecNssKeyDataX509GetIdentifier (xmlSecKeyDataPtr data);

static void             xmlSecNssKeyDataX509DebugDump   (xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecNssKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

typedef struct _xmlSecNssKeyDataX509Context {
    xmlSecSize crtPos;
    xmlSecSize crtSize;
    xmlSecSize crlPos;
    xmlSecSize crlSize;
} xmlSecNssDataX509Context;

static int              xmlSecNssKeyDataX509Read        (xmlSecKeyDataPtr data,
                                                         xmlSecKeyX509DataValuePtr x509Value,
                                                         xmlSecKeysMngrPtr keysMngr,
                                                         unsigned int flags);
static int              xmlSecNssKeyDataX509Write        (xmlSecKeyDataPtr data,
                                                         xmlSecKeyX509DataValuePtr x509Value,
                                                         int content,
                                                         void* context);

static xmlSecKeyDataKlass xmlSecNssKeyDataX509Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecNssX509DataSize,

    /* data */
    xmlSecNameX509Data,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefX509Data,                         /* const xmlChar* href; */
    xmlSecNodeX509Data,                         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecNssKeyDataX509Initialize,             /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecNssKeyDataX509Duplicate,              /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecNssKeyDataX509Finalize,               /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecNssKeyDataX509GetType,                /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    xmlSecNssKeyDataX509GetIdentifier,          /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecNssKeyDataX509XmlRead,                /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecNssKeyDataX509XmlWrite,               /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecNssKeyDataX509DebugDump,              /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecNssKeyDataX509DebugXmlDump,           /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssKeyDataX509GetKlass:
 *
 * The NSS X509 key data klass (http://www.w3.org/TR/xmldsig-core/#sec-X509Data).
 *
 * Returns: the X509 data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataX509GetKlass(void) {
    return(&xmlSecNssKeyDataX509Klass);
}

/**
 * xmlSecNssKeyDataX509GetKeyCert:
 * @data:               the pointer to X509 key data.
 *
 * Gets the certificate from which the key was extracted.
 *
 * Returns: the key's certificate or NULL if key data was not used for key
 * extraction or an error occurs.
 */
CERTCertificate*
xmlSecNssKeyDataX509GetKeyCert(xmlSecKeyDataPtr data) {
    xmlSecNssX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), NULL);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->keyCert);
}

CERTCertList*
xmlSecNssKeyDataX509GetCerts(xmlSecKeyDataPtr data) {
    xmlSecNssX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), NULL);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->certsList);
}

xmlSecNssX509CrlNodePtr
xmlSecNssKeyDataX509GetCrls(xmlSecKeyDataPtr data) {
    xmlSecNssX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), NULL);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->crlsList);
}

static CERTCertListNode*
xmlSecNssKeyDataX509FindCertInternal(xmlSecNssX509DataCtxPtr ctx, CERTCertificate* cert) {
    CERTCertListNode* cur;

    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);

    if(ctx->certsList == NULL) {
        return(NULL);
    }
    for(cur = CERT_LIST_HEAD(ctx->certsList); !CERT_LIST_END(cur, ctx->certsList); cur = CERT_LIST_NEXT(cur)) {
        if((cur->cert == cert) || (CERT_CompareCerts(cert, cur->cert) == PR_TRUE)) {
            return(cur);
        }
    }
    return(NULL);
}

static int
xmlSecNssKeyDataX509AddCertInternal(xmlSecNssX509DataCtxPtr ctx, CERTCertificate* cert, int isKeyCert) {
    CERTCertListNode* existingCertNode;
    SECStatus rv;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    if(ctx->certsList == NULL) {
        ctx->certsList = CERT_NewCertList();
        if(ctx->certsList == NULL) {
            xmlSecNssError("CERT_NewCertList", NULL);
            return(-1);
        }
    }

    /* we don't want duplicates */
    existingCertNode = xmlSecNssKeyDataX509FindCertInternal(ctx, cert);
    if(existingCertNode != NULL) {
        CERT_RemoveCertListNode(existingCertNode);
        --ctx->numCerts;
    }

    /* ensure that key cert is the first one */
    if(isKeyCert != 0) {
        rv = CERT_AddCertToListHead(ctx->certsList, cert);
        if(rv != SECSuccess) {
            xmlSecNssError("CERT_AddCertToListHead", NULL);
            return(-1);
        }
    } else {
        rv = CERT_AddCertToListTail(ctx->certsList, cert);
        if(rv != SECSuccess) {
            xmlSecNssError("CERT_AddCertToListTail", NULL);
            return(-1);
        }
    }
    ++ctx->numCerts;

    /* done */
    return(0);
}

/**
 * xmlSecNssKeyDataX509AdoptKeyCert:
 * @data:               the pointer to X509 key data.
 * @cert:               the pointer to NSS X509 certificate.
 *
 * Adds certificate to the X509 key data and sets the it as the key's
 * certificate in @data. On success, the @data owns the cert.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, CERTCertificate* cert) {
    xmlSecNssX509DataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* check if for some reasons same cert is used */
    if((ctx->keyCert != NULL) && ((ctx->keyCert == cert) || (CERT_CompareCerts(cert, ctx->keyCert) == PR_TRUE))) {
        CERT_DestroyCertificate(cert);  /* caller expects data to own the cert on success. */
        return(0);
    }
    xmlSecAssert2(ctx->keyCert == NULL, -1);

    ret = xmlSecNssKeyDataX509AddCertInternal(ctx, cert, 1); /* key cert */
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKeyDataX509AddCertInternal", NULL);
        return(-1);
    }

    /* cert is now owned by data, we can't fail or there will be a double free */
    ctx->keyCert = cert;
    return(0);
}

/**
 * xmlSecNssKeyDataX509AdoptCert:
 * @data:               the pointer to X509 key data.
 * @cert:               the pointer to NSS X509 certificate.
 *
 * Adds certificate to the X509 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataX509AdoptCert(xmlSecKeyDataPtr data, CERTCertificate* cert) {
    xmlSecNssX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

   /* pkcs12 files sometime have key cert twice: as the key cert and as the cert in the chain */
    if((ctx->keyCert != NULL) && ((ctx->keyCert == cert) || (CERT_CompareCerts(cert, ctx->keyCert) == PR_TRUE))) {
        CERT_DestroyCertificate(cert); /* caller expects data to own the cert on success. */
        return(0);
    }
    return(xmlSecNssKeyDataX509AddCertInternal(ctx, cert, 0)); /* not a key cert */
}

/**
 * xmlSecNssKeyDataX509GetCert:
 * @data:               the pointer to X509 key data.
 * @pos:                the desired certificate position.
 *
 * Gets a certificate from X509 key data.
 *
 * Returns: the pointer to certificate or NULL if @pos is larger than the
 * number of certificates in @data or an error occurs.
 */
CERTCertificate*
xmlSecNssKeyDataX509GetCert(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecNssX509DataCtxPtr ctx;
    CERTCertListNode* cur;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), NULL);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->certsList != NULL, NULL);
    xmlSecAssert2(pos < ctx->numCerts, NULL);

    /* to ensure that key cert is always first we put it at the top of the list
     * in xmlSecNssKeyDataX509AddCertInternal */
    for(cur = CERT_LIST_HEAD(ctx->certsList); !CERT_LIST_END(cur, ctx->certsList); cur = CERT_LIST_NEXT(cur)) {
        if(pos <= 0) {
            return(cur->cert);
        }
        --pos;
    }

    /* not found: should not be here */
    return (NULL);
}

/**
 * xmlSecNssKeyDataX509GetCertsSize:
 * @data:               the pointer to X509 key data.
 *
 * Gets the number of certificates in @data.
 *
 * Returns: te number of certificates in @data.
 */
xmlSecSize
xmlSecNssKeyDataX509GetCertsSize(xmlSecKeyDataPtr data) {
    xmlSecNssX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), 0);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);
    return(ctx->numCerts);
}

/**
 * xmlSecNssKeyDataX509AdoptCrl:
 * @data:               the pointer to X509 key data.
 * @crl:                the pointer to NSS X509 CRL.
 *
 * Adds CRL to the X509 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataX509AdoptCrl(xmlSecKeyDataPtr data, CERTSignedCrl* crl) {
    xmlSecNssX509DataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), -1);
    xmlSecAssert2(crl != NULL, -1);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecNssX509CrlListAdoptCrl(&(ctx->crlsList), crl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509CrlListAdoptCrl", xmlSecKeyDataGetName(data));
        return(-1);
    }
    /* keep the counter updated */
    ctx->numCrls++;
    return(0);
}

/**
 * xmlSecNssKeyDataX509GetCrl:
 * @data:               the pointer to X509 key data.
 * @pos:                the desired CRL position.
 *
 * Gets a CRL from X509 key data.
 *
 * Returns: the pointer to CRL or NULL if @pos is larger than the
 * number of CRLs in @data or an error occurs.
 */
CERTSignedCrl *
xmlSecNssKeyDataX509GetCrl(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecNssX509DataCtxPtr ctx;
    xmlSecNssX509CrlNodePtr head;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), NULL);
    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    xmlSecAssert2(ctx->crlsList != NULL, NULL);
    xmlSecAssert2(pos < ctx->numCrls, NULL);

    head = ctx->crlsList;
    while (pos > 0)
    {
        head = head->next;
        pos--;
    }

    return (head->crl);
}

/**
 * xmlSecNssKeyDataX509GetCrlsSize:
 * @data:               the pointer to X509 key data.
 *
 * Gets the number of CRLs in @data.
 *
 * Returns: te number of CRLs in @data.
 */
xmlSecSize
xmlSecNssKeyDataX509GetCrlsSize(xmlSecKeyDataPtr data) {
    xmlSecNssX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), 0);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->numCrls);
}

static int
xmlSecNssKeyDataX509Initialize(xmlSecKeyDataPtr data) {
    xmlSecNssX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), -1);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssX509DataCtx));
    return(0);
}

static void
xmlSecNssKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    xmlSecNssX509DataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id));

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->certsList != NULL) {
        CERT_DestroyCertList(ctx->certsList);
        ctx->certsList = NULL;
    }
    if(ctx->crlsList != NULL) {
        xmlSecNssX509CrlListDestroy(ctx->crlsList);
        ctx->crlsList = NULL;
    }

    memset(ctx, 0, sizeof(xmlSecNssX509DataCtx));
}

static int
xmlSecNssKeyDataX509Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecNssX509DataCtxPtr ctxSrc, ctxDst;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecNssKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecNssKeyDataX509Id), -1);

    ctxSrc = xmlSecNssX509DataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    /* dst should not have any data */
    ctxDst = xmlSecNssX509DataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxDst->keyCert == NULL, -1);
    xmlSecAssert2(ctxDst->certsList == NULL, -1);
    xmlSecAssert2(ctxDst->crlsList == NULL, -1);

    /* crts */
    if(ctxSrc->certsList != NULL) {
        CERTCertListNode* cur;
        CERTCertificate* cert;

        for(cur = CERT_LIST_HEAD(ctxSrc->certsList); !CERT_LIST_END(cur, ctxSrc->certsList); cur = CERT_LIST_NEXT(cur)) {
            xmlSecAssert2(cur->cert != NULL, -1);
            cert = CERT_DupCertificate(cur->cert);
            if(cert == NULL) {
                xmlSecNssError("CERT_DupCertificate", NULL);
                return(-1);
            }

            /* handle key cert */
            if(cur->cert == ctxSrc->keyCert) {
                ret = xmlSecNssKeyDataX509AdoptKeyCert(dst, cert);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecNssKeyDataX509AdoptKeyCert", NULL);
                    CERT_DestroyCertificate(cert);
                    return(-1);
                }
            } else {
                ret = xmlSecNssKeyDataX509AdoptCert(dst, cert);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecNssKeyDataX509AdoptCert", NULL);
                    CERT_DestroyCertificate(cert);
                    return(-1);
                }
            }
            /* cert is owned by dst now */
        }
    }

    /* crls */
    if(ctxSrc->crlsList != NULL) {
        ctxDst->crlsList = xmlSecNssX509CrlListDuplicate(ctxSrc->crlsList);
        if(ctxDst->crlsList == NULL) {
            xmlSecInternalError("xmlSecNssX509CrlListDuplicate", NULL);
            return(-1);
        }
        ctxDst->numCrls = ctxSrc->numCrls;
    }

    /* done */
    return(0);
}


static int
xmlSecNssKeyDataX509XmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                            xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id == xmlSecNssKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    data = xmlSecKeyDataCreate(xmlSecNssKeyDataX509Id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecNssKeyDataX509Id)", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecKeyDataX509XmlRead(key, data, node, keyInfoCtx, xmlSecNssKeyDataX509Read);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyDataX509XmlRead", xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    }

    /* did we find the key already? */
    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecKeyDataDestroy(data);
        return(0);
    }

    ret = xmlSecNssVerifyAndAdoptX509KeyData(key, data, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssVerifyAndAdoptX509KeyData", xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    } else if(ret != 1) {
        /* no errors but key was not found and data was not adopted */
        xmlSecKeyDataDestroy(data);
        return(0);
    }
    data = NULL; /* owned by data now */

    /* success */
    return(0);
}

static int
xmlSecNssKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlSecNssDataX509Context context;
    int ret;

    xmlSecAssert2(id == xmlSecNssKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* get x509 data */
    data = xmlSecKeyGetData(key, id);
    if(data == NULL) {
        /* no x509 data in the key */
        return(0);
    }

    /* setup context */
    context.crtPos = context.crlPos = 0;
    context.crtSize = xmlSecNssKeyDataX509GetCertsSize(data);
    context.crlSize = xmlSecNssKeyDataX509GetCrlsSize(data);

    ret = xmlSecKeyDataX509XmlWrite(data, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecNssKeyDataX509Write, &context);
    if(ret < 0) {
        xmlSecInternalError3("xmlSecKeyDataX509XmlWrite",
            xmlSecKeyDataKlassGetName(id),
            "crtSize=" XMLSEC_SIZE_FMT "; crlSize=" XMLSEC_SIZE_FMT,
            context.crtSize, context.crlSize);
        return(-1);
    }

    /* success */
    return(0);
}

static xmlSecKeyDataType
xmlSecNssKeyDataX509GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), xmlSecKeyDataTypeUnknown);

    /* TODO: return verified/not verified status */
    return(xmlSecKeyDataTypeUnknown);
}

static const xmlChar*
xmlSecNssKeyDataX509GetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), NULL);

    /* TODO */
    return(NULL);
}

static void
xmlSecNssKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    CERTCertificate* cert;
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== X509 Data:\n");
    cert = xmlSecNssKeyDataX509GetKeyCert(data);
    if(cert != NULL) {
        fprintf(output, "==== Key Certificate:\n");
        xmlSecNssX509CertDebugDump(cert, output);
    }

    size = xmlSecNssKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
        cert = xmlSecNssKeyDataX509GetCert(data, pos);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssKeyDataX509GetCert",
                                 xmlSecKeyDataGetName(data),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return;
        }
        fprintf(output, "==== Certificate:\n");
        xmlSecNssX509CertDebugDump(cert, output);
    }

    /* we don't print out crls */
}

static void
xmlSecNssKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    CERTCertificate* cert;
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<X509Data>\n");
    cert = xmlSecNssKeyDataX509GetKeyCert(data);
    if(cert != NULL) {
        fprintf(output, "<KeyCertificate>\n");
        xmlSecNssX509CertDebugXmlDump(cert, output);
        fprintf(output, "</KeyCertificate>\n");
    }

    size = xmlSecNssKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
        cert = xmlSecNssKeyDataX509GetCert(data, pos);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssKeyDataX509GetCert",
                                 xmlSecKeyDataGetName(data),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return;
        }
        fprintf(output, "<Certificate>\n");
        xmlSecNssX509CertDebugXmlDump(cert, output);
        fprintf(output, "</Certificate>\n");
    }

    /* we don't print out crls */
    fprintf(output, "</X509Data>\n");
}

/* xmlSecKeyDataX509Read: 0 on success and a negative value otherwise */
static int
xmlSecNssKeyDataX509Read(xmlSecKeyDataPtr data, xmlSecKeyX509DataValuePtr x509Value,
                         xmlSecKeysMngrPtr keysMngr, unsigned int flags) {
    CERTCertificate* cert = NULL;
    CERTSignedCrl* crl = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(keysMngr != NULL, -1);

    /* read CRT or CRL */
    if(xmlSecBufferGetSize(&(x509Value->cert)) > 0) {
        cert = xmlSecNssX509CertDerRead(CERT_GetDefaultCertDB(),
            xmlSecBufferGetData(&(x509Value->cert)),
            xmlSecBufferGetSize(&(x509Value->cert))
        );
        if(cert == NULL) {
            xmlSecInternalError("xmlSecNssX509CertDerRead", xmlSecKeyDataGetName(data));
            goto done;
        }
    }
    if(xmlSecBufferGetSize(&(x509Value->crl)) > 0) {
        crl = xmlSecNssX509CrlDerRead(xmlSecBufferGetData(&(x509Value->crl)),
            xmlSecBufferGetSize(&(x509Value->crl)), flags);
        if(crl == NULL) {
            xmlSecInternalError("xmlSecNssX509CrlDerRead", xmlSecKeyDataGetName(data));
            goto done;
        }
    }

    /* if there is no cert in the X509Data node then try to find one */
    if(cert == NULL) {
        xmlSecKeyDataStorePtr x509Store;
        int stopOnUnknownCert = 0;


        x509Store = xmlSecKeysMngrGetDataStore(keysMngr, xmlSecNssX509StoreId);
        if(x509Store == NULL) {
            xmlSecInternalError("xmlSecKeysMngrGetDataStore", xmlSecKeyDataGetName(data));
            goto done;
        }

        /* determine what to do */
        if((flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
            stopOnUnknownCert = 1;
        }
        cert = xmlSecNssX509StoreFindCertByValue(x509Store, x509Value);
        if((cert == NULL) && (stopOnUnknownCert != 0)) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data), "cert lookup");
            goto done;
        }
    }

    /* if we found a cert or a crl, then add it to the data */
    if(cert != NULL) {
        ret = xmlSecNssKeyDataX509AdoptCert(data, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssKeyDataX509AdoptCert", xmlSecKeyDataGetName(data));
            goto done;
        }
        cert = NULL; /* owned by data now */
    }
    if(crl != NULL) {
        ret = xmlSecNssKeyDataX509AdoptCrl(data, crl);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssKeyDataX509AdoptCrl", xmlSecKeyDataGetName(data));
            goto done;
        }
        crl = NULL; /* owned by data now */
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(cert != NULL) {
        CERT_DestroyCertificate(cert);
    }
    if(crl != NULL) {
        SEC_DestroyCrl(crl);
    }
    return(res);
}

/* xmlSecKeyDataX509Write: returns 1 on success, 0 if no more certs/crls are available,
 * or a negative value if an error occurs.
 */
static int
xmlSecNssKeyDataX509Write(xmlSecKeyDataPtr data, xmlSecKeyX509DataValuePtr x509Value,
                          int content, void* context) {
    xmlSecNssDataX509Context* ctx;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(context != NULL, -1);

    ctx = (xmlSecNssDataX509Context*)context;

    if(ctx->crtPos < ctx->crtSize) {
        /* write cert */
        CERTCertificate* cert = xmlSecNssKeyDataX509GetCert(data, ctx->crtPos);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssKeyDataX509GetCert",
                xmlSecKeyDataGetName(data),
                "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
            return(-1);
        }
        if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_CERTIFICATE_NODE)) {
            ret = xmlSecNssX509SECItemWrite(&(cert->derCert), &(x509Value->cert));
            if(ret < 0) {
                xmlSecInternalError2("xmlSecNssX509SECItemWrite(cert)",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_SKI_NODE)) {
            SECItem ski = { siBuffer, NULL, 0 };
            SECStatus rv;

            rv = CERT_FindSubjectKeyIDExtension(cert, &ski);
            if (rv != SECSuccess) {
                xmlSecNssError("CERT_FindSubjectKeyIDExtension", NULL);
                return(-1);
            }

            ret = xmlSecNssX509SECItemWrite(&ski, &(x509Value->ski));
            if(ret < 0) {
                xmlSecInternalError2("xmlSecNssX509SECItemWrite(ski)",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                SECITEM_FreeItem(&ski, PR_FALSE);
                return(-1);
            }
            SECITEM_FreeItem(&ski, PR_FALSE);
        }
        if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_SUBJECTNAME_NODE)) {
            xmlSecAssert2(x509Value->subject == NULL, -1);

            x509Value->subject = xmlSecNssX509NameWrite(&(cert->subject));
            if(x509Value->subject == NULL) {
                xmlSecInternalError2("xmlSecNssX509NameWrite(subject)",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_ISSUERSERIAL_NODE)) {
            xmlSecAssert2(x509Value->issuerName == NULL, -1);
            xmlSecAssert2(x509Value->issuerSerial == NULL, -1);

            x509Value->issuerName = xmlSecNssX509NameWrite(&(cert->issuer));
            if(x509Value->issuerName == NULL) {
                xmlSecInternalError2("xmlSecNssX509NameWrite(ssuer)",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
            x509Value->issuerSerial = xmlSecNssASN1IntegerWrite(&(cert->serialNumber));
            if(x509Value->issuerSerial == NULL) {
                xmlSecInternalError2("xmlSecNssASN1IntegerWrite(serialNumber))",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if((XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_DIGEST_NODE)) && (x509Value->digestAlgorithm != NULL)) {
            ret = xmlSecNssX509DigestWrite(cert, x509Value->digestAlgorithm, &(x509Value->digest));
            if(ret < 0) {
                xmlSecInternalError2("xmlSecNssX509DigestWrite",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        ++ctx->crtPos;
    } else if(ctx->crlPos < ctx->crlSize) {
        /* write crl */
        CERTSignedCrl* crl = xmlSecNssKeyDataX509GetCrl(data, ctx->crlPos);
        if(crl == NULL) {
            xmlSecInternalError2("xmlSecNssKeyDataX509GetCrl",
                xmlSecKeyDataGetName(data),
                "pos=" XMLSEC_SIZE_FMT, ctx->crlPos);
            return(-1);
        }

        if((content & XMLSEC_X509DATA_CRL_NODE) != 0) {
            ret = xmlSecNssX509SECItemWrite(crl->derCrl, &(x509Value->crl));
            if(ret < 0) {
                xmlSecInternalError2("xmlSecNssX509SECItemWrite(crl)",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crlPos);
                return(-1);
            }
        }
        ++ctx->crlPos;
    } else {
        /* no more certs or crls */
        return(0);
    }

    /* success */
    return(1);
}

/* returns 1 if cert was found and verified and also data was adopted, 0 if not, or negative value if an error occurs */
static int
xmlSecNssVerifyAndAdoptX509KeyData(xmlSecKeyPtr key, xmlSecKeyDataPtr data,  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecNssX509DataCtxPtr ctx;
    xmlSecKeyDataStorePtr x509Store;
    xmlSecKeyDataPtr keyValue;
    CERTCertificate* cert;
    CERTCertificate* keyCert;
    int ret;
    SECStatus status;
    PRTime notBefore, notAfter;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataX509Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    ctx = xmlSecNssX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyCert == NULL, -1);

    if((ctx->certsList == NULL) || (xmlSecKeyGetValue(key) != NULL)) {
        /* no certs or key was already found -> nothing to do (this shouldn't really happen) */
        return(0);
    }

    /* lets find a cert we can verify */
    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecNssX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore", xmlSecKeyDataGetName(data));
        return(-1);
    }
    cert = xmlSecNssX509StoreVerify(x509Store, ctx->certsList, keyInfoCtx);
    if(cert == NULL) {
        /* check if we want to fail if cert is not found */
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT) != 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data), NULL);
            return(-1);
        }
        return(0);
    }

    /* set cert into the x509 data, we don't know if the cert is already in KeyData or not
     * so assume we need to add it again.
     */
    keyCert = CERT_DupCertificate(cert);
    if(keyCert == NULL) {
        xmlSecNssError("CERT_DupCertificate", xmlSecKeyDataGetName(data));
        return(-1);
    }
    ret = xmlSecNssKeyDataX509AdoptKeyCert(data, keyCert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509CertGetKey", xmlSecKeyDataGetName(data));
        CERT_DestroyCertificate(keyCert);
        return(-1);
    }
    cert = keyCert = NULL; /* we should be using ctx->keyCert for everything */

    /* extract key from cert and verify that the key matches our expectations */
    keyValue = xmlSecNssX509CertGetKey(ctx->keyCert);
    if(keyValue == NULL) {
        xmlSecInternalError("xmlSecNssX509CertGetKey", xmlSecKeyDataGetName(data));
        return(-1);
    }
    if(xmlSecKeyReqMatchKeyValue(&(keyInfoCtx->keyReq), keyValue) != 1) {
        xmlSecInternalError("xmlSecKeyReqMatchKeyValue", xmlSecKeyDataGetName(data));
        xmlSecKeyDataDestroy(keyValue);
        return(-1);
    }
    ret = xmlSecKeySetValue(key, keyValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataGetName(data));
        xmlSecKeyDataDestroy(keyValue);
        return(-1);
    }
    keyValue = NULL; /* owned by key now */

    /* copy cert not before / not after times from the cert */
    status = CERT_GetCertTimes(ctx->keyCert, &notBefore, &notAfter);
    if (status == SECSuccess) {
        ret = xmlSecNssX509CertGetTime(&notBefore, &(key->notValidBefore));
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssX509CertGetTime(notValidBefore)", xmlSecKeyDataGetName(data));
            return(-1);
        }
        ret = xmlSecNssX509CertGetTime(&notAfter, &(key->notValidAfter));
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssX509CertGetTime(notValidAfter)", xmlSecKeyDataGetName(data));
            return(-1);
        }
    } else {
        key->notValidBefore = key->notValidAfter = 0;
    }

    /* THIS MUST BE THE LAST THING WE DO: add data to the key
     * if we do it sooner and fail later then both the caller and the key will free data
     * which would lead to double free */
    ret = xmlSecKeyAdoptData(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData", xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* success: cert found and data was adopted */
    return(1);
}

int
xmlSecNssX509CertGetTime(PRTime* t, time_t* res) {

    PRTime tmp64_1, tmp64_2;
    PRUint32 tmp32 = 1000000;

    xmlSecAssert2(t != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    /* PRTime is time in microseconds since epoch. Divide by 1000000 to
     * convert to seconds, then convert to an unsigned 32 bit number
     */
    (*res) = 0;
    LL_UI2L(tmp64_1, tmp32);
    LL_DIV(tmp64_2, *t, tmp64_1);
    LL_L2UI(tmp32, tmp64_2);

    (*res) = (time_t)(tmp32);

    return(0);
}

/**
 * xmlSecNssX509CertGetKey:
 * @cert:               the certificate.
 *
 * Extracts public key from the @cert.
 *
 * Returns: public key value or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecNssX509CertGetKey(CERTCertificate* cert) {
    xmlSecKeyDataPtr data;
    SECKEYPublicKey *pubkey = NULL;
    SECKEYPrivateKey *privkey = NULL;

    xmlSecAssert2(cert != NULL, NULL);

    pubkey = CERT_ExtractPublicKey(cert);
    if(pubkey == NULL) {
        xmlSecNssError("CERT_ExtractPublicKey", NULL);
        return(NULL);
    }

    /* see if we can find private key too for this cert */
    privkey = PK11_FindKeyByAnyCert(cert, NULL);

    data = xmlSecNssPKIAdoptKey(privkey, pubkey);
    if(data == NULL) {
        xmlSecInternalError("xmlSecNssPKIAdoptKey", NULL);
        SECKEY_DestroyPublicKey(pubkey);
        if(privkey != NULL) {
            SECKEY_DestroyPrivateKey(privkey);
        }
        return(NULL);
    }

    return(data);
}

static int
xmlSecNssX509SECItemWrite(SECItem* secItem, xmlSecBufferPtr buf) {
    xmlSecAssert2(secItem != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    if((secItem->data != NULL) && (secItem->len > 0)) {
        int ret;

        ret = xmlSecBufferSetData(buf, secItem->data, secItem->len);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData", NULL,
                "size=%u", secItem->len);
            return(-1);
        }
    } else {
        xmlSecBufferEmpty(buf);
    }
    return(0);
}

CERTCertificate*
xmlSecNssX509CertDerRead(CERTCertDBHandle *handle, xmlSecByte* buf, xmlSecSize size) {
    CERTCertificate *cert;
    SECItem  derCert = { siBuffer, NULL, 0 };

    xmlSecAssert2(handle != NULL, NULL);
    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    derCert.data = buf;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, derCert.len, return(NULL), NULL);

    /* decode cert and import to temporary cert db */
    cert = __CERT_NewTempCertificate(handle, &derCert, NULL, PR_FALSE, PR_TRUE);
    if(cert == NULL) {
        xmlSecNssError("__CERT_NewTempCertificate", NULL);
        return(NULL);
    }

    return(cert);
}

CERTSignedCrl*
xmlSecNssX509CrlDerRead(xmlSecByte* buf, xmlSecSize size, unsigned int flags) {
    CERTSignedCrl *crl = NULL;
    SECItem derCrl = { siBuffer, NULL, 0 };
    PK11SlotInfo *slot = NULL;
    PRInt32 importOptions = CRL_IMPORT_DEFAULT_OPTIONS;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    derCrl.data = buf;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, derCrl.len, return(NULL), NULL);

    /* we're importing a CRL, it is ok to use the internal slot.
     * crlutil does it :)
     */
    slot = xmlSecNssGetInternalKeySlot();
    if (slot == NULL) {
        xmlSecInternalError("xmlSecNssGetInternalKeySlot", NULL);
        return NULL;
    }

    if((flags & XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS) != 0) {
        importOptions |= CRL_IMPORT_BYPASS_CHECKS;
    }

    crl = PK11_ImportCRL(slot, &derCrl, NULL, SEC_CRL_TYPE, NULL,
                         importOptions, NULL, CRL_DECODE_DEFAULT_OPTIONS);
    if(crl == NULL) {
        xmlSecNssError("PK11_ImportCRL", NULL);
        PK11_FreeSlot(slot);
        return(NULL);
    }

    PK11_FreeSlot(slot);
    return(crl);
}

typedef struct _xmlSecNssX509CertReadResult {
    PLArenaPool* arena;
    SECItem cert;
} xmlSecNssX509CertReadResult;


static SECStatus
xmlSecNssX509CertReadCallback(void *arg, SECItem **certs, int numcerts) {
    xmlSecNssX509CertReadResult* result = (xmlSecNssX509CertReadResult *)arg;

    xmlSecAssert2(result != NULL, SECFailure);
    xmlSecAssert2(result->arena != NULL, SECFailure);
    xmlSecAssert2(numcerts > 0, SECFailure);
    xmlSecAssert2(certs != NULL, SECFailure);
    xmlSecAssert2((*certs) != NULL, SECFailure);

    return SECITEM_CopyItem(result->arena, &(result->cert), *certs);
}


CERTCertificate*
xmlSecNssX509CertPemRead(CERTCertDBHandle *handle, xmlSecByte* buf, xmlSecSize size) {
    xmlSecNssX509CertReadResult result;
    CERTCertificate *cert = NULL;
    int len;
    SECStatus rv;

    xmlSecAssert2(handle != NULL, NULL);
    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(size, len, return(NULL), NULL);

    result.arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if(result.arena == NULL) {
        xmlSecNssError("PORT_NewArena", NULL);
        return(NULL);
    }

    rv = CERT_DecodeCertPackage((char*)buf, len, xmlSecNssX509CertReadCallback, (void *)(&result));
    if(rv != SECSuccess) {
        xmlSecNssError("CERT_DecodeCertPackage", NULL);
        PORT_FreeArena(result.arena, PR_FALSE);
        return(NULL);
    }

    cert = __CERT_NewTempCertificate(handle, &(result.cert), NULL, PR_FALSE, PR_TRUE);
    if(cert == NULL) {
        xmlSecNssError("__CERT_NewTempCertificate", NULL);
        PORT_FreeArena(result.arena, PR_FALSE);
        return(NULL);
    }

    /* done */
    PORT_FreeArena(result.arena, PR_FALSE);
    return (cert);
}

static xmlChar*
xmlSecNssX509NameWrite(CERTName* nm) {
    xmlChar *res = NULL;
    char *str;

    xmlSecAssert2(nm != NULL, NULL);

    str = CERT_NameToAscii(nm);
    if (str == NULL) {
        xmlSecNssError("CERT_NameToAscii", NULL);
        return(NULL);
    }

    res = xmlStrdup(BAD_CAST str);
    if(res == NULL) {
        xmlSecStrdupError(BAD_CAST str, NULL);
        PORT_Free(str);
        return(NULL);
    }
    PORT_Free(str);
    return(res);
}


/* not more than 64 chars */
#define XMLSEC_NSS_INT_TO_STR_MAX_SIZE     64

static xmlChar*
xmlSecNssASN1IntegerWrite(SECItem *num) {
    xmlChar *res = NULL;
    PRUint64 val = 0;
    unsigned int ii = 0;
    int shift = 0;

    xmlSecAssert2(num != NULL, NULL);
    xmlSecAssert2(num->type == siBuffer, NULL);
    xmlSecAssert2(num->data != NULL, NULL);

    /* HACK : to be fixed after
     * NSS bug http://bugzilla.mozilla.org/show_bug.cgi?id=212864 is fixed
     */
    for(ii = num->len; ii > 0; --ii, shift += 8) {
        xmlSecAssert2(shift < 64 || num->data[ii - 1] == 0, NULL);
        if(num->data[ii - 1] != 0) {
            val |= ((PRUint64)num->data[ii - 1]) << shift;
        }
    }

    res = (xmlChar*)xmlMalloc(XMLSEC_NSS_INT_TO_STR_MAX_SIZE + 1);
    if(res == NULL) {
        xmlSecMallocError(XMLSEC_NSS_INT_TO_STR_MAX_SIZE + 1, NULL);
        return (NULL);
    }

    PR_snprintf((char*)res, XMLSEC_NSS_INT_TO_STR_MAX_SIZE, "%llu", val);
    return(res);
}

static int
xmlSecNssX509DigestWrite(CERTCertificate* cert, const xmlChar* algorithm, xmlSecBufferPtr buf) {
    SECOidTag digestAlg;
    xmlSecByte digest[XMLSEC_NSS_MAX_DIGEST_SIZE];
    unsigned int digestLen;
    SECStatus status;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    if((cert->derCert.type != siBuffer) || (cert->derCert.data == NULL) || (cert->derCert.len <= 0)) {
        xmlSecInternalError("cert->derCert is invalid", NULL);
        return(-1);
    }

    digestAlg = xmlSecNssX509GetDigestFromAlgorithm(algorithm);
    if(digestAlg == SEC_OID_UNKNOWN) {
        xmlSecInternalError("xmlSecNssX509GetDigestFromAlgorithm", NULL);
        return(-1);
    }

    digestLen = HASH_ResultLenByOidTag(digestAlg);
    if((digestLen == 0) || (digestLen > sizeof(digest))) {
        xmlSecNssError3("HASH_ResultLenByOidTag", NULL,
            "digestAlgOid=%d; len=%u", (int)digestAlg, digestLen);
        return(-1);
    }
    status = PK11_HashBuf(digestAlg, digest, cert->derCert.data, (PRInt32)cert->derCert.len);
    if (status != SECSuccess) {
        xmlSecNssError2("PK11_HashBuf(cert->derCert)", NULL,
            "digestAlgOid=%d", (int)digestAlg);
        return(-1);
    }

    ret = xmlSecBufferSetData(buf, digest, digestLen);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData", NULL);
        return(-1);
    }

    /* success */
    return(0);
}

static void
xmlSecNssX509CertDebugDump(CERTCertificate* cert, FILE* output) {
    SECItem *sn;
    unsigned int i;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "==== Subject Name: %s\n", cert->subjectName);
    fprintf(output, "==== Issuer Name: %s\n", cert->issuerName);
    sn = &cert->serialNumber;

    for (i = 0; i < sn->len; i++) {
        if (i != sn->len - 1) {
            fprintf(output, "%02x:", sn->data[i]);
        } else {
            fprintf(output, "%02x", sn->data[i]);
        }
    }
    fprintf(output, "\n");
}


static void
xmlSecNssX509CertDebugXmlDump(CERTCertificate* cert, FILE* output) {
    SECItem *sn;
    unsigned int i;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "<SubjectName>");
    xmlSecPrintXmlString(output, BAD_CAST cert->subjectName);
    fprintf(output, "</SubjectName>\n");

    fprintf(output, "<IssuerName>");
    xmlSecPrintXmlString(output, BAD_CAST cert->issuerName);
    fprintf(output, "</IssuerName>\n");

    fprintf(output, "<SerialNumber>");
    sn = &cert->serialNumber;
    for (i = 0; i < sn->len; i++) {
        if (i != sn->len - 1) {
            fprintf(output, "%02x:", sn->data[i]);
        } else {
            fprintf(output, "%02x", sn->data[i]);
        }
    }
    fprintf(output, "</SerialNumber>\n");
}

xmlSecNssX509CrlNodePtr
xmlSecNssX509CrlListDuplicate(xmlSecNssX509CrlNodePtr head) {
    xmlSecNssX509CrlNodePtr newHead = NULL;
    xmlSecNssX509CrlNodePtr cur;
    CERTSignedCrl* crl;
    int ret;

    xmlSecAssert2(head != NULL, NULL);

    for(cur = head; cur != NULL; cur = cur->next) {
        xmlSecAssert2(cur->crl != NULL, NULL);

        crl = SEC_DupCrl(cur->crl);
        if(crl == NULL) {
            xmlSecNssError("SEC_DupCrl", NULL);
            xmlSecNssX509CrlListDestroy(newHead);
            return(NULL);
        }

        ret = xmlSecNssX509CrlListAdoptCrl(&newHead, crl);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssX509CrlListAdoptCrl", NULL);
            SEC_DestroyCrl(crl);
            xmlSecNssX509CrlListDestroy(newHead);
            return(NULL);
        }
        /* crl is owned by newHead now */
    }

    /* done */
    return(newHead);
}

void
xmlSecNssX509CrlListDestroy(xmlSecNssX509CrlNodePtr head) {
    xmlSecNssX509CrlNodePtr tmp;

    while(head != NULL) {
        tmp = head->next;
        SEC_DestroyCrl(head->crl);
        PR_Free(head);
        head = tmp;
    }
}

int
xmlSecNssX509CrlListAdoptCrl(xmlSecNssX509CrlNodePtr * head, CERTSignedCrl* crl) {
    xmlSecNssX509CrlNodePtr crlnode;

    xmlSecAssert2(head != NULL, -1);
    xmlSecAssert2(crl != NULL, -1);

    crlnode = (xmlSecNssX509CrlNodePtr)PR_Malloc(sizeof(xmlSecNssX509CrlNode));
    if(crlnode == NULL) {
        xmlSecNssError("PR_Malloc", NULL);
        return(-1);
    }

    memset(crlnode, 0, sizeof(xmlSecNssX509CrlNode));
    crlnode->next = (*head);
    crlnode->crl = crl;
    (*head) = crlnode;
    return(0);
}

/**************************************************************************
 *
 * Raw X509 Certificate processing
 *
 *
 *************************************************************************/
static int              xmlSecNssKeyDataRawX509CertBinRead      (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 const xmlSecByte* buf,
                                                                 xmlSecSize bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataKlass xmlSecNssKeyDataRawX509CertKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameRawX509Cert,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageRetrievalMethodNodeBin,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRawX509Cert,                      /* const xmlChar* href; */
    NULL,                                       /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    NULL,                                       /* xmlSecKeyDataInitializeMethod initialize; */
    NULL,                                       /* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,                                       /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    NULL,                                       /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecNssKeyDataRawX509CertBinRead,         /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssKeyDataRawX509CertGetKlass:
 *
 * The raw X509 certificates key data klass.
 *
 * Returns: raw X509 certificates key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataRawX509CertGetKlass(void) {
    return(&xmlSecNssKeyDataRawX509CertKlass);
}

static int
xmlSecNssKeyDataRawX509CertBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    const xmlSecByte* buf, xmlSecSize bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    CERTCertificate* cert;
    int ret;

    xmlSecAssert2(id == xmlSecNssKeyDataRawX509CertId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cert = xmlSecNssX509CertDerRead(CERT_GetDefaultCertDB(), (xmlSecByte*)buf, bufSize);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecNssX509CertDerRead", NULL);
        return(-1);
    }

    data = xmlSecKeyDataCreate(xmlSecNssKeyDataX509Id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecNssKeyDataX509Id)", xmlSecKeyDataKlassGetName(id));
        CERT_DestroyCertificate(cert);
        return(-1);
    }

    ret = xmlSecNssKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKeyDataX509AdoptCert", xmlSecKeyDataKlassGetName(id));
        CERT_DestroyCertificate(cert);
        xmlSecKeyDataDestroy(data);
        return(-1);
    }
    cert = NULL; /* owned by data now */

    ret = xmlSecNssVerifyAndAdoptX509KeyData(key, data, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssVerifyAndAdoptX509KeyData", xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    } else if(ret != 1) {
        /* no errors but key was not found and data was not adopted */
        xmlSecKeyDataDestroy(data);
        return(0);
    }
    data = NULL; /* owned by data now */

    /* success */
    return(0);
}

#endif /* XMLSEC_NO_X509 */
