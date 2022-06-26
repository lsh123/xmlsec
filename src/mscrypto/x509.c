/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:x509
 * @Short_description: X509 certificates implementation for Microsoft Crypto API.
 * @Stability: Stable
 *
 */

#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include <windows.h>
#include <wincrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/x509.h>
#include <xmlsec/mscrypto/certkeys.h>
#include "private.h"

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

/*************************************************************************
 *
 * X509 utility functions
 *
 ************************************************************************/
static int              xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data,
                                                                xmlSecKeyPtr key,
                                                                xmlSecKeyInfoCtxPtr keyInfoCtx);

static PCCERT_CONTEXT   xmlSecMSCryptoX509CertDerRead           (const xmlSecByte* buf,
                                                                 xmlSecSize size);
static PCCRL_CONTEXT    xmlSecMSCryptoX509CrlDerRead            (xmlSecByte* buf,
                                                                 xmlSecSize size);
static xmlChar*         xmlSecMSCryptoX509NameWrite(PCERT_NAME_BLOB nm);
static xmlChar*         xmlSecMSCryptoASN1IntegerWrite          (PCRYPT_INTEGER_BLOB num);
static int              xmlSecMSCryptoX509SKIWrite              (PCCERT_CONTEXT cert,
                                                                 xmlSecBufferPtr buf);
static void             xmlSecMSCryptoX509CertDebugDump         (PCCERT_CONTEXT cert,
                                                                 FILE* output);
static void             xmlSecMSCryptoX509CertDebugXmlDump      (PCCERT_CONTEXT cert,
                                                                 FILE* output);
static int              xmlSecMSCryptoX509CertGetTime           (FILETIME t,
                                                                 time_t* res);


/*************************************************************************
 *
 * Internal MSCrypto X509 data CTX
 *
 ************************************************************************/
typedef struct _xmlSecMSCryptoX509DataCtx       xmlSecMSCryptoX509DataCtx,
                                                *xmlSecMSCryptoX509DataCtxPtr;

struct _xmlSecMSCryptoX509DataCtx {
    PCCERT_CONTEXT  keyCert;

    HCERTSTORE hMemStore;
    unsigned int numCerts;
    unsigned int numCrls;
};

/**************************************************************************
 *
 * <dsig:X509Data> processing (http://www.w3.org/TR/xmldsig-core/#sec-X509Data)
 *
 *************************************************************************/
XMLSEC_KEY_DATA_DECLARE(MSCryptoX509Data, xmlSecMSCryptoX509DataCtx)
#define xmlSecMSCryptoX509DataSize XMLSEC_KEY_DATA_SIZE(MSCryptoX509Data)

static int              xmlSecMSCryptoKeyDataX509Initialize     (xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataX509Duplicate      (xmlSecKeyDataPtr dst,
                                                                 xmlSecKeyDataPtr src);
static void             xmlSecMSCryptoKeyDataX509Finalize       (xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataX509XmlRead        (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataX509XmlWrite       (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 xmlNodePtr node,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyDataType xmlSecMSCryptoKeyDataX509GetType       (xmlSecKeyDataPtr data);
static const xmlChar* xmlSecMSCryptoKeyDataX509GetIdentifier    (xmlSecKeyDataPtr data);

static void             xmlSecMSCryptoKeyDataX509DebugDump      (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecMSCryptoKeyDataX509DebugXmlDump   (xmlSecKeyDataPtr data,
                                                                 FILE* output);

typedef struct _xmlSecMSCryptoKeyDataX509Context {
    xmlSecSize crtPos;
    xmlSecSize crtSize;
    xmlSecSize crlPos;
    xmlSecSize crlSize;
} xmlSecMSCryptoKeyDataX509Context;

static int              xmlSecMSCryptoKeyDataX509Read          (xmlSecKeyDataPtr data,
                                                                xmlSecKeyValueX509Ptr x509Value,
                                                                xmlSecKeysMngrPtr keysMngr,
                                                                unsigned int flags);
static int              xmlSecMSCryptoKeyDataX509Write         (xmlSecKeyDataPtr data,
                                                                xmlSecKeyValueX509Ptr x509Value,
                                                                int content,
                                                                void* context);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataX509Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoX509DataSize,

    /* data */
    xmlSecNameX509Data,
    xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefX509Data,                         /* const xmlChar* href; */
    xmlSecNodeX509Data,                         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCryptoKeyDataX509Initialize,        /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataX509Duplicate,         /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataX509Finalize,          /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCryptoKeyDataX509GetType,           /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    xmlSecMSCryptoKeyDataX509GetIdentifier,     /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCryptoKeyDataX509XmlRead,           /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCryptoKeyDataX509XmlWrite,          /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataX509DebugDump,         /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataX509DebugXmlDump,      /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoKeyDataX509GetKlass:
 *
 * The MSCrypto X509 key data klass (http://www.w3.org/TR/xmldsig-core/#sec-X509Data).
 *
 * Returns: the X509 data klass.
 */
xmlSecKeyDataId
xmlSecMSCryptoKeyDataX509GetKlass(void) {
    return(&xmlSecMSCryptoKeyDataX509Klass);
}

/**
 * xmlSecMSCryptoKeyDataX509GetKeyCert:
 * @data:               the pointer to X509 key data.
 *
 * Gets the certificate from which the key was extracted.
 *
 * Returns: the key's certificate or NULL if key data was not used for key
 * extraction or an error occurs.
 */
PCCERT_CONTEXT
xmlSecMSCryptoKeyDataX509GetKeyCert(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->keyCert);
}

/**
 * xmlSecMSCryptoKeyDataX509AdoptKeyCert:
 * @data:               the pointer to X509 key data.
 * @cert:               the pointer to MSCRYPTO X509 certificate.
 *
 * Sets the key's certificate in @data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    if(ctx->keyCert != NULL) {
        CertFreeCertificateContext(ctx->keyCert);
        ctx->keyCert = 0;
    }
    ctx->keyCert = cert;

    return(0);
}

/**
 * xmlSecMSCryptoKeyDataX509AdoptCert:
 * @data:               the pointer to X509 key data.
 * @cert:               the pointer to MSCRYPTO X509 certificate.
 *
 * Adds certificate to the X509 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeyDataX509AdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hMemStore != 0, -1);

    if (!CertAddCertificateContextToStore(ctx->hMemStore, cert, CERT_STORE_ADD_ALWAYS, NULL)) {
        xmlSecMSCryptoError("CertAddCertificateContextToStore",
                            xmlSecKeyDataGetName(data));
        return(-1);
    }
    CertFreeCertificateContext(cert);
    ctx->numCerts++;

    return(0);
}

/**
 * xmlSecMSCryptoKeyDataX509GetCert:
 * @data:               the pointer to X509 key data.
 * @pos:                the desired certificate position.
 *
 * Gets a certificate from X509 key data.
 *
 * Returns: the pointer to certificate or NULL if @pos is larger than the
 * number of certificates in @data or an error occurs.
 */
PCCERT_CONTEXT
xmlSecMSCryptoKeyDataX509GetCert(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCERT_CONTEXT pCert = NULL;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->hMemStore != 0, NULL);
    xmlSecAssert2(ctx->numCerts > pos, NULL);

    pCert = CertEnumCertificatesInStore(ctx->hMemStore, pCert);
    while ((pCert != NULL) && (pos > 0)) {
      pCert = CertEnumCertificatesInStore(ctx->hMemStore, pCert);
      pos--;
    }

    return(pCert);
}

/**
 * xmlSecMSCryptoKeyDataX509GetCertsSize:
 * @data:               the pointer to X509 key data.
 *
 * Gets the number of certificates in @data.
 *
 * Returns: te number of certificates in @data.
 */
xmlSecSize
xmlSecMSCryptoKeyDataX509GetCertsSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), 0);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->numCerts);
}

/**
 * xmlSecMSCryptoKeyDataX509AdoptCrl:
 * @data:               the pointer to X509 key data.
 * @crl:                the pointer to MSCrypto X509 CRL.
 *
 * Adds CRL to the X509 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeyDataX509AdoptCrl(xmlSecKeyDataPtr data, PCCRL_CONTEXT crl) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(crl != 0, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hMemStore != 0, -1);

    if (!CertAddCRLContextToStore(ctx->hMemStore, crl, CERT_STORE_ADD_ALWAYS, NULL)) {
        xmlSecMSCryptoError("CertAddCRLContextToStore",
                            xmlSecKeyDataGetName(data));
        return(-1);
    }
    ctx->numCrls++;

    return(0);
}

/**
 * xmlSecMSCryptoKeyDataX509GetCrl:
 * @data:               the pointer to X509 key data.
 * @pos:                the desired CRL position.
 *
 * Gets a CRL from X509 key data.
 *
 * Returns: the pointer to CRL or NULL if @pos is larger than the
 * number of CRLs in @data or an error occurs.
 */
PCCRL_CONTEXT
xmlSecMSCryptoKeyDataX509GetCrl(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCRL_CONTEXT pCRL = NULL;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);
    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->hMemStore != 0, NULL);
    xmlSecAssert2(ctx->numCrls > pos, NULL);

    pCRL = CertEnumCRLsInStore(ctx->hMemStore, pCRL);
    while ((pCRL != NULL) && (pos > 0)) {
      pCRL = CertEnumCRLsInStore(ctx->hMemStore, pCRL);
      pos--;
    }

    return(pCRL);
}

/**
 * xmlSecMSCryptoKeyDataX509GetCrlsSize:
 * @data:               the pointer to X509 key data.
 *
 * Gets the number of CRLs in @data.
 *
 * Returns: te number of CRLs in @data.
 */
xmlSecSize
xmlSecMSCryptoKeyDataX509GetCrlsSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), 0);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->numCrls);
}

static int
xmlSecMSCryptoKeyDataX509Initialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509DataCtx));

    ctx->hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
                                   0,
                                   0,
                                   CERT_STORE_CREATE_NEW_FLAG,
                                   NULL);
    if (ctx->hMemStore == 0) {
        xmlSecMSCryptoError("CertOpenStore",
                            xmlSecKeyDataGetName(data));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCryptoKeyDataX509Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    PCCERT_CONTEXT certSrc, certDst;
    PCCRL_CONTEXT crlSrc, crlDst;
    xmlSecSize size, pos;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataX509Id), -1);

    /* copy certsList */
    size = xmlSecMSCryptoKeyDataX509GetCertsSize(src);
    for(pos = 0; pos < size; ++pos) {
        /* TBD: function below does linear scan, eliminate loop within
        * loop
        */
        certSrc = xmlSecMSCryptoKeyDataX509GetCert(src, pos);
        if(certSrc == NULL) {
            xmlSecInternalError2("xmlSecMSCryptoKeyDataX509GetCert",
                                 xmlSecKeyDataGetName(src),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return(-1);
        }

        certDst = CertDuplicateCertificateContext(certSrc);
        if(certDst == NULL) {
            xmlSecMSCryptoError("CertDuplicateCertificateContext",
                                xmlSecKeyDataGetName(dst));
            return(-1);
        }

        ret = xmlSecMSCryptoKeyDataX509AdoptCert(dst, certDst);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCert",
                                xmlSecKeyDataGetName(dst));
            CertFreeCertificateContext(certDst);
            return(-1);
        }
    }

    /* copy crls */
    size = xmlSecMSCryptoKeyDataX509GetCrlsSize(src);
    for(pos = 0; pos < size; ++pos) {
        crlSrc = xmlSecMSCryptoKeyDataX509GetCrl(src, pos);
        if(crlSrc == NULL) {
            xmlSecInternalError2("xmlSecMSCryptoKeyDataX509GetCrl",
                                 xmlSecKeyDataGetName(src),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return(-1);
        }

        crlDst = CertDuplicateCRLContext(crlSrc);
        if(crlDst == NULL) {
            xmlSecMSCryptoError("CertDuplicateCRLContext",
                                xmlSecKeyDataGetName(dst));
            return(-1);
        }

        ret = xmlSecMSCryptoKeyDataX509AdoptCrl(dst, crlDst);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCrl",
                                xmlSecKeyDataGetName(dst));
            CertFreeCRLContext(crlDst);
            return(-1);
        }
    }

    /* copy key cert if exist */
    certSrc = xmlSecMSCryptoKeyDataX509GetKeyCert(src);
    if(certSrc != NULL) {
        certDst = CertDuplicateCertificateContext(certSrc);
        if(certDst == NULL) {
            xmlSecMSCryptoError("CertDuplicateCertificateContext",
                                xmlSecKeyDataGetName(dst));
            return(-1);
        }
        ret = xmlSecMSCryptoKeyDataX509AdoptKeyCert(dst, certDst);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptKeyCert",
                                xmlSecKeyDataGetName(dst));
            CertFreeCertificateContext(certDst);
            return(-1);
        }
    }
    return(0);
}

static void
xmlSecMSCryptoKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id));

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->keyCert != NULL) {
        CertFreeCertificateContext(ctx->keyCert);
        ctx->keyCert = NULL;
    }

    if (ctx->hMemStore != 0) {
        if (!CertCloseStore(ctx->hMemStore, CERT_CLOSE_STORE_FORCE_FLAG)) {
            xmlSecInternalError("CertCloseStore", NULL);
            return;
        }
    }

    memset(ctx, 0, sizeof(xmlSecMSCryptoX509DataCtx));
}

static int
xmlSecMSCryptoKeyDataX509XmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);

    data = xmlSecKeyEnsureData(key, id);
    if (data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecKeyDataX509XmlRead(data, node, keyInfoCtx,
        xmlSecMSCryptoKeyDataX509Read);
    if (ret < 0) {
        xmlSecInternalError("xmlSecKeyDataX509XmlRead",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataX509VerifyAndExtractKey",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCryptoKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    xmlSecMSCryptoKeyDataX509Context context;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);

    /* get x509 data */
    data = xmlSecKeyGetData(key, id);
    if (data == NULL) {
        /* no x509 data in the key */
        return(0);
    }

    /* setup context */
    context.crtPos = context.crlPos = 0;
    context.crtSize = xmlSecMSCryptoKeyDataX509GetCertsSize(data);
    context.crlSize = xmlSecMSCryptoKeyDataX509GetCrlsSize(data);

    ret = xmlSecKeyDataX509XmlWrite(data, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecMSCryptoKeyDataX509Write, &context);
    if (ret < 0) {
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
xmlSecMSCryptoKeyDataX509GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), xmlSecKeyDataTypeUnknown);

    /* TODO: return verified/not verified status */
    return(xmlSecKeyDataTypeUnknown);
}

static const xmlChar*
xmlSecMSCryptoKeyDataX509GetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);

    /* TODO */
    return(NULL);
}

static void
xmlSecMSCryptoKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    PCCERT_CONTEXT cert;
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== X509 Data:\n");
    cert = xmlSecMSCryptoKeyDataX509GetKeyCert(data);
    if(cert != NULL) {
        fprintf(output, "==== Key Certificate:\n");
        xmlSecMSCryptoX509CertDebugDump(cert, output);
    }

    size = xmlSecMSCryptoKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
        cert = xmlSecMSCryptoKeyDataX509GetCert(data, pos);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecMSCryptoKeyDataX509GetCert",
                                 xmlSecKeyDataGetName(data),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return;
        }
        fprintf(output, "==== Certificate:\n");
        xmlSecMSCryptoX509CertDebugDump(cert, output);
    }

    /* we don't print out crls */
}

static void
xmlSecMSCryptoKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    PCCERT_CONTEXT cert;
    xmlSecSize size, pos;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<X509Data>\n");
    cert = xmlSecMSCryptoKeyDataX509GetKeyCert(data);
    if(cert != NULL) {
        fprintf(output, "<KeyCertificate>\n");
        xmlSecMSCryptoX509CertDebugXmlDump(cert, output);
        fprintf(output, "</KeyCertificate>\n");
    }

    size = xmlSecMSCryptoKeyDataX509GetCertsSize(data);
    for(pos = 0; pos < size; ++pos) {
        cert = xmlSecMSCryptoKeyDataX509GetCert(data, pos);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecMSCryptoKeyDataX509GetCert",
                                 xmlSecKeyDataGetName(data),
                                 "pos=" XMLSEC_SIZE_FMT, pos);
            return;
        }
        fprintf(output, "<Certificate>\n");
        xmlSecMSCryptoX509CertDebugXmlDump(cert, output);
        fprintf(output, "</Certificate>\n");
    }

    /* we don't print out crls */
    fprintf(output, "</X509Data>\n");
}


static int
xmlSecMSCryptoKeyDataX509Read(xmlSecKeyDataPtr data, xmlSecKeyValueX509Ptr x509Value,
    xmlSecKeysMngrPtr keysMngr, unsigned int flags) {
    xmlSecKeyDataStorePtr x509Store;
    int stopOnUnknownCert = 0;
    PCCERT_CONTEXT cert = NULL;
    PCCRL_CONTEXT crl = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keysMngr, xmlSecMSCryptoX509StoreId);
    if (x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore", xmlSecKeyDataGetName(data));
        goto done;
    }

    /* determine what to do */
    if ((flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
        stopOnUnknownCert = 1;
    }

    if (xmlSecBufferGetSize(&(x509Value->cert)) > 0) {
        cert = xmlSecMSCryptoX509CertDerRead(xmlSecBufferGetData(&(x509Value->cert)),
            xmlSecBufferGetSize(&(x509Value->cert)));
        if (cert == NULL) {
            xmlSecInternalError("xmlSecMSCryptoX509CertDerRead", xmlSecKeyDataGetName(data));
            goto done;
        }
    }
    else if (xmlSecBufferGetSize(&(x509Value->crl)) > 0) {
        crl = xmlSecMSCryptoX509CrlDerRead(xmlSecBufferGetData(&(x509Value->crl)),
            xmlSecBufferGetSize(&(x509Value->crl)));
        if (crl == NULL) {
            xmlSecInternalError("xmlSecMSCryptoX509CertDerRead", xmlSecKeyDataGetName(data));
            goto done;
        }
    }
    else if (xmlSecBufferGetSize(&(x509Value->ski)) > 0) {
        cert = xmlSecMSCryptoX509StoreFindCert_ex(x509Store, NULL, NULL, NULL,
            xmlSecBufferGetData(&(x509Value->ski)), xmlSecBufferGetSize(&(x509Value->ski)),
            NULL /* unused */);
        if ((cert == NULL) && (stopOnUnknownCert != 0)) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data),
                "skiSize=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(&(x509Value->ski)));
            goto done;
        }
    }
    else if (x509Value->subject != NULL) {
        cert = xmlSecMSCryptoX509StoreFindCert_ex(x509Store, x509Value->subject,
            NULL, NULL, NULL, 0, NULL /* unused */);
        if ((cert == NULL) && (stopOnUnknownCert != 0)) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data),
                "subject=%s", xmlSecErrorsSafeString(x509Value->subject));
            goto done;
        }
    }
    else if ((x509Value->issuerName != NULL) && (x509Value->issuerSerial != NULL)) {
        cert = xmlSecMSCryptoX509StoreFindCert_ex(x509Store, NULL,
            x509Value->issuerName, x509Value->issuerSerial,
            NULL, 0, NULL /* unused */);
        if ((cert == NULL) && (stopOnUnknownCert != 0)) {
            xmlSecOtherError3(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data),
                "issuerName=%s;issuerSerial=%s",
                xmlSecErrorsSafeString(x509Value->issuerName),
                xmlSecErrorsSafeString(x509Value->issuerSerial));
            goto done;
        }
    }

    /* if we found a cert or a crl, then add it to the data */
    if (cert != NULL) {
        ret = xmlSecMSCryptoKeyDataX509AdoptCert(data, cert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCert", xmlSecKeyDataGetName(data));
            goto done;
        }
        cert = NULL; /* owned by data now */
    }
    if (crl != NULL) {
        ret = xmlSecMSCryptoKeyDataX509AdoptCrl(data, crl);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCrl", xmlSecKeyDataGetName(data));
            goto done;
        }
        crl = NULL; /* owned by data now */
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if (cert != NULL) {
        CertFreeCertificateContext(cert);
    }
    if (crl != NULL) {
        CertFreeCRLContext(crl);
    }
    return(res);
}


static int
xmlSecMSCryptoKeyDataX509Write(xmlSecKeyDataPtr data, xmlSecKeyValueX509Ptr x509Value,
    int content, void* context) {
    xmlSecMSCryptoKeyDataX509Context* ctx;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(context != NULL, -1);

    ctx = (xmlSecMSCryptoKeyDataX509Context*)context;
    if (ctx->crtPos < ctx->crtSize) {
        /* write cert */
        PCCERT_CONTEXT cert = xmlSecMSCryptoKeyDataX509GetCert(data, ctx->crtPos);
        if (cert == NULL) {
            xmlSecInternalError2("xmlSecMSCryptoKeyDataX509GetCert",
                xmlSecKeyDataGetName(data),
                "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
            return(-1);
        }
        if ((content & XMLSEC_X509DATA_CERTIFICATE_NODE) != 0) {
            xmlSecAssert2(cert->pbCertEncoded != NULL, -1);
            xmlSecAssert2(cert->cbCertEncoded > 0, -1);

            ret = xmlSecBufferSetData(&(x509Value->cert), cert->pbCertEncoded, cert->cbCertEncoded);
            if (ret < 0) {
                xmlSecInternalError3("xmlSecBufferSetData",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT "; certSize=%lu",
                    ctx->crtPos, cert->cbCertEncoded);
                return(-1);
            }
        }
        if ((content & XMLSEC_X509DATA_SKI_NODE) != 0) {
            ret = xmlSecMSCryptoX509SKIWrite(cert, &(x509Value->ski));
            if (ret < 0) {
                xmlSecInternalError2("xmlSecMSCryptoX509SKIWrite",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if ((content & XMLSEC_X509DATA_SUBJECTNAME_NODE) != 0) {
            xmlSecAssert2(x509Value->subject == NULL, -1);
            xmlSecAssert2(cert->pCertInfo != NULL, -1);

            x509Value->subject = xmlSecMSCryptoX509NameWrite(& (cert->pCertInfo->Subject));
            if (x509Value->subject == NULL) {
                xmlSecInternalError2("xmlSecMSCryptoX509NameWrite(subject)",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        if ((content & XMLSEC_X509DATA_ISSUERSERIAL_NODE) != 0) {
            xmlSecAssert2(x509Value->issuerName == NULL, -1);
            xmlSecAssert2(x509Value->issuerSerial == NULL, -1);
            xmlSecAssert2(cert->pCertInfo != NULL, -1);

            x509Value->issuerName = xmlSecMSCryptoX509NameWrite(&(cert->pCertInfo->Issuer));
            if (x509Value->issuerName == NULL) {
                xmlSecInternalError2("xmlSecMSCryptoX509NameWrite(issuer name)",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
            x509Value->issuerSerial = xmlSecMSCryptoASN1IntegerWrite(&(cert->pCertInfo->SerialNumber));
            if (x509Value->issuerSerial == NULL) {
                xmlSecInternalError2("xmlSecMSCryptoASN1IntegerWrite(issuer serial))",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT, ctx->crtPos);
                return(-1);
            }
        }
        ++ctx->crtPos;
    }
    else if (ctx->crlPos < ctx->crlSize) {
        /* write crl */
        PCCRL_CONTEXT crl = xmlSecMSCryptoKeyDataX509GetCrl(data, ctx->crlPos);
        if (crl == NULL) {
            xmlSecInternalError2("xmlSecMSCryptoKeyDataX509GetCrl",
                xmlSecKeyDataGetName(data),
                "pos=" XMLSEC_SIZE_FMT, ctx->crlPos);
            return(-1);
        }

        if ((content & XMLSEC_X509DATA_CRL_NODE) != 0) {
            ret = xmlSecBufferSetData(&(x509Value->crl), crl->pbCrlEncoded, crl->cbCrlEncoded);
            if (ret < 0) {
                xmlSecInternalError3("xmlSecBufferSetData",
                    xmlSecKeyDataGetName(data),
                    "pos=" XMLSEC_SIZE_FMT "; crlSize=%lu",
                    ctx->crlPos, crl->cbCrlEncoded);
                return(-1);
            }
        }
        ++ctx->crlPos;
    }
    else {
        /* no more certs or crls */
        return(1);
    }

    /* success */
    return(0);
}

static int
xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data, xmlSecKeyPtr key,
                                             xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    xmlSecKeyDataStorePtr x509Store;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hMemStore != 0, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCryptoX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore",
                            xmlSecKeyDataGetName(data));
        return(-1);
    }

    if((ctx->keyCert == NULL) && (xmlSecKeyGetValue(key) == NULL)) {
        PCCERT_CONTEXT cert;

        cert = xmlSecMSCryptoX509StoreVerify(x509Store, ctx->hMemStore, keyInfoCtx);
        if(cert != NULL) {
            xmlSecKeyDataPtr keyValue = NULL;
        PCCERT_CONTEXT pCert = NULL;

            ctx->keyCert = CertDuplicateCertificateContext(cert);
            if(ctx->keyCert == NULL) {
                    xmlSecMSCryptoError("CertDuplicateCertificateContext",
                                        xmlSecKeyDataGetName(data));
                    return(-1);
            }

                /* search key according to KeyReq */
                pCert = CertDuplicateCertificateContext( ctx->keyCert ) ;
                if( pCert == NULL ) {
                    xmlSecMSCryptoError("CertDuplicateCertificateContext",
                                        xmlSecKeyDataGetName(data));
                    return(-1);
                }

                if( ( keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate ) == xmlSecKeyDataTypePrivate ) {
                        keyValue = xmlSecMSCryptoCertAdopt( pCert, xmlSecKeyDataTypePrivate ) ;
                        if(keyValue == NULL) {
                                xmlSecInternalError("xmlSecMSCryptoCertAdopt",
                                                    xmlSecKeyDataGetName(data));
                                CertFreeCertificateContext( pCert ) ;
                                return(-1);
                        }
                        pCert = NULL ;
                } else if( ( keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePublic ) == xmlSecKeyDataTypePublic ) {
                        keyValue = xmlSecMSCryptoCertAdopt( pCert, xmlSecKeyDataTypePublic ) ;
                        if(keyValue == NULL) {
                                xmlSecInternalError("xmlSecMSCryptoCertAdopt",
                                                    xmlSecKeyDataGetName(data));
                                CertFreeCertificateContext( pCert ) ;
                                return(-1);
                        }
                        pCert = NULL ;
                }

            /* verify that the key matches our expectations */
            if(xmlSecKeyReqMatchKeyValue(&(keyInfoCtx->keyReq), keyValue) != 1) {
                    xmlSecInternalError("xmlSecKeyReqMatchKeyValue",
                                        xmlSecKeyDataGetName(data));
                    xmlSecKeyDataDestroy(keyValue);
                    return(-1);
            }

            ret = xmlSecKeySetValue(key, keyValue);
            if(ret < 0) {
                    xmlSecInternalError("xmlSecKeySetValue",
                                        xmlSecKeyDataGetName(data));
                    xmlSecKeyDataDestroy(keyValue);
                    return(-1);
            }

            ret = xmlSecMSCryptoX509CertGetTime(ctx->keyCert->pCertInfo->NotBefore, &(key->notValidBefore));
            if(ret < 0) {
                    xmlSecInternalError("xmlSecMSCryptoX509CertGetTime(notValidBefore)",
                                        xmlSecKeyDataGetName(data));
                    return(-1);
            }

            ret = xmlSecMSCryptoX509CertGetTime(ctx->keyCert->pCertInfo->NotAfter, &(key->notValidAfter));
            if(ret < 0) {
                    xmlSecInternalError("xmlSecMSCryptoX509CertGetTime(notValidAfter)",
                                        xmlSecKeyDataGetName(data));
                    return(-1);
            }
        } else if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT) != 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND,
                             xmlSecKeyDataGetName(data), NULL);
            return(-1);
        }
    }
    return(0);
}

static int
xmlSecMSCryptoX509CertGetTime(FILETIME t, time_t* res) {
    LONGLONG result;

    xmlSecAssert2(res != NULL, -1);

    result = t.dwHighDateTime;
    result = (result) << 32;
    result |= t.dwLowDateTime;
    result /= 10000;    /* Convert from 100 nano-sec periods to seconds. */
#if defined(__MINGW32__)
    result -= 11644473600000LL;  /* Convert from Windows epoch to Unix epoch */
#else
    result -= 11644473600000;  /* Convert from Windows epoch to Unix epoch */
#endif

    (*res) = (time_t)result;

    return(0);
}

static PCCERT_CONTEXT
xmlSecMSCryptoX509CertDerRead(const xmlSecByte* buf, xmlSecSize size) {
    PCCERT_CONTEXT cert;
    DWORD dwSize;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(size, dwSize, return(NULL), NULL);
    cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, dwSize);
    if(cert == NULL) {
        xmlSecMSCryptoError("CertCreateCertificateContext", NULL);
        return(NULL);
    }

    return(cert);
}

static PCCRL_CONTEXT
xmlSecMSCryptoX509CrlDerRead(xmlSecByte* buf, xmlSecSize size) {
    PCCRL_CONTEXT crl = NULL;
    DWORD dwSize;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(size, dwSize, return(NULL), NULL);
    crl = CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, dwSize);
    if(crl == NULL) {
        xmlSecMSCryptoError("CertCreateCRLContext", NULL);
        return(NULL);
    }

    return(crl);
}

static xmlChar*
xmlSecMSCryptoX509NameWrite(PCERT_NAME_BLOB nm) {
    LPTSTR resT = NULL;
    xmlChar *res = NULL;
    DWORD csz;


    xmlSecAssert2(nm->pbData != NULL, NULL);
    xmlSecAssert2(nm->cbData > 0, NULL);

    csz = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, nm, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, NULL, 0);
    if(csz <= 0) {
        xmlSecMSCryptoError("CertNameToStr", NULL);
        return(NULL);
    }

    resT = (LPTSTR)xmlMalloc(sizeof(TCHAR) * (csz + 1));
    if (NULL == resT) {
        xmlSecMallocError(sizeof(TCHAR) * (csz + 1), NULL);
        return (NULL);
    }

    csz = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, nm, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, resT, csz + 1);
    if (csz <= 0) {
        xmlSecMSCryptoError("CertNameToStr", NULL);
        xmlFree(resT);
        return(NULL);
    }

    res = xmlSecWin32ConvertTstrToUtf8(resT);
    if (NULL == res) {
        xmlSecInternalError("xmlSecWin32ConvertTstrToUtf8", NULL);
        xmlFree(resT);
        return(NULL);
    }

    xmlFree(resT);
    return(res);
}

static xmlChar*
xmlSecMSCryptoASN1IntegerWrite(PCRYPT_INTEGER_BLOB num) {
    xmlSecBn bn;
    xmlChar* res;
    int ret;

    xmlSecAssert2(num != NULL, NULL);

    ret = xmlSecBnInitialize(&bn, num->cbData + 1);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBnInitialize", NULL, "size=%lu", num->cbData + 1);
        return(NULL);
    }

    ret = xmlSecBnSetData(&bn, num->pbData, num->cbData);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBnSetData", NULL);
        xmlSecBnFinalize(&bn);
        return(NULL);
    }

    /* SerialNumber is little-endian, see <https://msdn.microsoft.com/en-us/library/windows/desktop/aa377200(v=vs.85).aspx>.
     * xmldsig wants big-endian, so reverse */
    ret = xmlSecBnReverse(&bn);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBnReverse", NULL);
        xmlSecBnFinalize(&bn);
        return(NULL);
    }

    res = xmlSecBnToDecString(&bn);
    if (res == NULL) {
        xmlSecInternalError("xmlSecBnToDecString", NULL);
        xmlSecBnFinalize(&bn);
        return(NULL);
    }

    /* done */
    xmlSecBnFinalize(&bn);
    return(res);
}

static int
xmlSecMSCryptoX509SKIWrite(PCCERT_CONTEXT cert, xmlSecBufferPtr buf) {
    PCERT_EXTENSION pCertExt;
    DWORD dwSize;
    BOOL rv;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    /* First check if the SKI extension actually exists, otherwise we get a SHA1 hash of the cert */
    pCertExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension);
    if (pCertExt == NULL) {
        xmlSecMSCryptoError("CertFindExtension", NULL);
        return (0);
    }

    rv = CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, NULL, &dwSize);
    if (!rv || dwSize <= 0) {
        xmlSecMSCryptoError("CertGetCertificateContextProperty", NULL);
        return(-1);
    }

    ret = xmlSecBufferSetMaxSize(buf, dwSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
            "size=%lu", dwSize);
        return(-1);
    }

    if (!CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, xmlSecBufferGetData(buf), &dwSize)) {
        xmlSecMSCryptoError("CertGetCertificateContextProperty", NULL);
        return(-1);
    }

    ret = xmlSecBufferSetSize(buf, dwSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=%lu", dwSize);
        return(-1);
    }
    return(0);
}

static void
xmlSecMSCryptoX509CertDebugDump(PCCERT_CONTEXT cert, FILE* output) {
    PCRYPT_INTEGER_BLOB sn;
    unsigned int i;
    xmlChar * subject = NULL;
    xmlChar * issuer = NULL;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "=== X509 Certificate\n");

    /* subject */
    subject = xmlSecMSCryptoX509GetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL);
    if(subject == NULL) {
        xmlSecInternalError("xmlSecMSCryptoX509GetNameString(subject)", NULL);
        goto done;
    }
    fprintf(output, "==== Subject Name: %s\n", subject);

    /* issuer */
    issuer = xmlSecMSCryptoX509GetNameString(cert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, NULL);
    if(issuer == NULL) {
        xmlSecInternalError("xmlSecMSCryptoX509GetNameString(issuer)", NULL);
        goto done;
    }
    fprintf(output, "==== Issuer Name: %s\n", issuer);

    /* serial number */
    sn = &(cert->pCertInfo->SerialNumber);
    for (i = 0; i < sn->cbData; i++) {
        if (i != sn->cbData - 1) {
            fprintf(output, "%02x:", sn->pbData[i]);
        } else {
            fprintf(output, "%02x", sn->pbData[i]);
        }
    }
    fprintf(output, "\n");

done:
    if (subject) xmlFree(subject);
    if (issuer) xmlFree(issuer);
}


static void
xmlSecMSCryptoX509CertDebugXmlDump(PCCERT_CONTEXT cert, FILE* output) {
    PCRYPT_INTEGER_BLOB sn;
    unsigned int i;
    xmlChar * subject = NULL;
    xmlChar * issuer = NULL;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(output != NULL);

    /* subject */
    subject = xmlSecMSCryptoX509GetNameString(cert, CERT_NAME_RDN_TYPE, 0, NULL);
    if(subject == NULL) {
        xmlSecInternalError("xmlSecMSCryptoX509GetNameString(subject)", NULL);
        goto done;
    }
    fprintf(output, "<SubjectName>");
    xmlSecPrintXmlString(output, BAD_CAST subject);
    fprintf(output, "</SubjectName>\n");

    /* issuer */
    issuer = xmlSecMSCryptoX509GetNameString(cert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, NULL);
    if(issuer == NULL) {
        xmlSecInternalError("xmlSecMSCryptoX509GetNameString(issuer)", NULL);
        goto done;
    }
    fprintf(output, "<IssuerName>");
    xmlSecPrintXmlString(output, BAD_CAST issuer);
    fprintf(output, "</IssuerName>\n");

    /* serial */
    fprintf(output, "<SerialNumber>");
    sn = &(cert->pCertInfo->SerialNumber);
    for (i = 0; i < sn->cbData; i++) {
        if (i != sn->cbData - 1) {
            fprintf(output, "%02x:", sn->pbData[i]);
        } else {
            fprintf(output, "%02x", sn->pbData[i]);
        }
    }
    fprintf(output, "</SerialNumber>\n");

done:
    xmlFree(subject);
    xmlFree(issuer);
}


/**************************************************************************
 *
 * Raw X509 Certificate processing
 *
 *
 *************************************************************************/
static int              xmlSecMSCryptoKeyDataRawX509CertBinRead (xmlSecKeyDataId id,
                                                                 xmlSecKeyPtr key,
                                                                 const xmlSecByte* buf,
                                                                 xmlSecSize bufSize,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataRawX509CertKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameRawX509Cert,
    xmlSecKeyDataUsageRetrievalMethodNodeBin,
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
    xmlSecMSCryptoKeyDataRawX509CertBinRead,    /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCryptoKeyDataRawX509CertGetKlass:
 *
 * The raw X509 certificates key data klass.
 *
 * Returns: raw X509 certificates key data klass.
 */
xmlSecKeyDataId
xmlSecMSCryptoKeyDataRawX509CertGetKlass(void) {
    return(&xmlSecMSCryptoKeyDataRawX509CertKlass);
}

static int
xmlSecMSCryptoKeyDataRawX509CertBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                    const xmlSecByte* buf, xmlSecSize bufSize,
                                    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    PCCERT_CONTEXT cert;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataRawX509CertId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cert = xmlSecMSCryptoX509CertDerRead(buf, bufSize);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecMSCryptoX509CertDerRead", NULL);
        return(-1);
    }

    data = xmlSecKeyEnsureData(key, xmlSecMSCryptoKeyDataX509Id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData",
                            xmlSecKeyDataKlassGetName(id));
        CertFreeCertificateContext(cert);
        return(-1);
    }

    ret = xmlSecMSCryptoKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCert",
                            xmlSecKeyDataKlassGetName(id));
        CertFreeCertificateContext(cert);
        return(-1);
    }

    ret = xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataX509VerifyAndExtractKey",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }
    return(0);
}

#endif /* XMLSEC_NO_X509 */
