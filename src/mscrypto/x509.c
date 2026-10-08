/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2003-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
/**
 * @addtogroup xmlsec_mscrypto_x509
 * @brief X509 certificates implementation for Microsoft Crypto API.
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/x509.h>
#include <xmlsec/mscrypto/certkeys.h>
#include "private.h"

#include "../cast_helpers.h"
#include "../x509_helpers.h"

/******************************************************************************
 *
 * X509 utility functions
 *
  *****************************************************************************/
static int              xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data,
                                                                xmlSecKeyPtr key,
                                                                xmlSecKeyInfoCtxPtr keyInfoCtx);

static PCCERT_CONTEXT   xmlSecMSCryptoX509CertDerRead           (const xmlSecByte* buf,
                                                                 xmlSecSize size);
static PCCRL_CONTEXT    xmlSecMSCryptoX509CrlDerRead            (const xmlSecByte* buf,
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


/******************************************************************************
 *
 * Internal MSCrypto X509 data CTX
 *
  *****************************************************************************/
typedef struct _xmlSecMSCryptoX509DataCtx       xmlSecMSCryptoX509DataCtx,
                                                *xmlSecMSCryptoX509DataCtxPtr;

struct _xmlSecMSCryptoX509DataCtx {
    PCCERT_CONTEXT  keyCert;
    HCERTSTORE hMemStore;
};

/******************************************************************************
 *
 * &lt;dsig:X509Data/&gt; processing (http://www.w3.org/TR/xmldsig-core/#sec-X509Data)
 *
  *****************************************************************************/
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

static void             xmlSecMSCryptoKeyDataX509DebugDump      (xmlSecKeyDataPtr data,
                                                                 FILE* output);
static void             xmlSecMSCryptoKeyDataX509DebugXmlDump   (xmlSecKeyDataPtr data,
                                                                 FILE* output);

static int              xmlSecMSCryptoKeyDataX509Read          (xmlSecKeyDataPtr data,
                                                                xmlSecKeyX509DataValuePtr x509Value,
                                                                xmlSecKeysMngrPtr keysMngr,
                                                                unsigned int flags);
static int              xmlSecMSCryptoKeyDataX509Write         (xmlSecKeyDataPtr data,
                                                                xmlSecKeyX509DataValuePtr x509Value,
                                                                int content,
                                                                void* context);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataX509Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoX509DataSize,

    /* data */
    xmlSecNameX509Data,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefX509Data,                         /* const xmlChar* href; */
    xmlSecNodeX509Data,                         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCryptoKeyDataX509Initialize,        /* xmlSecKeyDataInitMethod initialize; */
    xmlSecMSCryptoKeyDataX509Duplicate,         /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataX509Finalize,          /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    NULL,                                       /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */

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
 * @brief The MSCrypto X509 key data klass.
 * @details The MSCrypto X509 key data klass (http://www.w3.org/TR/xmldsig-core/#sec-X509Data).
 * @return the X509 data klass.
 */
xmlSecKeyDataId
xmlSecMSCryptoKeyDataX509GetKlass(void) {
    return(&xmlSecMSCryptoKeyDataX509Klass);
}

/**
 * @brief Gets the certificate from which the key was extracted.
 * @param data the pointer to X509 key data.
 *
 *
 * @return the key's certificate or NULL if key data was not used for key
 * extraction or an error occurs. : the returned PCCERT_CONTEXT is owned by
 * the key data and must NOT be CertFreeCertificateContext()-ed by the caller.
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
 * @brief Sets the key's certificate in @p data.
 * @param data the pointer to X509 key data.
 * @param cert the pointer to MSCRYPTO X509 certificate.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->keyCert == NULL, -1);

    /* CertAddCertificateContextToStore creates a new copy of the certificate context
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcertificatecontexttostore */
    if (!CertAddCertificateContextToStore(ctx->hMemStore, cert, CERT_STORE_ADD_USE_EXISTING,  NULL)) {
        xmlSecMSCryptoError("CertAddCertificateContextToStore", NULL);
        return(-1);
    }

    /* cert is now owned by data */
    ctx->keyCert = cert;
    return(0);
}

/**
 * @brief Adds certificate to the X509 key data.
 * @param data the pointer to X509 key data.
 * @param cert the pointer to MSCRYPTO X509 certificate.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeyDataX509AdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hMemStore != 0, -1);


    /* pkcs12 files sometimes have key cert twice: as the key cert and as the cert in the chain */
    if ((ctx->keyCert != NULL) && (CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert->pCertInfo, ctx->keyCert->pCertInfo) == TRUE)) {
        /* the pointer-equal cert is already owned by ctx->keyCert caller expects data to own the cert on success. */
        CertFreeCertificateContext(cert);
        return(0);
    }

    /* CertAddCertificateContextToStore creates a new copy of the certificate context
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcertificatecontexttostore */
    if (!CertAddCertificateContextToStore(ctx->hMemStore, cert, CERT_STORE_ADD_USE_EXISTING, NULL)) {
        xmlSecMSCryptoError("CertAddCertificateContextToStore", xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* caller expects data to own the cert on success. */
    CertFreeCertificateContext(cert);
    return(0);
}

/**
 * @brief Deprecated. Gets a certificate from X509 key data.
 * @param data the pointer to X509 key data.
 * @param pos the desired certificate position.
 *
 *
 * @return the pointer to certificate or NULL if @p pos is larger than the
 * number of certificates in @p data or an error occurs.
 */
PCCERT_CONTEXT
xmlSecMSCryptoKeyDataX509GetCert(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCERT_CONTEXT pCert = NULL;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->hMemStore != 0, NULL);

    /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
    pCert = CertEnumCertificatesInStore(ctx->hMemStore, pCert);
    while ((pCert != NULL) && (pos > 0)) {
        pCert = CertEnumCertificatesInStore(ctx->hMemStore, pCert);
        pos--;
    }

    return(pCert);
}

/**
 * @brief Deprecated. Gets the number of certificates in @p data.
 * @param data the pointer to X509 key data.
 * @return the number of certificates in @p data.
 */
xmlSecSize
xmlSecMSCryptoKeyDataX509GetCertsSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCERT_CONTEXT pCert = NULL;
    xmlSecSize size = 0;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), 0);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);
    xmlSecAssert2(ctx->hMemStore != 0, 0);
 
    /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
    pCert = CertEnumCertificatesInStore(ctx->hMemStore, pCert);
    while ((pCert != NULL)) {
        size++;
        pCert = CertEnumCertificatesInStore(ctx->hMemStore, pCert);
    }

    return(size);
}

/**
 * @brief Adds CRL to the X509 key data.
 * @param data the pointer to X509 key data.
 * @param crl the pointer to MSCrypto X509 CRL.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeyDataX509AdoptCrl(xmlSecKeyDataPtr data, PCCRL_CONTEXT crl) {
    xmlSecMSCryptoX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(crl != 0, -1);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hMemStore != 0, -1);

    /* CertAddCRLContextToStore creates a new copy of the certificate context
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcrlcontexttostore */     
    if (!CertAddCRLContextToStore(ctx->hMemStore, crl, CERT_STORE_ADD_USE_EXISTING, NULL)) {
        xmlSecMSCryptoError("CertAddCRLContextToStore", xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* caller expects data to own the crl on success. */
    CertFreeCRLContext(crl);
    return(0);
}

/**
 * @brief Deprecated. Gets a CRL from X509 key data.
 * @param data the pointer to X509 key data.
 * @param pos the desired CRL position.
 *
 *
 * @return the pointer to CRL or NULL if @p pos is larger than the
 * number of CRLs in @p data or an error occurs.
 */
PCCRL_CONTEXT
xmlSecMSCryptoKeyDataX509GetCrl(xmlSecKeyDataPtr data, xmlSecSize pos) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCRL_CONTEXT pCRL = NULL;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), NULL);
    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->hMemStore != 0, NULL);

    /* CertEnumCRLsInStore automatically frees the previous CRL context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcrlsinstore) */
    pCRL = CertEnumCRLsInStore(ctx->hMemStore, pCRL);
    while ((pCRL != NULL) && (pos > 0)) {
        pCRL = CertEnumCRLsInStore(ctx->hMemStore, pCRL);
        pos--;
    }
    return(pCRL);
}

/**
 * @brief Deprecated. Gets the number of CRLs in @p data.
 * @param data the pointer to X509 key data.
 * @return the number of CRLs in @p data.
 */
xmlSecSize
xmlSecMSCryptoKeyDataX509GetCrlsSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCRL_CONTEXT pCRL = NULL;
    xmlSecSize size = 0;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), 0);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);
    xmlSecAssert2(ctx->hMemStore != 0, 0);
    
    while ((pCRL = CertEnumCRLsInStore(ctx->hMemStore, pCRL)) != NULL) {
        size++;
    }
    return(size);
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
    xmlSecMSCryptoX509DataCtxPtr srcCtx;
    xmlSecMSCryptoX509DataCtxPtr dstCtx;
    PCCERT_CONTEXT srcCert = NULL;
    PCCERT_CONTEXT dstCert = NULL;
    PCCRL_CONTEXT srcCrl = NULL;
    PCCRL_CONTEXT dstCrl = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataX509Id), -1);

    srcCtx = xmlSecMSCryptoX509DataGetCtx(src);
    xmlSecAssert2(srcCtx != NULL, -1);
    dstCtx = xmlSecMSCryptoX509DataGetCtx(dst);
    xmlSecAssert2(dstCtx != NULL, -1);

    /* duplicate the certificate store: CertEnumCertificatesInStore automatically frees the previous certificate context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore)
     */
    while((srcCert = CertEnumCertificatesInStore(srcCtx->hMemStore, srcCert)) != NULL) {
        dstCert = CertDuplicateCertificateContext(srcCert);
        if(dstCert == NULL) {
            xmlSecMSCryptoError("CertDuplicateCertificateContext", NULL);
            CertFreeCertificateContext(srcCert);
            return(-1);
        }

        /* ensure to handle keyCert */
        if ((srcCtx->keyCert != NULL) && (srcCtx->keyCert->pCertInfo != NULL) && (srcCert->pCertInfo != NULL) && (CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, srcCert->pCertInfo, srcCtx->keyCert->pCertInfo) == TRUE)) {
            ret = xmlSecMSCryptoKeyDataX509AdoptKeyCert(dst, dstCert);
            if (ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptKeyCert", NULL);
                CertFreeCertificateContext(srcCert);
                CertFreeCertificateContext(dstCert);
                return(-1);
            }
        } else {
            ret = xmlSecMSCryptoKeyDataX509AdoptCert(dst, dstCert);
            if (ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCert", NULL);
                CertFreeCertificateContext(srcCert);
                CertFreeCertificateContext(dstCert);
                return(-1);
            }
        }
        dstCert = NULL; /* owned by dst now */
    }

    /* duplicate the CRLs: CertEnumCRLsInStore automatically frees the previous CRL context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcrlsinstore) */
    while((srcCrl = CertEnumCRLsInStore(srcCtx->hMemStore, srcCrl)) != NULL) {
        dstCrl = CertDuplicateCRLContext(srcCrl);
        if(dstCrl == NULL) {
            xmlSecMSCryptoError("CertDuplicateCRLContext", NULL);   
            CertFreeCRLContext(srcCrl);
            return(-1);
        }

        ret = xmlSecMSCryptoKeyDataX509AdoptCrl(dst, dstCrl);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCrl", NULL);
            CertFreeCRLContext(srcCrl);
            CertFreeCRLContext(dstCrl);
            return(-1);
        }
        dstCrl = NULL; /* owned by dst now */
    }

    /* Done */
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
        if (!CertCloseStore(ctx->hMemStore, XMLSEC_CLOSE_STORE_FLAG)) {
            xmlSecInternalError("CertCloseStore", NULL);
            /* ignore error */
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

    data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataX509Id);
    if (data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataX509Id)", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecKeyDataX509XmlRead(key, data, node, keyInfoCtx, xmlSecMSCryptoKeyDataX509Read);
    if (ret < 0) {
        xmlSecInternalError("xmlSecKeyDataX509XmlRead", xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    }

    /* did we find the key already? */
    if (xmlSecKeyGetValue(key) != NULL) {
        xmlSecKeyDataDestroy(data);
        return(0);
    }

    /* if not, then try to extract the key from certificates */
    ret = xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataX509VerifyAndExtractKey", xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        return(-1);
    }

    if (xmlSecKeyGetValue(key) != NULL) {
        ret = xmlSecKeyAdoptData(key, data);
        if (ret < 0) {
            xmlSecInternalError("xmlSecKeyAdoptData", xmlSecKeyDataKlassGetName(id));
            xmlSecKeyDataDestroy(data);
            return(-1);
        }
        data = NULL; /* owned by key now */
    } else {
        xmlSecKeyDataDestroy(data);
    }

    /* success */
    return(0);
}



typedef struct _xmlSecMSCryptoKeyDataX509WriteContext {
    HCERTSTORE store;
    PCCERT_CONTEXT crt;
    PCCRL_CONTEXT crl;
    int doneCrts;
    int doneCrls;
} xmlSecMSCryptoKeyDataX509WriteContext;

static int
xmlSecMSCryptoKeyDataX509WriteContextInitialize(xmlSecMSCryptoKeyDataX509WriteContext* ctx, HCERTSTORE store) {
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(store != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoKeyDataX509WriteContext));
    ctx->store = store;

    return(0);
}

static void
xmlSecMSCryptoKeyDataX509WriteContextFinalize(xmlSecMSCryptoKeyDataX509WriteContext* ctx) {
    xmlSecAssert(ctx != NULL);

    if(ctx->crt != NULL) {
        CertFreeCertificateContext(ctx->crt);
        ctx->crt = NULL;
    }
    if(ctx->crl != NULL) {
        CertFreeCRLContext(ctx->crl);
        ctx->crl = NULL;
    }
    ctx->store = 0;
    ctx->doneCrts = 0;
    ctx->doneCrls = 0;
}

static int
xmlSecMSCryptoKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoKeyDataX509WriteContext context;
    xmlSecMSCryptoX509DataCtxPtr x509DataCtx;
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);

    /* get x509 data */
    data = xmlSecKeyGetData(key, id);
    if (data == NULL) {
        /* no x509 data in the key */
        return(0);
    }

    x509DataCtx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert2(x509DataCtx != NULL, -1);

    ret = xmlSecMSCryptoKeyDataX509WriteContextInitialize(&context, x509DataCtx->hMemStore);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataX509WriteContextInitialize", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecKeyDataX509XmlWrite(data, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecMSCryptoKeyDataX509Write, &context);
    if (ret < 0) {
        xmlSecInternalError("xmlSecKeyDataX509XmlWrite", xmlSecKeyDataKlassGetName(id));
        xmlSecMSCryptoKeyDataX509WriteContextFinalize(&context);
        return(-1);
    }

    /* success */
    xmlSecMSCryptoKeyDataX509WriteContextFinalize(&context);
    return(0);
}

static void
xmlSecMSCryptoKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id));
    xmlSecAssert(output != NULL);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);    

    fprintf(output, "=== X509 Data:\n");
    /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
    while((cert = CertEnumCertificatesInStore(ctx->hMemStore, cert)) != NULL) {
        if((ctx->keyCert != NULL) && (cert->pCertInfo != NULL) && (ctx->keyCert->pCertInfo != NULL) &&
            (CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cert->pCertInfo, ctx->keyCert->pCertInfo) == TRUE)) {
            fprintf(output, "==== Key Certificate:\n");
        } else {
            fprintf(output, "==== Certificate:\n");
        }
        xmlSecMSCryptoX509CertDebugDump(cert, output);
    }
    /* we don't print out crls */
}

static void
xmlSecMSCryptoKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    PCCERT_CONTEXT cert = NULL;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id));
    xmlSecAssert(output != NULL);

    ctx = xmlSecMSCryptoX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);    

    fprintf(output, "<X509Data>\n");
    /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
     * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
    while((cert = CertEnumCertificatesInStore(ctx->hMemStore, cert)) != NULL) {
        if((ctx->keyCert != NULL) && (cert->pCertInfo != NULL) && (ctx->keyCert->pCertInfo != NULL) &&
            (CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cert->pCertInfo, ctx->keyCert->pCertInfo) == TRUE)) {
            fprintf(output, "<KeyCertificate>\n");
            xmlSecMSCryptoX509CertDebugXmlDump(cert, output);
            fprintf(output, "</KeyCertificate>\n");
        } else {
            fprintf(output, "<Certificate>\n");
            xmlSecMSCryptoX509CertDebugXmlDump(cert, output);
            fprintf(output, "</Certificate>\n");
        }
    }
    /* we don't print out crls */
    fprintf(output, "</X509Data>\n");
}

/* xmlSecKeyDataX509Read: 0 on success and a negative value otherwise */
static int
xmlSecMSCryptoKeyDataX509Read(xmlSecKeyDataPtr data, xmlSecKeyX509DataValuePtr x509Value,
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
            xmlSecInternalError("xmlSecMSCryptoX509CrlDerRead", xmlSecKeyDataGetName(data));
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


#define XMLSEC_MSCNG_SHA1_DIGEST_SIZE 20
#define XMLSEC_MSCNG_SHA256_DIGEST_SIZE 32

static int
xmlSecMSCryptoX509DigestWrite(PCCERT_CONTEXT cert, const xmlChar* algorithm, xmlSecBufferPtr buf) {
    DWORD certHashPropId;
    DWORD digestSize;
    xmlSecByte md[XMLSEC_MSCNG_SHA256_DIGEST_SIZE];
    DWORD mdLen = sizeof(md);
    BOOL status;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    /* SHA1 and SHA256 algorithms are currently supported */
    if (xmlStrcmp(algorithm, xmlSecHrefSha1) == 0) {
        certHashPropId = CERT_SHA1_HASH_PROP_ID;
        digestSize = XMLSEC_MSCNG_SHA1_DIGEST_SIZE;
    } else if (xmlStrcmp(algorithm, xmlSecHrefSha256) == 0) {
        certHashPropId = CERT_SHA256_HASH_PROP_ID;
        digestSize = XMLSEC_MSCNG_SHA256_DIGEST_SIZE;
    } else {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_ALGORITHM, NULL,
            "href=%s", xmlSecErrorsSafeString(algorithm));
        return(-1);
    }

    status = CertGetCertificateContextProperty(cert, certHashPropId, md, &mdLen);
    if ((!status) || (mdLen != digestSize)) {
        xmlSecMSCryptoError("CertGetCertificateContextProperty", NULL);
        return(-1);
    }

    ret = xmlSecBufferSetData(buf, md, mdLen);
    if (ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData", NULL);
        return(-1);
    }

    /* success */
    return(0);
}

/* xmlSecKeyDataX509Write: returns 1 on success, 0 if no more certs/crls are available,
 * or a negative value if an error occurs.
 */
static int
xmlSecMSCryptoKeyDataX509Write(
    xmlSecKeyDataPtr data,
    xmlSecKeyX509DataValuePtr x509Value,
    int content,
    void* context
) {
    xmlSecMSCryptoKeyDataX509WriteContext* ctx;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(context != NULL, -1);

    ctx = (xmlSecMSCryptoKeyDataX509WriteContext*)context;
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->store != NULL, -1);

    /* try to get and write the next cert if available */
    if (ctx->doneCrts == 0) {
        /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
         * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
        ctx->crt = CertEnumCertificatesInStore(ctx->store, ctx->crt);
        if (ctx->crt != NULL) {
            if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_CERTIFICATE_NODE)) {
                xmlSecAssert2(ctx->crt->pbCertEncoded != NULL, -1);
                xmlSecAssert2(ctx->crt->cbCertEncoded > 0, -1);

                ret = xmlSecBufferSetData(&(x509Value->cert), ctx->crt->pbCertEncoded, ctx->crt->cbCertEncoded);
                if (ret < 0) {
                    xmlSecInternalError("xmlSecBufferSetData", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_SKI_NODE)) {
                ret = xmlSecMSCryptoX509SKIWrite(ctx->crt, &(x509Value->ski));
                if (ret < 0) {
                    xmlSecInternalError("xmlSecMSCryptoX509SKIWrite", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_SUBJECTNAME_NODE)) {
                xmlSecAssert2(x509Value->subject == NULL, -1);
                xmlSecAssert2(ctx->crt->pCertInfo != NULL, -1);

                x509Value->subject = xmlSecMSCryptoX509NameWrite(&(ctx->crt->pCertInfo->Subject));
                if (x509Value->subject == NULL) {
                    xmlSecInternalError("xmlSecMSCryptoX509NameWrite(subject)", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_ISSUERSERIAL_NODE)) {
                xmlSecAssert2(x509Value->issuerName == NULL, -1);
                xmlSecAssert2(x509Value->issuerSerial == NULL, -1);
                xmlSecAssert2(ctx->crt->pCertInfo != NULL, -1);

                x509Value->issuerName = xmlSecMSCryptoX509NameWrite(&(ctx->crt->pCertInfo->Issuer));
                if (x509Value->issuerName == NULL) {
                    xmlSecInternalError("xmlSecMSCryptoX509NameWrite(issuer name)", xmlSecKeyDataGetName(data));
                    return(-1);
                }
                x509Value->issuerSerial = xmlSecMSCryptoASN1IntegerWrite(&(ctx->crt->pCertInfo->SerialNumber));
                if (x509Value->issuerSerial == NULL) {
                    xmlSecInternalError("xmlSecMSCryptoASN1IntegerWrite(issuer serial)", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            if( (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_DIGEST_NODE)) && (x509Value->digestAlgorithm != NULL)) {
                ret = xmlSecMSCryptoX509DigestWrite(ctx->crt, x509Value->digestAlgorithm, &(x509Value->digest));
                if (ret < 0) {
                    xmlSecInternalError("xmlSecMSCryptoX509DigestWrite", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            /* done */
            return(1);
        } else {
            ctx->doneCrts = 1;
        }
    }

    /* try to get and write the next crl if available */
    if (ctx->doneCrls == 0) {
        /* CertEnumCRLsInStore automatically frees the previous CRL context (see
         * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcrlsinstore) */
        ctx->crl = CertEnumCRLsInStore(ctx->store, ctx->crl);
        if (ctx->crl != NULL) {
            if (XMLSEC_X509DATA_HAS_EMPTY_NODE(content, XMLSEC_X509DATA_CRL_NODE)) {
                xmlSecAssert2(ctx->crl->pbCrlEncoded != NULL, -1);
                xmlSecAssert2(ctx->crl->cbCrlEncoded > 0, -1);

                ret = xmlSecBufferSetData(&(x509Value->crl), ctx->crl->pbCrlEncoded, ctx->crl->cbCrlEncoded);
                if (ret < 0) {
                    xmlSecInternalError("xmlSecBufferSetData", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            /* done */
            return(1);
        } else {
            ctx->doneCrls = 1;
        }
    }

    /* no more certs or crls */
    xmlSecAssert2(ctx->doneCrts != 0, -1);
    xmlSecAssert2(ctx->doneCrls != 0, -1);
    return(0);
}

static int
xmlSecMSCryptoKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data, xmlSecKeyPtr key,
                                              xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoX509DataCtxPtr ctx;
    xmlSecKeyDataStorePtr x509Store;
    time_t origNotValidBefore;
    time_t origNotValidAfter;
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
                CertFreeCertificateContext(cert);
                return(-1);
            }
            CertFreeCertificateContext(cert);

            /* search key according to KeyReq */
            pCert = CertDuplicateCertificateContext(ctx->keyCert);
            if(pCert == NULL) {
                xmlSecMSCryptoError("CertDuplicateCertificateContext",
                                    xmlSecKeyDataGetName(data));
                return(-1);
            }

            if((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) == xmlSecKeyDataTypePrivate) {
                keyValue = xmlSecMSCryptoCertAdopt(pCert, xmlSecKeyDataTypePrivate);
                if(keyValue == NULL) {
                    xmlSecInternalError("xmlSecMSCryptoCertAdopt",
                                        xmlSecKeyDataGetName(data));
                    CertFreeCertificateContext(pCert);
                    return(-1);
                }
                pCert = NULL;
            } else {
                keyValue = xmlSecMSCryptoCertAdopt(pCert, xmlSecKeyDataTypePublic);
                if(keyValue == NULL) {
                    xmlSecInternalError("xmlSecMSCryptoCertAdopt",
                                        xmlSecKeyDataGetName(data));
                    CertFreeCertificateContext(pCert);
                    return(-1);
                }
                pCert = NULL;
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

            if (ctx->keyCert->pCertInfo == NULL) {
                xmlSecInternalError("ctx->keyCert->pCertInfo is NULL",
                                    xmlSecKeyDataGetName(data));
                return(-1);
            }

            /* copy the cert validity period into the key; save the previous
             * values so they can be restored if the conversion fails */
            origNotValidBefore = key->notValidBefore;
            origNotValidAfter = key->notValidAfter;

            ret = xmlSecMSCryptoX509CertGetTime(ctx->keyCert->pCertInfo->NotBefore, &(key->notValidBefore));
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoX509CertGetTime(notValidBefore)",
                                    xmlSecKeyDataGetName(data));
                goto restore;
            }

            ret = xmlSecMSCryptoX509CertGetTime(ctx->keyCert->pCertInfo->NotAfter, &(key->notValidAfter));
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoX509CertGetTime(notValidAfter)",
                                    xmlSecKeyDataGetName(data));
                goto restore;
            }
        } else if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT) != 0) {
            xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND,
                             xmlSecKeyDataGetName(data), NULL);
            return(-1);
        }
    }
    return(0);
restore:
    key->notValidBefore = origNotValidBefore;
    key->notValidAfter = origNotValidAfter;
    return(-1);
}

static int
xmlSecMSCryptoX509CertGetTime(FILETIME t, time_t* res) {
    LONGLONG result;

    xmlSecAssert2(res != NULL, -1);

    result = t.dwHighDateTime;
    result = (result) << 32;
    result |= t.dwLowDateTime;
    /* 100 nanoseconds -> seconds */
    result /= 10000000;
    /* 1601-01-01 epoch -> 1970-01-01 epoch */
    result -= 11644473600LL;

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
xmlSecMSCryptoX509CrlDerRead(const xmlSecByte* buf, xmlSecSize size) {
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

    xmlSecAssert2(nm != NULL, NULL);
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
    DWORD dwSize = 0;
    BOOL rv;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);

    /* First check if the SKI extension actually exists, otherwise we get the SHA-1 hash of the public key */
    pCertExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension);
    if (pCertExt == NULL) {
        return(0);
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
    xmlSecAssert(cert->pCertInfo != NULL);
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

    /* serial number (CRYPT_INTEGER_BLOB is little-endian; print in big-endian X.509 order) */
    sn = &(cert->pCertInfo->SerialNumber);
    fprintf(output, "==== Serial Number: ");
    for (i = sn->cbData; i > 0; i--) {
        if (i != 1) {
            fprintf(output, "%02x:", sn->pbData[i - 1]);
        } else {
            fprintf(output, "%02x", sn->pbData[i - 1]);
        }
    }
    fprintf(output, "\n");

done:
    if (subject) xmlFree(subject);
    if (issuer) xmlFree(issuer);
}


static void
xmlSecMSCryptoX509CertDebugXmlDump(PCCERT_CONTEXT cert, FILE* output) {
    xmlChar * subject = NULL;
    xmlChar * issuer = NULL;
    xmlChar * serial = NULL;

    xmlSecAssert(cert != NULL);
    xmlSecAssert(cert->pCertInfo != NULL);
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

    /* serial number (decimal, same format as the XML writer) */
    serial = xmlSecMSCryptoASN1IntegerWrite(&(cert->pCertInfo->SerialNumber));
    if(serial == NULL) {
        xmlSecInternalError("xmlSecMSCryptoASN1IntegerWrite(serial)", NULL);
        goto done;
    }
    fprintf(output, "<SerialNumber>");
    xmlSecPrintXmlString(output, BAD_CAST serial);
    fprintf(output, "</SerialNumber>\n");

done:
    xmlFree(subject);
    xmlFree(issuer);
    xmlFree(serial);
}


/******************************************************************************
 *
 * Raw X509 Certificate processing
 *
 *
  *****************************************************************************/
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
    NULL,                                       /* xmlSecKeyDataInitMethod initialize; */
    NULL,                                       /* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,                                       /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    NULL,                                       /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */

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
 * @brief The raw X509 certificates key data klass.
 * @return raw X509 certificates key data klass.
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

#else /* XMLSEC_NO_X509 */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_X509 */
