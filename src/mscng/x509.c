/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
 */

#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <string.h>

#include <windows.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/x509.h>
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>

#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/x509.h>
#include <xmlsec/mscng/certkeys.h>

typedef struct _xmlSecMSCngX509DataCtx xmlSecMSCngX509DataCtx,
                                       *xmlSecMSCngX509DataCtxPtr;

struct _xmlSecMSCngX509DataCtx {
    HCERTSTORE hMemStore;
    PCCERT_CONTEXT cert;
};

#define xmlSecMSCngX509DataSize      \
    (sizeof(xmlSecKeyData) + sizeof(xmlSecMSCngX509DataCtx))
#define xmlSecMSCngX509DataGetCtx(data) \
    ((xmlSecMSCngX509DataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int
xmlSecMSCngKeyDataX509Initialize(xmlSecKeyDataPtr data) {
    xmlSecMSCngX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    memset(ctx, 0, sizeof(xmlSecMSCngX509DataCtx));

    ctx->hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
        0,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);
    if(ctx->hMemStore == 0) {
        xmlSecMSCngLastError("CertOpenStore", xmlSecKeyDataGetName(data));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngKeyDataX509Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataX509Id), -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static void
xmlSecMSCngKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    xmlSecMSCngX509DataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));

    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->cert != NULL) {
        CertFreeCertificateContext(ctx->cert);
    }

    if(ctx->hMemStore != 0) {
        if(!CertCloseStore(ctx->hMemStore, CERT_CLOSE_STORE_CHECK_FLAG)) {
            xmlSecMSCngLastError("CertCloseStore", NULL);
        }
    }

    memset(ctx, 0, sizeof(xmlSecMSCngX509DataCtx));
}

static xmlSecKeyDataType
xmlSecMSCngKeyDataX509GetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), xmlSecKeyDataTypeUnknown);

    return(xmlSecKeyDataTypeUnknown);
}

static const xmlChar*
xmlSecMSCngKeyDataX509GetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), NULL);

    return(NULL);
}

/**
 * xmlSecMSCngX509CertDerRead:
 *
 * The MSCng reader for the binary (DER-encoded) X509 certificate content.
 */
static PCCERT_CONTEXT
xmlSecMSCngX509CertDerRead(const xmlSecByte* buf, xmlSecSize size) {
    PCCERT_CONTEXT cert;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, size);
    if(cert == NULL) {
        xmlSecMSCngLastError("CertCreateCertificateContext", NULL);
        return(NULL);
    }

    return(cert);
}

/**
 * xmlSecMSCngX509CertBase64DerRead:
 *
 * The MSCng reader for the <X509Certificate> XML content.
 */
static PCCERT_CONTEXT
xmlSecMSCngX509CertBase64DerRead(xmlChar* buf) {
    int size;

    xmlSecAssert2(buf != NULL, NULL);

    /* in-place decoding */
    size = xmlSecBase64Decode(buf, (xmlSecByte*)buf, xmlStrlen(buf));
    if(size < 0) {
        xmlSecInternalError("xmlSecBase64Decode", NULL);
        return(NULL);
    }

    return(xmlSecMSCngX509CertDerRead((xmlSecByte*)buf, size));
}

static int
xmlSecMSCngKeyDataX509AdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert) {
    xmlSecMSCngX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hMemStore != 0, -1);

    if(!CertAddCertificateContextToStore(ctx->hMemStore,
        cert,
        CERT_STORE_ADD_ALWAYS,
        NULL)) {
        xmlSecMSCngLastError("CertAddCertificateContextToStore",
            xmlSecKeyDataGetName(data));
        return(-1);
    }

    /* this just decrements the refcount, so won't free */
    CertFreeCertificateContext(cert);
    return(0);
}

/**
 * xmlSecMSCngX509CertificateNodeRead:
 *
 * The MSCng reader for the <X509Certificate> XML element.
 */
static int
xmlSecMSCngX509CertificateNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node,
    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar* content;
    PCCERT_CONTEXT cert;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlNodeGetContent(node);
    if((content == NULL) || (xmlSecIsEmptyString(content) == 1)) {
        if(content != NULL) {
            xmlFree(content);
        }

        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
            xmlSecInvalidNodeContentError(node, xmlSecKeyDataGetName(data),
                "content is an empty string");
            return(-1);
        }

        return(0);
    }

    cert = xmlSecMSCngX509CertBase64DerRead(content);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecMSCngX509CertBase64DerRead",
            xmlSecKeyDataGetName(data));
        return(-1);
    }

    ret = xmlSecMSCngKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCert",
            xmlSecKeyDataGetName(data));
        return(-1);

    }

    xmlFree(content);
    return(0);
}

/**
 * xmlSecMSCngX509DataNodeRead:
 *
 * The MSCng reader for the <X509Data> XML element.
 */
static int
xmlSecMSCngX509DataNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node,
    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    for(cur = xmlSecGetNextElementNode(node->children);
        cur != NULL;
        cur = xmlSecGetNextElementNode(cur->next)) {
        if(xmlSecCheckNodeName(cur, xmlSecNodeX509Certificate, xmlSecDSigNs)) {
            ret = xmlSecMSCngX509CertificateNodeRead(data, cur, keyInfoCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509CertificateNodeRead",
                    xmlSecKeyDataGetName(data));
                return(-1);
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SubjectName, xmlSecDSigNs)) {
            xmlSecNotImplementedError(NULL);
            return(-1);
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerSerial, xmlSecDSigNs)) {
            xmlSecNotImplementedError(NULL);
            return(-1);
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SKI, xmlSecDSigNs)) {
            xmlSecNotImplementedError(NULL);
            return(-1);
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509CRL, xmlSecDSigNs)) {
            xmlSecNotImplementedError(NULL);
            return(-1);
        } else if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CHILD) != 0) {
            xmlSecUnexpectedNodeError(cur, xmlSecKeyDataGetName(data));
            return(-1);
        }
    }
    return(0);
}

static int
xmlSecMSCngX509CertGetTime(FILETIME in, time_t* out) {
    xmlSecAssert2(out != NULL, -1);

    *out = in.dwHighDateTime;
    *out <<= 32;
    *out |= in.dwLowDateTime;
    /* 100 nanoseconds -> seconds */
    *out /= 10000;
    /* WinAPI epoch -> Unix epoch */
    *out -= 11644473600000;

    return(0);
}

static int
xmlSecMSCngKeyDataX509VerifyAndExtractKey(xmlSecKeyDataPtr data,
    xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCngX509DataCtxPtr ctx;
    xmlSecKeyDataStorePtr store;
    PCCERT_CONTEXT cert;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        return(0);
    }

    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hMemStore != 0, -1);

    if(ctx->cert != NULL) {
        return(0);
    }

    store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCngX509StoreId);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore",
            xmlSecKeyDataGetName(data));
        return(-1);
    }

    cert = xmlSecMSCngX509StoreVerify(store, ctx->hMemStore, keyInfoCtx);
    if(cert != NULL) {
        int ret;
        PCCERT_CONTEXT certCopy;
        xmlSecKeyDataPtr keyValue = NULL;

        ctx->cert = CertDuplicateCertificateContext(cert);
        if(ctx->cert == NULL) {
            xmlSecMSCngLastError("CertDuplicateCertificateContext",
                xmlSecKeyDataGetName(data));
            return(-1);
        }

        /* copy the certificate, so it can be adopted according to the key data
         * type */
        certCopy = CertDuplicateCertificateContext(ctx->cert);
        if(certCopy == NULL) {
            xmlSecMSCngLastError("CertDuplicateCertificateContext",
                xmlSecKeyDataGetName(data));
            return(-1);
        }

        if((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate) != 0) {
            xmlSecNotImplementedError(NULL);
            return(-1);
        } else if((keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePublic) != 0) {
            keyValue = xmlSecMSCngCertAdopt(certCopy, xmlSecKeyDataTypePublic);
            if(keyValue == NULL) {
                xmlSecInternalError("xmlSecMSCngCertAdopt",
                    xmlSecKeyDataGetName(data));
                return(-1);
            }
        }

        /* verify that keyValue matches the key requirements */
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

        ret = xmlSecMSCngX509CertGetTime(ctx->cert->pCertInfo->NotBefore,
            &(key->notValidBefore));
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509CertGetTime",
                xmlSecKeyDataGetName(data));
            return(-1);
        }

        ret = xmlSecMSCngX509CertGetTime(ctx->cert->pCertInfo->NotAfter,
            &(key->notValidAfter));
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509CertGetTime",
                xmlSecKeyDataGetName(data));
            return(-1);
        }
    } else if((keyInfoCtx->flags &
            XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT) != 0) {
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_FOUND,
            xmlSecKeyDataGetName(data), NULL);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngKeyDataX509XmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                              xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    data = xmlSecKeyEnsureData(key, id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecMSCngX509DataNodeRead(data, node, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509DataNodeRead",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecMSCngKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509VerifyAndExtractKey",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                               xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static void
xmlSecMSCngKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));
    xmlSecAssert(output != NULL);

    xmlSecNotImplementedError(NULL);
}

static void
xmlSecMSCngKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));
    xmlSecAssert(output != NULL);

    xmlSecNotImplementedError(NULL);
}

static xmlSecKeyDataKlass xmlSecMSCngKeyDataX509Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCngX509DataSize,

    /* data */
    xmlSecNameX509Data,
    xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefX509Data,                         /* const xmlChar* href; */
    xmlSecNodeX509Data,                         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCngKeyDataX509Initialize,           /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCngKeyDataX509Duplicate,            /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCngKeyDataX509Finalize,             /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCngKeyDataX509GetType,              /* xmlSecKeyDataGetTypeMethod getType; */
    NULL,                                       /* xmlSecKeyDataGetSizeMethod getSize; */
    xmlSecMSCngKeyDataX509GetIdentifier,        /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCngKeyDataX509XmlRead,              /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCngKeyDataX509XmlWrite,             /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCngKeyDataX509DebugDump,            /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCngKeyDataX509DebugXmlDump,         /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataX509GetKlass:
 *
 * The MSCng X509 key data klass.
 *
 * Returns: the X509 data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataX509GetKlass(void) {
    return(&xmlSecMSCngKeyDataX509Klass);
}

#endif /* XMLSEC_NO_X509 */
