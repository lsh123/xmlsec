/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:x509
 * @Short_description: X509 certificates implementation for Microsoft Cryptography API: Next Generation (CNG). 
 * @Stability: Stable
 *
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
    PCCERT_CONTEXT srcCert = NULL;
    PCCERT_CONTEXT dstCert;
    xmlSecMSCngX509DataCtxPtr srcCtx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataX509Id), -1);
    srcCtx = xmlSecMSCngX509DataGetCtx(src);

    /* duplicate the certificate store */
    while((srcCert = CertEnumCertificatesInStore(srcCtx->hMemStore, srcCert)) != NULL) {
        dstCert = CertDuplicateCertificateContext(srcCert);
        if(dstCert == NULL) {
            xmlSecMSCngLastError("CertDuplicateCertificateContext",
                xmlSecKeyDataGetName(dst));
            return(-1);
        }

        ret = xmlSecMSCngKeyDataX509AdoptCert(dst, dstCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCert",
                xmlSecKeyDataGetName(dst));
            CertFreeCertificateContext(dstCert);
            return(-1);
        }
    }

    if(srcCtx->cert != NULL) {
        /* have a key certificate, duplicate that */
        dstCert = CertDuplicateCertificateContext(srcCtx->cert);
        if(dstCert == NULL) {
            xmlSecMSCngLastError("CertDuplicateCertificateContext",
                xmlSecKeyDataGetName(dst));
            return(-1);
        }

        ret = xmlSecMSCngKeyDataX509AdoptKeyCert(dst, dstCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptKeyCert",
                xmlSecKeyDataGetName(dst));
            CertFreeCertificateContext(dstCert);
            return(-1);
        }
    }

    return(0);
}

static void
xmlSecMSCngKeyDataX509Finalize(xmlSecKeyDataPtr data) {
    xmlSecMSCngX509DataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));

    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->cert != NULL) {
        if(!CertFreeCertificateContext(ctx->cert)) {
            xmlSecMSCngLastError("CertFreeCertificateContext", NULL);
        }
    }

    if(ctx->hMemStore != 0) {
        if(!CertCloseStore(ctx->hMemStore, 0)) {
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


int
xmlSecMSCngKeyDataX509AdoptKeyCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert) {
    xmlSecMSCngX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    if(ctx->cert != NULL) {
        CertFreeCertificateContext(ctx->cert);
    }
    ctx->cert = cert;

    return(0);
}

int
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
 * xmlSecMSCngKeyDataX509AdoptCrl:
 * @data:               the pointer to X509 key data.
 * @crl:                the pointer to MSCng X509 CRL.
 *
 * Adds CRL to the X509 key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeyDataX509AdoptCrl(xmlSecKeyDataPtr data, PCCRL_CONTEXT crl) {
    xmlSecMSCngX509DataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(crl != 0, -1);

    ctx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->hMemStore != 0, -1);

    if (!CertAddCRLContextToStore(ctx->hMemStore, crl, CERT_STORE_ADD_ALWAYS, NULL)) {
        xmlSecMSCngLastError("CertAddCRLContextToStore",
            xmlSecKeyDataGetName(data));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngX509SubjectNameNodeRead:
 *
 * The MSCng reader for the <X509SubjectName> XML element.
 */
static int
xmlSecMSCngX509SubjectNameNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node,
    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr store;
    xmlChar* subject;
    PCCERT_CONTEXT cert;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCngX509StoreId);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore",
            xmlSecKeyDataGetName(data));
        return(-1);
    }

    subject = xmlNodeGetContent(node);
    if((subject == NULL) || (xmlSecIsEmptyString(subject) == 1)) {
        if(subject != NULL) {
            xmlFree(subject);
        }
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
            xmlSecInvalidNodeContentError(node, xmlSecKeyDataGetName(data),
                "empty");
            return(-1);
        }

        return(0);
    }

    cert = xmlSecMSCngX509StoreFindCert(store, subject, NULL, NULL, NULL, keyInfoCtx);
    if(cert == NULL) {
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_NOT_FOUND,
                xmlSecKeyDataGetName(data), "subject=%s",
                xmlSecErrorsSafeString(subject));
            xmlFree(subject);
            return(-1);
        }

        xmlFree(subject);
        return(0);
    }

    ret = xmlSecMSCngKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCert",
            xmlSecKeyDataGetName(data));
        CertFreeCertificateContext(cert);
        xmlFree(subject);
        return(-1);
    }

    xmlFree(subject);
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
 * xmlSecMSCngX509IssuerSerialNodeRead:
 *
 * The MSCng reader for the <X509IssuerSerial> XML element.
 */
static int
xmlSecMSCngX509IssuerSerialNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node,
    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr store;
    xmlNodePtr cur;
    xmlChar* issuerName;
    xmlChar* issuerSerial;
    PCCERT_CONTEXT cert;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCngX509StoreId);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore",
            xmlSecKeyDataGetName(data));
        return(-1);
    }

    cur = xmlSecGetNextElementNode(node->children);
    if(cur == NULL) {
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
            xmlSecNodeNotFoundError("xmlSecGetNextElementNode", node, NULL,
                xmlSecKeyDataGetName(data));
            return(-1);
        }

        return(0);
    }

    /* handle X509IssuerName */
    if(!xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerName, xmlSecDSigNs)) {
        xmlSecInvalidNodeError(cur, xmlSecNodeX509IssuerName,
            xmlSecKeyDataGetName(data));
        return(-1);
    }

    issuerName = xmlNodeGetContent(cur);
    if(issuerName == NULL) {
        xmlSecInvalidNodeContentError(cur, xmlSecKeyDataGetName(data),
            "empty");
        return(-1);
    }

    cur = xmlSecGetNextElementNode(cur->next);
    if(cur == NULL) {
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
            xmlSecNodeNotFoundError("xmlSecGetNextElementNode", node, NULL,
                xmlSecKeyDataGetName(data));
            return(-1);
        }

        return(0);
    }

    /* handle X509SerialNumber */
    if(!xmlSecCheckNodeName(cur, xmlSecNodeX509SerialNumber, xmlSecDSigNs)) {
        xmlSecInvalidNodeError(cur, xmlSecNodeX509SerialNumber,
            xmlSecKeyDataGetName(data));
        xmlFree(issuerName);
        return(-1);
    }

    issuerSerial = xmlNodeGetContent(cur);
    if(issuerSerial == NULL) {
        xmlSecInvalidNodeContentError(cur, xmlSecKeyDataGetName(data),
            "empty");
        xmlFree(issuerSerial);
        return(-1);
    }

    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataGetName(data));
        xmlFree(issuerSerial);
        xmlFree(issuerName);
        return(-1);
    }

    cert = xmlSecMSCngX509StoreFindCert(store, NULL, issuerName, issuerSerial,
        NULL, keyInfoCtx);
    if(cert == NULL) {
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
            xmlSecOtherError3(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data),
                "issuerName=%s;issuerSerial=%s",
                xmlSecErrorsSafeString(issuerName),
                xmlSecErrorsSafeString(issuerSerial));
            xmlFree(issuerSerial);
            xmlFree(issuerName);
            return(-1);
        }

	xmlFree(issuerSerial);
	xmlFree(issuerName);
	return(0);
    }

    ret = xmlSecMSCngKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCert",
            xmlSecKeyDataGetName(data));
        CertFreeCertificateContext(cert);
        xmlFree(issuerSerial);
        xmlFree(issuerName);
        return(-1);
    }

    xmlFree(issuerSerial);
    xmlFree(issuerName);
    return(0);
}

/**
 * xmlSecMSCngX509SKINodeRead:
 *
 * The MSCng reader for the <X509SKI> XML element.
 */
static int
xmlSecMSCngX509SKINodeRead(xmlSecKeyDataPtr data, xmlNodePtr node,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr store;
    xmlChar* ski;
    PCCERT_CONTEXT cert;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2(keyInfoCtx->keysMngr != NULL, -1);

    store = xmlSecKeysMngrGetDataStore(keyInfoCtx->keysMngr, xmlSecMSCngX509StoreId);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore",
            xmlSecKeyDataGetName(data));
        return(-1);
    }

    ski = xmlNodeGetContent(node);
    if((ski == NULL) || (xmlSecIsEmptyString(ski) == 1)) {
        if(ski != NULL) {
            xmlFree(ski);
        }
        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE) != 0) {
            xmlSecInvalidNodeContentError(node, xmlSecKeyDataGetName(data),
                "empty");
            return(-1);
        }
        return(0);
    }

    cert = xmlSecMSCngX509StoreFindCert(store, NULL, NULL, NULL, ski, keyInfoCtx);
    if(cert == NULL){
        xmlFree(ski);

        if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data),
                              "ski=%s", xmlSecErrorsSafeString(ski));
            return(-1);
        }
        return(0);
    }

    ret = xmlSecMSCngKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCert",
                            xmlSecKeyDataGetName(data));
        CertFreeCertificateContext(cert);
        xmlFree(ski);
        return(-1);
    }

    xmlFree(ski);
    return(0);
}

static PCCRL_CONTEXT
xmlSecMSCngX509CrlDerRead(xmlSecByte* buf, xmlSecSize size,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    PCCRL_CONTEXT crl = NULL;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    crl = CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, size);

    if(crl == NULL) {
        xmlSecMSCngLastError("CertCreateCRLContext", NULL);
        return(NULL);
    }

    return(crl);
}

static PCCRL_CONTEXT
xmlSecMSCngX509CrlBase64DerRead(xmlChar* buf, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    int ret;

    xmlSecAssert2(buf != NULL, NULL);

    /* usual trick with base64 decoding in-place */
    ret = xmlSecBase64Decode(buf, (xmlSecByte*)buf, xmlStrlen(buf));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBase64Decode", NULL);
        return(NULL);
    }

    return(xmlSecMSCngX509CrlDerRead((xmlSecByte*)buf, ret, keyInfoCtx));
}

static int
xmlSecMSCngX509CRLNodeRead(xmlSecKeyDataPtr data, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar *content;
    PCCRL_CONTEXT crl;
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
            xmlSecInvalidNodeContentError(node, xmlSecKeyDataGetName(data), "empty");
            return(-1);
        }
        return(0);
    }

    crl = xmlSecMSCngX509CrlBase64DerRead(content, keyInfoCtx);
    if(crl == NULL) {
        xmlSecInternalError("xmlSecMSCngX509CrlBase64DerRead",
            xmlSecKeyDataGetName(data));
        xmlFree(content);
        return(-1);
    }

    ret = xmlSecMSCngKeyDataX509AdoptCrl(data, crl);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCrl",
            xmlSecKeyDataGetName(data));
        xmlFree(content);
        CertFreeCRLContext(crl);
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
            ret = xmlSecMSCngX509SubjectNameNodeRead(data, cur, keyInfoCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509SubjectNameNodeRead",
                    xmlSecKeyDataGetName(data));
                return(-1);
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509IssuerSerial, xmlSecDSigNs)) {
            ret = xmlSecMSCngX509IssuerSerialNodeRead(data, cur, keyInfoCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509IssuerSerialNodeRead", NULL);
                return(-1);
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509SKI, xmlSecDSigNs)) {
            ret = xmlSecMSCngX509SKINodeRead(data, cur, keyInfoCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509SKINodeRead", NULL);
                return(-1);
            }
        } else if(xmlSecCheckNodeName(cur, xmlSecNodeX509CRL, xmlSecDSigNs)) {
            ret = xmlSecMSCngX509CRLNodeRead(data, cur, keyInfoCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509CRLNodeRead",
                                    xmlSecKeyDataGetName(data));
                return(-1);
            }
        } else if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CHILD) != 0) {
            xmlSecUnexpectedNodeError(cur, xmlSecKeyDataGetName(data));
            return(-1);
        }
    }
    return(0);
}

/**
 * xmlSecMSCngX509CertGetTime:
 *
 * Converts FILETIME timestamp into time_t. See
 * <https://msdn.microsoft.com/en-us/library/windows/desktop/ms724284(v=vs.85).aspx>
 * for details.
 */
static int
xmlSecMSCngX509CertGetTime(FILETIME in, time_t* out) {
    xmlSecAssert2(out != NULL, -1);

    *out = in.dwHighDateTime;
    *out <<= 32;
    *out |= in.dwLowDateTime;
    /* 100 nanoseconds -> seconds */
    *out /= 10000;
    /* 1601-01-01 epoch -> 1970-01-01 epoch */
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
            keyValue = xmlSecMSCngCertAdopt(certCopy, xmlSecKeyDataTypePrivate);
            if(keyValue == NULL) {
                xmlSecInternalError("xmlSecMSCngCertAdopt",
                    xmlSecKeyDataGetName(data));
                return(-1);
            }
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
xmlSecMSCngX509CertificateNodeWrite(PCCERT_CONTEXT cert, xmlNodePtr node,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar* buf;
    xmlNodePtr child;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pbCertEncoded != NULL, -1);
    xmlSecAssert2(cert->cbCertEncoded > 0, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    buf = xmlSecBase64Encode(cert->pbCertEncoded, cert->cbCertEncoded,
        keyInfoCtx->base64LineSize);
    if(buf == NULL) {
        xmlSecInternalError("xmlSecBase64Encode", NULL);
        return(-1);
    }

    child = xmlSecEnsureEmptyChild(node, xmlSecNodeX509Certificate, xmlSecDSigNs);
    if(child == NULL) {
        xmlSecInternalError("xmlSecEnsureEmptyChild", NULL);
        xmlFree(buf);
        return(-1);
    }

    xmlNodeSetContent(child, buf);
    xmlFree(buf);

    return(0);
}

static xmlChar*
xmlSecMSCngX509NameWrite(PCERT_NAME_BLOB nm) {
    LPTSTR resT = NULL;
    xmlChar *res = NULL;
    DWORD csz;


    xmlSecAssert2(nm->pbData != NULL, NULL);
    xmlSecAssert2(nm->cbData > 0, NULL);

    csz = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, nm, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, NULL, 0);
    if(csz <= 0) {
        xmlSecMSCngLastError("CertNameToStr", NULL);
        return(NULL);
    }

    resT = (LPTSTR)xmlMalloc(sizeof(TCHAR) * (csz + 1));
    if (NULL == resT) {
        xmlSecMallocError(sizeof(TCHAR) * (csz + 1), NULL);
        return (NULL);
    }

    csz = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, nm, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, resT, csz + 1);
    if (csz <= 0) {
        xmlSecMSCngLastError("CertNameToStr", NULL);
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

static int
xmlSecMSCngX509SubjectNameNodeWrite(PCCERT_CONTEXT cert, xmlNodePtr node) {
    xmlChar* buf = NULL;
    xmlNodePtr cur = NULL;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    buf = xmlSecMSCngX509NameWrite(&(cert->pCertInfo->Subject));
    if(buf == NULL) {
        xmlSecInternalError("xmlSecMSCngX509NameWrite", NULL);
        return(-1);
    }

    cur = xmlSecEnsureEmptyChild(node, xmlSecNodeX509SubjectName, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecEnsureEmptyChild", NULL);
        xmlFree(buf);
        return(-1);
    }

    ret = xmlSecNodeEncodeAndSetContent(cur, buf);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNodeEncodeAndSetContent", NULL);
        xmlFree(buf);
        return(-1);
    }

    /* done */
    xmlFree(buf);
    return(0);
}

static int
xmlSecMSCngASN1IntegerWrite(xmlNodePtr node, PCRYPT_INTEGER_BLOB num) {
    xmlSecBn bn;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(num != NULL, -1);

    ret = xmlSecBnInitialize(&bn, num->cbData + 1);
    if(ret < 0) {
	xmlSecInternalError2("xmlSecBnInitialize", NULL, "size=%ld",
	    num->cbData + 1);
        return(-1);
    }

    ret = xmlSecBnSetData(&bn, num->pbData, num->cbData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnSetData", NULL);
        xmlSecBnFinalize(&bn);
        return(-1);
    }

    /* SerialNumber is little-endian, see <https://msdn.microsoft.com/en-us/library/windows/desktop/aa377200(v=vs.85).aspx>.
     * xmldsig wants big-endian, so enable reversing */
    ret = xmlSecBnSetNodeValue(&bn, node, xmlSecBnDec, 1, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnSetNodeValue", NULL);
        xmlSecBnFinalize(&bn);
        return(-1);
    }

    xmlSecBnFinalize(&bn);
    return(0);
}

static int
xmlSecMSCngX509IssuerSerialNodeWrite(PCCERT_CONTEXT cert, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlNodePtr issuerNameNode;
    xmlNodePtr issuerNumberNode;
    xmlChar* buf;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* create xml nodes */
    cur = xmlSecEnsureEmptyChild(node, xmlSecNodeX509IssuerSerial, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecEnsureEmptyChild", NULL);
        return(-1);
    }

    issuerNameNode = xmlSecEnsureEmptyChild(cur, xmlSecNodeX509IssuerName, xmlSecDSigNs);
    if(issuerNameNode == NULL) {
        xmlSecInternalError("xmlSecEnsureEmptyChild", NULL);
        return(-1);
    }

    issuerNumberNode = xmlSecEnsureEmptyChild(cur, xmlSecNodeX509SerialNumber, xmlSecDSigNs);
    if(issuerNumberNode == NULL) {
        xmlSecInternalError("xmlSecEnsureEmptyChild", NULL);
        return(-1);
    }

    /* write data */
    buf = xmlSecMSCngX509NameWrite(&(cert->pCertInfo->Issuer));
    if(buf == NULL) {
        xmlSecInternalError("xmlSecMSCngX509NameWrite", NULL);
        return(-1);
    }

    ret = xmlSecNodeEncodeAndSetContent(issuerNameNode, buf);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNodeEncodeAndSetContent", NULL);
        xmlFree(buf);
        return(-1);
    }

    xmlFree(buf);

    ret = xmlSecMSCngASN1IntegerWrite(issuerNumberNode, &(cert->pCertInfo->SerialNumber));
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngASN1IntegerWrite", NULL);
        return(-1);
    }
    return(0);
}

static xmlChar*
xmlSecMSCngX509SKIWrite(PCCERT_CONTEXT cert) {
    xmlChar *res = NULL;
    DWORD dwSize;
    BYTE *bSKI = NULL;
    PCERT_EXTENSION pCertExt;

    xmlSecAssert2(cert != NULL, NULL);

    /* First check if the SKI extension actually exists, otherwise we get a SHA1 hash of the cert */
    pCertExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension);
    if (pCertExt == NULL) {
        xmlSecMSCngLastError("CertFindExtension", NULL);
        return (NULL);
    }

    if (!CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, NULL, &dwSize) || dwSize < 1) {
        xmlSecMSCngLastError("CertGetCertificateContextProperty", NULL);
        return (NULL);
    }
    bSKI = xmlMalloc(dwSize);
    if (bSKI == NULL) {
        xmlSecMallocError(dwSize, NULL);
        return (NULL);
    }

    if (!CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, bSKI, &dwSize)) {
        xmlSecMSCngLastError("CertGetCertificateContextProperty", NULL);
        xmlFree(bSKI);
        return (NULL);
    }

    if (bSKI == NULL) {
        return(NULL);
    }

    res = xmlSecBase64Encode(bSKI, dwSize, 0);
    if(res == NULL) {
        xmlSecInternalError("xmlSecBase64Encode", NULL);
        xmlFree(bSKI);
        return(NULL);
    }
    xmlFree(bSKI);

    return(res);
}

static int
xmlSecMSCngX509SKINodeWrite(PCCERT_CONTEXT cert, xmlNodePtr node) {
    xmlChar *buf = NULL;
    xmlNodePtr cur = NULL;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    buf = xmlSecMSCngX509SKIWrite(cert);
    if(buf == NULL) {
        xmlSecInternalError("xmlSecMSCngX509SKIWrite", NULL);
        return(-1);
    }

    cur = xmlSecEnsureEmptyChild(node, xmlSecNodeX509SKI, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecEnsureEmptyChild", NULL);
        xmlFree(buf);
        return(-1);
    }

    ret = xmlSecNodeEncodeAndSetContent(cur, buf);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNodeEncodeAndSetContent", NULL);
        xmlFree(buf);
        return(-1);
    }

    xmlFree(buf);
    return(0);
}

static int
xmlSecMSCngX509CRLNodeWrite(PCCRL_CONTEXT crl, xmlNodePtr node,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(crl != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError(NULL);

    return(-1);
}

static int
xmlSecMSCngKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                               xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    int content;
    xmlSecKeyDataPtr keyData;
    xmlSecMSCngX509DataCtxPtr x509DataCtx;
    PCCERT_CONTEXT cert = NULL;
    HCERTSTORE certs;
    PCCRL_CONTEXT crlCtx = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    content = xmlSecX509DataGetNodeContent(node, keyInfoCtx);
    if(content < 0) {
        xmlSecInternalError("xmlSecX509DataGetNodeContent",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }
    if(content == 0) {
        /* no content -> writer the default */
        content = XMLSEC_X509DATA_DEFAULT;
    }

    keyData = xmlSecKeyGetData(key, id);
    if(keyData == NULL) {
        /* nothing to do */
        return(0);
    }

    xmlSecAssert2(xmlSecKeyDataCheckId(keyData, xmlSecMSCngKeyDataX509Id), -1);
    x509DataCtx = xmlSecMSCngX509DataGetCtx(keyData);
    certs = x509DataCtx->hMemStore;

    /* write certificates */
    while((cert = CertEnumCertificatesInStore(certs, cert)) != NULL) {
        if((content & XMLSEC_X509DATA_CERTIFICATE_NODE) != 0) {
            ret = xmlSecMSCngX509CertificateNodeWrite(cert, node, keyInfoCtx);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509CertificateNodeWrite",
                    xmlSecKeyDataKlassGetName(id));
                return(-1);
            }
        }

        if((content & XMLSEC_X509DATA_SUBJECTNAME_NODE) != 0) {
            ret = xmlSecMSCngX509SubjectNameNodeWrite(cert, node);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509SubjectNameNodeWrite",
                    xmlSecKeyDataKlassGetName(id));
                return(-1);
            }
        }

        if((content & XMLSEC_X509DATA_ISSUERSERIAL_NODE) != 0) {
            ret = xmlSecMSCngX509IssuerSerialNodeWrite(cert, node);
            if(ret< 0) {
                xmlSecInternalError("xmlSecMSCngX509IssuerSerialNodeWrite",
                    xmlSecKeyDataKlassGetName(id));
                return(-1);
            }
        }

        if((content & XMLSEC_X509DATA_SKI_NODE) != 0) {
            ret = xmlSecMSCngX509SKINodeWrite(cert, node);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngX509SKINodeWrite",
                    xmlSecKeyDataKlassGetName(id));
                return(-1);
            }
        }
    }

    /* write CRLs */
    while((crlCtx = CertEnumCRLsInStore(certs, crlCtx)) != NULL) {
        ret = xmlSecMSCngX509CRLNodeWrite(crlCtx, node, keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngX509CRLNodeWrite",
                xmlSecKeyDataKlassGetName(id));
            return(-1);
        }
    }

    return(0);
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

/**************************************************************************
 *
 * Raw X509 Certificate processing
 *
 *
 *************************************************************************/
static int
xmlSecMSCngKeyDataRawX509CertBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
        const xmlSecByte* buf, xmlSecSize bufSize,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    PCCERT_CONTEXT cert;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataRawX509CertId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cert = xmlSecMSCngX509CertDerRead(buf, bufSize);
    if(cert == NULL) {
        xmlSecInternalError("xmlSecMSCngX509CertDerRead", NULL);
        return(-1);
    }

    data = xmlSecKeyEnsureData(key, xmlSecMSCngKeyDataX509Id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData",
            xmlSecKeyDataKlassGetName(id));
        CertFreeCertificateContext(cert);
        return(-1);
    }

    ret = xmlSecMSCngKeyDataX509AdoptCert(data, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCert",
            xmlSecKeyDataKlassGetName(id));
        CertFreeCertificateContext(cert);
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

static xmlSecKeyDataKlass xmlSecMSCngKeyDataRawX509CertKlass = {
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
    xmlSecMSCngKeyDataRawX509CertBinRead,       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,                                       /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataRawX509CertGetKlass:
 *
 * The raw X509 certificates key data klass.
 *
 * Returns: raw X509 certificates key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataRawX509CertGetKlass(void) {
    return(&xmlSecMSCngKeyDataRawX509CertKlass);
}

#endif /* XMLSEC_NO_X509 */
