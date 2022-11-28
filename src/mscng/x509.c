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
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/x509.h>

#include <xmlsec/mscng/certkeys.h>
#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/x509.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"

typedef struct _xmlSecMSCngX509DataCtx xmlSecMSCngX509DataCtx,
                                       *xmlSecMSCngX509DataCtxPtr;

struct _xmlSecMSCngX509DataCtx {
    HCERTSTORE hMemStore;
    PCCERT_CONTEXT cert;
};

XMLSEC_KEY_DATA_DECLARE(MSCngX509Data, xmlSecMSCngX509DataCtx)
#define xmlSecMSCngX509DataSize XMLSEC_KEY_DATA_SIZE(MSCngX509Data)

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
            /* ignore error */
        }
    }

    if(ctx->hMemStore != 0) {
        if(!CertCloseStore(ctx->hMemStore, 0)) {
            xmlSecMSCngLastError("CertCloseStore", NULL);
            /* ignore error */
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
    DWORD dwSize;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(size, dwSize, return(NULL), NULL);
    cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, dwSize);
    if(cert == NULL) {
        xmlSecMSCngLastError("CertCreateCertificateContext", NULL);
        return(NULL);
    }

    return(cert);
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


static PCCRL_CONTEXT
xmlSecMSCngX509CrlDerRead(xmlSecByte* buf, xmlSecSize size) {
    PCCRL_CONTEXT crl = NULL;
    DWORD dwSize;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(size, dwSize, return(NULL), NULL);
    crl = CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, dwSize);
    if(crl == NULL) {
        xmlSecMSCngLastError("CertCreateCRLContext", NULL);
        return(NULL);
    }

    return(crl);
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
xmlSecMSCngKeyDataX509Read(xmlSecKeyDataPtr data, xmlSecKeyValueX509Ptr x509Value,
    xmlSecKeysMngrPtr keysMngr, unsigned int flags) {
    xmlSecKeyDataStorePtr x509Store;
    int stopOnUnknownCert = 0;
    PCCERT_CONTEXT cert = NULL;
    PCCRL_CONTEXT crl = NULL;
    int ret;
    int res = -1;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(keysMngr != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(keysMngr, xmlSecMSCngX509StoreId);
    if (x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore", xmlSecKeyDataGetName(data));
        goto done;
    }

    /* determine what to do */
    if ((flags & XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT) != 0) {
        stopOnUnknownCert = 1;
    }

    if (xmlSecBufferGetSize(&(x509Value->cert)) > 0) {
        cert = xmlSecMSCngX509CertDerRead(xmlSecBufferGetData(&(x509Value->cert)),
            xmlSecBufferGetSize(&(x509Value->cert)));
        if (cert == NULL) {
            xmlSecInternalError("xmlSecMSCngX509CertDerRead", xmlSecKeyDataGetName(data));
            goto done;
        }
    }
    else if (xmlSecBufferGetSize(&(x509Value->crl)) > 0) {
        crl = xmlSecMSCngX509CrlDerRead(xmlSecBufferGetData(&(x509Value->crl)),
            xmlSecBufferGetSize(&(x509Value->crl)));
        if (crl == NULL) {
            xmlSecInternalError("xmlSecMSCngX509CertDerRead", xmlSecKeyDataGetName(data));
            goto done;
        }
    }
    else if (xmlSecBufferGetSize(&(x509Value->ski)) > 0) {
        cert = xmlSecMSCngX509StoreFindCert_ex(x509Store, NULL, NULL, NULL,
            xmlSecBufferGetData(&(x509Value->ski)), xmlSecBufferGetSize(&(x509Value->ski)),
            NULL /* unused */);
        if ((cert == NULL) && (stopOnUnknownCert != 0)) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data),
                "skiSize=" XMLSEC_SIZE_FMT, xmlSecBufferGetSize(&(x509Value->ski)));
            goto done;
        }
    }
    else if (x509Value->subject != NULL) {
        cert = xmlSecMSCngX509StoreFindCert_ex(x509Store, x509Value->subject,
            NULL, NULL, NULL, 0, NULL /* unused */);
        if ((cert == NULL) && (stopOnUnknownCert != 0)) {
            xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_NOT_FOUND, xmlSecKeyDataGetName(data),
                "subject=%s", xmlSecErrorsSafeString(x509Value->subject));
            goto done;
        }
    }
    else if ((x509Value->issuerName != NULL) && (x509Value->issuerSerial != NULL)) {
        cert = xmlSecMSCngX509StoreFindCert_ex(x509Store, NULL,
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
        ret = xmlSecMSCngKeyDataX509AdoptCert(data, cert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCert", xmlSecKeyDataGetName(data));
            goto done;
        }
        cert = NULL; /* owned by data now */
    }
    if (crl != NULL) {
        ret = xmlSecMSCngKeyDataX509AdoptCrl(data, crl);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCrl", xmlSecKeyDataGetName(data));
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
xmlSecMSCngKeyDataX509XmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                              xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);

    data = xmlSecKeyEnsureData(key, id);
    if (data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecKeyDataX509XmlRead(data, node, keyInfoCtx,
        xmlSecMSCngKeyDataX509Read);
    if (ret < 0) {
        xmlSecInternalError("xmlSecKeyDataX509XmlRead",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecMSCngKeyDataX509VerifyAndExtractKey(data, key, keyInfoCtx);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509VerifyAndExtractKey",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }
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

static xmlChar*
xmlSecMSCngASN1IntegerWrite(PCRYPT_INTEGER_BLOB num) {
    xmlSecBn bn;
    xmlChar* res;
    int ret;

    xmlSecAssert2(num != NULL, NULL);

    ret = xmlSecBnInitialize(&bn, num->cbData + 1);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBnInitialize", NULL, "size=%lu", num->cbData + 1);
        return(NULL);
    }

    ret = xmlSecBnSetData(&bn, num->pbData, num->cbData);
    if(ret < 0) {
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
xmlSecMSCngX509SKIWrite(PCCERT_CONTEXT cert, xmlSecBufferPtr buf) {
    PCERT_EXTENSION pCertExt;
    DWORD dwSize;
    BOOL rv;
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    /* First check if the SKI extension actually exists, otherwise we get a SHA1 hash of the cert */
    pCertExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, cert->pCertInfo->cExtension, cert->pCertInfo->rgExtension);
    if (pCertExt == NULL) {
        xmlSecMSCngLastError("CertFindExtension", NULL);
        return (0);
    }

    rv = CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, NULL, &dwSize);
    if (!rv || dwSize <= 0) {
        xmlSecMSCngLastError("CertGetCertificateContextProperty", NULL);
        return(-1);
    }

    ret = xmlSecBufferSetMaxSize(buf, dwSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
            "size=%lu", dwSize);
        return(-1);
    }

    if (!CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, xmlSecBufferGetData(buf), &dwSize)) {
        xmlSecMSCngLastError("CertGetCertificateContextProperty", NULL);
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

typedef struct _xmlSecMSCngKeyDataX5099WriteContext {
    HCERTSTORE store;
    PCCERT_CONTEXT crt;
    PCCRL_CONTEXT crl;
    int doneCrts;
    int doneCrls;
} xmlSecMSCngKeyDataX5099WriteContext;

static int
xmlSecMSCngKeyDataX509Write(xmlSecKeyDataPtr data, xmlSecKeyValueX509Ptr x509Value,
                            int content, void* context) {
    xmlSecMSCngKeyDataX5099WriteContext* ctx;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id), -1);
    xmlSecAssert2(x509Value != NULL, -1);
    xmlSecAssert2(context != NULL, -1);

    ctx = (xmlSecMSCngKeyDataX5099WriteContext*)context;
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->store != NULL, -1);

    /* try to get and write the next cert if availablle */
    if (ctx->doneCrts == 0) {
        ctx->crt = CertEnumCertificatesInStore(ctx->store, ctx->crt);
        if (ctx->crt != NULL) {
            if ((content & XMLSEC_X509DATA_CERTIFICATE_NODE) != 0) {
                xmlSecAssert2(ctx->crt->pbCertEncoded != NULL, -1);
                xmlSecAssert2(ctx->crt->cbCertEncoded > 0, -1);

                ret = xmlSecBufferSetData(&(x509Value->cert), ctx->crt->pbCertEncoded, ctx->crt->cbCertEncoded);
                if (ret < 0) {
                    xmlSecInternalError("xmlSecBufferSetData", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            if ((content & XMLSEC_X509DATA_SKI_NODE) != 0) {
                ret = xmlSecMSCngX509SKIWrite(ctx->crt, &(x509Value->ski));
                if (ret < 0) {
                    xmlSecInternalError("xmlSecMSCngX509SKIWrite", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            if ((content & XMLSEC_X509DATA_SUBJECTNAME_NODE) != 0) {
                xmlSecAssert2(x509Value->subject == NULL, -1);
                xmlSecAssert2(ctx->crt->pCertInfo != NULL, -1);

                x509Value->subject = xmlSecMSCngX509NameWrite(&(ctx->crt->pCertInfo->Subject));
                if (x509Value->subject == NULL) {
                    xmlSecInternalError("xmlSecMSCngX509NameWrite(subject)", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            if ((content & XMLSEC_X509DATA_ISSUERSERIAL_NODE) != 0) {
                xmlSecAssert2(x509Value->issuerName == NULL, -1);
                xmlSecAssert2(x509Value->issuerSerial == NULL, -1);
                xmlSecAssert2(ctx->crt->pCertInfo != NULL, -1);

                x509Value->issuerName = xmlSecMSCngX509NameWrite(&(ctx->crt->pCertInfo->Issuer));
                if (x509Value->issuerName == NULL) {
                    xmlSecInternalError("xmlSecMSCngX509NameWrite(issuer name)", xmlSecKeyDataGetName(data));
                    return(-1);
                }
                x509Value->issuerSerial = xmlSecMSCngASN1IntegerWrite(&(ctx->crt->pCertInfo->SerialNumber));
                if (x509Value->issuerSerial == NULL) {
                    xmlSecInternalError("xmlSecMSCngASN1IntegerWrite(issuer serial))", xmlSecKeyDataGetName(data));
                   return(-1);
                }
            }
            /* done */
            return(0);
        } else {
            ctx->doneCrts = 1;
        }
    }

    /* try to get and write the next crl if availablle */
    if (ctx->doneCrls == 0) {
        ctx->crl = CertEnumCRLsInStore(ctx->store, ctx->crl);
        if (ctx->crl != NULL) {
            if ((content & XMLSEC_X509DATA_CRL_NODE) != 0) {
                xmlSecAssert2(ctx->crl->pbCrlEncoded != NULL, -1);
                xmlSecAssert2(ctx->crl->cbCrlEncoded > 0, -1);

                ret = xmlSecBufferSetData(&(x509Value->crl), ctx->crl->pbCrlEncoded, ctx->crl->cbCrlEncoded);
                if (ret < 0) {
                    xmlSecInternalError("xmlSecBufferSetData", xmlSecKeyDataGetName(data));
                    return(-1);
                }
            }
            /* done */
            return(0);
        } else {
            ctx->doneCrls = 1;
        }
    }

    /* no more certs or crls */
    xmlSecAssert2(ctx->doneCrts != 0, -1);
    xmlSecAssert2(ctx->doneCrls != 0, -1);
    return(1);
}

static int
xmlSecMSCngKeyDataX509XmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                               xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCngKeyDataX5099WriteContext context;
    xmlSecMSCngX509DataCtxPtr x509DataCtx;
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataX509Id, -1);
    xmlSecAssert2(key != NULL, -1);

    /* get x509 data */
    data = xmlSecKeyGetData(key, id);
    if (data == NULL) {
        /* no x509 data in the key */
        return(0);
    }
    x509DataCtx = xmlSecMSCngX509DataGetCtx(data);
    xmlSecAssert2(x509DataCtx != NULL, -1);

    /* setup context */
    context.store = x509DataCtx->hMemStore;
    context.crt = NULL;
    context.crl = NULL;
    context.doneCrts = context.doneCrls = 0;

    ret = xmlSecKeyDataX509XmlWrite(data, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecMSCngKeyDataX509Write, &context);
    if (ret < 0) {
        xmlSecInternalError("xmlSecKeyDataX509XmlWrite",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /* success */
    return(0);
}

static void
xmlSecMSCngKeyDataX509DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));
    xmlSecAssert(output != NULL);

    xmlSecNotImplementedError(NULL);
    /* ignore error */
}

static void
xmlSecMSCngKeyDataX509DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataX509Id));
    xmlSecAssert(output != NULL);

    xmlSecNotImplementedError(NULL);
    /* ignore error */
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
