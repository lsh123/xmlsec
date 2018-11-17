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
 * SECTION:certkeys
 * @Short_description: Certificate keys support functions for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <wincrypt.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>

#include <xmlsec/mscng/crypto.h>

typedef struct _xmlSecMSCngKeyDataCtx xmlSecMSCngKeyDataCtx,
                                      *xmlSecMSCngKeyDataCtxPtr;

struct _xmlSecMSCngKeyDataCtx {
    PCCERT_CONTEXT cert;
    NCRYPT_KEY_HANDLE privkey;
    BCRYPT_KEY_HANDLE pubkey;
};

#define xmlSecMSCngKeyDataSize       \
    (sizeof(xmlSecKeyData) + sizeof(xmlSecMSCngKeyDataCtx))
#define xmlSecMSCngKeyDataGetCtx(data) \
    ((xmlSecMSCngKeyDataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int xmlSecMSCngKeyDataGetSize(xmlSecKeyDataPtr data);

static int
xmlSecMSCngKeyDataCertGetPubkey(PCCERT_CONTEXT cert, BCRYPT_KEY_HANDLE* key) {
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    if(!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
            &cert->pCertInfo->SubjectPublicKeyInfo,
            0,
            NULL,
            key)) {
        xmlSecMSCngLastError("CryptImportPublicKeyInfoEx2", NULL);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngKeyDataCertGetPrivkey(PCCERT_CONTEXT cert, NCRYPT_KEY_HANDLE* key) {
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    DWORD keySpec = 0;
    BOOL callerFree = FALSE;

    ret = CryptAcquireCertificatePrivateKey(
        cert,
        CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
        NULL,
        key,
        &keySpec,
        &callerFree);
    if(ret == FALSE) {
        xmlSecMSCngLastError("CryptAcquireCertificatePrivateKey", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngKeyDataAdoptCert:
 * @data:               the pointer to MSCng pccert data.
 * @cert:               the pointer to PCCERT key.
 *
 * Sets the value of key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
static int
xmlSecMSCngKeyDataAdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT cert, xmlSecKeyDataType type) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    BCRYPT_KEY_HANDLE hPubKey;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(cert->pCertInfo != NULL, -1);
    xmlSecAssert2((type & (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate)) != 0, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey == NULL, -1);
    xmlSecAssert2(ctx->cert == NULL, -1);

    /* acquire the CNG key handle from the certificate */
    if((type & xmlSecKeyDataTypePrivate) != 0) {
        NCRYPT_KEY_HANDLE hPrivKey;

        ret = xmlSecMSCngKeyDataCertGetPrivkey(cert, &hPrivKey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataCertGetPrivkey", NULL);
            return(-1);
        }

        ctx->privkey = hPrivKey;
    }

    ret = xmlSecMSCngKeyDataCertGetPubkey(cert, &hPubKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataCertGetPubkey", NULL);
        return(-1);
    }

    ctx->pubkey = hPubKey;
    ctx->cert = cert;

    return(0);
}

static int
xmlSecMSCngKeyDataAdoptKey(xmlSecKeyDataPtr data, BCRYPT_KEY_HANDLE hPubKey) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);
    xmlSecAssert2(hPubKey != NULL, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey == NULL, -1);

    ctx->pubkey = hPubKey;

    return(0);
}

/**
 * xmlSecMSCngCertAdopt:
 * @pCert:              the pointer to cert.
 * @type:               the expected key type.
 *
 * Creates key data value from the cert.
 *
 * Returns: pointer to newly created xmlsec key or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecMSCngCertAdopt(PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecKeyDataPtr data = NULL;
    int ret;

    xmlSecAssert2(pCert != NULL, NULL);
    xmlSecAssert2(pCert->pCertInfo != NULL, NULL);
    xmlSecAssert2(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId != NULL, NULL);

#ifndef XMLSEC_NO_DSA
    if(!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_X957_DSA)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataDsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataDsaId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
    if(!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataRsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataRsaId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_ECDSA
    if(!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataEcdsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataEcdsaId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_ECDSA */

    if(data == NULL) {
        xmlSecInvalidStringTypeError("PCCERT_CONTEXT key type",
            pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
            "unsupported keytype",
            NULL);
        return(NULL);
    }

    ret = xmlSecMSCngKeyDataAdoptCert(data, pCert, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptCert", NULL);
        xmlSecKeyDataDestroy(data);
        return(NULL);
    }

    return(data);
}

/**
 * xmlSecMSCngKeyDataGetPubKey:
 * @data: the key data to retrieve certificate from.
 *
 * Native MSCng public key retrieval from xmlsec keydata. The returned key must
 * not be destroyed by the caller.
 *
 * Returns: key on success or 0 otherwise.
 */
BCRYPT_KEY_HANDLE
xmlSecMSCngKeyDataGetPubKey(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), 0);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->pubkey);
}

/**
 * xmlSecMSCngKeyDataGetPrivKey:
 * @data: the key data to retrieve certificate from.
 *
 * Native MSCng private key retrieval from xmlsec keydata. The returned key
 * must not be destroyed by the caller.
 *
 * Returns: key on success or 0 otherwise.
 */
NCRYPT_KEY_HANDLE
xmlSecMSCngKeyDataGetPrivKey(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), 0);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->privkey);
}

static int
xmlSecMSCngKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));

    return(0);
}

static void
xmlSecMSCngKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    NTSTATUS status;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize));

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if(ctx->privkey != 0) {
        status = NCryptFreeObject(ctx->privkey);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDestroyKey", NULL, status);
        }
    }

    if(ctx->pubkey != 0) {
        status = BCryptDestroyKey(ctx->pubkey);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDestroyKey", NULL, status);
        }
    }

    if(ctx->cert != NULL) {
        CertFreeCertificateContext(ctx->cert);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));
}

static int
xmlSecMSCngKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecMSCngKeyDataCtxPtr dstCtx;
    xmlSecMSCngKeyDataCtxPtr srcCtx;
    NTSTATUS status;
    DWORD cbBlob = 0;
    PUCHAR pbBlob;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    LPCWSTR pszAlgId;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecMSCngKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecMSCngKeyDataSize), -1);

    dstCtx = xmlSecMSCngKeyDataGetCtx(dst);
    xmlSecAssert2(dstCtx != NULL, -1);
    xmlSecAssert2(dstCtx->cert == NULL, -1);
    xmlSecAssert2(dstCtx->privkey == 0, -1);
    xmlSecAssert2(dstCtx->pubkey == NULL, -1);

    srcCtx = xmlSecMSCngKeyDataGetCtx(src);
    xmlSecAssert2(srcCtx != NULL, -1);

    if(srcCtx->cert != NULL) {
        dstCtx->cert = CertDuplicateCertificateContext(srcCtx->cert);
        if(dstCtx->cert == NULL) {
            xmlSecMSCngLastError("CertDuplicateCertificateContext", NULL);
            return(-1);
        }
    }

    if(srcCtx->privkey != 0) {
        ret = xmlSecMSCngKeyDataCertGetPrivkey(dstCtx->cert, &dstCtx->privkey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataCertGetPrivkey", NULL);
            return(-1);
        }
    }

    if(dstCtx->cert != NULL) {
        /* avoid BCryptDuplicateKey() here as that works for symmetric keys only */
        ret = xmlSecMSCngKeyDataCertGetPubkey(dstCtx->cert, &dstCtx->pubkey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataCertGetPubkey", NULL);
            return(-1);
        }
    } else if(srcCtx->pubkey != NULL) {
        /* BCryptDuplicateKey() works with symmetric keys only, so go with
         * export + import instead */
        status = BCryptExportKey(srcCtx->pubkey,
            NULL,
            BCRYPT_PUBLIC_KEY_BLOB,
            NULL,
            0,
            &cbBlob,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptExportKey", NULL, status);
            return(-1);
        }

        pbBlob = (PUCHAR)xmlMalloc(cbBlob);
        if(pbBlob == NULL) {
            xmlSecMallocError(cbBlob, NULL);
            return(-1);
        }

        status = BCryptExportKey(srcCtx->pubkey,
            NULL,
            BCRYPT_PUBLIC_KEY_BLOB,
            pbBlob,
            cbBlob,
            &cbBlob,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptExportKey", NULL, status);
            xmlFree(pbBlob);
            return(-1);
        }

        switch(((BCRYPT_KEY_BLOB*)pbBlob)->Magic) {
#ifndef XMLSEC_NO_DSA
            case BCRYPT_DSA_PUBLIC_MAGIC:
                pszAlgId = BCRYPT_DSA_ALGORITHM;
                break;
#endif
#ifndef XMLSEC_NO_RSA
            case BCRYPT_RSAPUBLIC_MAGIC:
                pszAlgId = BCRYPT_RSA_ALGORITHM;
                break;
#endif
            default:
                xmlSecNotImplementedError(NULL);
                xmlFree(pbBlob);
                return(-1);
        }

        status = BCryptOpenAlgorithmProvider(
            &hAlg,
            pszAlgId,
            NULL,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
                NULL, status);
            xmlFree(pbBlob);
            return(-1);
        }

        status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_PUBLIC_KEY_BLOB, &dstCtx->pubkey, pbBlob,
            cbBlob, 0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptImportKeyPair",
                NULL, status);
            xmlFree(pbBlob);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return(-1);
        }

        xmlFree(pbBlob);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return(0);
}

#ifndef XMLSEC_NO_DSA
static int
xmlSecMSCngKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCngKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataDsaId), -1);

    return(xmlSecMSCngKeyDataDuplicate(dst, src));
}

static xmlSecKeyDataType
xmlSecMSCngKeyDataDsaGetType(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDsaId), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if(ctx->privkey != 0) {
        return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    }

    return(xmlSecKeyDataTypePublic);
}

static xmlSecSize
xmlSecMSCngKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDsaId), 0);

    return(xmlSecMSCngKeyDataGetSize(data));
}

static int
xmlSecMSCngKeyDataDsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecBn p;
    xmlSecBn q;
    xmlSecBn g;
    xmlSecBn y;
    xmlSecBuffer blob;
    xmlNodePtr cur;
    xmlSecSize length;
    xmlSecSize offset;
    xmlSecSize blobLen;
    unsigned char* blobData;
    BCRYPT_DSA_KEY_BLOB* dsakey;
    LPCWSTR lpszBlobType;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
            xmlSecKeyDataKlassGetName(id), "key already has a value");
        return(-1);
    }

    /* initialize buffers */
    ret = xmlSecBnInitialize(&p, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(p)",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecBnInitialize(&q, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(q)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&p);
        return(-1);
    }

    ret = xmlSecBnInitialize(&g, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(g)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&p);
        xmlSecBnFinalize(&q);
        return(-1);
    }

    ret = xmlSecBnInitialize(&y, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(g)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&p);
        xmlSecBnFinalize(&q);
        xmlSecBnFinalize(&g);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&blob, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&p);
        xmlSecBnFinalize(&q);
        xmlSecBnFinalize(&g);
        xmlSecBnFinalize(&y);
        return(-1);
    }

    /* read xml */
    cur = xmlSecGetNextElementNode(node->children);

    /* P node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeDSAP, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAP,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* 0 as both the XML and CNG works with big-endian */
    ret = xmlSecBnGetNodeValue(&p, cur, xmlSecBnBase64, 0);
    if((ret < 0) || (xmlSecBnGetSize(&p) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(p)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    cur = xmlSecGetNextElementNode(cur->next);

    /* Q node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAQ, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAQ,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecBnGetNodeValue(&q, cur, xmlSecBnBase64, 0);
    if((ret < 0) || (xmlSecBnGetSize(&q) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(q)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    cur = xmlSecGetNextElementNode(cur->next);

    /* G node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAG, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAG,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecBnGetNodeValue(&g, cur, xmlSecBnBase64, 0);
    if((ret < 0) || (xmlSecBnGetSize(&q) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(g)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    cur = xmlSecGetNextElementNode(cur->next);

    /* TODO X node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAX, xmlSecNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* Y node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAY, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAY,
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecBnGetNodeValue(&y, cur, xmlSecBnBase64, 0);
    if((ret < 0) || (xmlSecBnGetSize(&y) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(y)",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    cur = xmlSecGetNextElementNode(cur->next);

    /* TODO J node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAJ, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* TODO Seed node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSASeed, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* TODO PgenCounter node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAPgenCounter, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* turn the read data into a public key blob, as documented at
     * <https://msdn.microsoft.com/library/windows/desktop/aa833126.aspx>: Q is
     * part of the struct, need to write P, G, Y after it */
    length = xmlSecBnGetSize(&p);
    offset = sizeof(BCRYPT_DSA_KEY_BLOB);
    blobLen = offset + length * 3;

    ret = xmlSecBufferSetSize(&blob, blobLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=%d", blobLen);
        goto done;
    }

    blobData = xmlSecBufferGetData(&blob);
    dsakey = (BCRYPT_DSA_KEY_BLOB *)blobData;
    dsakey->cbKey = length;

    memset(dsakey->Count, -1, sizeof(dsakey->Count));
    memset(dsakey->Seed, -1, sizeof(dsakey->Seed));

    if(xmlSecBnGetSize(&q) != 20) {
        xmlSecInternalError("assumed sizeof(q) == 20", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    memcpy(dsakey->q, xmlSecBnGetData(&q), 20);

    memcpy(blobData + offset, xmlSecBnGetData(&p), length);
    offset += length;

    if(xmlSecBnGetSize(&g) != xmlSecBnGetSize(&p)) {
        xmlSecInternalError("assumed sizeof(g) == sizeof(p)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    memcpy(blobData + offset, xmlSecBnGetData(&g), length);
    offset += length;

    if(xmlSecBnGetSize(&y) != xmlSecBnGetSize(&p)) {
        xmlSecInternalError("assumed sizeof(y) == sizeof(p)", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    memcpy(blobData + offset, xmlSecBnGetData(&y), length);

    lpszBlobType = BCRYPT_DSA_PUBLIC_BLOB;
    dsakey->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC;

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_DSA_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
            xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    status = BCryptImportKeyPair(hAlg, NULL, lpszBlobType, &hKey, blobData,
        blobLen, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair",
            xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    keyData = xmlSecKeyDataCreate(id);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(keyData, hKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey",
            xmlSecKeyDataGetName(keyData));
        goto done;
    }

    hKey = 0;
    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
	xmlSecInternalError("xmlSecKeySetValue",
            xmlSecKeyDataGetName(keyData));
        goto done;
    }

    keyData = NULL;
    res = 0;

done:
    xmlSecBnFinalize(&p);
    xmlSecBnFinalize(&q);
    xmlSecBnFinalize(&g);
    xmlSecBnFinalize(&y);
    xmlSecBufferFinalize(&blob);

    if(hAlg != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if(hKey != 0) {
        BCryptDestroyKey(hKey);
    }

    return(res);
}

static int
xmlSecMSCngKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
          xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    NTSTATUS status;
    xmlSecBuffer buf;
    xmlSecByte* bufData;
    DWORD bufLen;
    BCRYPT_DSA_KEY_BLOB* dsakey;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key),
        xmlSecMSCngKeyDataDsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(xmlSecKeyGetValue(key));
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey, -1);

    /* turn ctx->pubkey into dsakey */
    status = BCryptExportKey(ctx->pubkey,
        NULL,
        BCRYPT_DSA_PUBLIC_BLOB,
        NULL,
        0,
        &bufLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&buf, bufLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize",
            xmlSecKeyDataKlassGetName(id), "size=%ld", bufLen);
        return(-1);
    }

    bufData = xmlSecBufferGetData(&buf);
    dsakey = (BCRYPT_DSA_KEY_BLOB*)bufData;

    status = BCryptExportKey(ctx->pubkey,
        NULL,
        BCRYPT_DSA_PUBLIC_BLOB,
        (PUCHAR)dsakey,
        bufLen,
        &bufLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* write dsaykey in XML format, see xmlSecMSCngKeyDataDsaXmlRead() on the
     * memory layout of bufData: the struct contains Q, and P, G, Y follows it */

    /* P node */
    cur = xmlSecAddChild(node, xmlSecNodeDSAP, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(p)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* reverse is 0, both CNG and XML is big-endian */
    bufData += sizeof(BCRYPT_DSA_KEY_BLOB);
    ret = xmlSecBnBlobSetNodeValue(bufData, dsakey->cbKey, cur, xmlSecBnBase64, 0, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(p)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* Q node */
    cur = xmlSecAddChild(node, xmlSecNodeDSAQ, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(q)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* 20 is the documented size of BCRYPT_DSA_KEY_BLOB.q */
    ret = xmlSecBnBlobSetNodeValue((xmlSecByte*)dsakey->q, 20, cur, xmlSecBnBase64, 0, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(q)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* G node */
    cur = xmlSecAddChild(node, xmlSecNodeDSAG, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(g)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    bufData += dsakey->cbKey;
    ret = xmlSecBnBlobSetNodeValue(bufData, dsakey->cbKey, cur, xmlSecBnBase64, 0, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(g)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* Y node */
    cur = xmlSecAddChild(node, xmlSecNodeDSAY, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(y)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    bufData += dsakey->cbKey;
    ret = xmlSecBnBlobSetNodeValue(bufData, dsakey->cbKey, cur, xmlSecBnBase64, 0, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(y)",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    xmlSecBufferFinalize(&buf);

    return(0);
}

static void
xmlSecMSCngKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = %d\n",
            (int)xmlSecMSCngKeyDataDsaGetSize(data));
}

static void xmlSecMSCngKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<DSAKeyValue size=\"%d\" />\n",
            (int)xmlSecMSCngKeyDataDsaGetSize(data));
}

static int
xmlSecMSCngKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits,
        xmlSecKeyDataType type) {
    UNREFERENCED_PARAMETER(type);
    xmlSecMSCngKeyDataCtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hKey = 0;
    int res = -1;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_DSA_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
            xmlSecKeyDataGetName(data), status);
        goto done;
    }

    status = BCryptGenerateKeyPair(
        hAlg,
        &hKey,
        sizeBits,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGenerateKeyPair", xmlSecKeyDataGetName(data),
            status);
        goto done;
    }

    /* need to finalize the key before it can be used */
    status = BCryptFinalizeKeyPair(hKey, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptFinalizeKeyPair", xmlSecKeyDataGetName(data),
            status);
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(data, hKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    hKey = 0;

    /* success */
    res = 0;

done:
    if (hKey != 0) {
        BCryptDestroyKey(hKey);
    }

    if (hAlg != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return(res);
}

static xmlSecKeyDataKlass xmlSecMSCngKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCngKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefDSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeDSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCngKeyDataInitialize,               /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCngKeyDataDsaDuplicate,             /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCngKeyDataFinalize,                 /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCngKeyDataDsaGenerate,              /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCngKeyDataDsaGetType,               /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCngKeyDataDsaGetSize,               /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCngKeyDataDsaXmlRead,               /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCngKeyDataDsaXmlWrite,              /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCngKeyDataDsaDebugDump,             /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCngKeyDataDsaDebugXmlDump,          /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataDsaGetKlass:
 *
 * The MSCng DSA CertKey data klass.
 *
 * Returns: pointer to MSCng DSA key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataDsaGetKlass(void) {
    return(&xmlSecMSCngKeyDataDsaKlass);
}
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
static int
xmlSecMSCngKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCngKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataRsaId), -1);

    return(xmlSecMSCngKeyDataDuplicate(dst, src));
}

static xmlSecKeyDataType
xmlSecMSCngKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataRsaId), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if(ctx->privkey != 0) {
        return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    }

    return(xmlSecKeyDataTypePublic);
}

static int
xmlSecMSCngKeyDataGetSize(xmlSecKeyDataPtr data) {
    NTSTATUS status;
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), 0);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    if(ctx->cert != NULL) {
        xmlSecAssert2(ctx->cert->pCertInfo != NULL, 0);
        return(CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &ctx->cert->pCertInfo->SubjectPublicKeyInfo));
    } else if(ctx->pubkey != 0) {
        DWORD length = 0;
        DWORD lenlen = sizeof(DWORD);

        status = BCryptGetProperty(ctx->pubkey,
            BCRYPT_KEY_STRENGTH,
            (PUCHAR)&length,
            lenlen,
            &lenlen,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptGetproperty", NULL, status);
            return(0);
        }

        return(length);
    } else if(ctx->privkey != 0) {
        xmlSecNotImplementedError(NULL);
        return(0);
    }

    return(0);
}

static xmlSecSize
xmlSecMSCngKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataRsaId), 0);

    return(xmlSecMSCngKeyDataGetSize(data));
}


static void
xmlSecMSCngKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = %d\n",
            (int)xmlSecMSCngKeyDataRsaGetSize(data));
}

static void xmlSecMSCngKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<RSAKeyValue size=\"%d\" />\n",
            (int)xmlSecMSCngKeyDataRsaGetSize(data));
}

static int
xmlSecMSCngKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecBn modulus, exponent;
    xmlSecBuffer blob;
    xmlSecSize blobBufferLen;
    xmlSecSize offset;
    BCRYPT_RSAKEY_BLOB* rsakey;
    LPCWSTR lpszBlobType;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    BCRYPT_KEY_HANDLE hKey = 0;
    xmlNodePtr cur;
    int res = -1;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
                         xmlSecKeyDataKlassGetName(id),
                         "key already has a value");
        return(-1);
    }

    /* initialize buffers */
    ret = xmlSecBnInitialize(&modulus, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize",
            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecBnInitialize(&exponent, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&modulus);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&blob, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&modulus);
        xmlSecBnFinalize(&exponent);
        return(-1);
    }

    /* read xml */
    cur = xmlSecGetNextElementNode(node->children);

    /* first is Modulus node, it is required because we do not support Seed and PgenCounter */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeRSAModulus, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeRSAModulus,
                               xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* 0 as both the XML and CNG works with big-endian */
    ret = xmlSecBnGetNodeValue(&modulus, cur, xmlSecBnBase64, 0);
    if((ret < 0) || (xmlSecBnGetSize(&modulus) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Exponent node, it is required because we do not support Seed and PgenCounter */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeRSAExponent, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeRSAExponent, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecBnGetNodeValue(&exponent, cur, xmlSecBnBase64, 0);
    if((ret < 0) || (xmlSecBnGetSize(&exponent) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* TODO X node */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRSAPrivateExponent, xmlSecNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* turn the read data into a public key blob, as documented at
     * <https://msdn.microsoft.com/en-us/library/windows/desktop/aa375531(v=vs.85).aspx>:
     * need to write exponent and modulus after the struct */
    blobBufferLen = sizeof(BCRYPT_RSAKEY_BLOB) + xmlSecBnGetSize(&exponent) +
        xmlSecBnGetSize(&modulus);
    ret = xmlSecBufferSetSize(&blob, blobBufferLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize",
            xmlSecKeyDataKlassGetName(id), "size=%d", blobBufferLen);
        goto done;
    }

    rsakey = (BCRYPT_RSAKEY_BLOB *)xmlSecBufferGetData(&blob);
    rsakey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    rsakey->BitLength = xmlSecBnGetSize(&modulus) * 8;
    rsakey->cbPublicExp = xmlSecBnGetSize(&exponent);
    rsakey->cbModulus = xmlSecBnGetSize(&modulus);
    offset = sizeof(BCRYPT_RSAKEY_BLOB);

    memcpy(xmlSecBufferGetData(&blob) + offset, xmlSecBnGetData(&exponent),
        xmlSecBnGetSize(&exponent));
    offset += xmlSecBnGetSize(&exponent);

    memcpy(xmlSecBufferGetData(&blob) + offset, xmlSecBnGetData(&modulus),
        xmlSecBnGetSize(&modulus));

    lpszBlobType = BCRYPT_RSAPUBLIC_BLOB;

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
            xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    status = BCryptImportKeyPair(hAlg, NULL, lpszBlobType, &hKey,
        xmlSecBufferGetData(&blob), xmlSecBufferGetSize(&blob), 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair",
            xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    keyData = xmlSecKeyDataCreate(id);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(keyData, hKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey",
            xmlSecKeyDataGetName(keyData));
        goto done;
    }

    hKey = 0;
    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
	xmlSecInternalError("xmlSecKeySetValue",
            xmlSecKeyDataGetName(keyData));
        goto done;
    }

    keyData = NULL;
    res = 0;

done:
    xmlSecBnFinalize(&exponent);
    xmlSecBnFinalize(&modulus);
    xmlSecBufferFinalize(&blob);

    if(hKey != 0) {
        BCryptDestroyKey(hKey);
    }

    if(hAlg != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return(res);
}

static int
xmlSecMSCngKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
          xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    NTSTATUS status;
    xmlSecBuffer buf;
    xmlSecByte* bufData;
    DWORD bufLen;
    BCRYPT_RSAKEY_BLOB* rsakey;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key),
        xmlSecMSCngKeyDataRsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(xmlSecKeyGetValue(key));
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey, -1);

    /* turn ctx->pubkey into rsakey */
    status = BCryptExportKey(ctx->pubkey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        0,
        &bufLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&buf, bufLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize",
            xmlSecKeyDataKlassGetName(id), "size=%ld", bufLen);
        return(-1);
    }

    bufData = xmlSecBufferGetData(&buf);
    rsakey = (BCRYPT_RSAKEY_BLOB*)bufData;

    status = BCryptExportKey(ctx->pubkey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        (PUCHAR)rsakey,
        bufLen,
        &bufLen,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* write rsaykey in XML format, see xmlSecMSCngKeyDataRsaXmlRead() on the
     * memory layout of bufData: the struct is followed by Exponent and Modulus */

    /* Modulus node */
    cur = xmlSecAddChild(node, xmlSecNodeRSAModulus, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    bufData += sizeof(BCRYPT_RSAKEY_BLOB) + rsakey->cbPublicExp;
    ret = xmlSecBnBlobSetNodeValue(bufData, rsakey->cbModulus, cur, xmlSecBnBase64, 0, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* Exponent node */
    cur = xmlSecAddChild(node, xmlSecNodeRSAExponent, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    bufData = xmlSecBufferGetData(&buf);
    bufData += sizeof(BCRYPT_RSAKEY_BLOB);
    ret = xmlSecBnBlobSetNodeValue(bufData, rsakey->cbPublicExp, cur, xmlSecBnBase64, 0, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue",
            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    xmlSecBufferFinalize(&buf);

    return(0);
}

static int
xmlSecMSCngKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits,
        xmlSecKeyDataType type) {
    UNREFERENCED_PARAMETER(type);
    xmlSecMSCngKeyDataCtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hKey = 0;
    int res = -1;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider",
            xmlSecKeyDataGetName(data), status);
        goto done;
    }

    status = BCryptGenerateKeyPair(
        hAlg,
        &hKey,
        sizeBits,
        0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGenerateKeyPair", xmlSecKeyDataGetName(data),
            status);
        goto done;
    }

    /* need to finalize the key before it can be used */
    status = BCryptFinalizeKeyPair(hKey, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptFinalizeKeyPair", xmlSecKeyDataGetName(data),
            status);
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(data, hKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey",
            xmlSecKeyDataGetName(data));
        goto done;
    }
    hKey = 0;

    /* success */
    res = 0;

done:
    if (hKey != 0) {
        BCryptDestroyKey(hKey);
    }

    if (hAlg != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return(res);
}

static xmlSecKeyDataKlass xmlSecMSCngKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCngKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCngKeyDataInitialize,               /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCngKeyDataRsaDuplicate,             /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCngKeyDataFinalize,                 /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCngKeyDataRsaGenerate,              /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCngKeyDataRsaGetType,               /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCngKeyDataRsaGetSize,               /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCngKeyDataRsaXmlRead,               /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCngKeyDataRsaXmlWrite,              /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCngKeyDataRsaDebugDump,             /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCngKeyDataRsaDebugXmlDump,          /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataRsaGetKlass:
 *
 * The MSCng RSA CertKey data klass.
 *
 * Returns: pointer to MSCng RSA key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataRsaGetKlass(void) {
    return(&xmlSecMSCngKeyDataRsaKlass);
}
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_ECDSA
static int
xmlSecMSCngKeyDataEcdsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCngKeyDataEcdsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataEcdsaId), -1);

    return(xmlSecMSCngKeyDataDuplicate(dst, src));
}

static xmlSecKeyDataType
xmlSecMSCngKeyDataEcdsaGetType(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if(ctx->privkey != 0) {
        return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    }

    return(xmlSecKeyDataTypePublic);
}

static xmlSecSize
xmlSecMSCngKeyDataEcdsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId), 0);

    return(xmlSecMSCngKeyDataGetSize(data));
}


static void
xmlSecMSCngKeyDataEcdsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = %d\n",
            (int)xmlSecMSCngKeyDataEcdsaGetSize(data));
}

static void xmlSecMSCngKeyDataEcdsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<ECDSAKeyValue size=\"%d\" />\n",
            (int)xmlSecMSCngKeyDataEcdsaGetSize(data));
}

static xmlSecKeyDataKlass xmlSecMSCngKeyDataEcdsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCngKeyDataSize,

    /* data */
    xmlSecNameECDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefECDSAKeyValue,                    /* const xmlChar* href; */
    xmlSecNodeECDSAKeyValue,                    /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCngKeyDataInitialize,               /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCngKeyDataEcdsaDuplicate,           /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCngKeyDataFinalize,                 /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCngKeyDataEcdsaGetType,             /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCngKeyDataEcdsaGetSize,             /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCngKeyDataEcdsaDebugDump,           /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCngKeyDataEcdsaDebugXmlDump,        /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecMSCngKeyDataEcdsaGetKlass:
 *
 * The MSCng ECDSA CertKey data klass.
 *
 * Returns: pointer to MSCng ECDSA key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataEcdsaGetKlass(void) {
    return(&xmlSecMSCngKeyDataEcdsaKlass);
}
#endif /* XMLSEC_NO_ECDSA */
