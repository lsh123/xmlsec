/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
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

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/certkeys.h>
#include <xmlsec/mscng/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "private.h"

typedef struct _xmlSecMSCngKeyDataCtx xmlSecMSCngKeyDataCtx,
                                      *xmlSecMSCngKeyDataCtxPtr;

struct _xmlSecMSCngKeyDataCtx {
    PCCERT_CONTEXT cert;
    NCRYPT_KEY_HANDLE privkey;
    BCRYPT_KEY_HANDLE pubkey;
    BOOL privkeyNeedsFree;
};

XMLSEC_KEY_DATA_DECLARE(MSCngKeyData, xmlSecMSCngKeyDataCtx)
#define xmlSecMSCngKeyDataSize XMLSEC_KEY_DATA_SIZE(MSCngKeyData)

static int
xmlSecMSCngKeyDataCertGetPubkey(PCCERT_CONTEXT cert, BCRYPT_KEY_HANDLE* key) {
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    if(!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
            &(cert->pCertInfo->SubjectPublicKeyInfo),
            0,
            NULL,
            key)) {
        xmlSecMSCngLastError("CryptImportPublicKeyInfoEx2", NULL);
        return(-1);
    }

    return(0);
}

static int
xmlSecMSCngKeyDataCertGetPrivkey(PCCERT_CONTEXT cert, NCRYPT_KEY_HANDLE* key, BOOL* needsFree) {
    int ret;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(needsFree != NULL, -1);

    /* try non persistent key */
    CERT_KEY_CONTEXT ckc;
    DWORD dwCkcLen = sizeof(ckc);
    if (CertGetCertificateContextProperty(cert, CERT_KEY_CONTEXT_PROP_ID, &ckc, &dwCkcLen)) {
        (*key) = ckc.hNCryptKey;
        (*needsFree) = FALSE; /* this key doesnt need NCryptFreeObject */
        return(0);
    }

    /* try persistent key */
    DWORD dwData = 0;
    DWORD dwDataLen = sizeof(dwData);
    if (CertGetCertificateContextProperty(cert, CERT_KEY_SPEC_PROP_ID, &dwData, &dwDataLen)) {
        DWORD keySpec = 0;
        BOOL fCallerFreeProvOrNCryptKey = FALSE;
        ret = CryptAcquireCertificatePrivateKey(
            cert,
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            NULL,
            key,
            &keySpec,
            &fCallerFreeProvOrNCryptKey);
        if (ret == FALSE) {
            xmlSecMSCngLastError("CryptAcquireCertificatePrivateKey", NULL);
            return(-1);
        }
        (*needsFree) = TRUE;
        return(0);
    }


    /* no luck */
    xmlSecMSCngLastError("CertGetCertificateContextProperty(): cert doesn't have private key", NULL);
    return(-1);
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
        NCRYPT_KEY_HANDLE hPrivKey = 0;
        BOOL needsFree = TRUE;

        ret = xmlSecMSCngKeyDataCertGetPrivkey(cert, &hPrivKey, &needsFree);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataCertGetPrivkey", NULL);
            return(-1);
        }

        ctx->privkey = hPrivKey;
        ctx->privkeyNeedsFree = needsFree;
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

int
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

xmlSecKeyDataPtr
xmlSecMSCngKeyDataFromAlgorithm(LPSTR pszObjId) {
    xmlSecKeyDataPtr data = NULL;

    xmlSecAssert2(pszObjId != NULL, NULL);

#ifndef XMLSEC_NO_DSA
    if (!strcmp(pszObjId, szOID_X957_DSA)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataDsaId);
        if (data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataDsaId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
    if (!strcmp(pszObjId, szOID_RSA_RSA)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataRsaId);
        if (data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataRsaId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_EC
    if (!strcmp(pszObjId, szOID_ECC_PUBLIC_KEY)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataEcId);
        if (data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataEcId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_EC */

    if (data == NULL) {
        xmlSecInvalidStringTypeError("Algorithm",
            pszObjId,
            "unsupported keytype",
            NULL);
        return(NULL);
    }

    return(data);
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

    data = xmlSecMSCngKeyDataFromAlgorithm(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
    if (data == NULL) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptCert", NULL);
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
xmlSecMSCngCertKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));

    return(0);
}

static void
xmlSecMSCngCertKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    NTSTATUS status;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize));

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if((ctx->privkey != 0) && (ctx->privkeyNeedsFree == TRUE)) {
        status = NCryptFreeObject(ctx->privkey);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDestroyKey", NULL, status);
            /* ignore error */
        }
    }

    if(ctx->pubkey != 0) {
        status = BCryptDestroyKey(ctx->pubkey);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDestroyKey", NULL, status);
            /* ignore error */
        }
    }

    if(ctx->cert != NULL) {
        CertFreeCertificateContext(ctx->cert);
    }

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));
}

static int
xmlSecMSCngCertKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
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
        ret = xmlSecMSCngKeyDataCertGetPrivkey(dstCtx->cert, &dstCtx->privkey, &dstCtx->privkeyNeedsFree);
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

#ifndef XMLSEC_NO_EC
            case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
            case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
                pszAlgId = BCRYPT_ECDSA_P256_ALGORITHM;
                break;
            case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
            case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
                pszAlgId = BCRYPT_ECDSA_P384_ALGORITHM;
                break;
            case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
            case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
                pszAlgId = BCRYPT_ECDSA_P521_ALGORITHM;
                break;
#endif
            default:
                xmlSecNotImplementedError2("Unexpected key magic value: %llu", (unsigned long long)(((BCRYPT_KEY_BLOB*)pbBlob)->Magic));
                xmlFree(pbBlob);
                return(-1);
        }

        status = BCryptOpenAlgorithmProvider(
            &hAlg,
            pszAlgId,
            NULL,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
            xmlFree(pbBlob);
            return(-1);
        }

        status = BCryptImportKeyPair(
            hAlg,
            NULL,
            BCRYPT_PUBLIC_KEY_BLOB,
            &dstCtx->pubkey,
            pbBlob,
            cbBlob,
            0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptImportKeyPair", NULL, status);
            xmlFree(pbBlob);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return(-1);
        }

        xmlFree(pbBlob);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return(0);
}


static xmlSecKeyDataType
xmlSecMSCngCertKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    if(ctx->privkey != 0) {
        return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    }

    return(xmlSecKeyDataTypePublic);
}

xmlSecSize
xmlSecMSCngCertKeyDataGetSize(xmlSecKeyDataPtr data) {
    NTSTATUS status;
    xmlSecMSCngKeyDataCtxPtr ctx;
    DWORD length = 0;
    xmlSecSize res;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), 0);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    if(ctx->cert != NULL) {
        xmlSecAssert2(ctx->cert->pCertInfo != NULL, 0);
        length = CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &ctx->cert->pCertInfo->SubjectPublicKeyInfo);
    } else if(ctx->pubkey != 0) {
        DWORD lenlen = sizeof(length);
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
        xmlSecAssert2(lenlen == sizeof(length), 0);
    } else if(ctx->privkey != 0) {
        xmlSecNotImplementedError("MSCNG doesn't support getting key length from private key");
        return(0);
    }

    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(length, res, return(0), NULL);
    return(res);
}

#define XMLSEC_MSCNG_CERTKEY_KLASS_EX(klassName, xmlName, usage, dataNodeName, dataNodeNs, generate, xmlRead, xmlWrite) \
static xmlSecKeyDataKlass xmlSecMSCngKeyData ## klassName ## Klass = {                                  \
    sizeof(xmlSecKeyDataKlass),                 /* xmlSecSize klassSize */                               \
    xmlSecMSCngKeyDataSize,                     /* xmlSecSize objSize */                                 \
                                                                                                         \
    /* data */                                                                                           \
    xmlSecName ## xmlName ## KeyValue,         /* const xmlChar* name; */                               \
    usage,                                      /* xmlSecKeyDataUsage usage; */                          \
    xmlSecHref ## xmlName ## KeyValue,         /* const xmlChar* href; */                               \
    dataNodeName,                               /* const xmlChar* dataNodeName; */                       \
    dataNodeNs,                                 /* const xmlChar* dataNodeNs; */                         \
                                                                                                         \
    /* constructors/destructor */                                                                        \
    xmlSecMSCngCertKeyDataInitialize,           /* xmlSecKeyDataInitializeMethod initialize; */          \
    xmlSecMSCngCertKeyDataDuplicate,            /* xmlSecKeyDataDuplicateMethod duplicate; */            \
    xmlSecMSCngCertKeyDataFinalize,             /* xmlSecKeyDataFinalizeMethod finalize; */              \
    generate,                                   /* xmlSecKeyDataGenerateMethod generate; */              \
                                                                                                         \
    /* get info */                                                                                       \
    xmlSecMSCngCertKeyDataGetType,              /* xmlSecKeyDataGetTypeMethod getType; */                \
    xmlSecMSCngCertKeyDataGetSize,              /* xmlSecKeyDataGetSizeMethod getSize; */                \
    NULL,                                       /* DEPRECATED xmlSecKeyDataGetIdentifier getIdentifier; */ \
                                                                                                         \
    /* read/write */                                                                                     \
    xmlRead,                                    /* xmlSecKeyDataXmlReadMethod xmlRead; */                \
    xmlWrite,                                   /* xmlSecKeyDataXmlWriteMethod xmlWrite; */              \
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */                \
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */              \
                                                                                                         \
    /* debug */                                                                                          \
    xmlSecKeyDataDebugDumpImpl,                 /* xmlSecKeyDataDebugDumpMethod debugDump; */            \
    xmlSecKeyDataDebugXmlDumpImpl,              /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */         \
                                                                                                         \
    /* reserved for the future */                                                                        \
    NULL,                                       /* void* reserved0; */                                   \
    NULL,                                       /* void* reserved1; */                                   \
};




#ifndef XMLSEC_NO_DSA

#define XMLSEC_MSCNG_DSA_MAX_Q_SIZE     (20U)

static xmlSecKeyDataPtr
xmlSecMSCngKeyDataDsaRead(xmlSecKeyDataId id, xmlSecKeyValueDsaPtr dsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecBuffer blob;
    int blobInitialized = 0;
    xmlSecByte* blobData;
    xmlSecSize pSize, qSize, gSize, ySize;
    xmlSecSize offset, blobSize;
    DWORD dwBlobSize;
    BCRYPT_DSA_KEY_BLOB* dsakey;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataDsaId, NULL);
    xmlSecAssert2(dsaValue != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(dsaValue->p)) != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(dsaValue->q)) != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(dsaValue->g)) != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(dsaValue->y)) != NULL, NULL);

    /* dont reverse blobs as both the XML and CNG works with big-endian */
    pSize = xmlSecBufferGetSize(&(dsaValue->p));
    qSize = xmlSecBufferGetSize(&(dsaValue->q));
    gSize = xmlSecBufferGetSize(&(dsaValue->g));
    ySize = xmlSecBufferGetSize(&(dsaValue->y));
    xmlSecAssert2(pSize > 0, NULL);
    xmlSecAssert2(qSize > 0, NULL);
    xmlSecAssert2(gSize > 0, NULL);
    xmlSecAssert2(ySize > 0, NULL);

    /* turn the read data into a public key blob, as documented at
     * <https://msdn.microsoft.com/library/windows/desktop/aa833126.aspx>: Q is
     * part of the struct, need to write P, G, Y after it
     * we assume that:
     *    sizeof(q) <= XMLSEC_MSCNG_DSA_MAX_Q_SIZE,
     *    sizeof(g) <= sizeof(p)
     *    sizeof(y) <= sizeof(p)
     */
    xmlSecAssert2(qSize <= XMLSEC_MSCNG_DSA_MAX_Q_SIZE, NULL);
    xmlSecAssert2(gSize <= pSize, NULL);
    xmlSecAssert2(ySize <= pSize, NULL);
    offset = sizeof(BCRYPT_DSA_KEY_BLOB);
    blobSize = offset + pSize * 3;

    ret = xmlSecBufferInitialize(&blob, blobSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    blobInitialized = 1;

    ret = xmlSecBufferSetSize(&blob, blobSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    memset(xmlSecBufferGetData(&blob), 0, blobSize); // ensure all padding with 0s work

    blobData = xmlSecBufferGetData(&blob);
    dsakey = (BCRYPT_DSA_KEY_BLOB*)blobData;
    dsakey->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(pSize, dsakey->cbKey, goto done, xmlSecKeyDataKlassGetName(id));

    memset(dsakey->Count, -1, sizeof(dsakey->Count));
    memset(dsakey->Seed, -1, sizeof(dsakey->Seed));

    /*** q ***/
    xmlSecAssert2(sizeof(dsakey->q) == XMLSEC_MSCNG_DSA_MAX_Q_SIZE, NULL);
    memcpy(dsakey->q, xmlSecBufferGetData(&(dsaValue->q)), qSize); /* should be equal to XMLSEC_MSCNG_DSA_MAX_Q_SIZE */

    /*** p ***/
    memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->p)), pSize);
    offset += pSize;

    /*** g ***/
    memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->g)), gSize);
    offset += pSize; /* gSize <= pSize */

    /*** y ***/
    memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->y)), ySize);
    offset += pSize; /* gSize <= ySize */

    /* import the key blob */
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_DSA_ALGORITHM,
        NULL,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(blobSize, dwBlobSize, goto done, xmlSecKeyDataKlassGetName(id));
    status = BCryptImportKeyPair(
        hAlg,
        NULL,
        BCRYPT_DSA_PUBLIC_BLOB,
        &hKey,
        blobData,
        dwBlobSize,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair", xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if (data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(data, hKey);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey", xmlSecKeyDataGetName(data));
        goto done;
    }
    hKey = 0; /* now owned by data */

    /* success */
    res = data;
    data = NULL;

done:
    if (data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    if (hAlg != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (hKey != 0) {
        BCryptDestroyKey(hKey);
    }
    if (blobInitialized != 0) {
        xmlSecBufferFinalize(&blob);
    }
    return(res);
}

static int
xmlSecMSCngKeyDataDsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                        xmlSecKeyValueDsaPtr dsaValue,
                        int writePrivateKey XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    NTSTATUS status;
    xmlSecBuffer buf;
    int bufInitialized = 0;
    xmlSecByte* bufData;
    DWORD bufLen = 0;
    BCRYPT_DSA_KEY_BLOB* dsakey;
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecMSCngKeyDataDsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDsaId), -1);
    xmlSecAssert2(dsaValue != NULL, -1);
    UNREFERENCED_PARAMETER(writePrivateKey);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
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
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status, "bufLen=%lu", bufLen);
        goto done;
    }

    ret = xmlSecBufferInitialize(&buf, bufLen);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", xmlSecKeyDataKlassGetName(id),
            "size=%lu", bufLen);
        goto done;
    }
    bufInitialized = 1;

    bufData = xmlSecBufferGetData(&buf);
    xmlSecAssert2(bufData != NULL, -1);

    status = BCryptExportKey(ctx->pubkey,
        NULL,
        BCRYPT_DSA_PUBLIC_BLOB,
        bufData,
        bufLen,
        &bufLen,
        0);
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status, "bufLen=%lu", bufLen);
        goto done;
    }

    /* check BCRYPT_DSA_KEY_BLOB */
    if (bufLen < sizeof(BCRYPT_DSA_KEY_BLOB)) {
        xmlSecMSCngNtError2("BCRYPT_DSA_KEY_BLOB", xmlSecKeyDataKlassGetName(id),
            STATUS_SUCCESS, "dwBlobLen=%lu", bufLen);
        goto done;
    }
    dsakey = (BCRYPT_DSA_KEY_BLOB*)bufData;

    /* we assume that sizeof(q) < XMLSEC_MSCNG_DSA_MAX_Q_SIZE, sizeof(g) <= sizeof(p) and sizeof(y) <= sizeof(p) */
    if (bufLen < (sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * dsakey->cbKey)) {
        xmlSecMSCngNtError3("CryptExportKey", xmlSecKeyDataKlassGetName(id),
            STATUS_SUCCESS, "dwBlobLen: %lu; keyLen: %lu", bufLen, dsakey->cbKey);
        goto done;

    }
    bufData += sizeof(BCRYPT_DSA_KEY_BLOB);

    /*** p ***/
    ret = xmlSecBufferSetData(&(dsaValue->p), bufData, dsakey->cbKey);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(p)", xmlSecKeyDataKlassGetName(id),
            "keyLen=%lu", dsakey->cbKey);
        goto done;
    }
    bufData += dsakey->cbKey;

    /*** q ***/
    xmlSecAssert2(sizeof(dsakey->q) <= XMLSEC_MSCNG_DSA_MAX_Q_SIZE, -1);
    ret = xmlSecBufferSetData(&(dsaValue->q), (xmlSecByte*)dsakey->q, sizeof(dsakey->q));
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(q)", xmlSecKeyDataKlassGetName(id),
            "keyLen=%lu", dsakey->cbKey);
        goto done;
    }

    /*** g ***/
    ret = xmlSecBufferSetData(&(dsaValue->g), bufData, dsakey->cbKey);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(g)", xmlSecKeyDataKlassGetName(id),
            "keyLen=%lu", dsakey->cbKey);
        goto done;
    }
    bufData += dsakey->cbKey;

    /* X is REQUIRED for private key but MSCng does not support it,
     * so we just ignore it */

    /*** y ***/
    ret = xmlSecBufferSetData(&(dsaValue->y), bufData, dsakey->cbKey);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(y)", xmlSecKeyDataKlassGetName(id),
            "keyLen=%lu", dsakey->cbKey);
        goto done;
    }
    bufData += dsakey->cbKey;

    /* dont reverse blobs as both the XML and CNG works with big-endian */

    /* success */
    res = 0;

done:
    if (bufInitialized != 0) {
        xmlSecBufferFinalize(&buf);
    }
    return(res);
}

static int
xmlSecMSCngKeyDataDsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecMSCngKeyDataDsaRead));
}

static int
xmlSecMSCngKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
          xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecMSCngKeyDataDsaWrite));
}

static int
xmlSecMSCngKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits,
        xmlSecKeyDataType type) {
    UNREFERENCED_PARAMETER(type);
    xmlSecMSCngKeyDataCtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hKey = 0;
    NTSTATUS status;
    DWORD dwSizeBits;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DSA_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", xmlSecKeyDataGetName(data), status);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(sizeBits, dwSizeBits, goto done, xmlSecKeyDataGetName(data));
    status = BCryptGenerateKeyPair(hAlg, &hKey, dwSizeBits, 0);
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

XMLSEC_MSCNG_CERTKEY_KLASS_EX(Dsa, DSA,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
    xmlSecNodeDSAKeyValue, xmlSecDSigNs,
    xmlSecMSCngKeyDataDsaGenerate,
    xmlSecMSCngKeyDataDsaXmlRead,
    xmlSecMSCngKeyDataDsaXmlWrite)

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
static xmlSecKeyDataPtr
xmlSecMSCngKeyDataRsaRead(xmlSecKeyDataId id, xmlSecKeyValueRsaPtr rsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecBuffer blob;
    int blobInitialized = 0;
    xmlSecSize blobBufferSize, offset;
    xmlSecSize mSize, peSize;
    xmlSecByte* blobData;
    DWORD dwSize;
    BCRYPT_RSAKEY_BLOB* rsakey;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = 0;
    size_t size;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataRsaId, NULL);
    xmlSecAssert2(rsaValue != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(rsaValue->modulus)) != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(rsaValue->publicExponent)) != NULL, NULL);

    /* dont reverse blobs as both the XML and CNG works with big-endian */
    mSize = xmlSecBufferGetSize(&(rsaValue->modulus));
    peSize = xmlSecBufferGetSize(&(rsaValue->publicExponent));
    xmlSecAssert2(mSize > 0, NULL);
    xmlSecAssert2(peSize > 0, NULL);

    /* turn the read data into a public key blob, as documented at
     * <https://msdn.microsoft.com/en-us/library/windows/desktop/aa375531(v=vs.85).aspx>:
     * need to write exponent and modulus after the struct */
    size = sizeof(BCRYPT_RSAKEY_BLOB) + mSize + peSize;
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(size, blobBufferSize, goto done, xmlSecKeyDataKlassGetName(id));

    ret = xmlSecBufferInitialize(&blob, blobBufferSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_FMT, blobBufferSize);
        goto done;
    }
    blobInitialized = 1;

    ret = xmlSecBufferSetSize(&blob, blobBufferSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, blobBufferSize);
        goto done;
    }
    blobData = xmlSecBufferGetData(&blob);
    xmlSecAssert2(blobData != NULL, NULL);
    memset(blobData, 0, blobBufferSize); // ensure all padding with 0s work

    rsakey = (BCRYPT_RSAKEY_BLOB*)blobData;
    rsakey->Magic = BCRYPT_RSAPUBLIC_MAGIC;

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG((mSize * 8), rsakey->BitLength, goto done, xmlSecKeyDataKlassGetName(id));
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(peSize, rsakey->cbPublicExp, goto done, xmlSecKeyDataKlassGetName(id));
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(mSize, rsakey->cbModulus, goto done, xmlSecKeyDataKlassGetName(id));
    offset = sizeof(BCRYPT_RSAKEY_BLOB);

    /*** public exponent ***/
    memcpy(blobData + offset, xmlSecBufferGetData(&(rsaValue->publicExponent)), peSize);
    offset += peSize;

    /*** modulus ***/
    memcpy(blobData + offset, xmlSecBufferGetData(&(rsaValue->modulus)), mSize);
    offset += mSize;

    /* PrivateExponent is REQUIRED for private key but MSCng does not support it,
     * so we just ignore it */

    /* Now that we have the blob, import */
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_RSA_ALGORITHM,
        NULL,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(blobBufferSize, dwSize, goto done, xmlSecKeyDataKlassGetName(id));
    status = BCryptImportKeyPair(
        hAlg,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &hKey,
        blobData,
        dwSize,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError2("BCryptImportKeyPair", xmlSecKeyDataKlassGetName(id),
            status, "dwSize=%lu", dwSize);
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if (data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(data, hKey);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey", xmlSecKeyDataGetName(data));
        goto done;
    }
    hKey = 0; /* now owned by data */

    /* success */
    res = data;
    data = NULL;

done:
    if (data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    if (hKey != 0) {
        BCryptDestroyKey(hKey);
    }
    if (hAlg != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (blobInitialized != 0) {
        xmlSecBufferFinalize(&blob);
    }
    return(res);
}

static int
xmlSecMSCngKeyDataRsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                           xmlSecKeyValueRsaPtr rsaValue,
                           int writePrivateKey XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    NTSTATUS status;
    xmlSecBuffer buf;
    int bufInitialized = 0;
    xmlSecByte* bufData;
    DWORD bufLen = 0;
    BCRYPT_RSAKEY_BLOB* rsakey;
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecMSCngKeyDataRsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataRsaId), -1);
    xmlSecAssert2(rsaValue != NULL, -1);
    UNREFERENCED_PARAMETER(writePrivateKey);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
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
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status, "bufLen=%lu", bufLen);
        goto done;
    }

    ret = xmlSecBufferInitialize(&buf, bufLen);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", xmlSecKeyDataKlassGetName(id),
            "size=%lu", bufLen);
        goto done;
    }
    bufInitialized = 1;

    bufData = xmlSecBufferGetData(&buf);
    xmlSecAssert2(bufData != NULL, -1);

    status = BCryptExportKey(ctx->pubkey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        bufData,
        bufLen,
        &bufLen,
        0);
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status, "bufLen=%lu", bufLen);
        goto done;
    }

    ret = xmlSecBufferSetSize(&buf, bufLen);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecKeyDataKlassGetName(id),
            "size=%lu", bufLen);
        goto done;
    }

    /* check BCRYPT_RSAKEY_BLOB */
    if (bufLen < sizeof(BCRYPT_RSAKEY_BLOB)) {
        xmlSecMSCngNtError2("BCRYPT_RSAKEY_BLOB", xmlSecKeyDataKlassGetName(id),
            STATUS_SUCCESS, "dwBlobLen=%lu", bufLen);
        goto done;
    }
    rsakey = (BCRYPT_RSAKEY_BLOB*)bufData;

    /* check sizes */
    if (bufLen < (sizeof(BCRYPT_RSAKEY_BLOB) + rsakey->cbPublicExp + rsakey->cbModulus)) {
        xmlSecMSCngNtError3("CryptExportKey", xmlSecKeyDataKlassGetName(id),
            STATUS_SUCCESS, "dwBlobLen: %lu; keyLen: %lu", bufLen, rsakey->cbPublicExp);
        goto done;

    }
    bufData += sizeof(BCRYPT_RSAKEY_BLOB);

    /*** public exponent ***/
    ret = xmlSecBufferSetData(&(rsaValue->publicExponent), bufData, rsakey->cbPublicExp);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(publicExponent)", xmlSecKeyDataKlassGetName(id),
            "cbPublicExp=%lu", rsakey->cbPublicExp);
        goto done;
    }
    bufData += rsakey->cbPublicExp;

    /*** modulus ***/
    ret = xmlSecBufferSetData(&(rsaValue->modulus), bufData, rsakey->cbModulus);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(modulus)", xmlSecKeyDataKlassGetName(id),
            "cbModulus=%lu", rsakey->cbModulus);
        goto done;
    }
    bufData += rsakey->cbModulus;

    /* next is PrivateExponent node: not supported in MSCrypto */

    /* dont reverse blobs as both the XML and CNG works with big-endian */
    /* success */
    res = 0;

done:
    if (bufInitialized != 0) {
        xmlSecBufferFinalize(&buf);
    }
    return(res);
}

static int
xmlSecMSCngKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
        xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecMSCngKeyDataRsaRead));
}

static int
xmlSecMSCngKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
          xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecMSCngKeyDataRsaWrite));
}

static int
xmlSecMSCngKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits,
        xmlSecKeyDataType type) {
    UNREFERENCED_PARAMETER(type);
    xmlSecMSCngKeyDataCtxPtr ctx;
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwSizeBits;
    NTSTATUS status;
    int ret;
    int res = -1;

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
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", xmlSecKeyDataGetName(data), status);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(sizeBits, dwSizeBits, goto done, xmlSecKeyDataGetName(data));
    status = BCryptGenerateKeyPair(hAlg, &hKey, dwSizeBits, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGenerateKeyPair", xmlSecKeyDataGetName(data), status);
        goto done;
    }

    /* need to finalize the key before it can be used */
    status = BCryptFinalizeKeyPair(hKey, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptFinalizeKeyPair", xmlSecKeyDataGetName(data), status);
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(data, hKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey", xmlSecKeyDataGetName(data));
        goto done;
    }
    /* hKey is owned by data now */
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

XMLSEC_MSCNG_CERTKEY_KLASS_EX(Rsa, RSA,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
    xmlSecNodeRSAKeyValue, xmlSecDSigNs,
    xmlSecMSCngKeyDataRsaGenerate,
    xmlSecMSCngKeyDataRsaXmlRead,
    xmlSecMSCngKeyDataRsaXmlWrite)

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

#ifndef XMLSEC_NO_EC
typedef struct _xmlSecMSCngKeyDataEccCurveNameAndMagic {
    ULONG magic;
    LPCWSTR blobType;
    xmlChar oid[128];
} xmlSecMSCngKeyDataEccCurveNameAndMagic;

/* https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob */
static const xmlSecMSCngKeyDataEccCurveNameAndMagic g_xmlSecMSCngKeyDataEccCurveNameAndMagic[] = {
    { BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECDSA_P256_ALGORITHM, "1.2.840.10045.3.1.7" }, /* prime256v1 */
    { BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECDSA_P384_ALGORITHM, "1.3.132.0.34" }, /* secp384r1 */
    { BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_ECDSA_P521_ALGORITHM, "1.3.132.0.35" }  /* secp521r1 */
};


static const xmlChar*
xmlSecOpenSSLKeyDataEcGetOidFromMagic(ULONG magic) {
    xmlSecSize size = sizeof(g_xmlSecMSCngKeyDataEccCurveNameAndMagic) / sizeof(g_xmlSecMSCngKeyDataEccCurveNameAndMagic[0]);

    xmlSecAssert2(magic != 0, NULL);

    for (xmlSecSize ii = 0; ii < size; ++ii) {
        if (magic == g_xmlSecMSCngKeyDataEccCurveNameAndMagic[ii].magic) {
            return(g_xmlSecMSCngKeyDataEccCurveNameAndMagic[ii].oid);
        }
    }
    return(NULL);
}

static LPCWSTR
xmlSecMSCngKeyDataEcGetTypeAndMagicFromOid(const xmlChar* oid, ULONG * magic) {
    xmlSecSize size = sizeof(g_xmlSecMSCngKeyDataEccCurveNameAndMagic) / sizeof(g_xmlSecMSCngKeyDataEccCurveNameAndMagic[0]);

    xmlSecAssert2(oid != NULL, 0);
    xmlSecAssert2(magic != NULL, 0);

    for (xmlSecSize ii = 0; ii < size; ++ii) {
        if (xmlStrcmp(oid, g_xmlSecMSCngKeyDataEccCurveNameAndMagic[ii].oid) == 0) {
            (*magic) = g_xmlSecMSCngKeyDataEccCurveNameAndMagic[ii].magic;
            return(g_xmlSecMSCngKeyDataEccCurveNameAndMagic[ii].blobType);
        }
    }
    return(0);
}

static xmlSecKeyDataPtr
xmlSecMSCngKeyDataEcRead(xmlSecKeyDataId id, xmlSecKeyValueEcPtr ecValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecBuffer blob;
    int blobInitialized = 0;
    xmlSecByte* blobData;
    xmlSecByte* pubkeyData;
    xmlSecSize pubkeySize;
    xmlSecSize offset, blobSize;
    DWORD dwBlobSize;
    BCRYPT_ECCKEY_BLOB* eckey;
    LPCWSTR blobType;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataEcId, NULL);
    xmlSecAssert2(ecValue != NULL, NULL);
    xmlSecAssert2(ecValue->curve != NULL, NULL);

    /* first byte in ecValue->pubkey is the magical byte, we don't need it */
    pubkeyData = xmlSecBufferGetData(&(ecValue->pubkey));
    pubkeySize = xmlSecBufferGetSize(&(ecValue->pubkey));
    xmlSecAssert2(pubkeyData != NULL, NULL);
    xmlSecAssert2(pubkeySize > 1, NULL);
    pubkeyData += 1;
    pubkeySize -= 1;

    /* turn the read data into a public key blob, as documented at
     * https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob>
     *
     * dont reverse blobs as both the XML and CNG works with big-endian
     *
     */
    offset = sizeof(BCRYPT_ECCKEY_BLOB);
    blobSize = offset + pubkeySize;

    ret = xmlSecBufferInitialize(&blob, blobSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    blobInitialized = 1;

    ret = xmlSecBufferSetSize(&blob, blobSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    memset(xmlSecBufferGetData(&blob), 0, blobSize); // ensure all padding with 0s work

    blobData = xmlSecBufferGetData(&blob);
    eckey = (BCRYPT_ECCKEY_BLOB*)blobData;
    blobType = xmlSecMSCngKeyDataEcGetTypeAndMagicFromOid(ecValue->curve, &(eckey->dwMagic));
    if ((blobType == NULL) || (eckey->dwMagic == 0)) {
        xmlSecInternalError2("xmlSecOpenSSLKeyDataEcGetOidFromNid", xmlSecKeyDataKlassGetName(id),
            "curve=%s", xmlSecErrorsSafeString(ecValue->curve));
        goto done;
    }
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(pubkeySize / 2, eckey->cbKey, goto done, xmlSecKeyDataKlassGetName(id));

    /* pubkey */
    memcpy(blobData + offset, pubkeyData, pubkeySize);

    /* import the key blob */
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        blobType,
        NULL,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(blobSize, dwBlobSize, goto done, xmlSecKeyDataKlassGetName(id));
    status = BCryptImportKeyPair(
        hAlg,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        &hKey,
        blobData,
        dwBlobSize,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair", xmlSecKeyDataKlassGetName(id), status);
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if (data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(data, hKey);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey", xmlSecKeyDataGetName(data));
        goto done;
    }
    hKey = 0; /* now owned by data */

    /* success */
    res = data;
    data = NULL;

done:
    if (data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    if (hAlg != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (hKey != 0) {
        BCryptDestroyKey(hKey);
    }
    if (blobInitialized != 0) {
        xmlSecBufferFinalize(&blob);
    }
    return(res);
}

static int
xmlSecMSCngKeyDataEcWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data, xmlSecKeyValueEcPtr ecValue)
{
    xmlSecMSCngKeyDataCtxPtr ctx;
    NTSTATUS status;
    xmlSecBuffer buf;
    int bufInitialized = 0;
    xmlSecByte* bufData;
    DWORD bufLen = 0;
    BCRYPT_ECCKEY_BLOB* eckey;
    const xmlChar* curve;
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecMSCngKeyDataEcId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataEcId), -1);
    xmlSecAssert2(ecValue != NULL, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey, -1);

    /* turn ctx->pubkey into eckey */
    status = BCryptExportKey(ctx->pubkey,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        NULL,
        0,
        &bufLen,
        0);
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status, "bufLen=%lu", bufLen);
        goto done;
    }

    ret = xmlSecBufferInitialize(&buf, bufLen);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", xmlSecKeyDataKlassGetName(id),
            "size=%lu", bufLen);
        goto done;
    }
    bufInitialized = 1;

    bufData = xmlSecBufferGetData(&buf);
    xmlSecAssert2(bufData != NULL, -1);

    status = BCryptExportKey(ctx->pubkey,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        bufData,
        bufLen,
        &bufLen,
        0);
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", xmlSecKeyDataKlassGetName(id),
            status, "bufLen=%lu", bufLen);
        goto done;
    }

    /* check BCRYPT_ECCKEY_BLOB */
    if (bufLen < sizeof(BCRYPT_ECCKEY_BLOB)) {
        xmlSecMSCngNtError2("BCRYPT_ECCKEY_BLOB", xmlSecKeyDataKlassGetName(id),
            STATUS_SUCCESS, "dwBlobLen=%lu", bufLen);
        goto done;
    }
    eckey = (BCRYPT_ECCKEY_BLOB*)bufData;
    bufData += sizeof(BCRYPT_ECCKEY_BLOB);
    bufLen  -= (DWORD)sizeof(BCRYPT_ECCKEY_BLOB);
    if (bufLen != 2 * eckey->cbKey) {
        xmlSecMSCngNtError3("BCRYPT_ECCKEY_BLOB", xmlSecKeyDataKlassGetName(id),
            STATUS_SUCCESS, "bufLen=%lu, eckey->cbKey=%lu", bufLen, eckey->cbKey);
        goto done;
    }
    /* curve */
    curve = xmlSecOpenSSLKeyDataEcGetOidFromMagic(eckey->dwMagic);
    if (curve == NULL) {
        xmlSecInternalError2("xmlSecOpenSSLKeyDataEcGetOidFromMagic", xmlSecKeyDataKlassGetName(id),
            "magic=%lu", eckey->dwMagic);
        goto done;
    }
    ecValue->curve = xmlStrdup(curve);
    if (ecValue->curve == NULL) {
        xmlSecStrdupError(curve, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* public key is prefixed with magic 0x04 */
    xmlSecByte magic[] = { 0x04 };
    ret = xmlSecBufferSetData(&(ecValue->pubkey), magic, sizeof(magic));
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(pubkey)", xmlSecKeyDataKlassGetName(id),
            "magic size=%d", (int)sizeof(magic));
        goto done;
    }
    ret = xmlSecBufferAppend(&(ecValue->pubkey), bufData, bufLen);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferAppend(pubkey)", xmlSecKeyDataKlassGetName(id),
            "bufLen=%lu", bufLen);
        goto done;
    }

    /* dont reverse blobs as both the XML and CNG works with big-endian */

    /* success */
    res = 0;

done:
    if (bufInitialized != 0) {
        xmlSecBufferFinalize(&buf);
    }
    return(res);
}


static int
xmlSecMSCngKeyDataEcXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataEcId, -1);
    return(xmlSecKeyDataEcXmlRead(id, key, node, keyInfoCtx,
        xmlSecMSCngKeyDataEcRead));
}

static int
xmlSecMSCngKeyDataEcXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataEcId, -1);
    return(xmlSecKeyDataEcXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecMSCngKeyDataEcWrite));
}

XMLSEC_MSCNG_CERTKEY_KLASS_EX(Ec, EC,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
    xmlSecNodeECKeyValue, xmlSecDSig11Ns,
    NULL,
    xmlSecMSCngKeyDataEcXmlRead,
    xmlSecMSCngKeyDataEcXmlWrite)

/**
 * xmlSecMSCngKeyDataEcGetKlass:
 *
 * The MSCng EC CertKey data klass.
 *
 * Returns: pointer to MSCng EC key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataEcGetKlass(void) {
    return(&xmlSecMSCngKeyDataEcKlass);
}

#endif /* XMLSEC_NO_EC */
