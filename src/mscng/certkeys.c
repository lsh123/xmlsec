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
 * @addtogroup xmlsec_mscng_certkeys
 * @brief Certificate keys support functions for Microsoft Cryptography API: Next Generation (CNG).
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
    BCRYPT_KEY_HANDLE bcryptPrivkey; /* BCrypt DH private key (loaded from DER/PKCS8) */
    xmlSecBuffer dhQ;
};

XMLSEC_KEY_DATA_DECLARE(MSCngKeyData, xmlSecMSCngKeyDataCtx)
#define xmlSecMSCngKeyDataSize XMLSEC_KEY_DATA_SIZE(MSCngKeyData)

int
xmlSecMSCngKeyDataCertGetPubkey(PCERT_PUBLIC_KEY_INFO spki, BCRYPT_KEY_HANDLE* key) {
    xmlSecAssert2(spki != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    /* Try the standard API first: works for RSA, EC, and DSA up to 1024-bit.
     * For DSA > 1024-bit it fails (E_INVALIDARG) due to legacy CryptoAPI limits. */
    if(CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
            spki,
            0,
            NULL,
            key)) {
        return(0);
    }

#ifndef XMLSEC_NO_DSA
    /* CryptImportPublicKeyInfoEx2 fails for DSA > 1024-bit. For large DSA keys
     * fall back to BCryptImportKeyPair with a manually constructed blob. */
    if((spki->Algorithm.pszObjId != NULL) && (strcmp(spki->Algorithm.pszObjId, szOID_X957_DSA) == 0)) {
        return(xmlSecMSCngKeyDataCertGetDsaPubkey(spki, key));
    }
#endif /* XMLSEC_NO_DSA */


#ifndef XMLSEC_NO_XDH
    /* X25519 (OID 1.3.101.110) uses a 32-byte raw u-coordinate in SubjectPublicKey;
     * CryptImportPublicKeyInfoEx2 does not support this OID. */
    if((spki->Algorithm.pszObjId != NULL) && (strcmp(spki->Algorithm.pszObjId, szOID_X25519) == 0)) {
        return(xmlSecMSCngKeyDataCertGetXdhPubkey(spki, key));
    }
#endif /* XMLSEC_NO_XDH */

    xmlSecMSCngLastError("CryptImportPublicKeyInfoEx2", NULL);
    return(-1);
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
 * @brief Sets the value of key data.
 * @param data the pointer to MSCng pccert data.
 * @param cert the pointer to PCCERT key.
 * @param type the certificate type (trusted/untrusted).
 * @return 0 on success or a negative value otherwise.
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

    ret = xmlSecMSCngKeyDataCertGetPubkey(&(cert->pCertInfo->SubjectPublicKeyInfo), &hPubKey);
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

int
xmlSecMSCngKeyDataAdoptBCryptPrivKey(xmlSecKeyDataPtr data, BCRYPT_KEY_HANDLE hKey) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);
    xmlSecAssert2(hKey != NULL, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->bcryptPrivkey == NULL, -1);

    ctx->bcryptPrivkey = hKey;
    return(0);
}

/**
 * @brief BCrypt DH private key retrieval (for keys loaded from DER/PKCS8).
 * @param data the key data.
 *
 * The returned key must not be destroyed by the caller.
 *
 * @return key handle on success or NULL otherwise.
 */
BCRYPT_KEY_HANDLE
xmlSecMSCngKeyDataGetBCryptPrivKey(xmlSecKeyDataPtr data) {
    xmlSecMSCngKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), NULL);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    return(ctx->bcryptPrivkey);
}

#ifndef XMLSEC_NO_DH
int
xmlSecMSCngKeyDataSetDhQ(xmlSecKeyDataPtr data, const xmlSecByte* q, DWORD qLen) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    xmlSecSize qSize;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDhId), -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    if((q == NULL) || (qLen == 0)) {
        xmlSecBufferEmpty(&(ctx->dhQ));
        return(0);
    }

    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(qLen, qSize, return(-1), NULL);
    ret = xmlSecBufferSetData(&(ctx->dhQ), q, qSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(dhQ)", NULL,
            "size=" XMLSEC_SIZE_FMT, qSize);
        return(-1);
    }

    return(0);
}
#endif /* XMLSEC_NO_DH */

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

#ifndef XMLSEC_NO_DH
    /* OID for DH public key (X9.42 dhPublicKey, RFC 3279) */
    if (!strcmp(pszObjId, szOID_X942_DH)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataDhId);
        if (data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataDhId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_DH */

#ifndef XMLSEC_NO_XDH
    /* OID for X25519 public key (id-X25519, RFC 8410) */
    if (!strcmp(pszObjId, szOID_X25519)) {
        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataXdhId);
        if (data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataXdhId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_XDH */

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
 * @brief Creates key data value from the cert.
 * @param pCert the pointer to cert.
 * @param type the expected key type.
 * @return pointer to newly created xmlsec key or NULL if an error occurs.
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
 * @brief Native MSCng public key retrieval from xmlsec keydata. The returned key must
 * @param data the key data to retrieve certificate from.
 *
 * not be destroyed by the caller.
 *
 * @return key on success or 0 otherwise.
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
 * @brief Native MSCng private key retrieval from xmlsec keydata. The returned key
 * @param data the key data to retrieve certificate from.
 *
 * must not be destroyed by the caller.
 *
 * @return key on success or 0 otherwise.
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
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCngKeyDataSize), -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngKeyDataCtx));

    ret = xmlSecBufferInitialize(&(ctx->dhQ), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(dhQ)", NULL);
        return(-1);
    }

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

    if(ctx->bcryptPrivkey != 0) {
        status = BCryptDestroyKey(ctx->bcryptPrivkey);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDestroyKey(bcryptPrivkey)", NULL, status);
            /* ignore error */
        }
    }

    xmlSecBufferFinalize(&(ctx->dhQ));

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
    LPCWSTR pszCurveName = NULL;  /* non-NULL iff a curve property must be set before import */
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
    xmlSecAssert2(dstCtx->bcryptPrivkey == NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(dstCtx->dhQ)) == 0, -1);

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
        ret = xmlSecMSCngKeyDataCertGetPubkey(&(dstCtx->cert->pCertInfo->SubjectPublicKeyInfo), &dstCtx->pubkey);
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
#if XMLSEC_MSCNG_HAVE_DSA_V2
            case BCRYPT_DSA_PUBLIC_MAGIC_V2:
#endif /* XMLSEC_MSCNG_HAVE_DSA_V2 */
                pszAlgId = BCRYPT_DSA_ALGORITHM;
                break;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
            case BCRYPT_RSAPUBLIC_MAGIC:
                pszAlgId = BCRYPT_RSA_ALGORITHM;
                break;
#endif /* XMLSEC_NO_RSA */

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
#endif /* XMLSEC_NO_EC */

#ifndef XMLSEC_NO_DH
            case BCRYPT_DH_PUBLIC_MAGIC:
                pszAlgId = BCRYPT_DH_ALGORITHM;
                break;
#endif /* XMLSEC_NO_DH */

#ifndef XMLSEC_NO_XDH
            case BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC:
                pszAlgId = BCRYPT_ECDH_ALGORITHM;
                pszCurveName = BCRYPT_ECC_CURVE_25519;
                break;
#endif /* XMLSEC_NO_XDH */

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

        /* For generic-curve algorithms (e.g. X25519), set the curve name property */
        if(pszCurveName != NULL) {
            status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME,
                (PUCHAR)pszCurveName, (ULONG)((wcslen(pszCurveName) + 1) * sizeof(WCHAR)), 0);
            if(status != STATUS_SUCCESS) {
                xmlSecMSCngNtError("BCryptSetProperty(BCRYPT_ECC_CURVE_NAME)", NULL, status);
                xmlFree(pbBlob);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return(-1);
            }
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

    if(srcCtx->bcryptPrivkey != NULL) {
#ifndef XMLSEC_NO_DH
        if(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataDhId)) {
            ret = xmlSecMSCngKeyDataDuplicateBCryptDhPrivKey(srcCtx->bcryptPrivkey, &dstCtx->bcryptPrivkey);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngKeyDataDuplicateBCryptDhPrivKey", NULL);
                return(-1);
            }
        } else
#endif /* XMLSEC_NO_DH */
#ifndef XMLSEC_NO_XDH
        if(xmlSecKeyDataCheckId(src, xmlSecMSCngKeyDataXdhId)) {
            ret = xmlSecMSCngKeyDataDuplicateBCryptXdhPrivKey(srcCtx->bcryptPrivkey, &dstCtx->bcryptPrivkey);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCngKeyDataDuplicateBCryptXdhPrivKey", NULL);
                return(-1);
            }
        } else
#endif /* XMLSEC_NO_XDH */
        {
            xmlSecNotImplementedError("BCrypt private key duplication for unknown key type");
            return(-1);
        }
    }

    if(xmlSecBufferGetSize(&(srcCtx->dhQ)) > 0) {
        ret = xmlSecBufferSetData(&(dstCtx->dhQ),
            xmlSecBufferGetData(&(srcCtx->dhQ)),
            xmlSecBufferGetSize(&(srcCtx->dhQ)));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(dhQ)", NULL);
            return(-1);
        }
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

    if(ctx->bcryptPrivkey != 0) {
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

static int
xmlSecMSCngKeyDataDsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                        xmlSecKeyValueDsaPtr dsaValue,
                        int writePrivateKey XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataDsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDsaId), -1);
    xmlSecAssert2(dsaValue != NULL, -1);
    UNREFERENCED_PARAMETER(writePrivateKey);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey, -1);

    ret = xmlSecMSCngKeyDataDsaPubkeyWrite(ctx->pubkey, dsaValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataDsaPubkeyWrite", xmlSecKeyDataGetName(data));
        return(-1);
    }
    return(0);
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
 * @brief The MSCng DSA CertKey data klass.
 * @return pointer to MSCng DSA key data klass.
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

    /****************************************************************************** public exponent  *****************************************************************************/
    memcpy(blobData + offset, xmlSecBufferGetData(&(rsaValue->publicExponent)), peSize);
    offset += peSize;

    /****************************************************************************** modulus  *****************************************************************************/
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

    /****************************************************************************** public exponent  *****************************************************************************/
    ret = xmlSecBufferSetData(&(rsaValue->publicExponent), bufData, rsakey->cbPublicExp);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(publicExponent)", xmlSecKeyDataKlassGetName(id),
            "cbPublicExp=%lu", rsakey->cbPublicExp);
        goto done;
    }
    bufData += rsakey->cbPublicExp;

    /****************************************************************************** modulus  *****************************************************************************/
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
 * @brief The MSCng RSA CertKey data klass.
 * @return pointer to MSCng RSA key data klass.
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
 * @brief The MSCng EC CertKey data klass.
 * @return pointer to MSCng EC key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataEcGetKlass(void) {
    return(&xmlSecMSCngKeyDataEcKlass);
}

#endif /* XMLSEC_NO_EC */

/******************************************************************************
 *
 * DH key data
 *
  *****************************************************************************/
#ifndef XMLSEC_NO_DH

static int
xmlSecMSCngKeyDataDhWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                        xmlSecKeyValueDhPtr dhValue,
                        int writePrivateKey XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    int ret;

    UNREFERENCED_PARAMETER(writePrivateKey);

    xmlSecAssert2(id == xmlSecMSCngKeyDataDhId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDhId), -1);
    xmlSecAssert2(dhValue != NULL, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey, -1);

    ret = xmlSecMSCngKeyDataDhPubkeyWrite(ctx->pubkey, dhValue);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataDhPubkeyWrite", xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    if(xmlSecBufferGetSize(&(ctx->dhQ)) > 0) {
        ret = xmlSecBufferSetData(&(dhValue->q),
            xmlSecBufferGetData(&(ctx->dhQ)),
            xmlSecBufferGetSize(&(ctx->dhQ)));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(q)", xmlSecKeyDataKlassGetName(id));
            return(-1);
        }
    }

    /* done */
    return(0);
}


static int
xmlSecMSCngKeyDataDhXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataDhId, -1);
    return(xmlSecKeyDataDhXmlRead(id, key, node, keyInfoCtx,
        xmlSecMSCngKeyDataDhRead));
}

static int
xmlSecMSCngKeyDataDhXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecMSCngKeyDataDhId, -1);
    return(xmlSecKeyDataDhXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecMSCngKeyDataDhWrite));
}

XMLSEC_MSCNG_CERTKEY_KLASS_EX(Dh, DH,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
    xmlSecNodeDHKeyValue, xmlSecEncNs,
    NULL,
    xmlSecMSCngKeyDataDhXmlRead,
    xmlSecMSCngKeyDataDhXmlWrite)

/**
 * @brief The MSCng DH CertKey data klass.
 * @return pointer to MSCng DH key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataDhGetKlass(void) {
    return(&xmlSecMSCngKeyDataDhKlass);
}

#endif /* XMLSEC_NO_DH */

#ifndef XMLSEC_NO_DH
static int
xmlSecMSCngDhValueInitialize(xmlSecKeyValueDhPtr dhValue) {
    int ret;

    xmlSecAssert2(dhValue != NULL, -1);
    memset(dhValue, 0, sizeof(*dhValue));

    ret = xmlSecBufferInitialize(&(dhValue->p), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(p)", NULL);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(dhValue->q), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(q)", NULL);
        xmlSecBufferFinalize(&(dhValue->p));
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(dhValue->generator), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(generator)", NULL);
        xmlSecBufferFinalize(&(dhValue->q));
        xmlSecBufferFinalize(&(dhValue->p));
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(dhValue->public), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(public)", NULL);
        xmlSecBufferFinalize(&(dhValue->generator));
        xmlSecBufferFinalize(&(dhValue->q));
        xmlSecBufferFinalize(&(dhValue->p));
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(dhValue->seed), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(seed)", NULL);
        xmlSecBufferFinalize(&(dhValue->public));
        xmlSecBufferFinalize(&(dhValue->generator));
        xmlSecBufferFinalize(&(dhValue->q));
        xmlSecBufferFinalize(&(dhValue->p));
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(dhValue->pgenCounter), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(pgenCounter)", NULL);
        xmlSecBufferFinalize(&(dhValue->seed));
        xmlSecBufferFinalize(&(dhValue->public));
        xmlSecBufferFinalize(&(dhValue->generator));
        xmlSecBufferFinalize(&(dhValue->q));
        xmlSecBufferFinalize(&(dhValue->p));
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCngDhValueFinalize(xmlSecKeyValueDhPtr dhValue) {
    xmlSecAssert(dhValue != NULL);

    xmlSecBufferFinalize(&(dhValue->p));
    xmlSecBufferFinalize(&(dhValue->q));
    xmlSecBufferFinalize(&(dhValue->generator));
    xmlSecBufferFinalize(&(dhValue->public));
    xmlSecBufferFinalize(&(dhValue->seed));
    xmlSecBufferFinalize(&(dhValue->pgenCounter));
    memset(dhValue, 0, sizeof(*dhValue));
}

static int
xmlSecMSCngKeyDataDhExportValue(xmlSecKeyDataPtr data, xmlSecKeyValueDhPtr dhValue) {
    xmlSecMSCngKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCngKeyDataDhId), -1);
    xmlSecAssert2(dhValue != NULL, -1);

    ctx = xmlSecMSCngKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->pubkey != NULL, -1);

    ret = xmlSecMSCngKeyDataDhPubkeyWrite(ctx->pubkey, dhValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataDhPubkeyWrite", NULL);
        return(-1);
    }

    if(xmlSecBufferGetSize(&(ctx->dhQ)) > 0) {
        ret = xmlSecBufferSetData(&(dhValue->q),
            xmlSecBufferGetData(&(ctx->dhQ)),
            xmlSecBufferGetSize(&(ctx->dhQ)));
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferSetData(q)", NULL);
            return(-1);
        }
    }

    return(0);
}

static int
xmlSecMSCngDhCompareBigNums(const xmlSecByte* left, xmlSecSize leftSize,
    const xmlSecByte* right, xmlSecSize rightSize) {
    while((leftSize > 0) && (left[0] == 0)) {
        ++left;
        --leftSize;
    }
    while((rightSize > 0) && (right[0] == 0)) {
        ++right;
        --rightSize;
    }
    if(leftSize != rightSize) {
        return((leftSize > rightSize) ? 1 : -1);
    }
    if(leftSize == 0) {
        return(0);
    }
    return(memcmp(left, right, leftSize));
}

static int
xmlSecMSCngDhEnsureEqualParam(xmlSecBufferPtr left, xmlSecBufferPtr right, const char* name) {
    int cmp;

    xmlSecAssert2(left != NULL, -1);
    xmlSecAssert2(right != NULL, -1);

    cmp = xmlSecMSCngDhCompareBigNums(
        xmlSecBufferGetData(left), xmlSecBufferGetSize(left),
        xmlSecBufferGetData(right), xmlSecBufferGetSize(right));
    if(cmp != 0) {
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_DATA, NULL,
            "DH group parameter mismatch: %s", xmlSecErrorsSafeString(name));
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCngDhValidatePublicRange(xmlSecBufferPtr p, xmlSecBufferPtr publicValue) {
    static const xmlSecByte two[] = { 0x02 };
    xmlSecBn pMinusTwo;
    int bnInitialized = 0;
    int cmp;
    int ret;

    xmlSecAssert2(p != NULL, -1);
    xmlSecAssert2(publicValue != NULL, -1);

    cmp = xmlSecMSCngDhCompareBigNums(
        xmlSecBufferGetData(publicValue), xmlSecBufferGetSize(publicValue),
        two, sizeof(two));
    if(cmp < 0) {
        xmlSecInvalidDataError("DH public key is smaller than 2", NULL);
        return(-1);
    }

    ret = xmlSecBnInitialize(&pMinusTwo, xmlSecBufferGetSize(p));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize", NULL);
        return(-1);
    }
    bnInitialized = 1;

    ret = xmlSecBnSetData(&pMinusTwo, xmlSecBufferGetData(p), xmlSecBufferGetSize(p));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnSetData", NULL);
        goto done;
    }

    ret = xmlSecBnAdd(&pMinusTwo, -2);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnAdd", NULL);
        goto done;
    }

    cmp = xmlSecBnCompare(&pMinusTwo,
        xmlSecBufferGetData(publicValue), xmlSecBufferGetSize(publicValue));
    if(cmp < 0) {
        xmlSecInvalidDataError("DH public key is greater than p - 2", NULL);
        ret = -1;
        goto done;
    }

    ret = 0;

done:
    if(bnInitialized != 0) {
        xmlSecBnFinalize(&pMinusTwo);
    }
    return(ret);
}

static int
xmlSecMSCngDhValidatePublicSubgroup(xmlSecBufferPtr p, xmlSecBufferPtr g,
    xmlSecBufferPtr q, BCRYPT_KEY_HANDLE publicKey) {
    DWORD cbKey;
    DWORD cbPrivBlob;
    BCRYPT_DH_KEY_BLOB* dhPriv;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hQPrivKey = NULL;
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    PUCHAR pbPrivBlob = NULL;
    PUCHAR pbSecret = NULL;
    DWORD cbSecret = 0;
    NTSTATUS status;
    int ret = -1;

    xmlSecAssert2(p != NULL, -1);
    xmlSecAssert2(g != NULL, -1);
    xmlSecAssert2(q != NULL, -1);
    xmlSecAssert2(publicKey != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(p) > 0, -1);
    xmlSecAssert2(xmlSecBufferGetSize(g) > 0, -1);
    xmlSecAssert2(xmlSecBufferGetSize(q) > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(xmlSecBufferGetSize(p), cbKey, return(-1), NULL);
    if(cbKey > XMLSEC_MSCNG_DSA_MAX_P_SIZE) {
        xmlSecInvalidSizeMoreThanError("DSA P size", (xmlSecSize)cbKey, (xmlSecSize)XMLSEC_MSCNG_DSA_MAX_P_SIZE, NULL);
        goto done;
    }
    cbPrivBlob = (DWORD)sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 4U;

    pbPrivBlob = (PUCHAR)xmlMalloc(cbPrivBlob);
    if(pbPrivBlob == NULL) {
        xmlSecMallocError(cbPrivBlob, NULL);
        goto done;
    }
    memset(pbPrivBlob, 0, cbPrivBlob);

    dhPriv = (BCRYPT_DH_KEY_BLOB*)pbPrivBlob;
    dhPriv->dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
    dhPriv->cbKey = cbKey;

    ret = xmlSecMSCngDhBlobCopy(pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB), cbKey,
        xmlSecBufferGetData(p), cbKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhBlobCopy(P)", NULL);
        goto done;
    }
    ret = xmlSecMSCngDhBlobCopy(pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey, cbKey,
        xmlSecBufferGetData(g), xmlSecBufferGetSize(g));
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhBlobCopy(G)", NULL);
        goto done;
    }
    ret = xmlSecMSCngDhBlobCopy(pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 2, cbKey,
        xmlSecBufferGetData(g), xmlSecBufferGetSize(g));
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhBlobCopy(Y-placeholder)", NULL);
        goto done;
    }
    ret = xmlSecMSCngDhBlobCopy(pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 3, cbKey,
        xmlSecBufferGetData(q), xmlSecBufferGetSize(q));
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhBlobCopy(Q)", NULL);
        goto done;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DH_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider(DH subgroup)", NULL, status);
        goto done;
    }

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_DH_PRIVATE_BLOB,
        &hQPrivKey, pbPrivBlob, cbPrivBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(DH subgroup)", NULL, status);
        goto done;
    }

    status = BCryptSecretAgreement(hQPrivKey, publicKey, &hSecret, 0);
    if((status != STATUS_SUCCESS) || (hSecret == NULL)) {
        xmlSecMSCngNtError("BCryptSecretAgreement(DH subgroup)", NULL, status);
        goto done;
    }

    status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &cbSecret, 0);
    if((status != STATUS_SUCCESS) || (cbSecret == 0)) {
        xmlSecMSCngNtError("BCryptDeriveKey(DH subgroup size)", NULL, status);
        goto done;
    }

    pbSecret = (PUCHAR)xmlMalloc(cbSecret);
    if(pbSecret == NULL) {
        xmlSecMallocError(cbSecret, NULL);
        goto done;
    }

    status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
        pbSecret, cbSecret, &cbSecret, 0);
    if((status != STATUS_SUCCESS) || (cbSecret == 0)) {
        xmlSecMSCngNtError("BCryptDeriveKey(DH subgroup data)", NULL, status);
        goto done;
    }

    if(pbSecret[0] != 0x01) {
        xmlSecInvalidDataError("DH public key is not in the expected subgroup", NULL);
        goto done;
    }
    while(cbSecret > 1) {
        --cbSecret;
        if(pbSecret[cbSecret] != 0x00) {
            xmlSecInvalidDataError("DH public key is not in the expected subgroup", NULL);
            goto done;
        }
    }

    ret = 0;

done:
    if(pbSecret != NULL) {
        xmlFree(pbSecret);
    }
    if(hSecret != NULL) {
        BCryptDestroySecret(hSecret);
    }
    if(hQPrivKey != NULL) {
        BCryptDestroyKey(hQPrivKey);
    }
    if(hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if(pbPrivBlob != NULL) {
        xmlFree(pbPrivBlob);
    }
    return(ret);
}

int
xmlSecMSCngKeyDataDhEnsureValidAgreement(xmlSecKeyDataPtr myData, xmlSecKeyDataPtr otherData) {
    xmlSecMSCngKeyDataCtxPtr myCtx;
    xmlSecMSCngKeyDataCtxPtr otherCtx;
    xmlSecKeyValueDh myDh;
    xmlSecKeyValueDh otherDh;
    int myDhInitialized = 0;
    int otherDhInitialized = 0;
    int ret;

    xmlSecAssert2(myData != NULL, -1);
    xmlSecAssert2(otherData != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(myData, xmlSecMSCngKeyDataDhId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(otherData, xmlSecMSCngKeyDataDhId), -1);

    myCtx = xmlSecMSCngKeyDataGetCtx(myData);
    otherCtx = xmlSecMSCngKeyDataGetCtx(otherData);
    xmlSecAssert2(myCtx != NULL, -1);
    xmlSecAssert2(otherCtx != NULL, -1);
    xmlSecAssert2(myCtx->pubkey != NULL, -1);
    xmlSecAssert2(otherCtx->pubkey != NULL, -1);

    ret = xmlSecMSCngDhValueInitialize(&myDh);
    if(ret < 0) {
        return(-1);
    }
    myDhInitialized = 1;

    ret = xmlSecMSCngDhValueInitialize(&otherDh);
    if(ret < 0) {
        goto done;
    }
    otherDhInitialized = 1;

    ret = xmlSecMSCngKeyDataDhExportValue(myData, &myDh);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataDhExportValue(my)", NULL);
        goto done;
    }
    ret = xmlSecMSCngKeyDataDhExportValue(otherData, &otherDh);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataDhExportValue(other)", NULL);
        goto done;
    }

    if((xmlSecBufferGetSize(&(myDh.q)) == 0) || (xmlSecBufferGetSize(&(otherDh.q)) == 0)) {
        xmlSecInvalidDataError("DH subgroup order q is required for DH-ES", NULL);
        ret = -1;
        goto done;
    }

    ret = xmlSecMSCngDhEnsureEqualParam(&(myDh.p), &(otherDh.p), "p");
    if(ret < 0) {
        goto done;
    }
    ret = xmlSecMSCngDhEnsureEqualParam(&(myDh.generator), &(otherDh.generator), "g");
    if(ret < 0) {
        goto done;
    }
    ret = xmlSecMSCngDhEnsureEqualParam(&(myDh.q), &(otherDh.q), "q");
    if(ret < 0) {
        goto done;
    }

    ret = xmlSecMSCngDhValidatePublicRange(&(myDh.p), &(myDh.public));
    if(ret < 0) {
        goto done;
    }
    ret = xmlSecMSCngDhValidatePublicRange(&(otherDh.p), &(otherDh.public));
    if(ret < 0) {
        goto done;
    }

    ret = xmlSecMSCngDhValidatePublicSubgroup(&(myDh.p), &(myDh.generator), &(myDh.q), myCtx->pubkey);
    if(ret < 0) {
        goto done;
    }
    ret = xmlSecMSCngDhValidatePublicSubgroup(&(otherDh.p), &(otherDh.generator), &(otherDh.q), otherCtx->pubkey);
    if(ret < 0) {
        goto done;
    }

    ret = 0;

done:
    if(otherDhInitialized != 0) {
        xmlSecMSCngDhValueFinalize(&otherDh);
    }
    if(myDhInitialized != 0) {
        xmlSecMSCngDhValueFinalize(&myDh);
    }
    return(ret);
}
#endif /* XMLSEC_NO_DH */

/**
 * @brief Exports a BCrypt public key as DER SPKI blob.
 * @details Exports a BCrypt public key as a DER-encoded SubjectPublicKeyInfo blob.
 * @param data the MSCng key data.
 * @param ppDer output pointer for the DER-encoded SubjectPublicKeyInfo blob (caller must LocalFree).
 * @param pcbDer output length of the DER blob.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngCreateDerForBcryptPubkey(xmlSecKeyDataPtr data, LPVOID* ppDer, DWORD* pcbDer) {
    BCRYPT_KEY_HANDLE hPubkey;
    PUCHAR pInfo = NULL;
    DWORD cbInfo = 0;
    BOOL status;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(ppDer != NULL, -1);
    xmlSecAssert2(pcbDer != NULL, -1);

    hPubkey = xmlSecMSCngKeyDataGetPubKey(data);
    if(hPubkey == 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataGetPubKey", NULL);
        return(-1);
    }

    *ppDer = NULL;
    *pcbDer = 0;

#ifndef XMLSEC_NO_DSA
    ret = xmlSecMSCngIsDsaBcryptKey(hPubkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngIsDsaBcryptKey", NULL);
        return(-1);
    }
    if(ret == 1) {
         return xmlSecMSCngDsaBuildSubjectPublicKeyInfoDer(hPubkey, ppDer, pcbDer);
    }

#endif /* XMLSEC_NO_DSA */

    status = CryptExportPublicKeyInfoFromBCryptKeyHandle(
        hPubkey,
        X509_ASN_ENCODING,
        NULL,
        0,
        NULL,
        NULL,
        &cbInfo
    );
    if((status != TRUE) || (cbInfo <= 0)) {
        xmlSecMSCngNtError("CryptExportPublicKeyInfoFromBCryptKeyHandle", NULL, STATUS_SUCCESS);
        goto done;
    }

    pInfo = (PUCHAR)xmlMalloc(cbInfo);
    if(pInfo == NULL) {
        xmlSecMallocError(cbInfo, NULL);
        goto done;
    }

    status = CryptExportPublicKeyInfoFromBCryptKeyHandle(
        hPubkey,
        X509_ASN_ENCODING,
        NULL,
        0,
        NULL,
        (PCERT_PUBLIC_KEY_INFO)pInfo,
        &cbInfo
    );
    if((status != TRUE) || (cbInfo <= 0)) {
        xmlSecMSCngNtError("CryptExportPublicKeyInfoFromBCryptKeyHandle", NULL, STATUS_SUCCESS);
        goto done;
    }

    status = CryptEncodeObjectEx(
        X509_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        pInfo,
        CRYPT_ENCODE_ALLOC_FLAG,
        NULL,
        ppDer,
        pcbDer
    );
    if((status != TRUE) || (*ppDer == NULL) || (*pcbDer <= 0)) {
        xmlSecMSCngNtError("CryptEncodeObjectEx", NULL, STATUS_SUCCESS);
        goto done;
    }

    xmlFree(pInfo);
    return(0);

done:
    if(pInfo != NULL) {
        xmlFree(pInfo);
    }
    if(*ppDer != NULL) {
        LocalFree(*ppDer);
        *ppDer = NULL;
    }
    *pcbDer = 0;
    return(-1);
}


/**
 * @brief Loads a public key of any supported type (RSA, DSA, EC, DH) from a raw
 * @param derData DER-encoded SubjectPublicKeyInfo.
 * @param derDataLen length of @p derData.
 *
 * SubjectPublicKeyInfo DER blob.
 *
 * @return new key data or NULL on failure.
 */
xmlSecKeyDataPtr
xmlSecMSCngAppKeyReadPubKeyFromDer(const xmlSecByte* derData, DWORD derDataLen) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    CERT_PUBLIC_KEY_INFO* spki = NULL;
    DWORD spkiLen = 0;
    BCRYPT_KEY_HANDLE hPubKey = NULL;
    int ret;

    xmlSecAssert2(derData != NULL, NULL);
    xmlSecAssert2(derDataLen > 0, NULL);

    /* Decode SubjectPublicKeyInfo */
    if(!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, derData, derDataLen,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL, &spki, &spkiLen)) {
        xmlSecMSCngLastError("CryptDecodeObjectEx(SPKI)", NULL);
        goto done;
    }
    if(spki == NULL || spki->Algorithm.pszObjId == NULL) {
        xmlSecInternalError("CryptDecodeObjectEx returned NULL or no OID", NULL);
        goto done;
    }

#ifndef XMLSEC_NO_DH
    /* DH public keys require custom BCrypt blob construction since
     * CryptImportPublicKeyInfoEx2 does not support X9.42 DH (szOID_X942_DH). */
    if(strcmp(spki->Algorithm.pszObjId, szOID_X942_DH) == 0) {
        const xmlSecByte* pP = NULL;
        DWORD pPLen = 0;
        const xmlSecByte* pG = NULL;
        DWORD pGLen = 0;
        const xmlSecByte* pY = NULL;
        DWORD pYLen = 0;
        DWORD cbKey;
        PUCHAR pbPubBlob = NULL;
        DWORD cbPubBlob;
        BCRYPT_DH_KEY_BLOB* dhPub;
        BCRYPT_ALG_HANDLE hAlg = NULL;
        NTSTATUS status;

        if(spki->Algorithm.Parameters.cbData == 0 || spki->Algorithm.Parameters.pbData == NULL) {
            xmlSecInternalError("DH SPKI: missing AlgorithmIdentifier.Parameters", NULL);
            goto done;
        }
        if(spki->PublicKey.cbData == 0 || spki->PublicKey.pbData == NULL) {
            xmlSecInternalError("DH SPKI: missing PublicKey bits", NULL);
            goto done;
        }

        const xmlSecByte* pQ = NULL;
        DWORD pQLen = 0;

        ret = xmlSecMSCngDhParseDhParameters(
            spki->Algorithm.Parameters.pbData, spki->Algorithm.Parameters.cbData,
            &pP, &pPLen, &pG, &pGLen, &pQ, &pQLen);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngDhParseDhParameters", NULL);
            goto done;
        }

        /* Parse Y from PublicKey bits (BIT STRING content = DER INTEGER Y) */
        {
            const xmlSecByte* pkBits = spki->PublicKey.pbData;
            DWORD pkBitsLen = spki->PublicKey.cbData;
            if(pkBitsLen > 1 && *pkBits == 0x00) { pkBits++; pkBitsLen--; }
            pY = xmlSecMSCngDerDecodeInteger(pkBits, pkBits + pkBitsLen, &pYLen);
            if(pY == NULL) {
                xmlSecInternalError("DH SPKI: failed to parse public key INTEGER Y", NULL);
                goto done;
            }
        }

        cbKey = pPLen;
        cbPubBlob = sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 3;
        pbPubBlob = (PUCHAR)xmlMalloc(cbPubBlob);
        if(pbPubBlob == NULL) {
            xmlSecMallocError(cbPubBlob, NULL);
            goto done;
        }
        memset(pbPubBlob, 0, cbPubBlob);
        dhPub = (BCRYPT_DH_KEY_BLOB*)pbPubBlob;
        dhPub->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
        dhPub->cbKey = cbKey;
        ret = xmlSecMSCngDhBlobCopy(pbPubBlob + sizeof(BCRYPT_DH_KEY_BLOB),             cbKey, pP, pPLen);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngDhBlobCopy(P)", NULL);
            xmlFree(pbPubBlob);
            goto done;
        }
        ret = xmlSecMSCngDhBlobCopy(pbPubBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey,     cbKey, pG, pGLen);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngDhBlobCopy(G)", NULL);
            xmlFree(pbPubBlob);
            goto done;
        }
        ret = xmlSecMSCngDhBlobCopy(pbPubBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 2, cbKey, pY, pYLen);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngDhBlobCopy(Y)", NULL);
            xmlFree(pbPubBlob);
            goto done;
        }

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DH_ALGORITHM, NULL, 0);
        if(status != STATUS_SUCCESS) {
            xmlFree(pbPubBlob);
            xmlSecMSCngNtError("BCryptOpenAlgorithmProvider(DH pub)", NULL, status);
            goto done;
        }
        status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_DH_PUBLIC_BLOB, &hPubKey, pbPubBlob, cbPubBlob, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        xmlFree(pbPubBlob);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptImportKeyPair(DH pub SPKI)", NULL, status);
            goto done;
        }

        data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataDhId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(DH)", NULL);
            goto done;
        }
        ret = xmlSecMSCngKeyDataAdoptKey(data, hPubKey);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey(DH pub)", NULL);
            goto done;
        }
        ret = xmlSecMSCngKeyDataSetDhQ(data, pQ, pQLen);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataSetDhQ", NULL);
            goto done;
        }
        hPubKey = NULL; /* owned by data */
        res = data;
        data = NULL;
        goto done;
    }
#endif /* XMLSEC_NO_DH */

    /* All other key types: RSA, DSA, EC */
    ret = xmlSecMSCngKeyDataCertGetPubkey(spki, &hPubKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataCertGetPubkey", NULL);
        goto done;
    }

    data = xmlSecMSCngKeyDataFromAlgorithm(spki->Algorithm.pszObjId);
    if(data == NULL) {
        xmlSecInternalError("xmlSecMSCngKeyDataFromAlgorithm", NULL);
        goto done;
    }

    ret = xmlSecMSCngKeyDataAdoptKey(data, hPubKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey", NULL);
        goto done;
    }
    hPubKey = NULL; /* owned by data */

    res = data;
    data = NULL;

done:
    if(hPubKey != NULL) {
        BCryptDestroyKey(hPubKey);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    if(spki != NULL) {
        LocalFree(spki);
    }
    return(res);
}


/**
 * @brief Loads a private key from a raw PKCS8 PrivateKeyInfo DER blob.
 * @param data DER-encoded PKCS8 PrivateKeyInfo blob.
 * @param dataSize length of @p data.
 *
 * Currently only DH private keys are supported.
 *
 * @return new key data or NULL on failure.
 */
xmlSecKeyDataPtr
xmlSecMSCngAppKeyReadPrivKeyFromDer(const xmlSecByte* data, DWORD dataSize) {
    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

#ifndef XMLSEC_NO_DH
{
        xmlSecKeyDataPtr res;
        res = xmlSecMSCngKeyDataDhReadFromPkcs8Der(data, dataSize);
        if(res != NULL) { return(res); }
    }
#endif /* XMLSEC_NO_DH */

#ifndef XMLSEC_NO_XDH
    {
        xmlSecKeyDataPtr res;
        res = xmlSecMSCngKeyDataXdhReadFromPkcs8Der(data, dataSize);
        if(res != NULL) { return(res); }
    }
#endif /* XMLSEC_NO_XDH */

    xmlSecNotImplementedError("Only DH and XDH private keys are supported in DER format");
    return(NULL);
}

/******************************************************************************
 * XDH (X25519) key data
  *****************************************************************************/
#ifndef XMLSEC_NO_XDH

XMLSEC_MSCNG_CERTKEY_KLASS_EX(Xdh, XDH,
    xmlSecKeyDataUsageReadFromFile | xmlSecKeyDataUsageRetrievalMethodNodeXml,
    NULL,         /* dataNodeName */
    NULL,         /* dataNodeNs */
    NULL,         /* generate (not supported) */
    NULL,         /* xmlRead */
    NULL)         /* xmlWrite */

/**
 * @brief The MSCng XDH (X25519) key data klass.
 * @return pointer to MSCng XDH key data klass.
 */
xmlSecKeyDataId
xmlSecMSCngKeyDataXdhGetKlass(void) {
    return(&xmlSecMSCngKeyDataXdhKlass);
}

#endif /* XMLSEC_NO_XDH */
