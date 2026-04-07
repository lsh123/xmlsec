/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_certkeys
 * @brief DSA key support functions for Microsoft Cryptography API: Next Generation (CNG).
 */
#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>

#include <xmlsec/mscng/certkeys.h>
#include <xmlsec/mscng/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "private.h"

#ifndef XMLSEC_NO_DSA

/* Reverses a CRYPT_UINT_BLOB in-place (little-endian -> big-endian) and strips
 * any leading zero bytes. Updates *pSize with the resulting byte count. */
static void
xmlSecMSCngReverseBlob(CRYPT_UINT_BLOB* blob, DWORD* pSize) {
    xmlSecAssert(blob != NULL);
    xmlSecAssert(blob->pbData != NULL);
    xmlSecAssert(pSize != NULL);

    *pSize = blob->cbData;
    if(*pSize == 0) {
        return;
    }
    xmlSecMSCngReverseBytes(blob->pbData, *pSize);
    while(*pSize > 1 && blob->pbData[0] == 0) {
        blob->pbData++;
        (*pSize)--;
    }
    blob->cbData = *pSize;
}

/* Import a DSA public key from a certificate using BCryptImportKeyPair.
 * CryptImportPublicKeyInfoEx2 only supports DSA up to 1024-bit (legacy CryptoAPI
 * limitation), so for all DSA keys we manually decode the SubjectPublicKeyInfo
 * and construct the appropriate BCRYPT_DSA_KEY_BLOB (V1 <=1024-bit) or
 * BCRYPT_DSA_KEY_BLOB_V2 (>1024-bit) and call BCryptImportKeyPair directly. */
int
xmlSecMSCngKeyDataCertGetDsaPubkey(PCERT_PUBLIC_KEY_INFO spki, BCRYPT_KEY_HANDLE* key) {
    CERT_DSS_PARAMETERS* pDssParams = NULL;
    DWORD cbDssParams = 0;
    CRYPT_UINT_BLOB* pYBlob = NULL;
    DWORD cbYBlob = 0;
    BYTE* blobData = NULL;
    DWORD pSize, qSize, gSize, ySize, qBlobSize;
    DWORD blobSize, offset;
    BCRYPT_DSA_KEY_BLOB* dsakey;
#if XMLSEC_MSCNG_HAVE_DSA_V2
    BCRYPT_DSA_KEY_BLOB_V2* dsakey2;
#endif /* XMLSEC_MSCNG_HAVE_DSA_V2 */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    int ret = -1;

    xmlSecAssert2(spki != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    xmlSecAssert2(spki->Algorithm.Parameters.cbData != 0, -1);
    xmlSecAssert2(spki->Algorithm.Parameters.pbData != NULL, -1);

    /* Decode DSS parameters (p, q, g) from AlgorithmIdentifier.Parameters */
    if(!CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_DSS_PARAMETERS,
            spki->Algorithm.Parameters.pbData,
            spki->Algorithm.Parameters.cbData,
            CRYPT_DECODE_ALLOC_FLAG,
            NULL,
            (void**)&pDssParams,
            &cbDssParams)) {
        xmlSecMSCngLastError("CryptDecodeObjectEx(X509_DSS_PARAMETERS)", NULL);
        goto done;
    }

    /* Decode the DSA public key value (y) from SubjectPublicKeyInfo.PublicKey */
    if(!CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_DSS_PUBLICKEY,
            spki->PublicKey.pbData,
            spki->PublicKey.cbData,
            CRYPT_DECODE_ALLOC_FLAG,
            NULL,
            (void**)&pYBlob,
            &cbYBlob)) {
        xmlSecMSCngLastError("CryptDecodeObjectEx(X509_DSS_PUBLICKEY)", NULL);
        goto done;
    }

    /* CryptDecodeObjectEx with X509_DSS_PARAMETERS / X509_DSS_PUBLICKEY returns
     * values in little-endian (LSB-first) byte order inside CRYPT_UINT_BLOB.
     * BCrypt DSA key blobs require big-endian (MSB-first). Reverse each buffer
     * in-place, then strip any leftover leading zeros (ASN.1 sign bytes). */
    xmlSecMSCngReverseBlob(&pDssParams->p, &pSize);
    xmlSecMSCngReverseBlob(&pDssParams->q, &qSize);
    xmlSecMSCngReverseBlob(&pDssParams->g, &gSize);
    xmlSecMSCngReverseBlob(pYBlob,         &ySize);

    if(pSize == 0 || qSize == 0 || gSize == 0 || ySize == 0) {
        xmlSecInvalidDataError("invalid DSA key parameters (zero size)", NULL);
        goto done;
    }

    if(qSize > XMLSEC_MSCNG_DSA_V2_Q_SIZE) {
        xmlSecInvalidSizeMoreThanError("DSA Q size", (xmlSecSize)qSize, (xmlSecSize)XMLSEC_MSCNG_DSA_V2_Q_SIZE, NULL);
        goto done;
    }
    if((gSize > pSize) || (ySize > pSize)) {
        xmlSecInvalidDataError("invalid DSA key parameters (g/y longer than p)", NULL);
        goto done;
    }

    qBlobSize = (qSize <= XMLSEC_MSCNG_DSA_MAX_Q_SIZE) ? XMLSEC_MSCNG_DSA_MAX_Q_SIZE : qSize;
    if((pSize <= 128) && (qBlobSize == XMLSEC_MSCNG_DSA_MAX_Q_SIZE)) {
        /* V1: BCRYPT_DSA_KEY_BLOB for keys up to 1024-bit (128 bytes)
         * layout: header + p[cbKey] + g[cbKey] + y[cbKey] */
        if(pSize > XMLSEC_MSCNG_DSA_MAX_P_SIZE) {
            xmlSecInvalidSizeMoreThanError("DSA P size", (xmlSecSize)pSize, (xmlSecSize)XMLSEC_MSCNG_DSA_MAX_P_SIZE, NULL);
            goto done;
        }
        blobSize = (DWORD)sizeof(BCRYPT_DSA_KEY_BLOB) + pSize * 3U;
        blobData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, blobSize);
        if(blobData == NULL) {
            xmlSecMSCngLastError("LocalAlloc", NULL);
            goto done;
        }
        dsakey = (BCRYPT_DSA_KEY_BLOB*)blobData;
        dsakey->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC;
        dsakey->cbKey = pSize;
        memset(dsakey->Count, 0xFF, sizeof(dsakey->Count));
        memset(dsakey->Seed, 0xFF, sizeof(dsakey->Seed));
        /* q is stored right-aligned in the fixed 20-byte header field */
        memcpy(dsakey->q + (XMLSEC_MSCNG_DSA_MAX_Q_SIZE - qSize), pDssParams->q.pbData, qSize);

        offset = (DWORD)sizeof(BCRYPT_DSA_KEY_BLOB);
        /* p: cbData should equal pSize; copy right-aligned just in case */
        memcpy(blobData + offset + (pSize - pDssParams->p.cbData), pDssParams->p.pbData, pDssParams->p.cbData);
        offset += pSize;
        /* g: right-align in pSize-byte field (leading zeros already from LMEM_ZEROINIT) */
        memcpy(blobData + offset + (pSize - gSize), pDssParams->g.pbData, gSize);
        offset += pSize;
        /* y: right-align in pSize-byte field */
        memcpy(blobData + offset + (pSize - ySize), pYBlob->pbData, ySize);
    } else {
#if XMLSEC_MSCNG_HAVE_DSA_V2
        /* V2: BCRYPT_DSA_KEY_BLOB_V2 for keys > 1024-bit (2048/3072-bit)
         * layout: header + seed[cbGroupSize] + q[cbGroupSize] + p[cbKey] + g[cbKey] + y[cbKey] */
        if(qBlobSize > XMLSEC_MSCNG_DSA_V2_Q_SIZE) {
            xmlSecInvalidSizeMoreThanError("DSA Q size", (xmlSecSize)qBlobSize, (xmlSecSize)XMLSEC_MSCNG_DSA_MAX_Q_SIZE, NULL);
            goto done;
        }
        if(pSize > XMLSEC_MSCNG_DSA_MAX_P_SIZE) {
            xmlSecInvalidSizeMoreThanError("DSA P size", (xmlSecSize)pSize, (xmlSecSize)XMLSEC_MSCNG_DSA_MAX_P_SIZE, NULL);
            goto done;
        }
        blobSize = (DWORD)sizeof(BCRYPT_DSA_KEY_BLOB_V2) + qBlobSize * 2U + pSize * 3U;
        blobData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, blobSize);
        if(blobData == NULL) {
            xmlSecMSCngLastError("LocalAlloc", NULL);
            goto done;
        }
        dsakey2 = (BCRYPT_DSA_KEY_BLOB_V2*)blobData;
        dsakey2->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC_V2;
        dsakey2->cbKey = pSize;
        dsakey2->hashAlgorithm = DSA_HASH_ALGORITHM_SHA256;
        dsakey2->standardVersion = DSA_FIPS186_3;
        dsakey2->cbSeedLength = qBlobSize;
        dsakey2->cbGroupSize = qBlobSize;
        memset(dsakey2->Count, 0xFF, sizeof(dsakey2->Count));

        offset = (DWORD)sizeof(BCRYPT_DSA_KEY_BLOB_V2);
        /* seed: unknown at verification time, use 0xFF placeholder */
        memset(blobData + offset, 0xFF, qBlobSize);
        offset += qBlobSize;
        /* q is stored right-aligned in the fixed q field */
        memcpy(blobData + offset + (qBlobSize - qSize), pDssParams->q.pbData, qSize);
        offset += qBlobSize;
        /* p: right-align */
        memcpy(blobData + offset + (pSize - pDssParams->p.cbData), pDssParams->p.pbData, pDssParams->p.cbData);
        offset += pSize;
        /* g: right-align */
        memcpy(blobData + offset + (pSize - gSize), pDssParams->g.pbData, gSize);
        offset += pSize;
        /* y: right-align */
        memcpy(blobData + offset + (pSize - ySize), pYBlob->pbData, ySize);
    #else /* XMLSEC_MSCNG_HAVE_DSA_V2 */
        xmlSecNotImplementedError("DSA keys with q > 20 bytes require newer Windows SDK bcrypt definitions");
        goto done;
    #endif /* XMLSEC_MSCNG_HAVE_DSA_V2 */
    }

    /* Open DSA algorithm provider and import the key blob */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DSA_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_DSA_PUBLIC_BLOB, key, blobData, blobSize, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair", NULL, status);
        goto done;
    }

    ret = 0;

done:
    if(hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if(blobData != NULL) {
        LocalFree(blobData);
    }
    if(pYBlob != NULL) {
        LocalFree(pYBlob);
    }
    if(pDssParams != NULL) {
        LocalFree(pDssParams);
    }
    return(ret);
}

/* Builds the correct SubjectPublicKeyInfo DER for a DSA BCrypt public key.
 * CryptExportPublicKeyInfoFromBCryptKeyHandle misinterprets V2 (>1024-bit) DSA
 * blobs, reading all fields at V1 offsets and producing garbled P/Q/G/Y values.
 * This helper exports the BCrypt blob directly, extracts the correct fields, and
 * re-encodes them. On success returns 0; caller must LocalFree(*ppDer). */
int
xmlSecMSCngDsaBuildSubjectPublicKeyInfoDer(BCRYPT_KEY_HANDLE hKey, LPVOID* ppDer, DWORD* pcbDer) {
    BYTE* blobData = NULL;
    DWORD blobLen = 0;
    const BYTE* pBE = NULL;
    const BYTE* qBE = NULL;
    const BYTE* gBE = NULL;
    const BYTE* yBE = NULL;
    BCRYPT_DSA_KEY_BLOB* hdr;
    DWORD pSize = 0, qSize = 0, gSize = 0, ySize = 0;
    BYTE* pLE = NULL, * qLE = NULL, * gLE = NULL, * yLE = NULL;
    CERT_DSS_PARAMETERS dssParams;
    CRYPT_UINT_BLOB yBlob;
    BYTE* encodedParams = NULL;
    DWORD encodedParamsLen = 0;
    BYTE* encodedY = NULL;
    DWORD encodedYLen = 0;
    CERT_PUBLIC_KEY_INFO spki;
    NTSTATUS status;
    int ret = -1;

    xmlSecAssert2(hKey != 0, -1);
    xmlSecAssert2(ppDer != NULL, -1);
    xmlSecAssert2(pcbDer != NULL, -1);

    *ppDer = NULL;
    *pcbDer = 0;

    /* Export DSA public key to BCrypt blob */
    status = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PUBLIC_BLOB, NULL, 0, &blobLen, 0);
    if((status != STATUS_SUCCESS) || (blobLen < sizeof(BCRYPT_DSA_KEY_BLOB))) {
        xmlSecMSCngNtError("BCryptExportKey(size)", NULL, status);
        goto done;
    }
    blobData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, blobLen);
    if(blobData == NULL) {
        xmlSecMSCngLastError("LocalAlloc", NULL);
        goto done;
    }
    status = BCryptExportKey(hKey, NULL, BCRYPT_DSA_PUBLIC_BLOB, blobData, blobLen, &blobLen, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey", NULL, status);
        goto done;
    }

    /* Locate P, Q, G, Y within the blob (BCrypt stores all values big-endian) */
    hdr = (BCRYPT_DSA_KEY_BLOB*)blobData;
    if(hdr->dwMagic == BCRYPT_DSA_PUBLIC_MAGIC) {
        /* V1: header + p[cbKey] + g[cbKey] + y[cbKey], q fixed 20 bytes in header */
        BYTE* d = blobData + sizeof(BCRYPT_DSA_KEY_BLOB);
        pBE = d;       pSize = hdr->cbKey; d += pSize;
        qBE = hdr->q;  qSize = sizeof(hdr->q);
        gBE = d;       gSize = hdr->cbKey; d += gSize;
        yBE = d;       ySize = hdr->cbKey;
    }
#if XMLSEC_MSCNG_HAVE_DSA_V2
    else if(hdr->dwMagic == BCRYPT_DSA_PUBLIC_MAGIC_V2) {
        /* V2: header + seed[cbSeedLength] + q[cbGroupSize] + p[cbKey] + g[cbKey] + y[cbKey] */
        BCRYPT_DSA_KEY_BLOB_V2* h2 = (BCRYPT_DSA_KEY_BLOB_V2*)blobData;
        BYTE* d = blobData + sizeof(BCRYPT_DSA_KEY_BLOB_V2);
        d    += h2->cbSeedLength;               /* skip seed placeholder */
        qBE = d;  qSize = h2->cbGroupSize; d += qSize;
        pBE = d;  pSize = h2->cbKey;       d += pSize;
        gBE = d;  gSize = h2->cbKey;       d += gSize;
        yBE = d;  ySize = h2->cbKey;
    }
#endif /* XMLSEC_MSCNG_HAVE_DSA_V2 */
    else {
        xmlSecNotImplementedError2("Unexpected DSA blob magic: 0x%08lX",
            (unsigned long)hdr->dwMagic);
        goto done;
    }

    /* Reverse each big-endian BCrypt value to little-endian for CryptEncodeObjectEx
     * (CRYPT_UINT_BLOB values are expected in little-endian / LSB-first order). */
    pLE = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pSize);
    qLE = (BYTE*)LocalAlloc(LMEM_ZEROINIT, qSize);
    gLE = (BYTE*)LocalAlloc(LMEM_ZEROINIT, gSize);
    yLE = (BYTE*)LocalAlloc(LMEM_ZEROINIT, ySize);
    if(!pLE || !qLE || !gLE || !yLE) {
        xmlSecMSCngLastError("LocalAlloc", NULL);
        goto done;
    }
    xmlSecMSCngReverseCopy(pLE, pBE, pSize);
    xmlSecMSCngReverseCopy(qLE, qBE, qSize);
    xmlSecMSCngReverseCopy(gLE, gBE, gSize);
    xmlSecMSCngReverseCopy(yLE, yBE, ySize);

    /* Encode DSS domain parameters: SEQUENCE { INTEGER p, INTEGER q, INTEGER g } */
    memset(&dssParams, 0, sizeof(dssParams));
    dssParams.p.cbData = pSize; dssParams.p.pbData = pLE;
    dssParams.q.cbData = qSize; dssParams.q.pbData = qLE;
    dssParams.g.cbData = gSize; dssParams.g.pbData = gLE;
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_DSS_PARAMETERS, &dssParams,
            CRYPT_ENCODE_ALLOC_FLAG, NULL, (PVOID*)&encodedParams, &encodedParamsLen)) {
        xmlSecMSCngLastError("CryptEncodeObjectEx(X509_DSS_PARAMETERS)", NULL);
        goto done;
    }

    /* Encode public key value Y as DER INTEGER */
    memset(&yBlob, 0, sizeof(yBlob));
    yBlob.cbData = ySize; yBlob.pbData = yLE;
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_DSS_PUBLICKEY, &yBlob,
            CRYPT_ENCODE_ALLOC_FLAG, NULL, (PVOID*)&encodedY, &encodedYLen)) {
        xmlSecMSCngLastError("CryptEncodeObjectEx(X509_DSS_PUBLICKEY)", NULL);
        goto done;
    }

    /* Build SubjectPublicKeyInfo and encode as DER */
    memset(&spki, 0, sizeof(spki));
    spki.Algorithm.pszObjId          = (LPSTR)szOID_X957_DSA;
    spki.Algorithm.Parameters.pbData = encodedParams;
    spki.Algorithm.Parameters.cbData = encodedParamsLen;
    spki.PublicKey.pbData             = encodedY;
    spki.PublicKey.cbData             = encodedYLen;
    spki.PublicKey.cUnusedBits        = 0;
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &spki,
            CRYPT_ENCODE_ALLOC_FLAG, NULL, ppDer, pcbDer)) {
        xmlSecMSCngLastError("CryptEncodeObjectEx(X509_PUBLIC_KEY_INFO)", NULL);
        goto done;
    }

    ret = 0;
done:
    if(pLE != NULL) LocalFree(pLE);
    if(qLE != NULL) LocalFree(qLE);
    if(gLE != NULL) LocalFree(gLE);
    if(yLE != NULL) LocalFree(yLE);
    if(encodedParams != NULL) LocalFree(encodedParams);
    if(encodedY != NULL) LocalFree(encodedY);
    if(blobData != NULL) LocalFree(blobData);
    return(ret);
}

int
xmlSecMSCngIsDsaBcryptKey(BCRYPT_KEY_HANDLE hKey) {
    WCHAR algName[64] = {0};
    ULONG algNameLen = 0;
    NTSTATUS ntstatus;

    xmlSecAssert2(hKey != 0, -1);

    ntstatus = BCryptGetProperty(hKey, BCRYPT_ALGORITHM_NAME, (PUCHAR)algName, sizeof(algName) - sizeof(WCHAR), &algNameLen, 0);
    if(ntstatus != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptGetProperty", NULL, ntstatus);
        return(-1);

    }
    return ((wcsncmp(algName, BCRYPT_DSA_ALGORITHM, wcslen(BCRYPT_DSA_ALGORITHM)) == 0) ? 1 : 0);
}

xmlSecKeyDataPtr
xmlSecMSCngKeyDataDsaRead(xmlSecKeyDataId id, xmlSecKeyValueDsaPtr dsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecBuffer blob;
    int blobInitialized = 0;
    xmlSecByte* blobData;
    xmlSecSize pSize, qSize, gSize, ySize, qBlobSize;
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

    /* turn the read data into a public key blob.
     * We support both V1 (BCRYPT_DSA_KEY_BLOB, q up to 20 bytes, keys up to 1024-bit)
     * and V2 (BCRYPT_DSA_KEY_BLOB_V2, q up to 32 bytes, keys up to 3072-bit).
     * Both use BCRYPT_DSA_ALGORITHM and BCRYPT_DSA_PUBLIC_BLOB; the magic field
     * distinguishes them.
     */
    if(qSize > XMLSEC_MSCNG_DSA_V2_Q_SIZE) {
        xmlSecInvalidSizeMoreThanError("DSA Q size", (xmlSecSize)qSize, (xmlSecSize)XMLSEC_MSCNG_DSA_V2_Q_SIZE, NULL);
        goto done;
    }
    xmlSecAssert2(gSize <= pSize, NULL);
    xmlSecAssert2(ySize <= pSize, NULL);

    qBlobSize = (qSize <= XMLSEC_MSCNG_DSA_MAX_Q_SIZE) ? XMLSEC_MSCNG_DSA_MAX_Q_SIZE : qSize;

    if(qBlobSize == XMLSEC_MSCNG_DSA_MAX_Q_SIZE) {
        /* V1: BCRYPT_DSA_KEY_BLOB for keys up to 1024-bit (q up to 20 bytes),
         * layout: header + p[cbKey] + g[cbKey] + y[cbKey] */
        offset = sizeof(BCRYPT_DSA_KEY_BLOB);
        blobSize = offset + pSize * 3;
    } else {
#if XMLSEC_MSCNG_HAVE_DSA_V2
        /* V2: BCRYPT_DSA_KEY_BLOB_V2 for larger keys (2048/3072-bit),
         * layout: header + seed[cbSeedLength] + q[cbGroupSize] + p[cbKey] + g[cbKey] + y[cbKey] */
        offset = sizeof(BCRYPT_DSA_KEY_BLOB_V2);
        blobSize = offset + qBlobSize + qBlobSize + pSize * 3; /* seed + q + p + g + y */
#else /* XMLSEC_MSCNG_HAVE_DSA_V2 */
        xmlSecNotImplementedError("DSA keys with q > 20 bytes require newer Windows SDK bcrypt definitions");
        goto done;
#endif /* XMLSEC_MSCNG_HAVE_DSA_V2 */
    }

    ret = xmlSecBufferInitialize(&blob, blobSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", NULL,
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    blobInitialized = 1;

    ret = xmlSecBufferSetSize(&blob, blobSize);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, blobSize);
        goto done;
    }
    memset(xmlSecBufferGetData(&blob), 0, blobSize); /* ensure all gaps are zero-padded */

    blobData = xmlSecBufferGetData(&blob);
    if(qBlobSize == XMLSEC_MSCNG_DSA_MAX_Q_SIZE) {
        /* V1: BCRYPT_DSA_KEY_BLOB */
        dsakey = (BCRYPT_DSA_KEY_BLOB*)blobData;
        dsakey->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC;
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(pSize, dsakey->cbKey, goto done, NULL);
        memset(dsakey->Count, 0xFF, sizeof(dsakey->Count));
        memset(dsakey->Seed, 0xFF, sizeof(dsakey->Seed));

        /* q (in header, fixed 20 bytes) */
        xmlSecAssert2(sizeof(dsakey->q) == XMLSEC_MSCNG_DSA_MAX_Q_SIZE, NULL);
        memcpy(dsakey->q + (XMLSEC_MSCNG_DSA_MAX_Q_SIZE - qSize), xmlSecBufferGetData(&(dsaValue->q)), qSize);

        /*  p  */
        memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->p)), pSize);
        offset += pSize;

        /*  g  */
        memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->g)), gSize);
        offset += pSize; /* gSize <= pSize */

        /*  y  */
        memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->y)), ySize);
        offset += pSize; /* ySize <= pSize */
    } else {
#if XMLSEC_MSCNG_HAVE_DSA_V2
        /* V2: BCRYPT_DSA_KEY_BLOB_V2 for 2048/3072-bit keys */
        DWORD dwQLen;
        BCRYPT_DSA_KEY_BLOB_V2* dsakey2;

        dsakey2 = (BCRYPT_DSA_KEY_BLOB_V2*)blobData;
        dsakey2->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC_V2;
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(pSize, dsakey2->cbKey, goto done, NULL);
        dsakey2->hashAlgorithm = DSA_HASH_ALGORITHM_SHA256;
        dsakey2->standardVersion = DSA_FIPS186_3;
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(qBlobSize, dwQLen, goto done, NULL);
        dsakey2->cbSeedLength = dwQLen;
        dsakey2->cbGroupSize = dwQLen;
        memset(dsakey2->Count, 0xFF, sizeof(dsakey2->Count));

        /*  seed (placeholder: unknown, use 0xFF)  */
        memset(blobData + offset, 0xFF, qBlobSize);
        offset += qBlobSize;

        /*  q (fixed 32-byte field, right-aligned)  */
        memcpy(blobData + offset + (qBlobSize - qSize), xmlSecBufferGetData(&(dsaValue->q)), qSize);
        offset += qBlobSize;

        /*  p  */
        memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->p)), pSize);
        offset += pSize;

        /*  g  */
        memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->g)), gSize);
        offset += pSize; /* gSize <= pSize */

        /*  y  */
        memcpy(blobData + offset, xmlSecBufferGetData(&(dsaValue->y)), ySize);
        offset += pSize; /* ySize <= pSize */
#else /* XMLSEC_MSCNG_HAVE_DSA_V2 */
    xmlSecNotImplementedError("DSA keys with q > 20 bytes require newer Windows SDK bcrypt definitions");
    goto done;
#endif /* XMLSEC_MSCNG_HAVE_DSA_V2 */
    }

    /* import the key blob */
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_DSA_ALGORITHM,
        NULL,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(blobSize, dwBlobSize, goto done, NULL);
    status = BCryptImportKeyPair(
        hAlg,
        NULL,
        BCRYPT_DSA_PUBLIC_BLOB,
        &hKey,
        blobData,
        dwBlobSize,
        0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair", NULL, status);
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if (data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate", NULL);
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

int
xmlSecMSCngKeyDataDsaPubkeyWrite(BCRYPT_KEY_HANDLE pubkey,  xmlSecKeyValueDsaPtr dsaValue) {
    NTSTATUS status;
    xmlSecBuffer buf;
    int bufInitialized = 0;
    xmlSecByte* bufData;
    DWORD bufLen = 0;
    BCRYPT_DSA_KEY_BLOB* dsakey;
    int ret;
    int res = -1;

    xmlSecAssert2(pubkey != NULL, -1);
    xmlSecAssert2(dsaValue != NULL, -1);

    /* turn ctx->pubkey into dsakey */
    status = BCryptExportKey(pubkey,
        NULL,
        BCRYPT_DSA_PUBLIC_BLOB,
        NULL,
        0,
        &bufLen,
        0);
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", NULL, status, "bufLen=%lu", bufLen);
        goto done;
    }

    ret = xmlSecBufferInitialize(&buf, bufLen);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", NULL, "size=%lu", bufLen);
        goto done;
    }
    bufInitialized = 1;

    bufData = xmlSecBufferGetData(&buf);
    xmlSecAssert2(bufData != NULL, -1);

    status = BCryptExportKey(pubkey,
        NULL,
        BCRYPT_DSA_PUBLIC_BLOB,
        bufData,
        bufLen,
        &bufLen,
        0);
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", NULL, status, "bufLen=%lu", bufLen);
        goto done;
    }

    /* check minimum blob size and detect V1 vs V2 by magic */
    if (bufLen < sizeof(BCRYPT_DSA_KEY_BLOB)) {
        xmlSecMSCngNtError2("BCRYPT_DSA_KEY_BLOB", NULL, STATUS_SUCCESS, "dwBlobLen=%lu", bufLen);
        goto done;
    }
    dsakey = (BCRYPT_DSA_KEY_BLOB*)bufData;

    if(dsakey->dwMagic == BCRYPT_DSA_PUBLIC_MAGIC) {
        /* V1: BCRYPT_DSA_KEY_BLOB + p[cbKey] + g[cbKey] + y[cbKey], q in header */
        if((dsakey->cbKey > XMLSEC_MSCNG_DSA_MAX_CBKEY_SIZE) || (bufLen < (sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * dsakey->cbKey))) {
            xmlSecMSCngNtError3("BCryptExportKey(V1)", NULL, STATUS_SUCCESS, "dwBlobLen: %lu; keyLen: %lu", bufLen, dsakey->cbKey);
            goto done;
        }
        bufData += sizeof(BCRYPT_DSA_KEY_BLOB);

        /* p */
        ret = xmlSecBufferSetData(&(dsaValue->p), bufData, dsakey->cbKey);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData(p)", NULL, "keyLen=%lu", dsakey->cbKey);
            goto done;
        }
        bufData += dsakey->cbKey;

        /* q (in header, fixed 20 bytes) */
        xmlSecAssert2(sizeof(dsakey->q) <= XMLSEC_MSCNG_DSA_MAX_Q_SIZE, -1);
        ret = xmlSecBufferSetData(&(dsaValue->q), (xmlSecByte*)dsakey->q, sizeof(dsakey->q));
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData(q)", NULL, "keyLen=%lu", dsakey->cbKey);
            goto done;
        }

        /* g */
        ret = xmlSecBufferSetData(&(dsaValue->g), bufData, dsakey->cbKey);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData(g)", NULL,"keyLen=%lu", dsakey->cbKey);
            goto done;
        }
        bufData += dsakey->cbKey;

        /* X is REQUIRED for private key but MSCng does not support it,
         * so we just ignore it */

        /* y */
        ret = xmlSecBufferSetData(&(dsaValue->y), bufData, dsakey->cbKey);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData(y)", NULL, "keyLen=%lu", dsakey->cbKey);
            goto done;
        }
    }
#if XMLSEC_MSCNG_HAVE_DSA_V2
    else if(dsakey->dwMagic == BCRYPT_DSA_PUBLIC_MAGIC_V2) {
        /* V2: BCRYPT_DSA_KEY_BLOB_V2 + seed[cbSeedLength] + q[cbGroupSize] + p[cbKey] + g[cbKey] + y[cbKey] */
        BCRYPT_DSA_KEY_BLOB_V2* dsakey2v;
        xmlSecByte* v2Data;
        if (bufLen < sizeof(BCRYPT_DSA_KEY_BLOB_V2)) {
            xmlSecMSCngNtError2("BCRYPT_DSA_KEY_BLOB_V2", NULL, STATUS_SUCCESS, "dwBlobLen=%lu", bufLen);
            goto done;
        }
        dsakey2v = (BCRYPT_DSA_KEY_BLOB_V2*)bufData;
        if (bufLen < (sizeof(BCRYPT_DSA_KEY_BLOB_V2) + dsakey2v->cbSeedLength + dsakey2v->cbGroupSize + 3 * dsakey2v->cbKey)) {
            xmlSecMSCngNtError3("BCryptExportKey(V2)", NULL, STATUS_SUCCESS, "dwBlobLen: %lu; keyLen: %lu", bufLen, dsakey2v->cbKey);
            goto done;
        }
        v2Data = bufData + sizeof(BCRYPT_DSA_KEY_BLOB_V2);

        /* q (after seed) */
        ret = xmlSecBufferSetData(&(dsaValue->q), v2Data + dsakey2v->cbSeedLength, dsakey2v->cbGroupSize);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData(q)", NULL, "qLen=%lu", dsakey2v->cbGroupSize);
            goto done;
        }
        v2Data += dsakey2v->cbSeedLength + dsakey2v->cbGroupSize;

        /* p */
        ret = xmlSecBufferSetData(&(dsaValue->p), v2Data, dsakey2v->cbKey);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData(p)", NULL, "keyLen=%lu", dsakey2v->cbKey);
            goto done;
        }
        v2Data += dsakey2v->cbKey;

        /* g */
        ret = xmlSecBufferSetData(&(dsaValue->g), v2Data, dsakey2v->cbKey);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData(g)", NULL, "keyLen=%lu", dsakey2v->cbKey);
            goto done;
        }
        v2Data += dsakey2v->cbKey;

        /* X is REQUIRED for private key but MSCng does not support it,
         * so we just ignore it */

        /* y */
        ret = xmlSecBufferSetData(&(dsaValue->y), v2Data, dsakey2v->cbKey);
        if (ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetData(y)", NULL, "keyLen=%lu", dsakey2v->cbKey);
            goto done;
        }
    }
#endif /* XMLSEC_MSCNG_HAVE_DSA_V2 */
    else {
        xmlSecNotImplementedError2("Unexpected DSA blob magic: 0x%08lX", (unsigned long)dsakey->dwMagic);
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

#endif /* XMLSEC_NO_DSA */
