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
 * @brief DH key support functions for Microsoft Cryptography API: Next Generation (CNG).
 */
#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/private.h>
#include <xmlsec/buffer.h>

#include <xmlsec/mscng/certkeys.h>
#include <xmlsec/mscng/crypto.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"
#include "private.h"

#ifndef XMLSEC_NO_DH

int
xmlSecMSCngKeyDataDuplicateBCryptDhPrivKey(BCRYPT_KEY_HANDLE src, BCRYPT_KEY_HANDLE* dst) {
    BCRYPT_ALG_HANDLE hDhAlg = NULL;
    DWORD cbPrivBlob = 0;
    PUCHAR pbPrivBlob;
    BCRYPT_KEY_HANDLE hDhAlgKey = NULL;
    NTSTATUS status;

    xmlSecAssert2(src != NULL, -1);
    xmlSecAssert2(dst != NULL, -1);

    /* export DH private key blob */
    status = BCryptExportKey(src, NULL, BCRYPT_DH_PRIVATE_BLOB, NULL, 0, &cbPrivBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(DH priv)", NULL, status);
        return(-1);
    }
    pbPrivBlob = (PUCHAR)xmlMalloc(cbPrivBlob);
    if(pbPrivBlob == NULL) {
        xmlSecMallocError(cbPrivBlob, NULL);
        return(-1);
    }
    status = BCryptExportKey(src, NULL, BCRYPT_DH_PRIVATE_BLOB, pbPrivBlob, cbPrivBlob, &cbPrivBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey2(DH priv)", NULL, status);
        xmlSecMemCleanse(pbPrivBlob, cbPrivBlob);
        xmlFree(pbPrivBlob);
        return(-1);
    }
    status = BCryptOpenAlgorithmProvider(&hDhAlg, BCRYPT_DH_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider(DH priv dup)", NULL, status);
        xmlSecMemCleanse(pbPrivBlob, cbPrivBlob);
        xmlFree(pbPrivBlob);
        return(-1);
    }
    status = BCryptImportKeyPair(hDhAlg, NULL, BCRYPT_DH_PRIVATE_BLOB, &hDhAlgKey, pbPrivBlob, cbPrivBlob, 0);
    BCryptCloseAlgorithmProvider(hDhAlg, 0);
    memset(pbPrivBlob, 0, cbPrivBlob);
    xmlFree(pbPrivBlob);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(DH priv dup)", NULL, status);
        return(-1);
    }
    *dst = hDhAlgKey;
    return(0);
}

/* DER parsing helpers */

/* Read a DER TLV: returns pointer to value bytes and sets *pLen.
   Tag must match expectedTag. Returns NULL on error. */
static const xmlSecByte*
xmlSecMSCngDerReadTlv(const xmlSecByte* p, const xmlSecByte* end, BYTE expectedTag, DWORD* pLen) {
    DWORD len;

    if(p >= end || *p != expectedTag) {
        return(NULL);
    }
    p++;
    if(p >= end) {
        return(NULL);
    }
    if(*p & 0x80) {
        BYTE nBytes = (*p) & 0x7F;
        p++;
        if(nBytes == 0 || nBytes > 4 || p + nBytes > end) {
            return(NULL);
        }
        len = 0;
        while(nBytes-- > 0) {
            len = (len << 8) | (*p++);
        }
    } else {
        len = *p++;
    }
    if(p + len > end) {
        return(NULL);
    }
    *pLen = len;
    return(p);
}

/* Parse DER INTEGER → strip leading sign byte if present.
 * Returns pointer to big-endian integer bytes (inside src buffer), sets *pLen. */
const xmlSecByte*
xmlSecMSCngDerDecodeInteger(const xmlSecByte* p, const xmlSecByte* end, DWORD* pLen) {
    const xmlSecByte* val;
    DWORD len;

    val = xmlSecMSCngDerReadTlv(p, end, 0x02 /* INTEGER */, &len);
    if(val == NULL || len == 0) {
        return(NULL);
    }
    /* skip optional leading zero (sign byte) */
    if(len > 1 && *val == 0x00) {
        val++;
        len--;
    }
    *pLen = len;
    return(val);
}

/* Parse DH AlgorithmIdentifier parameters: SEQUENCE { INTEGER p, INTEGER g [, INTEGER q] }
 * On success sets output pointers and lengths for p and g (big-endian, no sign byte). */
int
xmlSecMSCngDhParseDhParameters(const xmlSecByte* params, DWORD paramsLen,
    const xmlSecByte** ppP, DWORD* pPLen,
    const xmlSecByte** ppG, DWORD* pGLen,
    const xmlSecByte** ppQ, DWORD* pQLen)
{
    const xmlSecByte* end = params + paramsLen;
    const xmlSecByte* seq;
    const xmlSecByte* next;
    DWORD seqLen;
    DWORD tlvLen;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(ppP != NULL, -1);
    xmlSecAssert2(pPLen != NULL, -1);
    xmlSecAssert2(ppG != NULL, -1);
    xmlSecAssert2(pGLen != NULL, -1);
    xmlSecAssert2(ppQ != NULL, -1);
    xmlSecAssert2(pQLen != NULL, -1);

    *ppQ = NULL;
    *pQLen = 0;

    seq = xmlSecMSCngDerReadTlv(params, end, 0x30 /* SEQUENCE */, &seqLen);
    if(seq == NULL) {
        xmlSecInternalError("xmlSecMSCngDerReadTlv(SEQUENCE)", NULL);
        return(-1);
    }
    end = seq + seqLen;

    *ppP = xmlSecMSCngDerDecodeInteger(seq, end, pPLen);
    if(*ppP == NULL) {
        xmlSecInternalError("xmlSecMSCngDerDecodeInteger(P)", NULL);
        return(-1);
    }
    next = xmlSecMSCngDerReadTlv(seq, end, 0x02 /* INTEGER */, &tlvLen);
    if(next == NULL) {
        xmlSecInternalError("xmlSecMSCngDerReadTlv(P)", NULL);
        return(-1);
    }
    next += tlvLen;

    *ppG = xmlSecMSCngDerDecodeInteger(next, end, pGLen);
    if(*ppG == NULL) {
        xmlSecInternalError("xmlSecMSCngDerDecodeInteger(G)", NULL);
        return(-1);
    }
    next = xmlSecMSCngDerReadTlv(next, end, 0x02 /* INTEGER */, &tlvLen);
    if(next == NULL) {
        xmlSecInternalError("xmlSecMSCngDerReadTlv(G)", NULL);
        return(-1);
    }
    next += tlvLen;

    if(next < end) {
        *ppQ = xmlSecMSCngDerDecodeInteger(next, end, pQLen);
        if(*ppQ == NULL) {
            xmlSecInternalError("xmlSecMSCngDerDecodeInteger(Q)", NULL);
            return(-1);
        }

        next = xmlSecMSCngDerReadTlv(next, end, 0x02 /* INTEGER */, &tlvLen);
        if(next == NULL) {
            xmlSecInternalError("xmlSecMSCngDerReadTlv(Q)", NULL);
            return(-1);
        }
        next += tlvLen;
    }

    if(next != end) {
        xmlSecInvalidSizeError("DH parameters trailing bytes", (xmlSecSize)0, (xmlSecSize)(end - next), NULL);
        return(-1);
    }
    return(0);
}

/* Copy val (big-endian, possibly shorter than cbKey) right-justified into dest[cbKey] with leading zeros */
int
xmlSecMSCngDhBlobCopy(PUCHAR dest, DWORD cbKey, const xmlSecByte* val, xmlSecSize valLen) {
    xmlSecAssert2(dest != NULL, -1);
    xmlSecAssert2(cbKey > 0, -1);
    xmlSecAssert2(val != NULL, -1);
    xmlSecAssert2(valLen > 0, -1);

    if(valLen > cbKey) {
        xmlSecInvalidSizeMoreThanError("DH parameter size", valLen, (xmlSecSize)cbKey, NULL);
        return(-1);
    }

    if(valLen == cbKey) {
        memcpy(dest, val, cbKey);
    } else {
        xmlSecSize pad = cbKey - valLen;
        memset(dest, 0, pad);
        memcpy(dest + pad, val, valLen);
    }
    return(0);
}

static int
xmlSecMSCngBufferTrimLeadingZeros(xmlSecBufferPtr buffer) {
    const xmlSecByte* data;
    xmlSecSize size;
    xmlSecSize offset = 0;
    int ret;

    xmlSecAssert2(buffer != NULL, -1);

    data = xmlSecBufferGetData(buffer);
    size = xmlSecBufferGetSize(buffer);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    while((offset + 1) < size && data[offset] == 0) {
        ++offset;
    }
    if(offset > 0) {
        ret = xmlSecBufferRemoveHead(buffer, offset);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferRemoveHead", NULL,
                "size=" XMLSEC_SIZE_FMT, offset);
            return(-1);
        }
    }
    return(0);
}

xmlSecKeyDataPtr
xmlSecMSCngKeyDataDhRead(xmlSecKeyDataId id, xmlSecKeyValueDhPtr dhValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    xmlSecBuffer blob;
    int blobInitialized = 0;
    xmlSecByte* blobData;
    xmlSecSize pSize, gSize, publicSize;
    xmlSecSize offset, blobSize;
    DWORD dwBlobSize;
    BCRYPT_DH_KEY_BLOB* dhkey;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecMSCngKeyDataDhId, NULL);
    xmlSecAssert2(dhValue != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(dhValue->p)) != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(dhValue->generator)) != NULL, NULL);
    xmlSecAssert2(xmlSecBufferGetData(&(dhValue->public)) != NULL, NULL);

    /* don't reverse blobs: both XML and CNG use big-endian */
    pSize = xmlSecBufferGetSize(&(dhValue->p));
    gSize = xmlSecBufferGetSize(&(dhValue->generator));
    publicSize = xmlSecBufferGetSize(&(dhValue->public));
    xmlSecAssert2(pSize > 0, NULL);
    xmlSecAssert2(gSize > 0, NULL);
    xmlSecAssert2(publicSize > 0, NULL);
    xmlSecAssert2(gSize <= pSize, NULL);
    xmlSecAssert2(publicSize <= pSize, NULL);

    /* BCrypt DH key blob:
     * BCRYPT_DH_KEY_BLOB header (dwMagic + cbKey)
     * followed by: P[cbKey] + G[cbKey] + Public[cbKey]
     * All values are big-endian; shorter values must be right-justified with leading zeros. */
    offset = sizeof(BCRYPT_DH_KEY_BLOB);
    blobSize = offset + pSize * 3;

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
    memset(xmlSecBufferGetData(&blob), 0, blobSize);

    blobData = xmlSecBufferGetData(&blob);
    dhkey = (BCRYPT_DH_KEY_BLOB*)blobData;
    dhkey->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(pSize, dhkey->cbKey, goto done, NULL);

    /*  P  */
    memcpy(blobData + offset, xmlSecBufferGetData(&(dhValue->p)), pSize);
    offset += pSize;

    /*  G (right-justified with leading zeros for small generators like g=2)  */
    memcpy(blobData + offset + (pSize - gSize), xmlSecBufferGetData(&(dhValue->generator)), gSize);
    offset += pSize;

    /*  Public (right-justified)  */
    memcpy(blobData + offset + (pSize - publicSize), xmlSecBufferGetData(&(dhValue->public)), publicSize);
    offset += pSize;

    /* import the key blob */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DH_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider", NULL, status);
        goto done;
    }

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(blobSize, dwBlobSize, goto done, NULL);
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_DH_PUBLIC_BLOB, &hKey, blobData, dwBlobSize, 0);
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

    if(xmlSecBufferGetSize(&(dhValue->q)) > 0) {
        XMLSEC_SAFE_CAST_SIZE_TO_UINT(xmlSecBufferGetSize(&(dhValue->q)), dwBlobSize, goto done, NULL);
        ret = xmlSecMSCngKeyDataSetDhQ(data, xmlSecBufferGetData(&(dhValue->q)), dwBlobSize);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataSetDhQ", NULL);
            goto done;
        }
    }

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
xmlSecMSCngKeyDataDhPubkeyWrite(BCRYPT_KEY_HANDLE pubkey, xmlSecKeyValueDhPtr dhValue) {
    NTSTATUS status;
    xmlSecBuffer buf;
    int bufInitialized = 0;
    xmlSecByte* bufData;
    DWORD bufLen = 0;
    BCRYPT_DH_KEY_BLOB* dhkey;
    int ret;
    int res = -1;

    /* export public key as DH public blob */
    status = BCryptExportKey(pubkey, NULL, BCRYPT_DH_PUBLIC_BLOB, NULL, 0, &bufLen, 0);
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", NULL,
            status, "bufLen=%lu", bufLen);
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

    status = BCryptExportKey(pubkey, NULL, BCRYPT_DH_PUBLIC_BLOB, bufData, bufLen, &bufLen, 0);
    if ((status != STATUS_SUCCESS) || (bufLen <= 0)) {
        xmlSecMSCngNtError2("BCryptExportKey", NULL, status, "bufLen=%lu", bufLen);
        goto done;
    }

    /* parse blob: header + P[cbKey] + G[cbKey] + Public[cbKey] */
    if (bufLen < sizeof(BCRYPT_DH_KEY_BLOB)) {
        xmlSecMSCngNtError2("BCryptExportKey size check", NULL, STATUS_SUCCESS, "bufLen=%lu", bufLen);
        goto done;
    }
    dhkey = (BCRYPT_DH_KEY_BLOB*)bufData;
    if (dhkey->dwMagic != BCRYPT_DH_PUBLIC_MAGIC) {
        xmlSecNotImplementedError2("Unexpected DH blob magic: 0x%08lX", (unsigned long)dhkey->dwMagic);
        goto done;
    }
    bufData += sizeof(BCRYPT_DH_KEY_BLOB);
    bufLen  -= (DWORD)sizeof(BCRYPT_DH_KEY_BLOB);
    if (bufLen != 3 * dhkey->cbKey) {
        xmlSecMSCngNtError3("BCRYPT_DH_KEY_BLOB size mismatch", NULL, STATUS_SUCCESS, "bufLen=%lu, cbKey=%lu", bufLen, dhkey->cbKey);
        goto done;
    }

    /* don't reverse blobs: both XML and CNG use big-endian */

    /* P */
    ret = xmlSecBufferSetData(&(dhValue->p), bufData, dhkey->cbKey);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(p)", NULL, "cbKey=%lu", dhkey->cbKey);
        goto done;
    }
    bufData += dhkey->cbKey;

    /* G */
    ret = xmlSecBufferSetData(&(dhValue->generator), bufData, dhkey->cbKey);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(generator)", NULL, "cbKey=%lu", dhkey->cbKey);
        goto done;
    }
    ret = xmlSecMSCngBufferTrimLeadingZeros(&(dhValue->generator));
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngBufferTrimLeadingZeros(generator)", NULL);
        goto done;
    }
    bufData += dhkey->cbKey;

    /* Public */
    ret = xmlSecBufferSetData(&(dhValue->public), bufData, dhkey->cbKey);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData(public)", NULL, "cbKey=%lu", dhkey->cbKey);
        goto done;
    }
    ret = xmlSecMSCngBufferTrimLeadingZeros(&(dhValue->public));
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngBufferTrimLeadingZeros(public)", NULL);
        goto done;
    }

    /* Note: Q (dhValue->q) is not present in the BCrypt DH key blob, left empty */

    /* success */
    res = 0;

done:
    if (bufInitialized != 0) {
        xmlSecBufferFinalize(&buf);
    }
    return(res);
}

/**
 * @brief Builds a BCRYPT_DH_PRIVATE_BLOB for an X9.42 DH key and imports it with a placeholder public key.
 * @details Allocates and fills a BCRYPT_DH_PRIVATE_BLOB (P | G | Y | X) from the given DH parameters,
 *          using G as a placeholder for the public value Y, then imports it so BCrypt accepts the blob.
 *          The real Y = G^X mod P is derived later and written into the blob before the final re-import.
 *          The caller owns the returned blob and key handle and must free/destroy them.
 * @param hAlg open DH algorithm provider.
 * @param pP prime P (big-endian).
 * @param pPLen length of P in bytes.
 * @param pG generator G (big-endian).
 * @param pGLen length of G in bytes.
 * @param pX private exponent X (big-endian).
 * @param pXLen length of X in bytes.
 * @param pbPrivBlob receives the allocated blob; caller frees with xmlSecMemCleanse + xmlFree.
 * @param cbPrivBlob receives the blob size in bytes.
 * @param hPrivKey receives the imported (placeholder) key handle; caller destroys with BCryptDestroyKey.
 * @return 0 on success, -1 on failure.
 */
static int
xmlSecMSCngDhBuildPrivBlobAndImport(BCRYPT_ALG_HANDLE hAlg,
    const xmlSecByte* pP, DWORD pPLen,
    const xmlSecByte* pG, DWORD pGLen,
    const xmlSecByte* pX, DWORD pXLen,
    PUCHAR* pbPrivBlob, DWORD* cbPrivBlob, 
    BCRYPT_KEY_HANDLE* hPrivKey
) {
    DWORD cbKey;
    PUCHAR pb = NULL;
    BCRYPT_DH_KEY_BLOB* dhPriv;
    NTSTATUS status;
    int ret;
    int res = -1;

    xmlSecAssert2(hAlg != NULL, -1);
    xmlSecAssert2(pP != NULL, -1);
    xmlSecAssert2(pG != NULL, -1);
    xmlSecAssert2(pX != NULL, -1);
    xmlSecAssert2(pbPrivBlob != NULL, -1);
    xmlSecAssert2(cbPrivBlob != NULL, -1);
    xmlSecAssert2(hPrivKey != NULL, -1);

    /* p is the largest DH value, so its length is used as the key size */
    cbKey = pPLen;
    if(cbKey > ((((DWORD)~0U) - sizeof(BCRYPT_DH_KEY_BLOB)) / 4)) {
        xmlSecInvalidSizeError("DH key size too large",
            (xmlSecSize)cbKey,
            (xmlSecSize)((((DWORD)~0U) - sizeof(BCRYPT_DH_KEY_BLOB)) / 4),
            NULL);
        goto done;
    }

    /* BCRYPT_DH_PRIVATE_BLOB layout: P[cbKey] | G[cbKey] | Public(Y)[cbKey] | Private(X)[cbKey] */
    *cbPrivBlob = sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 4;
    pb = (PUCHAR)xmlMalloc(*cbPrivBlob);
    if(pb == NULL) {
        xmlSecMallocError(*cbPrivBlob, NULL);
        goto done;
    }
    xmlSecMemCleanse(pb, (*cbPrivBlob));

    dhPriv = (BCRYPT_DH_KEY_BLOB*)pb;
    dhPriv->dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
    dhPriv->cbKey = cbKey;

    ret = xmlSecMSCngDhBlobCopy(pb + sizeof(BCRYPT_DH_KEY_BLOB),              cbKey, pP, pPLen); /* P */
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhBlobCopy(P)", NULL);
        goto done;
    }
    ret = xmlSecMSCngDhBlobCopy(pb + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey,      cbKey, pG, pGLen); /* G */
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhBlobCopy(G)", NULL);
        goto done;
    }
    ret = xmlSecMSCngDhBlobCopy(pb + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 2,  cbKey, pG, pGLen); /* Public(Y) = G placeholder */
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhBlobCopy(Y-placeholder)", NULL);
        goto done;
    }
    ret = xmlSecMSCngDhBlobCopy(pb + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 3,  cbKey, pX, pXLen); /* Private(X) */
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhBlobCopy(X)", NULL);
        goto done;
    }

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_DH_PRIVATE_BLOB, hPrivKey, pb, (*cbPrivBlob), 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(DH priv)", NULL, status);
        goto done;
    }

    /* success */
    (*pbPrivBlob) = pb;
    pb = NULL; /* ownership transferred to caller */
    res = 0;

done:
    if(pb != NULL) {
        xmlSecMemCleanse(pb, (*cbPrivBlob));
        xmlFree(pb);
    }
    return(res);
}

/**
 * @brief Derives the DH public value Y = G^X mod P and writes it into the private blob.
 * @details Performs a self-agreement between the (placeholder) private key and a public key whose
 *          Y is set to G, which computes G^X mod P. The result (little-endian from BCrypt) is reversed
 *          to big-endian and written right-aligned into slot 2 (the Y field) of the private blob.
 * @param hAlg open DH algorithm provider.
 * @param hPrivKey imported (placeholder) DH private key handle.
 * @param pbPrivBlob the BCRYPT_DH_PRIVATE_BLOB whose Y field is updated in place.
 * @return 0 on success, -1 on failure.
 */
static int
xmlSecMSCngDhDerivePubKeyY(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hPrivKey, PUCHAR pbPrivBlob) {
    DWORD cbKey;
    BCRYPT_KEY_HANDLE hGPubKey = NULL;
    BCRYPT_SECRET_HANDLE hSelfSecret = NULL;
    BCRYPT_DH_KEY_BLOB* dhGPub;
    DWORD cbGPubBlob;
    DWORD cbY = 0;
    PUCHAR pbY, pbYtmp;
    PUCHAR pbGPubBlob = NULL;
    NTSTATUS status;
    int res = -1;

    xmlSecAssert2(hAlg != NULL, -1);
    xmlSecAssert2(hPrivKey != NULL, -1);
    xmlSecAssert2(pbPrivBlob != NULL, -1);

    cbKey = ((BCRYPT_DH_KEY_BLOB*)pbPrivBlob)->cbKey;
    cbGPubBlob = sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 3;

    /* Build a public key blob (P | G | Y=G) to use as the self-agreement peer */
    pbGPubBlob = (PUCHAR)xmlMalloc(cbGPubBlob);
    if(pbGPubBlob == NULL) {
        xmlSecMallocError(cbGPubBlob, NULL);
        goto done;
    }
    memset(pbGPubBlob, 0, cbGPubBlob);

    /* header */
    dhGPub = (BCRYPT_DH_KEY_BLOB*)pbGPubBlob;
    dhGPub->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
    dhGPub->cbKey = cbKey;
    
    /* P and G same as our key; Y = G (the generator itself) */
    memcpy(pbGPubBlob + sizeof(BCRYPT_DH_KEY_BLOB),              pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB),         cbKey); /* P */
    memcpy(pbGPubBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey,      pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey, cbKey); /* G */
    memcpy(pbGPubBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 2,  pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey, cbKey); /* Y = G */
    
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_DH_PUBLIC_BLOB, &hGPubKey, pbGPubBlob, cbGPubBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(DH G pub)", NULL, status);
        goto done;
    }

    status = BCryptSecretAgreement(hPrivKey, hGPubKey, &hSelfSecret, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSecretAgreement(self Y)", NULL, status);
        goto done;
    }

    /* Get Y = G^X mod P (little-endian from BCrypt) */
    status = BCryptDeriveKey(hSelfSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &cbY, 0);
    if((status != STATUS_SUCCESS) || (cbY == 0)) {
        xmlSecMSCngNtError("BCryptDeriveKey(Y size)", NULL, status);
        goto done;
    }
    cbY = min(cbY, cbKey); /* safety */

    /* derive into Y field of the private blob (right-aligned) */
    pbY = pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 2;
    memset(pbY, 0, cbKey);
    
    pbYtmp = pbY + cbKey - cbY;
    status = BCryptDeriveKey(hSelfSecret, BCRYPT_KDF_RAW_SECRET, NULL, pbYtmp, cbY, &cbY, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptDeriveKey(Y data)", NULL, status);
        goto done;
    }

    /* BCrypt returns little-endian; reverse to big-endian */
    xmlSecMSCngReverseBytes(pbYtmp, cbY);
    
    /* success */
    res = 0;

done:
    if(hSelfSecret != NULL) {
        BCryptDestroySecret(hSelfSecret);
    }
    if(hGPubKey != NULL) {
        BCryptDestroyKey(hGPubKey);
    }
    if(pbGPubBlob != NULL) {
        xmlFree(pbGPubBlob);
    }
    return(res);
}

/**
 * @brief Imports a DH public key handle from the P, G, Y values stored in a private blob.
 * @details Builds a BCRYPT_DH_PUBLIC_BLOB (P | G | Y) by copying slots 0, 1, 2 of the given private
 *          blob (where Y is already correct), then imports it as a standalone public key handle.
 * @param hAlg open DH algorithm provider.
 * @param pbPrivBlob the BCRYPT_DH_PRIVATE_BLOB with a correct Y in slot 2.
 * @param hPubKey receives the imported public key handle; caller destroys with BCryptDestroyKey.
 * @return 0 on success, -1 on failure.
 */
static int
xmlSecMSCngDhImportPubKeyHandle(BCRYPT_ALG_HANDLE hAlg, PUCHAR pbPrivBlob, BCRYPT_KEY_HANDLE* hPubKey) {
    DWORD cbKey;
    DWORD cbPubBlob;
    PUCHAR pbPubBlob = NULL;
    BCRYPT_DH_KEY_BLOB* dhPub;
    NTSTATUS status;
    int res = -1;

    xmlSecAssert2(hAlg != NULL, -1);
    xmlSecAssert2(pbPrivBlob != NULL, -1);
    xmlSecAssert2(hPubKey != NULL, -1);

    cbKey = ((BCRYPT_DH_KEY_BLOB*)pbPrivBlob)->cbKey;
    cbPubBlob = sizeof(BCRYPT_DH_KEY_BLOB) + cbKey * 3;

    pbPubBlob = (PUCHAR)xmlMalloc(cbPubBlob);
    if(pbPubBlob == NULL) {
        xmlSecMallocError(cbPubBlob, NULL);
        goto done;
    }
    memset(pbPubBlob, 0, cbPubBlob);
    
    
    /* header */
    dhPub = (BCRYPT_DH_KEY_BLOB*)pbPubBlob;
    dhPub->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
    dhPub->cbKey = cbKey;

    /* copy P, G, Y (slots 0, 1, 2) from the private blob — Y is now correct */
    memcpy(pbPubBlob + sizeof(BCRYPT_DH_KEY_BLOB), pbPrivBlob + sizeof(BCRYPT_DH_KEY_BLOB), cbKey * 3);

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_DH_PUBLIC_BLOB, hPubKey, pbPubBlob, cbPubBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(DH pub)", NULL, status);
        goto done;
    }

    res = 0;

done:
    if(pbPubBlob != NULL) {
        xmlFree(pbPubBlob);
    }
    return(res);
}

/**
 * @brief Loads an X9.42 DH private key (and derives public key) from a PKCS8 DER blob.
 * @param derData DER-encoded PKCS8 PrivateKeyInfo for an X9.42 DH key.
 * @param derDataLen length of @p derData.
 *
 * Windows CNG does not support PKCS12 loading of X9.42 DH keys, so DER is used.
 *
 * @return new key data or NULL on failure.
 */
xmlSecKeyDataPtr
xmlSecMSCngKeyDataDhReadFromPkcs8Der(const xmlSecByte* derData, DWORD derDataLen) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    CRYPT_PRIVATE_KEY_INFO* pki = NULL;
    DWORD pkiLen = 0;
    const xmlSecByte* pP = NULL;
    DWORD pPLen = 0;
    const xmlSecByte* pG = NULL;
    DWORD pGLen = 0;
    const xmlSecByte* pQ = NULL;
    DWORD pQLen = 0;
    const xmlSecByte* pX = NULL;
    DWORD pXLen = 0;
    PUCHAR pbPrivBlob = NULL;
    DWORD cbPrivBlob = 0;
    const xmlSecByte* inner;
    DWORD innerLen;
    BCRYPT_KEY_HANDLE hPrivKey = NULL;
    BCRYPT_KEY_HANDLE hPubKey = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    int ret;

    xmlSecAssert2(derData != NULL, NULL);
    xmlSecAssert2(derDataLen > 0, NULL);

    /* Decode PKCS8 PrivateKeyInfo */
    if(!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            derData, derDataLen,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL, &pki, &pkiLen)
    ) {
        xmlSecMSCngLastError("CryptDecodeObjectEx(PKCS8)", NULL);
        goto done;
    }
    if(pki == NULL) {
        xmlSecInternalError("CryptDecodeObjectEx returned NULL", NULL);
        goto done;
    }
    /* Validate OID — must be X9.42 DH */
    if(pki->Algorithm.pszObjId == NULL || strcmp(pki->Algorithm.pszObjId, szOID_X942_DH) != 0) {
        /* Not a DH key — silently fail so caller can try other formats */
        goto done;
    }
    if(pki->Algorithm.Parameters.cbData == 0 || pki->Algorithm.Parameters.pbData == NULL) {
        xmlSecInternalError("DH PKCS8: missing AlgorithmIdentifier.Parameters", NULL);
        goto done;
    }

    /* Parse P and G from AlgorithmIdentifier.Parameters */
    ret = xmlSecMSCngDhParseDhParameters(
        pki->Algorithm.Parameters.pbData, pki->Algorithm.Parameters.cbData,
        &pP, &pPLen,
        &pG, &pGLen,
        &pQ, &pQLen
    );
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngDhParseDhParameters", NULL);
        goto done;
    }

    /* Parse X from PrivateKey (inner OCTET STRING contains a DER INTEGER X) */
    inner = pki->PrivateKey.pbData;
    innerLen = pki->PrivateKey.cbData;
    if((innerLen == 0) || (inner == NULL)) {
        xmlSecInternalError("DH PKCS8: missing private key payload", NULL);
        goto done;
    }

    pX = xmlSecMSCngDerDecodeInteger(inner, inner + innerLen, &pXLen);
    if(pX == NULL) {
        xmlSecInternalError("DH PKCS8: failed to parse private key INTEGER X", NULL);
        goto done;
    }
   
    /* Open DH algorithm provider (shared by all steps below) */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DH_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider(DH)", NULL, status);
        goto done;
    }

    /* Build the BCRYPT_DH_PRIVATE_BLOB (Y=G placeholder) and import the private key */
    ret = xmlSecMSCngDhBuildPrivBlobAndImport(
        hAlg,
        pP, pPLen,
        pG, pGLen,
        pX, pXLen,
        &pbPrivBlob, &cbPrivBlob,
        &hPrivKey
    );
    if(ret < 0) {
        goto done;
    }

    /* Derive the real Y = G^X mod P and write it into the blob's Y field */
    ret = xmlSecMSCngDhDerivePubKeyY(hAlg, hPrivKey, pbPrivBlob);
    if(ret < 0) {
        goto done;
    }

    /* Destroy the placeholder private key handle; re-import with correct Y */
    BCryptDestroyKey(hPrivKey);
    hPrivKey = NULL;
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_DH_PRIVATE_BLOB, &hPrivKey, pbPrivBlob, cbPrivBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(DH priv with Y)", NULL, status);
        goto done;
    }

    /* Import the public key handle from the P, G, Y values in the private blob */
    ret = xmlSecMSCngDhImportPubKeyHandle(hAlg, pbPrivBlob, &hPubKey);
    if(ret < 0) {
        goto done;
    }

    /* Assemble key data */
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
    hPubKey = NULL; /* owned by data */

    ret = xmlSecMSCngKeyDataAdoptBCryptPrivKey(data, hPrivKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptBCryptPrivKey", NULL);
        goto done;
    }
    hPrivKey = NULL; /* owned by data */

    ret = xmlSecMSCngKeyDataSetDhQ(data, pQ, pQLen);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataSetDhQ", NULL);
        goto done;
    }

    res = data;
    data = NULL;

done:
    if(hPrivKey != NULL) {
        BCryptDestroyKey(hPrivKey);
    }
    if(hPubKey != NULL) {
        BCryptDestroyKey(hPubKey);
    }
    if(hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if(pbPrivBlob != NULL) {
        xmlSecMemCleanse(pbPrivBlob, cbPrivBlob);
        xmlFree(pbPrivBlob);
    }
    if(pki != NULL) {
        LocalFree(pki);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

#endif /* XMLSEC_NO_DH */
