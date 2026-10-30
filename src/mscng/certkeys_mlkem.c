/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_certkeys
 * @brief ML-KEM (FIPS 203) key support functions for Microsoft Cryptography API: Next Generation (CNG).
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

#ifndef XMLSEC_NO_MLKEM

/* Returns the CNG ML-KEM parameter set name for the given raw public key
 * size, or NULL if the size does not match a known ML-KEM parameter set. */
static const WCHAR*
xmlSecMSCngMlKemGetParamsetByPkSize(xmlSecSize pkSize) {
    switch(pkSize) {
    case XMLSEC_MSCNG_MLKEM_512_PK_SIZE:
        return(L"512");
    case XMLSEC_MSCNG_MLKEM_768_PK_SIZE:
        return(L"768");
    case XMLSEC_MSCNG_MLKEM_1024_PK_SIZE:
        return(L"1024");
    default:
        return(NULL);
    }
}

/* Returns the CNG ML-KEM parameter set name for the given secret key
 * size, or NULL if the size does not match a known ML-KEM parameter set. */
static const WCHAR*
xmlSecMSCngMlKemGetParamsetBySkSize(xmlSecSize skSize) {
    switch(skSize) {
    case XMLSEC_MSCNG_MLKEM_512_SK_SIZE:
        return(L"512");
    case XMLSEC_MSCNG_MLKEM_768_SK_SIZE:
        return(L"768");
    case XMLSEC_MSCNG_MLKEM_1024_SK_SIZE:
        return(L"1024");
    default:
        return(NULL);
    }
}

/* Reads a DER length at @pBuf (up to @pLen bytes); on success sets @pValue
 * and returns the number of bytes consumed (1..5), or 0 on error. */
static DWORD
xmlSecMSCngReadDerLength(const xmlSecByte* pBuf, DWORD len, DWORD* pValue) {
    DWORD v;
    DWORD n;
    DWORD i;

    if((pBuf == NULL) || (pValue == NULL) || (len < 1)) {
        return(0);
    }
    v = pBuf[0];
    if(v < 0x80) {
        (*pValue) = v;
        return(1);
    }
    n = v & 0x7F;
    if((n < 1) || (n > 4) || (n + 1 > len)) {
        return(0);
    }
    v = 0;
    for(i = 0; i < n; i++) {
        v = (v << 8) | pBuf[1 + i];
    }
    (*pValue) = v;
    return(n + 1);
}

/* Builds a CNG ML-KEM key blob: DWORD dwMagic, DWORD cbParameterSet,
 * DWORD cbKey, WCHAR parameterSet[], BYTE key[] (all fields little-endian;
 * parameterSet is \0-terminated). The layout was verified against the CNG
 * ML-KEM provider on Windows build 26300.
 * (https://learn.microsoft.com/en-us/windows/win32/seccng/cng-mlkem-examples)
 * Returns the allocated blob (size in @pCbBlobOut) or NULL on failure; the
 * caller frees it with xmlFree(). */
static PUCHAR
xmlSecMSCngMlKemBuildBlob(DWORD dwMagic, const WCHAR* pszParamset,
    const xmlSecByte* pKey, xmlSecSize keySize, DWORD* pCbBlobOut) {
    DWORD dwCbParamset;
    DWORD dwCbKey;
    DWORD cbBlob;
    PUCHAR pbBlob;

    xmlSecAssert2(pszParamset != NULL, NULL);
    xmlSecAssert2(pKey != NULL, NULL);
    xmlSecAssert2(pCbBlobOut != NULL, NULL);

    (*pCbBlobOut) = 0;

    dwCbParamset = (DWORD)((wcslen(pszParamset) + 1) * sizeof(WCHAR));
    dwCbKey = (DWORD)keySize;
    cbBlob = (DWORD)(12 + dwCbParamset + dwCbKey);
    pbBlob = (PUCHAR)xmlMalloc(cbBlob);
    if(pbBlob == NULL) {
        xmlSecMallocError(cbBlob, NULL);
        return(NULL);
    }
    memcpy(pbBlob, &dwMagic, sizeof(dwMagic));
    memcpy(pbBlob + 4, &dwCbParamset, sizeof(dwCbParamset));
    memcpy(pbBlob + 8, &dwCbKey, sizeof(dwCbKey));
    memcpy(pbBlob + 12, pszParamset, dwCbParamset);
    memcpy(pbBlob + 12 + dwCbParamset, pKey, dwCbKey);
    (*pCbBlobOut) = cbBlob;
    return(pbBlob);
}

/**
 * @brief Imports an ML-KEM public key into a BCrypt handle.
 * @details Builds a CNG ML-KEM public key blob (BCRYPT_MLKEM_PUBLIC_MAGIC)
 *          from the raw public key bytes and imports it via
 *          BCryptImportKeyPair with the BCRYPT_MLKEM_ALG_HANDLE.
 * @param pubKeyBytes pointer to the raw ML-KEM public key.
 * @param pubKeyLen size of the public key; must be 800 (ML-KEM-512),
 *          1184 (ML-KEM-768) or 1568 (ML-KEM-1024) bytes.
 * @return BCrypt key handle on success, or 0 on failure.
 */
BCRYPT_KEY_HANDLE
xmlSecMSCngKeyDataMlKemImportPublicKey(const xmlSecByte* pubKeyBytes, DWORD pubKeyLen) {
    const WCHAR* pszParamset;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PUCHAR pbBlob = NULL;
    DWORD cbBlob = 0;
    NTSTATUS status;

    xmlSecAssert2(pubKeyBytes != NULL, 0);

    pszParamset = xmlSecMSCngMlKemGetParamsetByPkSize(pubKeyLen);
    if(pszParamset == NULL) {
        xmlSecInvalidSizeDataError("ML-KEM public key size", pubKeyLen, "800, 1184 or 1568 bytes", NULL);
        goto done;
    }

    pbBlob = xmlSecMSCngMlKemBuildBlob(BCRYPT_MLKEM_PUBLIC_MAGIC, pszParamset, pubKeyBytes, pubKeyLen, &cbBlob);
    if(pbBlob == NULL) {
        goto done;
    }

    status = BCryptImportKeyPair(BCRYPT_MLKEM_ALG_HANDLE, NULL, BCRYPT_MLKEM_PUBLIC_BLOB, &hKey, pbBlob, cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(ML-KEM pub)", NULL, status);
        goto done;
    }

done:
    if(pbBlob != NULL) {
        xmlFree(pbBlob);
    }
    return(hKey);
}

/**
 * @brief Imports an ML-KEM private (secret) key into a BCrypt handle.
 * @details Builds a CNG ML-KEM private key blob (BCRYPT_MLKEM_PRIVATE_MAGIC)
 *          from the raw secret key bytes and imports it via
 *          BCryptImportKeyPair with the BCRYPT_MLKEM_ALG_HANDLE. The
 *          resulting handle can be used for decapsulation and to export the
 *          public key.
 * @param privKeyBytes pointer to the raw ML-KEM secret key.
 * @param privKeyLen size of the secret key; must be 1632 (ML-KEM-512),
 *          2400 (ML-KEM-768) or 3168 (ML-KEM-1024) bytes.
 * @return BCrypt key handle on success, or 0 on failure.
 */
BCRYPT_KEY_HANDLE
xmlSecMSCngKeyDataMlKemImportPrivateKey(const xmlSecByte* privKeyBytes, DWORD privKeyLen) {
    const WCHAR* pszParamset;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PUCHAR pbBlob = NULL;
    DWORD cbBlob = 0;
    NTSTATUS status;

    xmlSecAssert2(privKeyBytes != NULL, 0);

    pszParamset = xmlSecMSCngMlKemGetParamsetBySkSize(privKeyLen);
    if(pszParamset == NULL) {
        xmlSecInvalidSizeDataError("ML-KEM secret key size", privKeyLen,
            "1632, 2400 or 3168 bytes", NULL);
        goto done;
    }

    pbBlob = xmlSecMSCngMlKemBuildBlob(BCRYPT_MLKEM_PRIVATE_MAGIC, pszParamset, privKeyBytes, privKeyLen, &cbBlob);
    if(pbBlob == NULL) {
        goto done;
    }

    status = BCryptImportKeyPair(BCRYPT_MLKEM_ALG_HANDLE, NULL, BCRYPT_MLKEM_PRIVATE_BLOB, &hKey, pbBlob, cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(ML-KEM priv)", NULL, status);
        goto done;
    }

done:
    if(pbBlob != NULL) {
        xmlSecMemCleanse(pbBlob, cbBlob);
        xmlFree(pbBlob);
    }
    return(hKey);
}

/**
 * @brief Duplicates a BCrypt ML-KEM public key.
 * @details Duplicates a BCrypt ML-KEM public key by export and re-import.
 *          The ML-KEM provider does not support the generic
 *          BCRYPT_PUBLIC_KEY_BLOB format, so the ML-KEM-specific
 *          BCRYPT_MLKEM_PUBLIC_BLOB format must be used.
 * @param src source BCrypt ML-KEM public key handle.
 * @param dst destination pointer; receives the duplicated key handle on success.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeyDataDuplicateMlKemPubKey(BCRYPT_KEY_HANDLE src, BCRYPT_KEY_HANDLE* dst) {
    PUCHAR pbBlob = NULL;
    DWORD cbBlob = 0;
    NTSTATUS status;
    int res = -1;

    xmlSecAssert2(src != NULL, -1);
    xmlSecAssert2(dst != NULL, -1);

    (*dst) = NULL;

    /* export the key */
    status = BCryptExportKey(src, NULL, BCRYPT_MLKEM_PUBLIC_BLOB, NULL, 0, &cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(ML-KEM pub dup, size)", NULL, status);
        goto done;
    }
    pbBlob = (PUCHAR)xmlMalloc(cbBlob);
    if(pbBlob == NULL) {
        xmlSecMallocError(cbBlob, NULL);
        goto done;
    }
    status = BCryptExportKey(src, NULL, BCRYPT_MLKEM_PUBLIC_BLOB, pbBlob, cbBlob, &cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(ML-KEM pub dup, data)", NULL, status);
        goto done;
    }

    /* import the key */
    status = BCryptImportKeyPair(BCRYPT_MLKEM_ALG_HANDLE, NULL, BCRYPT_MLKEM_PUBLIC_BLOB, dst, pbBlob, cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(ML-KEM pub dup)", NULL, status);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(pbBlob != NULL) {
        xmlSecMemCleanse(pbBlob, cbBlob);
        xmlFree(pbBlob);
    }

    return(res);
}

/**
 * @brief Duplicates a BCrypt ML-KEM private key.
 * @details Duplicates a BCrypt ML-KEM private key by export and re-import.
 *          The ML-KEM provider does not support the generic
 *          BCRYPT_PRIVATE_KEY_BLOB format, so the ML-KEM-specific
 *          BCRYPT_MLKEM_PRIVATE_BLOB format must be used.
 * @param src source BCrypt ML-KEM private key handle.
 * @param dst destination pointer; receives the duplicated key handle on success.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeyDataDuplicateMlKemPrivKey(BCRYPT_KEY_HANDLE src, BCRYPT_KEY_HANDLE* dst) {
    PUCHAR pbBlob = NULL;
    DWORD cbBlob = 0;
    DWORD cbBlobAlloc = 0;
    NTSTATUS status;
    int res = -1;

    xmlSecAssert2(src != NULL, -1);
    xmlSecAssert2(dst != NULL, -1);

    (*dst) = NULL;

    /* export the private key */
    status = BCryptExportKey(src, NULL, BCRYPT_MLKEM_PRIVATE_BLOB, NULL, 0, &cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(ML-KEM priv dup, size)", NULL, status);
        goto done;
    }
    pbBlob = (PUCHAR)xmlMalloc(cbBlob);
    if(pbBlob == NULL) {
        xmlSecMallocError(cbBlob, NULL);
        goto done;
    }
    cbBlobAlloc = cbBlob;

    status = BCryptExportKey(src, NULL, BCRYPT_MLKEM_PRIVATE_BLOB, pbBlob, cbBlobAlloc, &cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(ML-KEM priv dup, data)", NULL, status);
        goto done;
    }

    /* import the private key */
    status = BCryptImportKeyPair(BCRYPT_MLKEM_ALG_HANDLE, NULL, BCRYPT_MLKEM_PRIVATE_BLOB, dst, pbBlob, cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(ML-KEM priv dup)", NULL, status);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(pbBlob != NULL) {
        xmlSecMemCleanse(pbBlob, cbBlobAlloc);
        xmlFree(pbBlob);
    }
    return(res);
}

/**
 * @brief Imports an ML-KEM public key from a SubjectPublicKeyInfo.
 * @details CryptImportPublicKeyInfoEx2 does not support the ML-KEM OIDs, so
 *          the raw public key bytes from the SubjectPublicKey field are used
 *          to build a CNG ML-KEM public key blob and imported via
 *          BCryptImportKeyPair.
 *
 * @param spki SubjectPublicKeyInfo of the certificate.
 * @param key receives the imported BCRYPT key handle on success.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeyDataCertGetMlKemPubkey(PCERT_PUBLIC_KEY_INFO spki, BCRYPT_KEY_HANDLE* key) {
    const xmlSecByte* pkData;
    xmlSecSize pkSize;
    BCRYPT_KEY_HANDLE hKey = NULL;
    int ret = -1;

    xmlSecAssert2(spki != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    (*key) = NULL;

    if(spki->PublicKey.cbData == 0 || spki->PublicKey.pbData == NULL) {
        xmlSecInvalidDataError("ML-KEM SubjectPublicKeyInfo: missing PublicKey field", NULL);
        goto done;
    }

    /* The SubjectPublicKey field carries the raw ML-KEM public key. Some
     * encoders (e.g. OpenSSL) prefix it with a single zero byte; strip one
     * leading zero byte only when the resulting length matches a known
     * ML-KEM parameter set size. */
    pkData = (const xmlSecByte*)spki->PublicKey.pbData;
    pkSize = (xmlSecSize)spki->PublicKey.cbData;
    if((pkSize > 0) && (pkData[0] == 0x00) &&
       (xmlSecMSCngMlKemGetParamsetByPkSize(pkSize) == NULL) &&
       (xmlSecMSCngMlKemGetParamsetByPkSize(pkSize - 1) != NULL)
    ) {
        pkData++;
        pkSize--;
    }

    hKey = xmlSecMSCngKeyDataMlKemImportPublicKey(pkData, (DWORD)pkSize);
    if(hKey == NULL) {
        goto done;
    }

    /* done */
    ret = 0;
    (*key) = hKey;
    hKey = NULL; /* owned by the caller now */

done:
    if(hKey != NULL) {
        BCryptDestroyKey(hKey);
    }
    return(ret);
}

/**
 * @brief Loads an ML-KEM private key from a PKCS8 DER blob.
 * @details Loads an ML-KEM private key (and the corresponding public key)
 *          from a PKCS8 DER blob. The PrivateKey field of the ML-KEM
 *          PrivateKeyInfo is a DER SEQUENCE of two OCTET STRINGs: a
 *          64-byte auxiliary value (unused by CNG) and the full secret key.
 *          The secret key is imported as a CNG private key blob; the public
 *          key is exported from the imported private key and re-imported as
 *          a standalone public key handle.
 * @param derData DER-encoded PKCS8 OneAsymmetricKey for an ML-KEM key.
 * @param derDataLen length of @p derData.
 * @return new key data on success, or NULL on failure.
 */
xmlSecKeyDataPtr
xmlSecMSCngKeyDataMlKemReadFromPkcs8Der(const xmlSecByte* derData, DWORD derDataLen) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    CRYPT_PRIVATE_KEY_INFO* pki = NULL;
    DWORD pkiLen = 0;
    const xmlSecByte* pInner = NULL;
    const xmlSecByte* pPos;
    const xmlSecByte* pSk = NULL;
    DWORD innerLen = 0;
    DWORD seqLen = 0;
    DWORD lenConsumed = 0;
    DWORD firstLen = 0;
    DWORD skLen = 0;
    BCRYPT_KEY_HANDLE hPrivKey = NULL;
    BCRYPT_KEY_HANDLE hPubKey = NULL;
    PUCHAR pbPubBlob = NULL;
    DWORD cbPubBlob = 0;
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
        /* silently fail so callers can try other formats */
        goto done;
    }
    if(pki == NULL || pki->Algorithm.pszObjId == NULL) {
        goto done;
    }
    /* Must be an ML-KEM OID */
    if(strcmp(pki->Algorithm.pszObjId, XMLSEC_MSCNG_OID_MLKEM_512) != 0 &&
       strcmp(pki->Algorithm.pszObjId, XMLSEC_MSCNG_OID_MLKEM_768) != 0 &&
       strcmp(pki->Algorithm.pszObjId, XMLSEC_MSCNG_OID_MLKEM_1024) != 0) {
        goto done;  /* not an ML-KEM key - silent fail */
    }

    /* Parse the PrivateKey field: SEQUENCE { OCTET STRING (64), OCTET STRING (sk) } */
    pInner = pki->PrivateKey.pbData;
    innerLen = pki->PrivateKey.cbData;
    if((pInner == NULL) || (innerLen < 4) || (pInner[0] != 0x30)) {
        xmlSecInternalError("ML-KEM PKCS8: malformed PrivateKey field (expected SEQUENCE)", NULL);
        goto done;
    }
    lenConsumed = xmlSecMSCngReadDerLength(pInner + 1, innerLen - 1, &seqLen);
    if((lenConsumed == 0) || (seqLen != (innerLen - 1 - lenConsumed))) {
        xmlSecInternalError("ML-KEM PKCS8: malformed SEQUENCE length in PrivateKey field", NULL);
        goto done;
    }
    pPos = pInner + 1 + lenConsumed;
    if((pPos + seqLen != pInner + innerLen) || (seqLen < 2)) {
        xmlSecInternalError("ML-KEM PKCS8: SEQUENCE in PrivateKey field is truncated", NULL);
        goto done;
    }

    /* first OCTET STRING: the 64-byte auxiliary value */
    if(*pPos != 0x04) {
        xmlSecInternalError("ML-KEM PKCS8: expected OCTET STRING in PrivateKey field", NULL);
        goto done;
    }
    pPos++;
    lenConsumed = xmlSecMSCngReadDerLength(pPos, (DWORD)(pInner + innerLen - pPos), &firstLen);
    if(lenConsumed == 0) {
        xmlSecInternalError("ML-KEM PKCS8: malformed OCTET STRING length in PrivateKey field", NULL);
        goto done;
    }
    pPos += lenConsumed;
    if(firstLen != XMLSEC_MSCNG_MLKEM_PKCS8_PREFIX_SIZE) {
        xmlSecInvalidSizeDataError("ML-KEM PKCS8 auxiliary value size", firstLen,
            "64 bytes", NULL);
        goto done;
    }
    if((DWORD)(pInner + innerLen - pPos) < firstLen) {
        xmlSecInternalError("ML-KEM PKCS8: PrivateKey field is truncated", NULL);
        goto done;
    }
    pPos += firstLen;

    /* require at least a tag and a length byte to remain, so the tag read below
     * cannot run past the end of the PrivateKey field */
    if((DWORD)(pInner + innerLen - pPos) < 2) {
        xmlSecInternalError("ML-KEM PKCS8: PrivateKey field is truncated", NULL);
        goto done;
    }

    /* second OCTET STRING: the full secret key */
    if(*pPos != 0x04) {
        xmlSecInternalError("ML-KEM PKCS8: expected OCTET STRING for the secret key", NULL);
        goto done;
    }
    pPos++;
    lenConsumed = xmlSecMSCngReadDerLength(pPos, (DWORD)(pInner + innerLen - pPos), &skLen);
    if(lenConsumed == 0) {
        xmlSecInternalError("ML-KEM PKCS8: malformed secret key OCTET STRING length", NULL);
        goto done;
    }
    pPos += lenConsumed;
    if((DWORD)(pInner + innerLen - pPos) != skLen) {
        xmlSecInternalError("ML-KEM PKCS8: unexpected trailing data in PrivateKey field", NULL);
        goto done;
    }
    pSk = pPos;

    /* Import the secret key */
    hPrivKey = xmlSecMSCngKeyDataMlKemImportPrivateKey(pSk, skLen);
    if(hPrivKey == NULL) {
        goto done;
    }

    /* Export the public key from the private key and re-import it as a
     * standalone public key handle. */
    status = BCryptExportKey(hPrivKey, NULL, BCRYPT_MLKEM_PUBLIC_BLOB,
        NULL, 0, &cbPubBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(ML-KEM pub from priv, size)", NULL, status);
        goto done;
    }
    pbPubBlob = (PUCHAR)xmlMalloc(cbPubBlob);
    if(pbPubBlob == NULL) {
        xmlSecMallocError(cbPubBlob, NULL);
        goto done;
    }
    status = BCryptExportKey(hPrivKey, NULL, BCRYPT_MLKEM_PUBLIC_BLOB,
        pbPubBlob, cbPubBlob, &cbPubBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(ML-KEM pub from priv, data)", NULL, status);
        goto done;
    }
    status = BCryptImportKeyPair(BCRYPT_MLKEM_ALG_HANDLE, NULL, BCRYPT_MLKEM_PUBLIC_BLOB, &hPubKey, pbPubBlob, cbPubBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(ML-KEM pub from priv)", NULL, status);
        goto done;
    }

    /* Assemble ML-KEM key data */
    data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataMLKEMId);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(MLKEMId)", NULL);
        goto done;
    }
    ret = xmlSecMSCngKeyDataAdoptKey(data, hPubKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey(ML-KEM pub)", NULL);
        goto done;
    }
    hPubKey = NULL; /* owned by data */

    ret = xmlSecMSCngKeyDataAdoptBCryptPrivKey(data, hPrivKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptBCryptPrivKey(ML-KEM priv)", NULL);
        goto done;
    }
    hPrivKey = NULL; /* owned by data */

    /* success! */
    res = data;
    data = NULL;

done:
    if(hPrivKey != NULL) {
        status = BCryptDestroyKey(hPrivKey);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDestroyKey(ML-KEM priv)", NULL, status);
            /* ignore error */
        }
    }
    if(hPubKey != NULL) {
        status = BCryptDestroyKey(hPubKey);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDestroyKey(ML-KEM pub)", NULL, status);
            /* ignore error */
        }
    }
    if(pbPubBlob != NULL) {
        xmlFree(pbPubBlob);
    }
    if(pki != NULL) {
        /* LocalFree also frees pki->Algorithm.pszObjId: CryptDecodeObjectEx
         * (CRYPT_DECODE_ALLOC_FLAG) allocates it inside the pki block */
        SecureZeroMemory(pki, pkiLen);
        LocalFree(pki);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

#else /* XMLSEC_NO_MLKEM */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_MLKEM */
