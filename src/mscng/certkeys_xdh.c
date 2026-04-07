/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_certkeys
 * @brief XDH (X25519) key support functions for Microsoft Cryptography API: Next Generation (CNG).
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

#ifndef XMLSEC_NO_XDH

/**
 * @brief Imports an X25519 public key into a BCrypt handle.
 * @details Imports a raw 32-byte Curve25519 u-coordinate as a BCrypt X25519 public key handle.
 * @param pubKeyBytes pointer to 32-byte X25519 public key (u-coordinate, little-endian).
 * @param pubKeyLen must be 32.
 * @return BCrypt key handle on success, or 0 on failure.
 */
BCRYPT_KEY_HANDLE
xmlSecMSCngKeyDataXdhImportPublicKey(const xmlSecByte* pubKeyBytes, DWORD pubKeyLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_ECCKEY_BLOB* pBlob;
    PUCHAR pbBlob = NULL;
    DWORD cbBlob;
    NTSTATUS status;

    xmlSecAssert2(pubKeyBytes != NULL, 0);
    xmlSecAssert2(pubKeyLen == 32, 0);

    /* Allocate BCRYPT_ECCKEY_BLOB header + u-coord (32) + v-coord (32) = 72 bytes.
     * BCrypt X25519 public blobs use the 2*cbKey layout (u, v) matching BCryptExportKey output.
     * The v-coordinate is unused for Montgomery curves and stays zero. */
    cbBlob = sizeof(BCRYPT_ECCKEY_BLOB) + 64;   /* header + u(32) + v(32) */
    pbBlob = (PUCHAR)xmlMalloc(cbBlob);
    if(pbBlob == NULL) {
        xmlSecMallocError(cbBlob, NULL);
        goto done;
    }
    memset(pbBlob, 0, cbBlob);

    pBlob = (BCRYPT_ECCKEY_BLOB*)pbBlob;
    pBlob->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
    pBlob->cbKey = 32;
    /* BCRYPT_ECCPUBLIC_BLOB stores the u-coordinate in the same byte order as the
     * standard X25519 wire format (little-endian per RFC 7748/8410).  Copy as-is. */
    memcpy(pbBlob + sizeof(BCRYPT_ECCKEY_BLOB), pubKeyBytes, 32); /* u-coord at offset 8; v stays zero */

    /* Open ECDH algorithm provider and set Curve25519 */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider(X25519 pub)", NULL, status);
        goto done;
    }
    status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME,
        (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSetProperty(BCRYPT_ECC_CURVE_NAME, curve25519)", NULL, status);
        goto done;
    }

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey, pbBlob, cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(X25519 pub)", NULL, status);
        hKey = NULL;
        goto done;
    }

done:
    if(hAlg != NULL) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if(pbBlob != NULL) {
        xmlFree(pbBlob);
    }
    return(hKey);
}

/**
 * @brief Duplicates a BCrypt X25519 private key.
 * @details Duplicates a BCrypt Curve25519 private key by export and re-import.
 * @param src source BCrypt X25519 private key handle.
 * @param dst destination pointer; receives the duplicated key handle on success.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeyDataDuplicateBCryptXdhPrivKey(BCRYPT_KEY_HANDLE src, BCRYPT_KEY_HANDLE* dst) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    DWORD cbPrivBlob = 0;
    PUCHAR pbPrivBlob = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    xmlSecAssert2(src != NULL, -1);
    xmlSecAssert2(dst != NULL, -1);

    /* export X25519 private key blob */
    status = BCryptExportKey(src, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &cbPrivBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(X25519 priv, size)", NULL, status);
        return(-1);
    }
    pbPrivBlob = (PUCHAR)xmlMalloc(cbPrivBlob);
    if(pbPrivBlob == NULL) {
        xmlSecMallocError(cbPrivBlob, NULL);
        return(-1);
    }
    status = BCryptExportKey(src, NULL, BCRYPT_ECCPRIVATE_BLOB, pbPrivBlob, cbPrivBlob, &cbPrivBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptExportKey(X25519 priv, data)", NULL, status);
        xmlFree(pbPrivBlob);
        return(-1);
    }

    /* Open ECDH provider with Curve25519 and re-import */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider(X25519 priv dup)", NULL, status);
        xmlFree(pbPrivBlob);
        return(-1);
    }
    status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME,
        (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSetProperty(curve25519 priv dup)", NULL, status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        xmlFree(pbPrivBlob);
        return(-1);
    }

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB, &hKey, pbPrivBlob, cbPrivBlob, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    xmlFree(pbPrivBlob);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(X25519 priv dup)", NULL, status);
        return(-1);
    }
    *dst = hKey;
    return(0);
}

/**
 * @brief Loads an X25519 private key from a PKCS8 DER blob.
 * @details Loads an X25519 private key (and derives the public key) from a PKCS8 DER blob.
 * @param derData DER-encoded PKCS8 OneAsymmetricKey for an X25519 key (RFC 8410).
 * @param derDataLen length of @p derData.
 * @return new key data on success, or NULL on failure.
 */
xmlSecKeyDataPtr
xmlSecMSCngKeyDataXdhReadFromPkcs8Der(const xmlSecByte* derData, DWORD derDataLen) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    CRYPT_PRIVATE_KEY_INFO* pki = NULL;
    DWORD pkiLen = 0;
    const xmlSecByte* pScalar = NULL;   /* raw 32-byte private scalar */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hPrivKeyTemp = NULL;
    BCRYPT_KEY_HANDLE hPrivKey = NULL;
    BCRYPT_KEY_HANDLE hPubKey = NULL;
    PUCHAR pbPrivBlob = NULL;
    DWORD cbPrivBlob = 0;
    xmlSecByte pubKeyU[32];             /* derived public key u-coordinate (LE) */
    NTSTATUS status;
    int ret;

    xmlSecAssert2(derData != NULL, NULL);
    xmlSecAssert2(derDataLen > 0, NULL);

    /* Decode PKCS8 PrivateKeyInfo */
    if(!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            derData, derDataLen,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL, &pki, &pkiLen)) {
        /* silently fail so callers can try other formats */
        goto done;
    }
    if(pki == NULL) {
        goto done;
    }
    /* Must be X25519 OID "1.3.101.110" */
    if(pki->Algorithm.pszObjId == NULL || strcmp(pki->Algorithm.pszObjId, szOID_X25519) != 0) {
        goto done;  /* not an X25519 key – silent fail */
    }

    /* PrivateKey field (RFC 8410): outer OCTET STRING wraps inner CurvePrivateKey ::= OCTET STRING */
    if(pki->PrivateKey.cbData < 2 ||
       pki->PrivateKey.pbData == NULL ||
       pki->PrivateKey.pbData[0] != 0x04 /* OCTET STRING */ ||
       pki->PrivateKey.pbData[1] != 32   /* length 32 */ ||
       pki->PrivateKey.cbData < 34) {
        xmlSecInternalError("X25519 PKCS8: malformed or non-32-byte CurvePrivateKey", NULL);
        goto done;
    }
    pScalar = pki->PrivateKey.pbData + 2;  /* 32-byte little-endian private scalar */

    /* Build BCRYPT_ECCPRIVATE_BLOB: header (8) + u-coord (32) + v-coord (32) + private scalar (32) = 104 bytes.
     * BCrypt X25519 private blobs always use the 3*cbKey layout (u, v, d) even though X25519 is a
     * Montgomery curve and v is unused (kept as zero).  The correct public key u-coordinate is
     * derived and filled in before the final re-import; BCRYPT_NO_KEY_VALIDATION lets BCrypt accept
     * any placeholder public key for the temporary first import. */
    cbPrivBlob = sizeof(BCRYPT_ECCKEY_BLOB) + 96;   /* header + u(32) + v(32) + d(32) */
    pbPrivBlob = (PUCHAR)xmlMalloc(cbPrivBlob);
    if(pbPrivBlob == NULL) {
        xmlSecMallocError(cbPrivBlob, NULL);
        goto done;
    }
    memset(pbPrivBlob, 0, cbPrivBlob);
    {
        BCRYPT_ECCKEY_BLOB* pHdr = (BCRYPT_ECCKEY_BLOB*)pbPrivBlob;
        pHdr->dwMagic = BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
        pHdr->cbKey = 32;
    }
    pbPrivBlob[sizeof(BCRYPT_ECCKEY_BLOB)] = 0x09; /* base point u=9 (LE) as placeholder for u-coord */
    /* v-coord (offset 40) stays zero (unused for Montgomery curve) */
    memcpy(pbPrivBlob + sizeof(BCRYPT_ECCKEY_BLOB) + 64, pScalar, 32); /* private scalar d at offset 72 */

    /* Open ECDH algorithm provider with Curve25519 */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider(X25519 PKCS8)", NULL, status);
        goto done;
    }
    status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME,
        (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptSetProperty(curve25519 PKCS8)", NULL, status);
        goto done;
    }

    /* Import private key with zeroed public key; skip public key validation so
     * BCrypt accepts the blob even though public[32] is all-zeros.
     * On Windows 10 1709+ BCRYPT_NO_KEY_VALIDATION is supported for ECDH curves. */
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB, &hPrivKeyTemp,
        pbPrivBlob, cbPrivBlob, BCRYPT_NO_KEY_VALIDATION);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(X25519 priv PKCS8, no-validate)", NULL, status);
        goto done;
    }

    /* Derive the public key u = X25519(d, 9) by performing a self-agreement with the
     * Curve25519 base point (u=9 in little-endian: first byte 0x09, rest 0x00). */
    {
        BCRYPT_KEY_HANDLE hBasePoint = NULL;
        BCRYPT_SECRET_HANDLE hSelfSecret = NULL;
        xmlSecByte basePointBlob[sizeof(BCRYPT_ECCKEY_BLOB) + 64]; /* header + u(32) + v(32) */
        DWORD cbDerived = 0;

        memset(basePointBlob, 0, sizeof(basePointBlob));
        {
            BCRYPT_ECCKEY_BLOB* pHdr = (BCRYPT_ECCKEY_BLOB*)basePointBlob;
            pHdr->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
            pHdr->cbKey = 32;
        }
        basePointBlob[sizeof(BCRYPT_ECCKEY_BLOB)] = 0x09;  /* base point u = 9 (little-endian); v stays zero */

        status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hBasePoint,
            (PUCHAR)basePointBlob, sizeof(basePointBlob), 0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptImportKeyPair(X25519 base point)", NULL, status);
            goto done;
        }

        status = BCryptSecretAgreement(hPrivKeyTemp, hBasePoint, &hSelfSecret, 0);
        BCryptDestroyKey(hBasePoint);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptSecretAgreement(X25519 self u)", NULL, status);
            goto done;
        }

        /* BCryptDeriveKey with BCRYPT_KDF_RAW_SECRET gives us X25519(d, 9) = u in LE. */
        status = BCryptDeriveKey(hSelfSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &cbDerived, 0);
        if((status != STATUS_SUCCESS) || (cbDerived == 0)) {
            BCryptDestroySecret(hSelfSecret);
            xmlSecMSCngNtError("BCryptDeriveKey(X25519 u size)", NULL, status);
            goto done;
        }
        if(cbDerived > 32) { cbDerived = 32; }  /* safety guard */
        memset(pubKeyU, 0, sizeof(pubKeyU));
        status = BCryptDeriveKey(hSelfSecret, BCRYPT_KDF_RAW_SECRET, NULL,
            pubKeyU + (32 - cbDerived), cbDerived, &cbDerived, 0);
        BCryptDestroySecret(hSelfSecret);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptDeriveKey(X25519 u data)", NULL, status);
            goto done;
        }
        /* BCrypt returns Curve25519 scalar result in little-endian (LE). For the key
         * blob the public u-coordinate is also LE, so no reversal needed here. */
    }

    /* Destroy the temp key (had wrong public key) and re-import with correct public key */
    BCryptDestroyKey(hPrivKeyTemp);
    hPrivKeyTemp = NULL;

    /* Write the correct public key u-coordinate into the blob.
     * BCryptDeriveKey(BCRYPT_KDF_RAW_SECRET) returns u in little-endian but
     * BCRYPT_ECCPRIVATE_BLOB expects the u-coordinate in big-endian.  Reverse. */
    xmlSecMSCngReverseCopy(pbPrivBlob + sizeof(BCRYPT_ECCKEY_BLOB), pubKeyU, 32);

    /* Re-import with the correct public key */
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB, &hPrivKey,
        pbPrivBlob, cbPrivBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(X25519 priv PKCS8, final)", NULL, status);
        goto done;
    }

    /* Import public key handle by round-tripping through BCrypt's own ECCPUBLIC_BLOB.
     * Deriving the public key ourselves and crafting an ECCPUBLIC_BLOB is fragile
     * (byte-order, canonicity constraints).  Instead export the public portion from
     * the successfully imported hPrivKey — BCrypt guarantees the exported blob is valid
     * and can be re-imported without any transformation. */
    {
        PUCHAR pbPubBlob = NULL;
        DWORD cbPubBlob = 0;

        status = BCryptExportKey(hPrivKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cbPubBlob, 0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptExportKey(X25519 pub from priv, size)", NULL, status);
            goto done;
        }
        pbPubBlob = (PUCHAR)xmlMalloc(cbPubBlob);
        if(pbPubBlob == NULL) {
            xmlSecMallocError(cbPubBlob, NULL);
            goto done;
        }
        status = BCryptExportKey(hPrivKey, NULL, BCRYPT_ECCPUBLIC_BLOB, pbPubBlob, cbPubBlob, &cbPubBlob, 0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptExportKey(X25519 pub from priv, data)", NULL, status);
            xmlFree(pbPubBlob);
            goto done;
        }
        status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hPubKey, pbPubBlob, cbPubBlob, 0);
        xmlFree(pbPubBlob);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptImportKeyPair(X25519 pub from priv)", NULL, status);
            goto done;
        }
    }

    /* Assemble XDH key data */
    data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataXdhId);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(XdhId)", NULL);
        goto done;
    }
    ret = xmlSecMSCngKeyDataAdoptKey(data, hPubKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptKey(X25519 pub)", NULL);
        goto done;
    }
    hPubKey = NULL; /* owned by data */

    ret = xmlSecMSCngKeyDataAdoptBCryptPrivKey(data, hPrivKey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataAdoptBCryptPrivKey(X25519 priv)", NULL);
        goto done;
    }
    hPrivKey = NULL; /* owned by data */

    res = data;
    data = NULL;

done:
    if(hPrivKeyTemp != NULL) {
        BCryptDestroyKey(hPrivKeyTemp);
    }
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

int
xmlSecMSCngKeyDataCertGetXdhPubkey(PCERT_PUBLIC_KEY_INFO spki, BCRYPT_KEY_HANDLE* key) {
    const xmlSecByte* pKeyBytes;
    DWORD keyBytesLen;

    xmlSecAssert2(spki != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    if((spki->PublicKey.cbData == 0) || (spki->PublicKey.pbData == NULL)) {
        xmlSecInternalError("X25519 SPKI: PublicKey empty", NULL);
        return(-1);
    }

    pKeyBytes   = spki->PublicKey.pbData;
    keyBytesLen = spki->PublicKey.cbData;

    /* CertCreateCertificateContext may or may not include the DER BIT STRING
     * unused-bits prefix byte (0x00).  Skip it when present. */
    if((keyBytesLen > 32) && (pKeyBytes[0] == 0x00)) {
        pKeyBytes++;
        keyBytesLen--;
    }
    if(keyBytesLen != 32) {
        xmlSecInternalError2("X25519 SPKI: PublicKey wrong size", NULL,
            "size=%u", (unsigned)keyBytesLen);
        return(-1);
    }

    *key = xmlSecMSCngKeyDataXdhImportPublicKey(pKeyBytes, 32);
    if(*key == NULL) {
        xmlSecInternalError("xmlSecMSCngKeyDataXdhImportPublicKey", NULL);
        return(-1);
    }
    return(0);
}

#endif /* XMLSEC_NO_XDH */
