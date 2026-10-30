/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_certkeys
 * @brief ML-DSA (FIPS 204) key support functions for Microsoft Cryptography API: Next Generation (CNG).
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

#ifndef XMLSEC_NO_MLDSA

/* Returns the CNG ML-DSA parameter set name for the given raw public key size,
 * or NULL if the size does not match a known ML-DSA parameter set. */
static const WCHAR*
xmlSecMSCngMlDsaGetParamsetName(xmlSecSize pkSize) {
    switch(pkSize) {
    case XMLSEC_MSCNG_MLDSA_44_PK_SIZE:
        return(L"44");
    case XMLSEC_MSCNG_MLDSA_65_PK_SIZE:
        return(L"65");
    case XMLSEC_MSCNG_MLDSA_87_PK_SIZE:
        return(L"87");
    default:
        return(NULL);
    }
}

/**
 * @brief Imports an ML-DSA public key from a SubjectPublicKeyInfo.
 * @details CryptImportPublicKeyInfoEx2 does not support the ML-DSA OIDs, so the
 *          raw public key bytes from the SubjectPublicKey field are used to
 *          build a CNG PQDSA public key blob and imported via BCryptImportKeyPair.
 *          The blob layout (all fields little-endian): DWORD dwMagic
 *          (BCRYPT_PQDSA_PUBLIC_MAGIC), DWORD cbParamSet, DWORD cbKey,
 *          WCHAR pszParamSet[], BYTE pbKey[]; this layout was verified against
 *          the CNG ML-DSA provider on Windows 11 version 26H2 (build 26300).
 *          (https://learn.microsoft.com/en-us/windows/win32/seccng/cng-mldsa-examples)
 *
 * @param spki SubjectPublicKeyInfo of the certificate.
 * @param key receives the imported BCRYPT key handle on success.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeyDataCertGetMlDsaPubkey(PCERT_PUBLIC_KEY_INFO spki, BCRYPT_KEY_HANDLE* key) {
    const xmlSecByte* pkData;
    xmlSecSize pkSize;
    const WCHAR* pszParamset;
    DWORD dwMagic = BCRYPT_PQDSA_PUBLIC_MAGIC;
    DWORD dwCbParamset;
    DWORD dwCbKey;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PUCHAR pbBlob = NULL;
    DWORD cbBlob;
    NTSTATUS status;
    int ret = -1;

    xmlSecAssert2(spki != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    (*key) = NULL;

    if(spki->PublicKey.cbData == 0 || spki->PublicKey.pbData == NULL) {
        xmlSecInvalidDataError("ML-DSA SubjectPublicKeyInfo: missing PublicKey field", NULL);
        goto done;
    }

    /* The SubjectPublicKey field carries the raw ML-DSA public key. Some
     * encoders (e.g. OpenSSL) prefix it with a single zero byte; strip one
     * leading zero byte only when the resulting length matches a known
     * ML-DSA parameter set size. */
    pkData = spki->PublicKey.pbData;
    pkSize = (xmlSecSize)spki->PublicKey.cbData;
    if((pkSize > 0) && (pkData[0] == 0x00) &&
       (xmlSecMSCngMlDsaGetParamsetName(pkSize) == NULL) &&
       (xmlSecMSCngMlDsaGetParamsetName(pkSize - 1) != NULL)
    ) {
        pkData++;
        pkSize--;
    }

    pszParamset = xmlSecMSCngMlDsaGetParamsetName(pkSize);
    if(pszParamset == NULL) {
        xmlSecInvalidSizeDataError("ML-DSA public key size", pkSize,
            "1312, 1952 or 2592 bytes", NULL);
        goto done;
    }

    dwCbParamset = (DWORD)((wcslen(pszParamset) + 1) * sizeof(WCHAR));
    dwCbKey = (DWORD)pkSize;
    cbBlob = (DWORD)(12 + dwCbParamset + dwCbKey);
    pbBlob = (PUCHAR)xmlMalloc(cbBlob);
    if(pbBlob == NULL) {
        xmlSecMallocError(cbBlob, NULL);
        goto done;
    }
    memcpy(pbBlob, &dwMagic, sizeof(dwMagic));
    memcpy(pbBlob + 4, &dwCbParamset, sizeof(dwCbParamset));
    memcpy(pbBlob + 8, &dwCbKey, sizeof(dwCbKey));
    memcpy(pbBlob + 12, pszParamset, dwCbParamset);
    memcpy(pbBlob + 12 + dwCbParamset, pkData, pkSize);

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MLDSA_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptOpenAlgorithmProvider(ML-DSA pub)", NULL, status);
        goto done;
    }

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_PQDSA_PUBLIC_BLOB, &hKey, pbBlob, cbBlob, 0);
    if(status != STATUS_SUCCESS) {
        xmlSecMSCngNtError("BCryptImportKeyPair(ML-DSA pub)", NULL, status);
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
    if(hAlg != NULL) {
        status = BCryptCloseAlgorithmProvider(hAlg, 0);
        if(status != STATUS_SUCCESS) {
            xmlSecMSCngNtError("BCryptCloseAlgorithmProvider", NULL, status);
            /* ignore error */
        }
    }
    if(pbBlob != NULL) {
        xmlFree(pbBlob);
    }
    return(ret);
}

#endif /* XMLSEC_NO_MLDSA */
