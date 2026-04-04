/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscrypto_app
 * @brief Application support functions for MSCrypto.
 * @details Common functions for the xmlsec1 command-line utility for MSCrypto.
 */
#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/private.h>

#include <xmlsec/mscrypto/app.h>
#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/certkeys.h>
#include <xmlsec/mscrypto/keysstore.h>
#include <xmlsec/mscrypto/x509.h>

#include "../cast_helpers.h"
#include "private.h"

#ifndef PKCS12_NO_PERSIST_KEY
/* Windows Server 2003:  This value is not supported. */
#  define PKCS12_NO_PERSIST_KEY    0x00008000
#endif

/* I don't see any other way than to use a global var to get the
 * config info to the mscrypto keysstore :(  WK
 */
static LPTSTR gXmlSecMSCryptoAppCertStoreName = NULL;

/**
 * @brief Initializes the MSCrypto crypto engine.
 * @details General crypto engine initialization. This function is used
 * by the XMLSec command-line utility and is called before the
 * #xmlSecInit function.
 *
 * @param config the name of a certificate store other than the default Microsoft certificate store.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppInit(const char* config) {
    /* initialize MSCrypto crypto engine */

    /* The config parameter can contain *another* MS cert store name
     * than the default (MY).
     */
    if (NULL != config && strlen(config) > 0) {
        if (gXmlSecMSCryptoAppCertStoreName != NULL) {
            /* This should not happen, initialize twice */
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_CONFIG, NULL,
                              "config=%s, config already set",
                              xmlSecErrorsSafeString(config));
            return (-1);
        }

        gXmlSecMSCryptoAppCertStoreName = xmlSecWin32ConvertUtf8ToTstr((const xmlChar *)config);
        if (gXmlSecMSCryptoAppCertStoreName == NULL) {
            xmlSecInternalError2("xmlSecWin32ConvertUtf8ToTstr", NULL,
                                 "config=%s", xmlSecErrorsSafeString(config));
            return (-1);
        }
    }

    return(0);
}

/**
 * @brief Shuts down the MSCrypto crypto engine.
 * @details General crypto engine shutdown. This function is used
 * by the XMLSec command-line utility and is called after the
 * #xmlSecShutdown function.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppShutdown(void) {
    /* shutdown MSCrypto crypto engine */
    if (NULL != gXmlSecMSCryptoAppCertStoreName) {
        xmlFree(gXmlSecMSCryptoAppCertStoreName);
        gXmlSecMSCryptoAppCertStoreName = NULL;
    }
    return(0);
}

/**
 * @brief Gets the MSCrypto certs store name.
 * @details Gets the MS Crypto certs store name set by #xmlSecMSCryptoAppInit function.
 *
 * @return the MS Crypto certs name used by xmlsec-mscrypto.
 */
LPCTSTR
xmlSecMSCryptoAppGetCertStoreName(void) {
    return(gXmlSecMSCryptoAppCertStoreName);
}

/******************************************************************************
 * Keys
  *****************************************************************************/

/**
 * @brief Reads a key from a file.
 * @param filename the key filename.
 * @param type the expected key type.
 * @param format the key file format.
 * @param pwd the key file password.
 * @param pwdCallback the key password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCryptoAppKeyLoadEx(const char *filename, xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED, xmlSecKeyDataFormat format,
    const char *pwd, void* pwdCallback, void* pwdCallbackCtx
) {
    xmlSecBuffer buffer;
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    UNREFERENCED_PARAMETER(type);

    switch (format) {
    case xmlSecKeyDataFormatPkcs12:
        key = xmlSecMSCryptoAppPkcs12Load(filename, pwd, pwdCallback, pwdCallbackCtx);
        if(key == NULL) {
            xmlSecInternalError("xmlSecMSCryptoAppPkcs12Load", NULL);
            return(NULL);
        }
        break;
    case xmlSecKeyDataFormatCertDer:
        ret = xmlSecBufferInitialize(&buffer, 0);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferInitialize", NULL);
            return(NULL);
        }

        ret = xmlSecBufferReadFile(&buffer, filename);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferReadFile", NULL,
                                 "filename=%s", xmlSecErrorsSafeString(filename));
            xmlSecBufferFinalize(&buffer);
            return (NULL);
        }

        key = xmlSecMSCryptoAppKeyLoadMemory(xmlSecBufferGetData(&buffer),
                                        xmlSecBufferGetSize(&buffer), format,
                                        pwd, pwdCallback, pwdCallbackCtx);
        if(key == NULL) {
            xmlSecInternalError("xmlSecMSCryptoAppKeyLoadMemory", NULL);
            xmlSecBufferFinalize(&buffer);
            return(NULL);
        }
        xmlSecBufferFinalize(&buffer);
        break;
    default:
        /* Any other format like PEM keys is currently not supported */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        return(NULL);
    }

    return(key);
}

/**
 * @brief Reads a key from the binary @p data.
 * @param data the key binary data.
 * @param dataSize the key data size.
 * @param format the key format.
 * @param pwd the key password.
 * @param pwdCallback the key password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCryptoAppKeyLoadMemory(const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format,
                               const char *pwd, void* pwdCallback, void* pwdCallbackCtx) {
    PCCERT_CONTEXT pCert = NULL;
    PCCERT_CONTEXT tmpcert = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr res = NULL;
    DWORD dwDataSize;
    int ret;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);
    xmlSecAssert2(format == xmlSecKeyDataFormatCertDer, NULL);
    UNREFERENCED_PARAMETER(pwd);
    UNREFERENCED_PARAMETER(pwdCallback);
    UNREFERENCED_PARAMETER(pwdCallbackCtx);

    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(dataSize, dwDataSize, goto done, NULL);
    pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, data, dwDataSize);
    if (NULL == pCert) {
        xmlSecMSCryptoError("CertCreateCertificateContext", NULL);
        goto done;
    }

    x509Data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataX509Id)", NULL);
        goto done;
    }

    tmpcert = CertDuplicateCertificateContext(pCert);
    if(tmpcert == NULL) {
        xmlSecMSCryptoError("CertDuplicateCertificateContext",
                            xmlSecKeyDataGetName(x509Data));
        goto done;
    }

    ret = xmlSecMSCryptoKeyDataX509AdoptKeyCert(x509Data, tmpcert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptKeyCert",
                            xmlSecKeyDataGetName(x509Data));
        CertFreeCertificateContext(tmpcert);
        goto done;
    }
    tmpcert = NULL;

    keyData = xmlSecMSCryptoCertAdopt(pCert, xmlSecKeyDataTypePublic);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecMSCryptoCertAdopt",
                            xmlSecKeyDataGetName(x509Data));
        goto done;
    }
    pCert = NULL;

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate",
                            xmlSecKeyDataGetName(x509Data));
        goto done;
    }

    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(x509Data));
        goto done;
    }
    keyData = NULL;

    ret = xmlSecKeyAdoptData(key, x509Data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData",
                            xmlSecKeyDataGetName(x509Data));
        goto done;
    }
    x509Data = NULL;

    /* success */
    res = key;
    key = NULL;
done:
    if(pCert != NULL) {
        CertFreeCertificateContext(pCert);
    }
    if(tmpcert != NULL) {
        CertFreeCertificateContext(tmpcert);
    }
    if(x509Data != NULL) {
        xmlSecKeyDataDestroy(x509Data);
    }
    if(keyData != NULL) {
        xmlSecKeyDataDestroy(keyData);
    }
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    return(res);
}


/******************************************************************************
 * X509 certificates
  *****************************************************************************/

#ifndef XMLSEC_NO_X509

/**
 * @brief Reads the certificate from a file and adds to key.
 * @details Reads the certificate from @p filename and adds it to key.
 *
 * @param key the pointer to key.
 * @param filename the certificate filename.
 * @param format the certificate file format.
 * @return 0 on success or a negative value otherwise.
 */

int
xmlSecMSCryptoAppKeyCertLoad(xmlSecKeyPtr key, const char* filename,
                             xmlSecKeyDataFormat format) {
    xmlSecBuffer buffer;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(-1);
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return (-1);
    }

    ret = xmlSecMSCryptoAppKeyCertLoadMemory(key, xmlSecBufferGetData(&buffer),
                    xmlSecBufferGetSize(&buffer), format);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoAppKeyCertLoadMemory", NULL);
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    xmlSecBufferFinalize(&buffer);
    return(0);
}

/**
 * @brief Reads the certificate from memory and adds to key.
 * @details Reads the certificate from @p data and adds it to key.
 *
 * @param key the pointer to key.
 * @param data the binary certificate.
 * @param dataSize size of certificate binary (data)
 * @param format the certificate file format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppKeyCertLoadMemory(xmlSecKeyPtr key, const xmlSecByte* data, xmlSecSize dataSize,
                                   xmlSecKeyDataFormat format) {
    PCCERT_CONTEXT pCert, pKeyCert;
    xmlSecKeyDataPtr kdata;
    DWORD dwDataSize;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    kdata = xmlSecKeyEnsureData(key, xmlSecMSCryptoKeyDataX509Id);
    if(kdata == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData(xmlSecMSCryptoKeyDataX509Id)", NULL);
        return(-1);
    }

    /* For now only DER certificates are supported */
    /* adjust cert format */
    switch(format) {
    case xmlSecKeyDataFormatDer:
    case xmlSecKeyDataFormatCertDer:
        XMLSEC_SAFE_CAST_SIZE_TO_ULONG(dataSize, dwDataSize, return(-1), NULL);

        /* read cert and make a copy for key cert */
        pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, data, dwDataSize);
        if (NULL == pCert) {
            xmlSecInternalError2("CertCreateCertificateContext", xmlSecKeyDataGetName(kdata),
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            return(-1);
        }
        pKeyCert = CertDuplicateCertificateContext(pCert);
        if(pKeyCert == NULL) {
            xmlSecMSCryptoError("CertDuplicateCertificateContext", xmlSecKeyDataGetName(kdata));
            CertFreeCertificateContext(pCert);
            return(-1);
        }

        /* add cert and key cert */
        ret = xmlSecMSCryptoKeyDataX509AdoptCert(kdata, pCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCert", xmlSecKeyDataGetName(kdata));
            CertFreeCertificateContext(pCert);
            CertFreeCertificateContext(pKeyCert);
            return(-1);
        }
        pCert = NULL; /* owned by kdata */

        ret = xmlSecMSCryptoKeyDataX509AdoptKeyCert(kdata, pKeyCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptKeyCert", xmlSecKeyDataGetName(kdata));
            CertFreeCertificateContext(pKeyCert);
            return(-1);
        }
        pKeyCert = NULL; /* owned by kdata */

        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, xmlSecKeyDataGetName(kdata),
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        return(-1);
    }

    return(0);
}

/**
 * @brief Reads key and certificates from PKCS12 file.
 * @details Reads a key and all associated certificates from the PKCS12 file.
 *
 * @param filename the PKCS12 key filename.
 * @param pwd the PKCS12 file password.
 * @param pwdCallback the password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCryptoAppPkcs12Load(const char *filename,
                            const char *pwd,
                            void* pwdCallback XMLSEC_ATTRIBUTE_UNUSED,
                            void* pwdCallbackCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecBuffer buffer;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(pwd != NULL, NULL);

    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(NULL);
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return (NULL);
    }
    if(xmlSecBufferGetData(&buffer) == NULL) {
        xmlSecInvalidDataError("data buffer is empty", NULL);
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    key = xmlSecMSCryptoAppPkcs12LoadMemory(xmlSecBufferGetData(&buffer),
                                            xmlSecBufferGetSize(&buffer), pwd,
                                            pwdCallback, pwdCallbackCtx);
    if (key == NULL) {
        xmlSecInternalError("xmlSecMSCryptoAppPkcs12LoadMemory", NULL);
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    xmlSecBufferFinalize(&buffer);
    return(key);
}

/**
 * @brief Reads key and certificates from PKCS12 binary.
 * @details Reads a key and all associated certificates from the PKCS12 binary.
 *
 * @param data the binary PKCS12 key in data.
 * @param dataSize size of binary pkcs12 data
 * @param pwd the PKCS12 file password.
 * @param pwdCallback the password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCryptoAppPkcs12LoadMemory(const xmlSecByte* data,
                                  xmlSecSize dataSize,
                                  const char *pwd,
                                  void* pwdCallback XMLSEC_ATTRIBUTE_UNUSED,
                                  void* pwdCallbackCtx XMLSEC_ATTRIBUTE_UNUSED) {
    CRYPT_DATA_BLOB pfx;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT tmpcert = NULL;
    PCCERT_CONTEXT pCert = NULL;
    WCHAR* wcPwd = NULL;
    DWORD dwFlags;
    xmlSecKeyDataPtr x509Data = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlSecKeyPtr key = NULL;
    int ret;
    DWORD dwData = 0;
    DWORD dwDataLen;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 1, NULL);
    xmlSecAssert2(pwd != NULL, NULL);
    UNREFERENCED_PARAMETER(pwdCallback);
    UNREFERENCED_PARAMETER(pwdCallbackCtx);

    memset(&pfx, 0, sizeof(pfx));
    pfx.pbData = (BYTE *)data;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(dataSize, pfx.cbData, return(NULL), NULL);

    if(FALSE == PFXIsPFXBlob(&pfx)) {
        xmlSecMSCryptoError2("PFXIsPFXBlob", NULL, "size=%lu", pfx.cbData);
        goto done;
    }

    wcPwd = xmlSecWin32ConvertLocaleToUnicode(pwd);
    if (wcPwd == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertLocaleToUnicode(pw)", NULL);
        goto done;
    }

    if (FALSE == PFXVerifyPassword(&pfx, wcPwd, 0)) {
        xmlSecMSCryptoError("PFXVerifyPassword", NULL);
        goto done;
    }

    dwFlags = CRYPT_EXPORTABLE;
    if (!xmlSecImportGetPersistKey()) {
        dwFlags |= PKCS12_NO_PERSIST_KEY;
    }
    hCertStore = PFXImportCertStore(&pfx, wcPwd, dwFlags);
    if (NULL == hCertStore) {
        xmlSecMSCryptoError("PFXImportCertStore", NULL);
        goto done;
    }

    x509Data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataX509Id)", NULL);
        goto done;
    }

    while (1) {
        pCert = CertEnumCertificatesInStore(hCertStore, pCert);
        if(pCert == NULL) {
            break;
        }

        dwDataLen = sizeof(dwData);
        dwData = 0;
        /* Find the certificate that has the private key */
        if((TRUE == CertGetCertificateContextProperty(pCert, CERT_KEY_SPEC_PROP_ID, &dwData, &dwDataLen)) && (dwData > 0)) {
            tmpcert = CertDuplicateCertificateContext(pCert);
            if(tmpcert == NULL) {
                xmlSecMSCryptoError("CertDuplicateCertificateContext",
                                    xmlSecKeyDataGetName(x509Data));
                goto done;
            }

            keyData = xmlSecMSCryptoCertAdopt(tmpcert, xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
            if(keyData == NULL) {
                xmlSecInternalError("xmlSecMSCryptoCertAdopt",
                                    xmlSecKeyDataGetName(x509Data));
                goto done;
            }
            tmpcert = NULL;

            tmpcert = CertDuplicateCertificateContext(pCert);
            if(tmpcert == NULL) {
                xmlSecMSCryptoError("CertDuplicateCertificateContext",
                                    xmlSecKeyDataGetName(x509Data));
                goto done;
            }

            ret = xmlSecMSCryptoKeyDataX509AdoptKeyCert(x509Data, tmpcert);
            if(ret < 0) {
                xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptKeyCert",
                                    xmlSecKeyDataGetName(x509Data));
                goto done;
            }
            tmpcert = NULL;
        }

        /* load certificate in the x509 key data */
        tmpcert = CertDuplicateCertificateContext(pCert);
        if(tmpcert == NULL) {
            xmlSecMSCryptoError("CertDuplicateCertificateContext",
                xmlSecKeyDataGetName(x509Data));
            goto done;
        }

        ret = xmlSecMSCryptoKeyDataX509AdoptCert(x509Data, tmpcert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCert",
                xmlSecKeyDataGetName(x509Data));
            goto done;
        }
        tmpcert = NULL;
    }

    if (keyData == NULL) {
        /* private key not found in PKCS12 file */
        xmlSecInternalError2("xmlSecMSCryptoAppPkcs12Load", xmlSecKeyDataGetName(x509Data),
            "private key not found in PKCS12 file, size = %lu", pfx.cbData);
        goto done;
    }

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", xmlSecKeyDataGetName(x509Data));
        goto done;
    }

    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataGetName(x509Data));
        xmlSecKeyDestroy(key);
        key = NULL;
        goto done;
    }
    keyData = NULL;

    ret = xmlSecKeyAdoptData(key, x509Data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData", xmlSecKeyDataGetName(x509Data));
        xmlSecKeyDestroy(key);
        key = NULL;
        goto done;
    }
    x509Data = NULL;

done:
    if(hCertStore != NULL) {
        CertCloseStore(hCertStore, 0);
    }
    if(wcPwd != NULL) {
        xmlFree(wcPwd);
    }
    if(x509Data != NULL) {
        xmlSecKeyDataDestroy(x509Data);
    }
    if(keyData != NULL) {
        xmlSecKeyDataDestroy(keyData);
    }
    if(pCert != NULL) {
        CertFreeCertificateContext(pCert);
    }
    if(tmpcert != NULL) {
        CertFreeCertificateContext(tmpcert);
    }
    return(key);
}

/**
 * @brief Reads a cert from a file and adds to the key store.
 * @details Reads cert from @p filename and adds to the list of trusted or known
 * untrusted certs in @p store.
 *
 * @param mngr the keys manager.
 * @param filename the certificate file.
 * @param format the certificate file format.
 * @param type the flag that indicates is the certificate in @p filename
 *                      trusted or not.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename,
                                xmlSecKeyDataFormat format,
                                xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecBuffer buffer;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(-1);
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return (-1);
    }

    ret = xmlSecMSCryptoAppKeysMngrCertLoadMemory(mngr, xmlSecBufferGetData(&buffer),
        xmlSecBufferGetSize(&buffer), format, type);
    if (ret < 0) {
        xmlSecInternalError2("xmlSecMSCryptoAppKeysMngrCertLoadMemory", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    xmlSecBufferFinalize(&buffer);
    return(ret);
}

/**
 * @brief Reads cert from buffer and adds to the key store.
 * @details Reads cert from @p data and adds to the list of trusted or known
 * untrusted certs in @p store.
 *
 * @param mngr the keys manager.
 * @param data the binary certificate.
 * @param dataSize size of binary certificate (data)
 * @param format the certificate file format.
 * @param type the flag that indicates is the certificate in @p filename
 *                      trusted or not.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte* data,
                                        xmlSecSize dataSize, xmlSecKeyDataFormat format,
                                        xmlSecKeyDataType type) {
    xmlSecKeyDataStorePtr x509Store;
    PCCERT_CONTEXT pCert = NULL;
    DWORD dwDataSize;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecMSCryptoX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecMSCryptoX509StoreId)", NULL);
        return(-1);
    }

    switch (format) {
        case xmlSecKeyDataFormatDer:
        case xmlSecKeyDataFormatCertDer:
            XMLSEC_SAFE_CAST_SIZE_TO_ULONG(dataSize, dwDataSize, return(-1), NULL);
            pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, data, dwDataSize);
            if (NULL == pCert) {
                xmlSecMSCryptoError("CertCreateCertificateContext", NULL);
                return (-1);
            }
            break;
        default:
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            return(-1);
    }

    xmlSecAssert2(pCert != NULL, -1);
    ret = xmlSecMSCryptoX509StoreAdoptCert(x509Store, pCert, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoX509StoreAdoptCert", NULL);
        CertFreeCertificateContext(pCert);
        return(-1);
    }

    return(0);
}

/**
 * @brief Reads CRLs from a file and adds to the store.
 * @details Reads crl from @p filename and adds to the list of crls in @p store.
 *
 * @param mngr the keys manager.
 * @param filename the CRL file.
 * @param format the CRL file format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppKeysMngrCrlLoad(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataFormat format) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    xmlSecNotImplementedError("MSCrypto doesn't support loading X509 CRLs at runtime");
    return(-1);
}

/**
 * @brief Loads and verifies a CRL from a file.
 * @details Atomically loads and verifies a CRL from @p filename.
 *
 * @param mngr the keys manager.
 * @param filename the CRL filename.
 * @param format the CRL format (PEM or DER).
 * @param keyInfoCtx the key info context for verification parameters.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppKeysMngrCrlLoadAndVerify(xmlSecKeysMngrPtr mngr, const char *filename,
    xmlSecKeyDataFormat format, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError("MSCrypto doesn't support loading X509 CRLs at runtime");
    return(-1);
}

/**
 * @brief Reads CRLs from memory and adds to the store.
 * @details Reads crl from @p data and adds to the list of crls in @p store.
 *
 * @param mngr the keys manager.
 * @param data the binary CRL.
 * @param dataSize size of binary CRL (data)
 * @param format the CRL format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppKeysMngrCrlLoadMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    xmlSecNotImplementedError("MSCrypto doesn't support loading X509 CRLs at runtime");
    return(-1);
}

/**
 * @brief Adds @p keyStore to the keys manager.
 * @details Adds @p keyStore to the list of key stores in the keys manager @p mngr.
 *
 * @param mngr the keys manager.
 * @param keyStore the pointer to keys store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrAdoptKeyStore(xmlSecKeysMngrPtr mngr, HCERTSTORE keyStore)
{
        xmlSecKeyDataStorePtr x509Store ;

        xmlSecAssert2( mngr != NULL, -1 ) ;
        xmlSecAssert2( keyStore != NULL, -1 ) ;

    x509Store = xmlSecKeysMngrGetDataStore( mngr, xmlSecMSCryptoX509StoreId) ;
        if( x509Store == NULL ) {
            xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecMSCryptoX509StoreId)", NULL);
            return(-1) ;
        }

        if( xmlSecMSCryptoX509StoreAdoptKeyStore( x509Store, keyStore ) < 0 ) {
            xmlSecInternalError("xmlSecMSCryptoX509StoreAdoptKeyStore",
                                xmlSecKeyDataStoreGetName(x509Store));
            return(-1) ;
        }

        return (0) ;
}

/**
 * @brief Adds @p trustedStore to the trusted cert stores.
 * @details Adds @p trustedStore to the list of trusted cert stores in the keys manager @p mngr.
 *
 * @param mngr the keys manager.
 * @param trustedStore the pointer to certs store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrAdoptTrustedStore(xmlSecKeysMngrPtr mngr, HCERTSTORE trustedStore)
{
        xmlSecKeyDataStorePtr x509Store ;

        xmlSecAssert2( mngr != NULL, -1 ) ;
        xmlSecAssert2( trustedStore != NULL, -1 ) ;

    x509Store = xmlSecKeysMngrGetDataStore( mngr, xmlSecMSCryptoX509StoreId ) ;
        if( x509Store == NULL ) {
            xmlSecInternalError("xmlSecKeysMngrGetDataStore", NULL);
            return(-1) ;
        }

        if( xmlSecMSCryptoX509StoreAdoptTrustedStore( x509Store, trustedStore ) < 0 ) {
            xmlSecInternalError("xmlSecMSCryptoX509StoreAdoptKeyStore",
                                xmlSecKeyDataStoreGetName(x509Store));
            return(-1) ;
        }

        return(0);
}

/**
 * @brief Adds @p untrustedStore to the untrusted cert stores.
 * @details Adds @p untrustedStore to the list of un-trusted cert stores in the keys manager @p mngr.
 *
 * @param mngr the keys manager.
 * @param untrustedStore the pointer to certs store.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrAdoptUntrustedStore(xmlSecKeysMngrPtr mngr, HCERTSTORE untrustedStore)
{
        xmlSecKeyDataStorePtr x509Store ;

        xmlSecAssert2( mngr != NULL, -1 ) ;
        xmlSecAssert2( untrustedStore != NULL, -1 ) ;

    x509Store = xmlSecKeysMngrGetDataStore( mngr, xmlSecMSCryptoX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore", NULL);
        return(-1);
    }

    if(xmlSecMSCryptoX509StoreAdoptUntrustedStore(x509Store, untrustedStore) < 0) {
        xmlSecInternalError("xmlSecMSCryptoX509StoreAdoptKeyStore",
                            xmlSecKeyDataStoreGetName(x509Store));
        return(-1);
    }

    return(0) ;
}

#endif /* XMLSEC_NO_X509 */

/**
 * @brief Initializes the default key manager for MSCrypto.
 * @details Initializes @p mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default MSCrypto crypto key data stores.
 *
 * @param mngr the pointer to keys manager.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

    /* create MSCrypto keys store if needed */
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
        xmlSecKeyStorePtr keysStore;

        keysStore = xmlSecKeyStoreCreate(xmlSecMSCryptoKeysStoreId);
        if(keysStore == NULL) {
            xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecMSCryptoX509StoreId)", NULL);
            return(-1);
        }

        ret = xmlSecKeysMngrAdoptKeysStore(mngr, keysStore);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeysMngrAdoptKeysStore", NULL);
            xmlSecKeyStoreDestroy(keysStore);
            return(-1);
        }
    }

    ret = xmlSecMSCryptoKeysMngrInit(mngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeysMngrInit", NULL);
        return(-1);
    }

    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * @brief Adds @p key to the keys manager.
 * @details Adds @p key to the keys manager @p mngr created with #xmlSecMSCryptoAppDefaultKeysMngrInit
 * function.
 *
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecMSCryptoKeysStoreAdoptKey(store, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeysStoreAdoptKey", NULL);
        return(-1);
    }

    return(0);
}


/**
 * @brief Verifies @p key using the keys manager.
 * @details Verifies @p key with the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Adds @p key to the keys manager @p mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 *
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @param keyInfoCtx the key info context for verification.
 * @return 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrVerifyKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError("MSCrypto doesn't support key verification while loading key into keys manager");
    return(-1);
}


/**
 * @brief Loads the XML keys file into the keys manager.
 * @details Loads XML keys file from @p uri to the keys manager @p mngr created
 * with #xmlSecMSCryptoAppDefaultKeysMngrInit function.
 *
 * @param mngr the pointer to keys manager.
 * @param uri the uri.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecMSCryptoKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecMSCryptoKeysStoreLoad", NULL,
                             "uri=%s", xmlSecErrorsSafeString(uri));
        return(-1);
    }

    return(0);
}

/**
 * @brief Saves keys from @p mngr to XML keys file.
 * @param mngr the pointer to keys manager.
 * @param filename the destination filename.
 * @param type the type of keys to save (public/private/symmetric).
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecMSCryptoKeysStoreSave(store, filename, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecMSCryptoKeysStoreSave", NULL, "filename=%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}

/**
 * @brief Adds private key @p hKey to the keys manager.
 * @details Adds private key @p hKey to the keys manager @p mngr.
 *
 * @param mngr the pointer to keys manager.
 * @param hKey the key handle.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrPrivateKeyLoad(xmlSecKeysMngrPtr mngr, HCRYPTKEY hKey) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(hKey != 0, -1);

    xmlSecNotImplementedError("MSCrypto doesn't support loading private keys at runtime");
    return(0);
}

/**
 * @brief Adds public key @p hKey to the keys manager.
 * @details Adds public key @p hKey to the keys manager @p mngr.
 *
 * @param mngr the pointer to keys manager.
 * @param hKey the key handle.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrPublicKeyLoad(xmlSecKeysMngrPtr mngr, HCRYPTKEY hKey) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(hKey != 0, -1);

    xmlSecNotImplementedError("MSCrypto doesn't support loading public keys at runtime");
    return(0);
}

/**
 * @brief Adds symmetric key @p hKey to the keys manager.
 * @details Adds symmetric key @p hKey to the keys manager @p mngr.
 *
 * @param mngr the pointer to keys manager.
 * @param hKey the key handle.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecMSCryptoAppDefaultKeysMngrSymKeyLoad(xmlSecKeysMngrPtr mngr, HCRYPTKEY hKey) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(hKey != 0, -1);

    xmlSecNotImplementedError("MSCrypto doesn't support loading symmetric keys at runtime");
    return(0);
}

/**
 * @brief Gets default password callback.
 *
 * @return default password callback.
 */
void*
xmlSecMSCryptoAppGetDefaultPwdCallback(void) {
    /* TODO: MSCrypto doesn't support password callback */
    return(NULL);
}
