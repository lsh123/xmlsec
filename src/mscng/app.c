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
 * SECTION:app
 * @Short_description: Application support functions for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <string.h>

#include <windows.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/mscng/app.h>
#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/symbols.h>
#include <xmlsec/mscng/x509.h>
#include <xmlsec/mscng/certkeys.h>
#include <xmlsec/mscng/keysstore.h>

/* config info for the mscng keysstore */
static LPTSTR gXmlSecMSCngAppCertStoreName = NULL;

/**
 * xmlSecMSCngAppInit:
 * @config:             the path to MSCng configuration (unused).
 *
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before
 * @xmlSecInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppInit(const char* config) {
    /* initialize MSCng crypto engine */

    /* config parameter is an ms cert store name */
    if(config != NULL && strlen(config) > 0) {
        if(gXmlSecMSCngAppCertStoreName != NULL) {
            /* deny double initialization */
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_CONFIG, NULL,
                "config=%s, config already set",
                xmlSecErrorsSafeString(config));
            return(-1);
        }

        gXmlSecMSCngAppCertStoreName = xmlSecWin32ConvertUtf8ToTstr((const xmlChar*)config);
        if(gXmlSecMSCngAppCertStoreName == NULL) {
            xmlSecInternalError2("xmlSecWin32ConvertUtf8ToTstr", NULL,
                "config=%s", xmlSecErrorsSafeString(config));
            return(-1);
        }
    }

    return(0);
}

/**
 * xmlSecMSCngAppShutdown:
 *
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after
 * @xmlSecShutdown function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppShutdown(void) {
    /* shutdown MSCng crypto engine */
    if(gXmlSecMSCngAppCertStoreName != NULL) {
        xmlFree(gXmlSecMSCngAppCertStoreName);
        gXmlSecMSCngAppCertStoreName = NULL;
    }
    return(0);
}

/**
 * xmlSecMSCngAppGetCertStoreName:
 *
 * Gets the MS Cng certs store name set by @xmlSecMSCngAppInit function.
 *
 * Returns: the MS Cng certs name used by xmlsec-mscng.
 */
LPCTSTR
xmlSecMSCngAppGetCertStoreName(void) {
    return(gXmlSecMSCngAppCertStoreName);
}

/**
 * xmlSecMSCngAppKeyLoad:
 * @filename:           the key filename.
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the a file (not implemented yet).
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCngAppKeyLoad(const char *filename, xmlSecKeyDataFormat format,
                      const char *pwd,
                      void* pwdCallback,
                      void* pwdCallbackCtx) {
    xmlSecBuffer buffer;
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    switch(format) {
    case xmlSecKeyDataFormatPkcs12:
        key = xmlSecMSCngAppPkcs12Load(filename, pwd, pwdCallback,
            pwdCallbackCtx);
        if(key == NULL) {
            xmlSecInternalError("xmlSecMSCngAppPkcs12Load", NULL);
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

        key = xmlSecMSCngAppKeyLoadMemory(xmlSecBufferGetData(&buffer),
                                        xmlSecBufferGetSize(&buffer), format,
                                        pwd, pwdCallback, pwdCallbackCtx);
        if(key == NULL) {
            xmlSecInternalError("xmlSecMSCngAppKeyLoadMemory", NULL);
            xmlSecBufferFinalize(&buffer);
            return(NULL);
        }
        xmlSecBufferFinalize(&buffer);
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL, "format=%d",
            (int)format);
        return(NULL);
        break;
    }

    return(key);
}

/**
 * xmlSecMSCngAppKeyLoadMemory:
 * @data:               the key binary data.
 * @dataSize:           the key binary data size.
 * @format:             the key data format.
 * @pwd:                the key data2 password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from a binary @data.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCngAppKeyLoadMemory(const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format,
                            const char *pwd, void* pwdCallback, void* pwdCallbackCtx) {
    PCCERT_CONTEXT pCert = NULL;
    PCCERT_CONTEXT tmpcert = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);
    xmlSecAssert2(format == xmlSecKeyDataFormatCertDer, NULL);
    UNREFERENCED_PARAMETER(pwd);
    UNREFERENCED_PARAMETER(pwdCallback);
    UNREFERENCED_PARAMETER(pwdCallbackCtx);

    pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, data, dataSize);
    if(pCert == NULL) {
        xmlSecMSCngLastError("CertCreateCertificateContext", NULL);
        goto done;
    }

    x509Data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate", NULL);
        goto done;
    }

    tmpcert = CertDuplicateCertificateContext(pCert);
    if(tmpcert == NULL) {
        xmlSecMSCngLastError("CertDuplicateCertificateContext",
            xmlSecKeyDataGetName(x509Data));
        goto done;
    }

    ret = xmlSecMSCngKeyDataX509AdoptKeyCert(x509Data, tmpcert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptKeyCert",
            xmlSecKeyDataGetName(x509Data));
        goto done;
    }
    tmpcert = NULL;

    keyData = xmlSecMSCngCertAdopt(pCert, xmlSecKeyDataTypePublic);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecMSCngCertAdopt",
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


#ifndef XMLSEC_NO_X509
/**
 * xmlSecMSCngAppKeyCertLoad:
 * @key:                the pointer to key.
 * @filename:           the certificate filename.
 * @format:             the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key
 * (not implemented yet).
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppKeyCertLoad(xmlSecKeyPtr key, const char* filename,
                          xmlSecKeyDataFormat format) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO */
    xmlSecNotImplementedError(NULL);
    return(-1);
}

/**
 * xmlSecMSCngAppKeyCertLoadMemory:
 * @key:                the pointer to key.
 * @data:               the certificate binary data.
 * @dataSize:           the certificate binary data size.
 * @format:             the certificate file format.
 *
 * Reads the certificate from memory buffer and adds it to key.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppKeyCertLoadMemory(xmlSecKeyPtr key, const xmlSecByte* data, xmlSecSize dataSize,
                                xmlSecKeyDataFormat format) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO */
    xmlSecNotImplementedError(NULL);
    return(-1);
}

/**
 * xmlSecMSCngAppPkcs12Load:
 * @filename:           the PKCS12 key filename.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file
 * (not implemented yet).
 * For uniformity, call xmlSecMSCngAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCngAppPkcs12Load(const char *filename,
                         const char *pwd,
                         void* pwdCallback,
                         void* pwdCallbackCtx) {
    xmlSecBuffer buffer;
    xmlSecByte* data;
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
        xmlSecInternalError2("xmlSecBufferReadFile", NULL, "filename=%s",
            xmlSecErrorsSafeString(filename));
        return(NULL);
    }

    data = xmlSecBufferGetData(&buffer);
    if(data == NULL) {
        xmlSecInternalError("xmlSecBufferGetData", NULL);
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    key = xmlSecMSCngAppPkcs12LoadMemory(data, xmlSecBufferGetSize(&buffer),
        pwd, pwdCallback, pwdCallbackCtx);
    if(key == NULL) {
        xmlSecInternalError("xmlSecMSCngAppPkcs12LoadMemory", NULL);
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    xmlSecBufferFinalize(&buffer);
    return(key);
}

/**
 * xmlSecMSCngAppPkcs12LoadMemory:
 * @data:               the key binary data.
 * @dataSize:           the key binary data size.
 * @pwd:                the PKCS12 password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 binary data.
 * For uniformity, call xmlSecMSCngAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecMSCngAppPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize, const char *pwd,
                               void *pwdCallback,
                               void* pwdCallbackCtx) {
    UNREFERENCED_PARAMETER(pwdCallback);
    UNREFERENCED_PARAMETER(pwdCallbackCtx);
    CRYPT_DATA_BLOB pfx;
    xmlSecKeyPtr key = NULL;
    WCHAR* pwdWideChar = NULL;
    HCERTSTORE certStore = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlSecKeyDataPtr privKeyData = NULL;
    PCCERT_CONTEXT cert = NULL;
    PCCERT_CONTEXT certDuplicate = NULL;
    int ret;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 1, NULL);
    xmlSecAssert2(pwd != NULL, NULL);

    memset(&pfx, 0, sizeof(pfx));
    pfx.pbData = (BYTE *)data;
    pfx.cbData = dataSize;
    ret = PFXIsPFXBlob(&pfx);
    if(ret == FALSE) {
        xmlSecMSCngLastError("PFXIsPFXBlob", NULL);
        return(NULL);
    }

    pwdWideChar = xmlSecWin32ConvertLocaleToUnicode(pwd);
    if(pwdWideChar == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertLocaleToUnicode", NULL);
        goto cleanup;
    }

    ret = PFXVerifyPassword(&pfx, pwdWideChar, 0);
    if(ret == FALSE) {
        xmlSecMSCngLastError("PFXVerifyPassword", NULL);
        goto cleanup;
    }

    DWORD flags = CRYPT_EXPORTABLE;
    if (!xmlSecImportGetPersistKey()) {
        flags |= PKCS12_NO_PERSIST_KEY;
    }
    certStore = PFXImportCertStore(&pfx, pwdWideChar, flags);
    if(certStore == NULL) {
        xmlSecMSCngLastError("PFXImportCertStore", NULL);
        goto cleanup;
    }

    keyData = xmlSecKeyDataCreate(xmlSecMSCngKeyDataX509Id);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate", NULL);
        goto cleanup;
    }

    /* enumerate over certifiates in the store */
    while((cert = CertEnumCertificatesInStore(certStore, cert)) != NULL) {
        DWORD dwData = 0;
        DWORD dwDataLen = sizeof(DWORD);

        ret = CertGetCertificateContextProperty(cert, CERT_KEY_SPEC_PROP_ID,
            &dwData, &dwDataLen);
        if(ret == TRUE) {
            /* adopt private key */
            certDuplicate = CertDuplicateCertificateContext(cert);
            if(certDuplicate == NULL) {
                xmlSecMSCngLastError("CertDuplicateCertificateContext", NULL);
                goto cleanup;
            }

            privKeyData = xmlSecMSCngCertAdopt(certDuplicate,
                xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
            if(privKeyData == NULL) {
                xmlSecInternalError("xmlSecMSCngCertAdopt", NULL);
                goto cleanup;
            }
            certDuplicate = NULL;
        }

        /* adopt certificate */
        certDuplicate = CertDuplicateCertificateContext(cert);
        if(certDuplicate == NULL) {
            xmlSecMSCngLastError("CertDuplicateCertificateContext", NULL);
            goto cleanup;
        }

        ret = xmlSecMSCngKeyDataX509AdoptCert(keyData, certDuplicate);
        if(ret < 0) {
            xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptKeyCert", NULL);
            goto cleanup;
        }
        certDuplicate = NULL;
    }

    /* at this point we should have a private key */
    if(privKeyData == NULL) {
        xmlSecInternalError2("xmlSecMSCngAppPkcs12LoadMemory",
            xmlSecKeyDataGetName(keyData), "privKeyData is NULL", NULL);
        goto cleanup;
    }

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        goto cleanup;
    }

    ret = xmlSecKeySetValue(key, privKeyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        xmlSecKeyDestroy(key);
        key = NULL;
        goto cleanup;
    }
    privKeyData = NULL;

    ret = xmlSecKeyAdoptData(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData", NULL);
        xmlSecKeyDestroy(key);
        key = NULL;
        goto cleanup;
    }
    keyData = NULL;

cleanup:
    if(certStore != NULL) {
        CertCloseStore(certStore, 0);
    }
    if(pwdWideChar != NULL) {
        xmlFree(pwdWideChar);
    }
    if(keyData != NULL) {
        xmlSecKeyDataDestroy(keyData);
    }
    if(privKeyData != NULL) {
        xmlSecKeyDataDestroy(privKeyData);
    }
    if(certDuplicate != NULL) {
        CertFreeCertificateContext(certDuplicate);
    }
    return(key);
}

/**
 * xmlSecMSCngAppKeysMngrCertLoad:
 * @mngr:               the keys manager.
 * @filename:           the certificate file.
 * @format:             the certificate file format.
 * @type:               the flag that indicates is the certificate in @filename
 *                      trusted or not.
 *
 * Reads cert from @filename and adds to the list of trusted or known
 * untrusted certs in @store (not implemented yet).
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename,
                               xmlSecKeyDataFormat format,
                               xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
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
        return(-1);
    }

    ret = xmlSecMSCngAppKeysMngrCertLoadMemory(mngr, xmlSecBufferGetData(&buffer),
        xmlSecBufferGetSize(&buffer), format, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecMSCngAppKeysMngrCertLoadMemory", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(-1);
    }

    xmlSecBufferFinalize(&buffer);
    return(ret);
}

/**
 * xmlSecMSCngAppKeysMngrCertLoadMemory:
 * @mngr:               the pointer to keys manager.
 * @data:               the key binary data.
 * @dataSize:           the key binary data size.
 * @format:             the certificate format (PEM or DER).
 * @type:               the certificate type (trusted/untrusted).
 *
 * Reads cert from @data and adds to the list of trusted or known
 * untrusted certs in @store
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte* data,
                                     xmlSecSize dataSize, xmlSecKeyDataFormat format,
                                     xmlSecKeyDataType type) {
    xmlSecKeyDataStorePtr x509Store;
    PCCERT_CONTEXT pCert = NULL;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecMSCngX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecMSCngX509StoreId)", NULL);
        return(-1);
    }

    switch (format) {
        case xmlSecKeyDataFormatDer:
            pCert = CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                data,
                dataSize);
            if(pCert == NULL) {
                xmlSecMSCngLastError("CertCreateCertificateContext", NULL)
                return(-1);
            }
            break;
        default:
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
                              "format=%d", (int)format);
            return(-1);
            break;
    }

    xmlSecAssert2(pCert != NULL, -1);
    ret = xmlSecMSCngX509StoreAdoptCert(x509Store, pCert, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509StoreAdoptCert", NULL);
        CertFreeCertificateContext(pCert);
        return(-1);
    }

    return(0);
}

#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecMSCngAppDefaultKeysMngrInit:
 * @mngr:               the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default MSCng crypto key data stores.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

    /* create MSCng keys store if needed */
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
        xmlSecKeyStorePtr keysStore;

        keysStore = xmlSecKeyStoreCreate(xmlSecMSCngKeysStoreId);
        if(keysStore == NULL) {
            xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecMSCngKeysStoreId)", NULL);
            return(-1);
        }

        ret = xmlSecKeysMngrAdoptKeysStore(mngr, keysStore);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeysMngrAdoptKeysStore", NULL);
            xmlSecKeyStoreDestroy(keysStore);
            return(-1);
        }
    }

    ret = xmlSecMSCngKeysMngrInit(mngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeysMngrInit", NULL);
        return(-1);
    }

    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * xmlSecMSCngAppDefaultKeysMngrAdoptKey:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecMSCngAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecMSCngKeysStoreAdoptKey(store, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeysStoreAdoptKey", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngAppDefaultKeysMngrLoad:
 * @mngr:               the pointer to keys manager.
 * @uri:                the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created
 * with #xmlSecMSCngAppDefaultKeysMngrInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecMSCngKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecMSCngKeysStoreLoad", NULL, "uri=%s",
            xmlSecErrorsSafeString(uri));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngAppDefaultKeysMngrSave:
 * @mngr:               the pointer to keys manager.
 * @filename:           the destination filename.
 * @type:               the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecMSCngAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecMSCngKeysStoreSave(store, filename, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecMSCngKeysStoreSave", NULL, "filename%s",
            xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecMSCngAppGetDefaultPwdCallback:
 *
 * Gets default password callback.
 *
 * Returns: default password callback.
 */
void*
xmlSecMSCngAppGetDefaultPwdCallback(void) {
    /* TODO */
    return(NULL);
}

