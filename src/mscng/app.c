/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna <vmiklos@vmiklos.hu>. All Rights Reserved.
 */
#include "globals.h"

#include <string.h>

#include <windows.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/keysmngr.h>

#include <xmlsec/mscng/app.h>
#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/symbols.h>
#include <xmlsec/mscng/x509.h>

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
xmlSecMSCngAppInit(const char* config ATTRIBUTE_UNUSED) {
    /* TODO: initialize MSCng crypto engine */
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
    /* TODO: shutdown MSCng crypto engine */

    return(0);
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
    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    /* TODO: load key */
    xmlSecNotImplementedError(NULL);
    return(NULL);
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
    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    /* TODO: load key */
    xmlSecNotImplementedError(NULL);
    return(NULL);
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
                         const char *pwd ATTRIBUTE_UNUSED,
                         void* pwdCallback ATTRIBUTE_UNUSED,
                         void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecAssert2(filename != NULL, NULL);

    /* TODO: load pkcs12 file */
    xmlSecNotImplementedError(NULL);
    return(NULL);
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
                               void *pwdCallback ATTRIBUTE_UNUSED,
                               void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecAssert2(data != NULL, NULL);

    /* TODO: load pkcs12 file */
    xmlSecNotImplementedError(NULL);
    return(NULL);
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

    /* TODO: if MSCng crypto engine has another default
     * keys storage then use it!
     */

    /* create simple keys store if needed */
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
        xmlSecKeyStorePtr keysStore;

        keysStore = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
        if(keysStore == NULL) {
            xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId)", NULL);
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

    /* TODO: if MSCng crypto engine has another default
     * keys storage then use it!
     */

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreAdoptKey(store, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecSimpleKeysStoreAdoptKey", NULL);
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

    /* TODO: if MSCng crypto engine has another default
     * keys storage then use it!
     */

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecSimpleKeysStoreLoad", NULL,
                             "uri=%s", xmlSecErrorsSafeString(uri));
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

    /* TODO: if MSCng crypto engine has another default
     * keys storage then use it!
     */

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreSave(store, filename, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecSimpleKeysStoreSave", NULL,
                             "filename=%s",
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

