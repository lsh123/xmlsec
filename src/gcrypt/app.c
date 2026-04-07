/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_gcrypt_app
 * @brief Application support functions for GCrypt.
 */
#include "globals.h"

#include <string.h>

#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/transforms.h>
#include <xmlsec/private.h>

#include <xmlsec/gcrypt/app.h>
#include <xmlsec/gcrypt/crypto.h>

#include "asn1.h"
#include "../cast_helpers.h"

/**
 * @brief Initializes the GCrypt crypto engine.
 * @details General crypto engine initialization. This function is used
 * by the XMLSec command-line utility and is called before the
 * #xmlSecInit function.
 *
 * @param config the path to GCrypt configuration (unused).
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppInit(const char* config XMLSEC_ATTRIBUTE_UNUSED) {
    gcry_error_t err;
    /* Secure memory initialisation based on documentation from:
         http://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html
       NOTE sample code don't check gcry_control(...) return code

       All flags from:
         http://www.gnupg.org/documentation/manuals/gcrypt/Controlling-the-library.html

       Also libgcrypt NEWS entries:
+++++
.....
Noteworthy changes in version 1.4.3 (2008-09-18)
------------------------------------------------

 * Try to auto-initialize Libgcrypt to minimize the effect of
   applications not doing that correctly.  This is not a perfect
   solution but given that many applicationion would totally fail
   without such a hack, we try to help at least with the most common
   cases.  Folks, please read the manual to learn how to properly
   initialize Libgcrypt!

 * Auto-initialize the secure memory to 32k instead of aborting the
   process.
.....
+++++
    */

    /* Version check should be the very first call because it
       makes sure that important subsystems are initialized. */

    /* NOTE configure.in defines GCRYPT_MIN_VERSION */
    if (!gcry_check_version (GCRYPT_MIN_VERSION)) {
        xmlSecGCryptError2("gcry_check_version", (gcry_error_t)GPG_ERR_NO_ERROR, NULL,
                           "min_version=%s", GCRYPT_MIN_VERSION);
        return(-1);
    }

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN)", err, NULL);
        return(-1);
    }

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been initialized.  */

    /* Allocate a pool of 32k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    err = gcry_control(GCRYCTL_INIT_SECMEM, 32768, 0);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_control(GCRYCTL_INIT_SECMEM)", err, NULL);
        /* ignore this error because of libgrcypt bug in allocating memory,
        see https://github.com/lsh123/xmlsec/issues/415 for more details */
    }

    /* It is now okay to let Libgcrypt complain when there was/is
      a problem with the secure memory. */
    err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_control(GCRYCTL_RESUME_SECMEM_WARN)", err, NULL);
        return(-1);
    }

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_control(GCRYCTL_INITIALIZATION_FINISHED)", err, NULL);
        return(-1);
    }

    /* done */
    return(0);
}

/**
 * @brief Shuts down the GCrypt crypto engine.
 * @details General crypto engine shutdown. This function is used
 * by the XMLSec command-line utility and is called after the
 * #xmlSecShutdown function.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppShutdown(void) {
    gcry_error_t err;

    err = gcry_control(GCRYCTL_TERM_SECMEM);
    if(err != GPG_ERR_NO_ERROR) {
        xmlSecGCryptError("gcry_control(GCRYCTL_TERM_SECMEM)", err, NULL);
        return(-1);
    }

    /* done */
    return(0);
}

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
xmlSecGCryptAppKeyLoadEx(const char *filename, xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED, xmlSecKeyDataFormat format,
    const char *pwd, void* pwdCallback, void* pwdCallbackCtx
) {
    xmlSecKeyPtr key;
    xmlSecBuffer buffer;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    UNREFERENCED_PARAMETER(type);

    ret = xmlSecBufferInitialize(&buffer, 4*1024);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(NULL);
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if((ret < 0) || (xmlSecBufferGetData(&buffer) == NULL) || (xmlSecBufferGetSize(&buffer) <= 0)) {
        xmlSecInternalError2("xmlSecBufferReadFile", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    key = xmlSecGCryptAppKeyLoadMemory(xmlSecBufferGetData(&buffer),
                    xmlSecBufferGetSize(&buffer),
                    format, pwd, pwdCallback, pwdCallbackCtx);
    if(key == NULL) {
        xmlSecInternalError2("xmlSecGCryptAppKeyLoadMemory", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    /* cleanup */
    xmlSecBufferFinalize(&buffer);
    return(key);
}

/**
 * @brief Reads a key from the memory buffer.
 * @param data the binary key data.
 * @param dataSize the size of binary key.
 * @param format the key file format.
 * @param pwd the key file password.
 * @param pwdCallback the key password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGCryptAppKeyLoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecKeyDataFormat format,
                        const char *pwd XMLSEC_ATTRIBUTE_UNUSED,
                        void* pwdCallback XMLSEC_ATTRIBUTE_UNUSED,
                        void* pwdCallbackCtx XMLSEC_ATTRIBUTE_UNUSED)
{
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr key_data = NULL;
    int ret;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    switch(format) {
    case xmlSecKeyDataFormatDer:
        key_data = xmlSecGCryptParseDer(data, dataSize, xmlSecGCryptDerKeyTypeAuto);
        if(key_data == NULL) {
            xmlSecInternalError("xmlSecGCryptParseDer", NULL);
            return(NULL);
        }
        break;
    case xmlSecKeyDataFormatPem:
        xmlSecNotImplementedError("GCrypt doesn't support PEM keys");
        return (NULL);
#ifndef XMLSEC_NO_X509
    case xmlSecKeyDataFormatPkcs12:
        xmlSecNotImplementedError("GCrypt doesn't support PKCS12");
        return (NULL);
#endif /* XMLSEC_NO_X509 */
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        return(NULL);
    }

    /* we should have key data by now */
    xmlSecAssert2(key_data != NULL, NULL);
    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        xmlSecKeyDataDestroy(key_data);
        return(NULL);
    }

    ret = xmlSecKeySetValue(key, key_data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(key_data));
        xmlSecKeyDestroy(key);
        xmlSecKeyDataDestroy(key_data);
        return(NULL);
    }
    key_data = NULL; /* key_data is owned by key */

    /* done */
    return(key);
}

#ifndef XMLSEC_NO_X509
/**
 * @brief GCrypt does not support X509 certificates.
 * @details Reads the certificate from @p filename and adds it to key.
 *
 * @param key the pointer to key.
 * @param filename the certificate filename.
 * @param format the certificate file format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeyCertLoad(xmlSecKeyPtr key, const char* filename,
                          xmlSecKeyDataFormat format) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(-1);
}

/**
 * @brief GCrypt does not support X509 certificates.
 * @details Reads the certificate from memory buffer and adds it to key.
 *
 * @param key the pointer to key.
 * @param data the certificate binary data.
 * @param dataSize the certificate binary data size.
 * @param format the certificate file format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeyCertLoadMemory(xmlSecKeyPtr key,
                                 const xmlSecByte* data,
                                 xmlSecSize dataSize,
                                 xmlSecKeyDataFormat format) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(-1);
}

/**
 * @brief GCrypt does not support X509 certificates.
 * @details Reads a key and all associated certificates from the PKCS12 file.
 * For uniformity, call #xmlSecGCryptAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * @param filename the PKCS12 key filename.
 * @param pwd the PKCS12 file password.
 * @param pwdCallback the password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGCryptAppPkcs12Load(const char *filename,
                          const char *pwd XMLSEC_ATTRIBUTE_UNUSED,
                          void* pwdCallback XMLSEC_ATTRIBUTE_UNUSED,
                          void* pwdCallbackCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecAssert2(filename != NULL, NULL);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(NULL);
}

/**
 * @brief GCrypt does not support X509 certificates.
 * @details Reads a key and all associated certificates from the PKCS12 data in the memory buffer.
 * For uniformity, call xmlSecGCryptAppKeyLoadMemory instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * @param data the PKCS12 binary data.
 * @param dataSize the PKCS12 binary data size.
 * @param pwd the PKCS12 file password.
 * @param pwdCallback the password callback.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGCryptAppPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
                           const char *pwd XMLSEC_ATTRIBUTE_UNUSED,
                           void* pwdCallback XMLSEC_ATTRIBUTE_UNUSED,
                           void* pwdCallbackCtx XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(NULL);
}

/**
 * @brief GCrypt does not support X509 certificates.
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
xmlSecGCryptAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr,
                                const char *filename,
                                xmlSecKeyDataFormat format,
                                xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(-1);
}

/**
 * @brief GCrypt does not support X509 certificates.
 * @details Reads crls from @p filename and adds to the list of crls in @p store.
 *
 * @param mngr the keys manager.
 * @param filename the CRL file.
 * @param format the CRL file format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeysMngrCrlLoad(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataFormat format) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(-1);
}

/**
 * @brief GCrypt does not support X509 certificates.
 * @details Atomically loads and verifies a CRL from @p filename.
 *
 * @param mngr the keys manager.
 * @param filename the CRL filename.
 * @param format the CRL format (PEM or DER).
 * @param keyInfoCtx the key info context for verification parameters.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeysMngrCrlLoadAndVerify(xmlSecKeysMngrPtr mngr, const char *filename,
    xmlSecKeyDataFormat format, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(-1);
}

/**
 * @brief GCrypt does not support X509 certificates.
 * @details Reads cert from binary buffer @p data and adds to the list of trusted or known
 * untrusted certs in @p store.
 *
 * @param mngr the keys manager.
 * @param data the certificate binary data.
 * @param dataSize the certificate binary data size.
 * @param format the certificate file format.
 * @param type the flag that indicates is the certificate trusted or not.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr,
                                      const xmlSecByte* data,
                                      xmlSecSize dataSize,
                                      xmlSecKeyDataFormat format,
                                      xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(-1);
}

#endif /* XMLSEC_NO_X509 */

/**
 * @brief Initializes the default key manager for GCrypt.
 * @details Initializes @p mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default GCrypt crypto key data stores.
 *
 * @param mngr the pointer to keys manager.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

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

    ret = xmlSecGCryptKeysMngrInit(mngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptKeysMngrInit", NULL);
        return(-1);
    }

    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * @brief Adds @p key to the keys manager.
 * @details Adds @p key to the keys manager @p mngr created with #xmlSecGCryptAppDefaultKeysMngrInit
 * function.
 *
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

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
xmlSecGCryptAppDefaultKeysMngrVerifyKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError("GCrypt doesn't support X509 certificates");
    return(-1);
}

/**
 * @brief Loads the XML keys file into the keys manager.
 * @details Loads XML keys file from @p uri to the keys manager @p mngr created
 * with #xmlSecGCryptAppDefaultKeysMngrInit function.
 *
 * @param mngr the pointer to keys manager.
 * @param uri the uri.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);

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
 * @brief Saves keys from @p mngr to XML keys file.
 * @param mngr the pointer to keys manager.
 * @param filename the destination filename.
 * @param type the type of keys to save (public/private/symmetric).
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreSave(store, filename, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecSimpleKeysStoreSave", NULL,
                             "filename=%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}

/**
 * @brief Gets default password callback.
 *
 * @return default password callback.
 */
void*
xmlSecGCryptAppGetDefaultPwdCallback(void) {
    /* TODO: GCrypt doesn't support password callback */
    return(NULL);
}
