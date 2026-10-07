/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscrypto_keysstore
 * @brief Keys store implementation for Microsoft Crypto API.
 * MSCrypto keys store that uses Simple Keys Store under the hood. Uses the
 * MS Certificate store as a backing store for finding keys, but the
 * MS Certificate store is not written to by the keys store.
 * So, if store->findkey is done and the key is not found in the simple
 * keys store, the MS Certificate store is looked up.
 * Thus, the MS Certificate store can be used to pre-load keys and becomes
 * an alternate source of keys for xmlsec.
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/mscrypto/app.h>
#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/keysstore.h>
#include <xmlsec/mscrypto/x509.h>
#include <xmlsec/mscrypto/certkeys.h>

#include "private.h"
#include "../cast_helpers.h"

#define XMLSEC_MSCRYPTO_APP_DEFAULT_CERT_STORE_NAME_A     "MY"
#define XMLSEC_MSCRYPTO_APP_DEFAULT_CERT_STORE_NAME_W     L"MY"
#ifdef UNICODE
#define XMLSEC_MSCRYPTO_APP_DEFAULT_CERT_STORE_NAME XMLSEC_MSCRYPTO_APP_DEFAULT_CERT_STORE_NAME_W
#else  /* UNICODE */
#define XMLSEC_MSCRYPTO_APP_DEFAULT_CERT_STORE_NAME XMLSEC_MSCRYPTO_APP_DEFAULT_CERT_STORE_NAME_A
#endif /* UNICODE */

/******************************************************************************
 *
 * MSCrypto Keys Store. Uses Simple Keys Store under the hood
 *
  *****************************************************************************/
 typedef struct _xmlSecMSCryptoKeysStoreCtx {
    xmlSecKeyStorePtr   simpleKeyStore;
    HCERTSTORE          hStoreHandle;
} xmlSecMSCryptoKeysStoreCtx;

XMLSEC_KEY_STORE_DECLARE(MSCryptoKeysStore, xmlSecMSCryptoKeysStoreCtx)
#define xmlSecMSCryptoKeysStoreSize XMLSEC_KEY_STORE_SIZE(MSCryptoKeysStore)

static int                      xmlSecMSCryptoKeysStoreInitialize   (xmlSecKeyStorePtr store);
static void                     xmlSecMSCryptoKeysStoreFinalize     (xmlSecKeyStorePtr store);
static xmlSecKeyPtr             xmlSecMSCryptoKeysStoreFindKey      (xmlSecKeyStorePtr store,
                                                                     const xmlChar* name,
                                                                     xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyStoreKlass xmlSecMSCryptoKeysStoreKlass = {
    sizeof(xmlSecKeyStoreKlass),
    xmlSecMSCryptoKeysStoreSize,

    /* data */
    BAD_CAST "MSCrypto-keys-store",             /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecMSCryptoKeysStoreInitialize,          /* xmlSecKeyStoreInitializeMethod initialize; */
    xmlSecMSCryptoKeysStoreFinalize,            /* xmlSecKeyStoreFinalizeMethod finalize; */
    xmlSecMSCryptoKeysStoreFindKey,             /* xmlSecKeyStoreFindKeyMethod findKey; */
    NULL,                                       /* xmlSecKeyStoreFindKeyFromX509DataMethod findKeyFromX509Data; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
};

/**
 * @brief The MSCrypto list based keys store klass.
 * @return MSCrypto list based keys store klass.
 */
xmlSecKeyStoreId
xmlSecMSCryptoKeysStoreGetKlass(void) {
    return(&xmlSecMSCryptoKeysStoreKlass);
}

/**
 * @brief Adds @p key to the @p store.
 * @param store the pointer to MSCrypto keys store.
 * @param key the pointer to key.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeysStoreAdoptKey(xmlSecKeyStorePtr store, xmlSecKeyPtr key) {
    xmlSecMSCryptoKeysStoreCtx* ctx;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCryptoKeysStoreId), -1);
    xmlSecAssert2((key != NULL), -1);

    ctx = xmlSecMSCryptoKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->simpleKeyStore != NULL, -1);
    xmlSecAssert2((xmlSecKeyStoreCheckId(ctx->simpleKeyStore, xmlSecSimpleKeysStoreId)), -1);

    return (xmlSecSimpleKeysStoreAdoptKey(ctx->simpleKeyStore, key));
}

/**
 * @brief Reads keys from an XML file.
 * @param store the pointer to MSCrypto keys store.
 * @param uri the filename.
 * @param keysMngr the pointer to associated keys manager.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri,
                            xmlSecKeysMngrPtr keysMngr) {
    return(xmlSecSimpleKeysStoreLoad_ex(store, uri, keysMngr,
        xmlSecMSCryptoKeysStoreAdoptKey));
}

/**
 * @brief Writes keys from @p store to an XML file.
 * @param store the pointer to MSCrypto keys store.
 * @param filename the filename.
 * @param type the saved keys type (public, private, ...).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCryptoKeysStoreSave(xmlSecKeyStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecMSCryptoKeysStoreCtx* ctx;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCryptoKeysStoreId), -1);
    xmlSecAssert2((filename != NULL), -1);

    ctx = xmlSecMSCryptoKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->simpleKeyStore != NULL, -1);
    xmlSecAssert2(xmlSecKeyStoreCheckId(ctx->simpleKeyStore, xmlSecSimpleKeysStoreId), -1);

    return (xmlSecSimpleKeysStoreSave(ctx->simpleKeyStore, filename, type));
}

static HCERTSTORE
xmlSecMSCryptoOpenDefaultCertStore(void) {
    LPCTSTR storeName;
    HCERTSTORE hStoreHandle = NULL;

    storeName = xmlSecMSCryptoAppGetCertStoreName();
    if(storeName == NULL) {
        storeName = XMLSEC_MSCRYPTO_APP_DEFAULT_CERT_STORE_NAME;
    }

    hStoreHandle = CertOpenSystemStore(0, storeName);
    if (NULL == hStoreHandle) {
        xmlChar* storeNameUtf8;

        storeNameUtf8 = xmlSecWin32ConvertTstrToUtf8(storeName);
        if(storeNameUtf8 != NULL) {
            xmlSecMSCryptoError2("CertOpenSystemStore",
                                 NULL,
                                 "storeName=%s",
                                 storeNameUtf8);
            xmlFree(storeNameUtf8);
        } else {
            xmlSecMSCryptoError("CertOpenSystemStore", NULL);
        }
        return(NULL);
    }

    return(hStoreHandle);
}

static int
xmlSecMSCryptoKeysStoreInitialize(xmlSecKeyStorePtr store) {
    xmlSecMSCryptoKeysStoreCtx* ctx;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCryptoKeysStoreId), -1);

    ctx = xmlSecMSCryptoKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->simpleKeyStore == NULL, -1);
    xmlSecAssert2(ctx->hStoreHandle == NULL, -1);

    ctx->simpleKeyStore = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
    if(ctx->simpleKeyStore == NULL) {
        xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId)", xmlSecKeyStoreGetName(store));
        return(-1);
    }

    ctx->hStoreHandle = xmlSecMSCryptoOpenDefaultCertStore();
    if(ctx->hStoreHandle == NULL) {
        xmlSecInternalError("xmlSecMSCryptoOpenDefaultCertStore", xmlSecKeyStoreGetName(store));
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCryptoKeysStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecMSCryptoKeysStoreCtx* ctx;

    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecMSCryptoKeysStoreId));

    ctx = xmlSecMSCryptoKeysStoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    if(ctx->hStoreHandle != NULL) {
        if (!CertCloseStore(ctx->hStoreHandle, XMLSEC_CLOSE_STORE_FLAG)) {
            xmlSecMSCryptoError("CertCloseStore", xmlSecKeyStoreGetName(store));
            /* cleanup: the returned cert context may still reference the closed store
            * (see the todo note above); nothing else can be done here */
        }
        ctx->hStoreHandle = NULL;
    }

    if(ctx->simpleKeyStore != NULL) {
        xmlSecKeyStoreDestroy(ctx->simpleKeyStore);
        ctx->simpleKeyStore = NULL;
    }
}


static PCCERT_CONTEXT
xmlSecMSCryptoKeysStoreFindCert(xmlSecKeyStorePtr store, HCERTSTORE hStoreHandle, const xmlChar* name) {
    PCCERT_CONTEXT pCertContext = NULL;
    LPTSTR tstrName = NULL;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCryptoKeysStoreId), NULL);
    xmlSecAssert2(hStoreHandle != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    /* convert name to TSTR */
    tstrName = xmlSecWin32ConvertUtf8ToTstr(name);
    if(tstrName == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertUtf8ToTstr(name)",
                            xmlSecKeyStoreGetName(store));
        return(NULL);
    }

    /* first attempt: try to find the cert with a full blown subject dn */
#ifndef XMLSEC_NO_X509
    if(NULL == pCertContext) {
        pCertContext = xmlSecMSCryptoX509FindCertBySubject(
            hStoreHandle,
            tstrName,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
    }
#endif /* XMLSEC_NO_X509 */

    /*
     * Try to find certificate with name="Friendly Name". This is an O(N)
     * enumeration over the store: a targeted CertFindCertificateInStore() match
     * is not possible because CERT_FIND_PROPERTY is an existence check, not a
     * value match on the friendly-name string.
     */
    if (NULL == pCertContext) {
        DWORD dwPropSize;
        DWORD dwAllocSize;
        DWORD dwFetchSize;
        PBYTE pbFriendlyName;
        PCCERT_CONTEXT pCertCtxIter = NULL;
        LPWSTR lpwName;

        /* convert name to unicode */
        lpwName = xmlSecWin32ConvertUtf8ToUnicode(name);
        if (lpwName == NULL) {
            xmlSecInternalError("xmlSecWin32ConvertUtf8ToUnicode(name)",
                                xmlSecKeyStoreGetName(store));
            xmlFree(tstrName);
            return(NULL);
        }

        while (1) {
            /* CertEnumCertificatesInStore automatically frees the previous certificate context (see
             * https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore) */
            pCertCtxIter = CertEnumCertificatesInStore(hStoreHandle, pCertCtxIter);
            if(pCertCtxIter == NULL) {
                break;
            }

            /* CertGetCertificateContextProperty takes a generic LPVOID and has
             * no _A/_W variant; the friendly-name property (CERT_FRIENDLY_NAME_PROP_ID)
             * is always a NULL-terminated UTF-16 string, so it can be compared
             * with lstrcmpW regardless of the library's TCHAR width */
            if (TRUE != CertGetCertificateContextProperty(pCertCtxIter,
                                                      CERT_FRIENDLY_NAME_PROP_ID,
                                                      NULL,
                                                      &dwPropSize)) {
                continue;
            }
            dwAllocSize = dwPropSize + 2;   /* +2: guaranteed UTF-16 NUL terminator */

            pbFriendlyName = xmlMalloc(dwAllocSize);
            if(pbFriendlyName == NULL) {
                xmlSecMallocError(dwAllocSize, xmlSecKeyStoreGetName(store));
                xmlFree(lpwName);
                xmlFree(tstrName);
                CertFreeCertificateContext(pCertCtxIter);
                return(NULL);
            }
            dwFetchSize = dwAllocSize;    /* input to the fetch: buffer capacity */
            if (TRUE != CertGetCertificateContextProperty(pCertCtxIter,
                                                      CERT_FRIENDLY_NAME_PROP_ID,
                                                      pbFriendlyName,
                                                      &dwFetchSize)) {
                xmlFree(pbFriendlyName);
                continue;
            }

            /* The friendly-name property lives in a mutable OS-owned collection, so its
             * size can theoretically differ between the probe and the fetch; reject
             * anything that does not fit the allocation made from the probe. */
            if ((dwFetchSize == 0) || (dwFetchSize > dwPropSize)) {
                xmlSecMSCryptoError("CertGetCertificateContextProperty",
                                    xmlSecKeyStoreGetName(store));
                xmlFree(pbFriendlyName);
                continue;
            }

            /* guarantee the NULL terminator based on the actual fetched size */
            pbFriendlyName[dwFetchSize] = 0;
            pbFriendlyName[dwFetchSize + 1] = 0;

            /* Compare FriendlyName to name */
            if (lstrcmpW(lpwName, (LPCWSTR)pbFriendlyName) == 0) {
              pCertContext = pCertCtxIter;
              pCertCtxIter = NULL; /* just in case */
              xmlFree(pbFriendlyName);
              break;
            }
            xmlFree(pbFriendlyName);
        }

        xmlFree(lpwName);
    }
    /* We don't give up easily, now try to find cert with part of the name.
     * This is an indexed lookup. */
    if (NULL == pCertContext) {
        pCertContext = CertFindCertificateInStore(
            hStoreHandle,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR,
            tstrName,
            NULL);
    }

    /* We could do the following here:
     * It would be nice if we could locate the cert with issuer name and
     * serial number, the given keyname can be something like this:
     * 'serial=1234567;issuer=CN=ikke, C=NL'
     * to be implemented by the first person who reads this, and thinks it's
     * a good idea :) WK
     */

    /* OK, I give up, I'm gone :( */

    xmlFree(tstrName);
    return(pCertContext);
}

static xmlSecKeyPtr
xmlSecMSCryptoKeysStoreFindKey(xmlSecKeyStorePtr store, const xmlChar* name,
                               xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoKeysStoreCtx* ctx;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyReqPtr keyReq = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CONTEXT pCertContext2 = NULL;
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCryptoKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCryptoKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->simpleKeyStore != NULL, NULL);
    xmlSecAssert2(ctx->hStoreHandle != NULL, NULL);

    /* first try to find key in the simple keys store */
    key = xmlSecKeyStoreFindKey(ctx->simpleKeyStore, name, keyInfoCtx);
    if (key != NULL) {
        return (key);
    }

    /* Next try to find the key in the MS Certificate store, and construct an xmlSecKey.
    *  we must have a name to lookup keys in the certificate store.
    */
    if (name == NULL) {
        goto done;
    }

    /* what type of key are we looking for?
    * WK: For now, we'll look only for public/private keys using the
    * name as a cert nickname. Then the name is regarded as the subject
    * dn of the certificate to be searched for.
    */
    keyReq = &(keyInfoCtx->keyReq);
    if (keyReq->keyType & (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate)) {
        pCertContext = xmlSecMSCryptoKeysStoreFindCert(store, ctx->hStoreHandle, name);
        if(pCertContext == NULL) {
            goto done;
        }

#ifndef XMLSEC_NO_X509
        /* set cert in x509 data */
        x509Data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataX509Id);
        if(x509Data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate", xmlSecKeyStoreGetName(store));
            goto done;
        }

        pCertContext2 = CertDuplicateCertificateContext(pCertContext);
        if (NULL == pCertContext2) {
            xmlSecMSCryptoError("CertDuplicateCertificateContext", xmlSecKeyStoreGetName(store));
            goto done;
        }

        ret = xmlSecMSCryptoKeyDataX509AdoptCert(x509Data, pCertContext2);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptCert", xmlSecKeyStoreGetName(store));
            goto done;
        }
        pCertContext2 = NULL;

        pCertContext2 = CertDuplicateCertificateContext(pCertContext);
        if (NULL == pCertContext2) {
            xmlSecMSCryptoError("CertDuplicateCertificateContext", xmlSecKeyStoreGetName(store));
            goto done;
        }

        ret = xmlSecMSCryptoKeyDataX509AdoptKeyCert(x509Data, pCertContext2);
        if (ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataX509AdoptKeyCert", xmlSecKeyStoreGetName(store));
            goto done;
        }
        pCertContext2 = NULL;
#endif /* XMLSEC_NO_X509 */

        /* set cert in key data */
        data = xmlSecMSCryptoCertAdopt(pCertContext, keyReq->keyType);
        if(data == NULL) {
            xmlSecInternalError("xmlSecMSCryptoCertAdopt", xmlSecKeyStoreGetName(store));
            goto done;
        }
        pCertContext = NULL;

        /* create key and add key data and x509 data to it */
        key = xmlSecKeyCreate();
        if (key == NULL) {
            xmlSecInternalError("xmlSecKeyCreate", xmlSecKeyStoreGetName(store));
            goto done;
        }

        ret = xmlSecKeySetValue(key, data);
        if (ret < 0) {
            xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyStoreGetName(store));
            goto done;
        }
        data = NULL;

#ifndef XMLSEC_NO_X509
        ret = xmlSecKeyAdoptData(key, x509Data);
        if (ret < 0) {
            xmlSecInternalError("xmlSecKeyAdoptData", xmlSecKeyStoreGetName(store));
            goto done;
        }
        x509Data = NULL;
#endif /* XMLSEC_NO_X509 */

        /* Set the name of the key to the given name */
        ret = xmlSecKeySetName(key, name);
        if (ret < 0) {
            xmlSecInternalError("xmlSecKeySetName", xmlSecKeyStoreGetName(store));
            goto done;
        }

        /* now that we have a key, make sure it is valid; the key is returned
        * to the caller (it is not cached in the simple store) */
        if (xmlSecKeyIsValid(key)) {
            res = key;
            key = NULL;
        }
    }

done:
    if (NULL != pCertContext) {
        CertFreeCertificateContext(pCertContext);
    }
    if (NULL != pCertContext2) {
        CertFreeCertificateContext(pCertContext2);
    }
    if (data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    if (x509Data != NULL) {
        xmlSecKeyDataDestroy(x509Data);
    }
    if (key != NULL) {
        xmlSecKeyDestroy(key);
    }

    return (res);
}
