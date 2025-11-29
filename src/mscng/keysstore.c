/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * SECTION:keysstore
 * @Short_description: Keys store implementation for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/mscng/app.h>
#include <xmlsec/mscng/crypto.h>
#include <xmlsec/mscng/keysstore.h>
#include <xmlsec/mscng/certkeys.h>
#include <xmlsec/mscng/x509.h>

#include "../cast_helpers.h"
#include "private.h"

#define XMLSEC_MSCNG_APP_DEFAULT_CERT_STORE_NAME TEXT("MY")

/****************************************************************************
 *
 * MSCng Keys Store. Uses Simple Keys Store under the hood
 *
 ***************************************************************************/
XMLSEC_KEY_STORE_DECLARE(MSCngKeysStore, xmlSecKeyStorePtr)
#define xmlSecMSCngKeysStoreSize XMLSEC_KEY_STORE_SIZE(MSCngKeysStore)

static int
xmlSecMSCngKeysStoreInitialize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *simpleKeyStore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);

    simpleKeyStore = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(*simpleKeyStore == NULL, -1);

    *simpleKeyStore = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
    if(*simpleKeyStore == NULL) {
        xmlSecInternalError("xmlSecKeyStoreCreate", xmlSecKeyStoreGetName(store));
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCngKeysStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *simpleKeyStore;

    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId));

    simpleKeyStore = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert((simpleKeyStore != NULL) && (*simpleKeyStore != NULL));

    xmlSecKeyStoreDestroy(*simpleKeyStore);
}

static PCCERT_CONTEXT
xmlSecMSCngKeysStoreFindCert(xmlSecKeyStorePtr store, const xmlChar* name, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    LPCTSTR storeName;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT cert = NULL;
    LPTSTR lptName = NULL;
    LPWSTR lpwName = NULL;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), NULL);
    xmlSecAssert2(name != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    storeName = xmlSecMSCngAppGetCertStoreName();
    if(storeName == NULL) {
        storeName = XMLSEC_MSCNG_APP_DEFAULT_CERT_STORE_NAME;
    }

    hStore = CertOpenSystemStore(0, storeName);
    if(hStore == NULL) {
        xmlSecMSCngLastError2("CertOpenSystemStore", xmlSecKeyStoreGetName(store),
            "name=%s", xmlSecErrorsSafeString(storeName));
        goto done;
    }

    /* convert name to tstr */
    lptName = xmlSecWin32ConvertUtf8ToTstr(name);
    if(lptName == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertUtf8ToTstr(name)",
                            xmlSecKeyStoreGetName(store));
        goto done;
    }

    /* find cert based on subject */
    if (cert == NULL) {
        cert = xmlSecMSCngX509FindCertBySubject(
            hStore,
            lptName,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
    }

    /* find cert based on friendly name */
    if(cert == NULL) {
        PCCERT_CONTEXT pCertCtxIter = NULL;

        /* convert name to unicode */
        lpwName = xmlSecWin32ConvertUtf8ToUnicode(name);
        if (lpwName == NULL) {
            xmlSecInternalError("xmlSecWin32ConvertUtf8ToUnicode(name)",
                xmlSecKeyStoreGetName(store));
            goto done;
        }

        /* find cert based on friendly name */
        while (1) {
            LPCWSTR lpwFriendlyName;

            pCertCtxIter = CertEnumCertificatesInStore(hStore, pCertCtxIter);
            if(pCertCtxIter == NULL) {
                break;
            }

            lpwFriendlyName = xmlSecMSCngX509GetFriendlyNameUnicode(pCertCtxIter);
            if (lpwFriendlyName == NULL) {
                continue;
            }

            if(lstrcmpW(lpwName, lpwFriendlyName) == 0) {
              cert = pCertCtxIter;
              xmlFree((void*)lpwFriendlyName);
              break;
            }

            xmlFree((void*)lpwFriendlyName);
        }
    }

    /* find cert based on part of the name */
    if(cert == NULL) {
        cert = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR,
            lptName,
            NULL);
    }

    /* done */

done:
    if (lptName != NULL) {
        xmlFree(lptName);
    }
    if (lpwName != NULL) {
        xmlFree(lpwName);
    }
    if(hStore != NULL) {
        /* dwFlags=0 means close the store with memory remaining allocated for
         * contexts that have not been freed */
        CertCloseStore(hStore, 0);
    }

    return(cert);
}


static int
xmlSecMSCngKeysStoreAddCertDataToKey(xmlSecKeyPtr key, PCCERT_CONTEXT cert) {
    xmlSecKeyDataPtr x509Data = NULL;
    PCCERT_CONTEXT certTmp = NULL;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    /* create x509 data  */
    x509Data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataX509Id);
    if (x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate", NULL);
        return(-1);
    }

    /* set cert as the key cert */
    certTmp = CertDuplicateCertificateContext(cert);
    if (certTmp == NULL) {
        xmlSecMSCngLastError("CertDuplicateCertificateContext", NULL);
        xmlSecKeyDataDestroy(x509Data);
        return(-1);
    }
    ret = xmlSecMSCngKeyDataX509AdoptKeyCert(x509Data, certTmp);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptKeyCert", NULL);
        CertFreeCertificateContext(certTmp);
        xmlSecKeyDataDestroy(x509Data);
        return(-1);
    }
    certTmp = NULL; /* owned by x509Data*/

    /* lastly, add x509 data to the key */
    ret = xmlSecKeyAdoptData(key, x509Data);
    if (ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData", NULL);
        xmlSecKeyDataDestroy(x509Data);
        return(-1);
    }
    x509Data = NULL; /* owned by key */

    /* success */
    return(0);
}

static int
xmlSecMSCngKeysStoreSetKeyValueFromCert(xmlSecKeyPtr key, PCCERT_CONTEXT cert, xmlSecKeyReqPtr keyReq) {
    PCCERT_CONTEXT certTmp;
    xmlSecKeyDataPtr keyValue;
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(keyReq != NULL, -1);

    /* create key value data from cert */
    certTmp = CertDuplicateCertificateContext(cert);
    if (certTmp == NULL) {
        xmlSecMSCngLastError("CertDuplicateCertificateContext", NULL);
        return(-1);
    }

    keyValue = xmlSecMSCngCertAdopt(cert, keyReq->keyType);
    if (keyValue == NULL) {
        xmlSecInternalError("xmlSecMSCngCertAdopt", NULL);
        CertFreeCertificateContext(certTmp);
        return(-1);
    }
    certTmp = NULL; /* owned by key value now */

    /* add key value data to the key */
    ret = xmlSecKeySetValue(key, keyValue);
    if (ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        xmlSecKeyDataDestroy(keyValue);
        return(-1);
    }
    keyValue = NULL; /* owned by key  now */

    /* success */
    return(0);
}

static xmlSecKeyPtr
xmlSecMSCngKeysStoreCreateKeyFromCert(PCCERT_CONTEXT cert, xmlSecKeyReqPtr keyReq) {
    xmlSecKeyPtr key = NULL;
    int ret;

    xmlSecAssert2(cert != NULL, NULL);
    xmlSecAssert2(keyReq != NULL, NULL);

    /* create key */
    key = xmlSecKeyCreate();
    if (key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        return(NULL);
    }

    /* set key value */
    ret = xmlSecMSCngKeysStoreSetKeyValueFromCert(key, cert, keyReq);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeysStoreSetKeyValueFromCert", NULL);
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    /* create and add x509 data to the key */
    ret = xmlSecMSCngKeysStoreAddCertDataToKey(key, cert);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeysStoreAddCertDataToKey", NULL);
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    /* success */
    return(key);
}

static xmlSecKeyPtr
xmlSecMSCngKeysStoreFindKey(xmlSecKeyStorePtr store, const xmlChar* name, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyStorePtr* simpleKeyStore;
    xmlSecKeyReqPtr keyReq = NULL;
    PCCERT_CONTEXT cert = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    simpleKeyStore = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(((simpleKeyStore != NULL) && (*simpleKeyStore != NULL)), NULL);

    /* look for the key in the simple store */
    key = xmlSecKeyStoreFindKey(*simpleKeyStore, name, keyInfoCtx);
    if(key != NULL) {
        return(key);
    }

    /* look for a named public or private key in the OS store */
    if(name == NULL) {
        goto done;
    }

    keyReq = &(keyInfoCtx->keyReq);
    if(!(keyReq->keyType & (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate))) {
        goto done;
    }

    cert = xmlSecMSCngKeysStoreFindCert(store, name, keyInfoCtx);
    if(cert == NULL) {
        /* cert not found */
        goto done;
    }

    key = xmlSecMSCngKeysStoreCreateKeyFromCert(cert, keyReq);
    if (key == NULL) {
        xmlSecInternalError("xmlSecMSCngKeysStoreCreateKeyFromCert", xmlSecKeyStoreGetName(store));
        goto done;
    }

    /* set the name of the key to the given name */
    ret = xmlSecKeySetName(key, name);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetName", xmlSecKeyStoreGetName(store));
        goto done;
    }

    /* now that we have a key, make sure it is valid */
    if(xmlSecKeyIsValid(key)) {
        res = key;
        key = NULL;
    }

done:
    if(cert != NULL) {
        CertFreeCertificateContext(cert);
    }
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    return(res);
}

static xmlSecKeyPtr
xmlSecMSCngKeysStoreFindKeyFromX509Data(xmlSecKeyStorePtr store, xmlSecKeyX509DataValuePtr x509Data, xmlSecKeyInfoCtxPtr keyInfoCtx) {
#ifndef XMLSEC_NO_X509
    LPCTSTR storeName;
    HCERTSTORE hStore = NULL;
    xmlSecMSCngX509FindCertCtx findCertCtx;
    PCCERT_CONTEXT cert = NULL;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), NULL);
    xmlSecAssert2(x509Data != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    /* open system store */
    storeName = xmlSecMSCngAppGetCertStoreName();
    if (storeName == NULL) {
        storeName = XMLSEC_MSCNG_APP_DEFAULT_CERT_STORE_NAME;
    }

    hStore = CertOpenSystemStore(0, storeName);
    if (hStore == NULL) {
        xmlSecMSCngLastError2("CertOpenSystemStore", xmlSecKeyStoreGetName(store),
            "name=%s", xmlSecErrorsSafeString(storeName));
        return(NULL);
    }

    /* init find certs */
    ret = xmlSecMSCngX509FindCertCtxInitializeFromValue(&findCertCtx, x509Data);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509FindCertCtxInitializeFromValue", NULL);
        xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
        CertCloseStore(hStore, 0);
        return(NULL);
    }

    /* do we have a cert we can use? not an error if we don't! */
    cert = xmlSecMSCngX509FindCert(hStore, &findCertCtx);
    if (cert == NULL) {
        xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
        CertCloseStore(hStore, 0);
        return(NULL);
    }

    /* create a key */
    key = xmlSecMSCngKeysStoreCreateKeyFromCert(cert, &(keyInfoCtx->keyReq));
    if (key == NULL) {
        xmlSecInternalError("xmlSecMSCngKeysStoreCreateKeyFromCert", xmlSecKeyStoreGetName(store));
        CertFreeCertificateContext(cert);
        xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
        CertCloseStore(hStore, 0);
        return(NULL);
    }

    /* TODO: search simple keys store? */
    /* 
    simplekeystore = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(((simplekeystore != NULL) && (*simplekeystore != NULL)), NULL);

    keysList = xmlSecSimpleKeysStoreGetKeys(*simplekeystore);
    if (keysList == NULL) {
        xmlSecInternalError("xmlSecSimpleKeysStoreGetKeys", NULL);
        return(NULL);
    }
    key = xmlSecMSCngX509FindKeyByValue(keysList, x509Data);
    if (key == NULL) {
        return(NULL);
    }
    */

    /* done! */
    CertFreeCertificateContext(cert);
    xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
    CertCloseStore(hStore, 0);
    return(key);
#else  /* XMLSEC_NO_X509 */
    return(NULL);
#endif /* XMLSEC_NO_X509 */
}


static xmlSecKeyStoreKlass xmlSecMSCngKeysStoreKlass = {
    sizeof(xmlSecKeyStoreKlass),
    xmlSecMSCngKeysStoreSize,

    /* data */
    BAD_CAST "MSCng-keys-store",                /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecMSCngKeysStoreInitialize,             /* xmlSecKeyStoreInitializeMethod initialize; */
    xmlSecMSCngKeysStoreFinalize,               /* xmlSecKeyStoreFinalizeMethod finalize; */
    xmlSecMSCngKeysStoreFindKey,                /* xmlSecKeyStoreFindKeyMethod findKey; */
    xmlSecMSCngKeysStoreFindKeyFromX509Data,    /* xmlSecKeyStoreFindKeyFromX509DataMethod findKeyFromX509Data; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
};

/**
 * xmlSecMSCngKeysStoreGetKlass:
 *
 * The MSCng list based keys store klass.
 *
 * Returns: MSCng list based keys store klass.
 */
xmlSecKeyStoreId
xmlSecMSCngKeysStoreGetKlass(void) {
    return(&xmlSecMSCngKeysStoreKlass);
}

/**
 * xmlSecMSCngKeysStoreAdoptKey:
 * @store:              the pointer to MSCng keys store.
 * @key:                the pointer to key.
 *
 * Adds @key to the @store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeysStoreAdoptKey(xmlSecKeyStorePtr store, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr *simpleKeyStore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);
    xmlSecAssert2((key != NULL), -1);

    simpleKeyStore = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(simpleKeyStore != NULL, -1);
    xmlSecAssert2(*simpleKeyStore != NULL, -1);
    xmlSecAssert2(xmlSecKeyStoreCheckId(*simpleKeyStore, xmlSecSimpleKeysStoreId), -1);

    return(xmlSecSimpleKeysStoreAdoptKey(*simpleKeyStore, key));
}

/**
 * xmlSecMSCngKeysStoreLoad:
 * @store:              the pointer to MSCng keys store.
 * @uri:                the filename.
 * @keysMngr:           the pointer to associated keys manager.
 *
 * Reads keys from an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri, xmlSecKeysMngrPtr keysMngr) {
    return(xmlSecSimpleKeysStoreLoad_ex(store, uri, keysMngr, xmlSecMSCngKeysStoreAdoptKey));
}

/**
 * xmlSecMSCngKeysStoreSave:
 * @store:              the pointer to MSCng keys store.
 * @filename:           the filename.
 * @type:               the saved keys type (public, private, ...).
 *
 * Writes keys from @store to an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeysStoreSave(xmlSecKeyStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr *simpleKeyStore;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);
    xmlSecAssert2((filename != NULL), -1);

    simpleKeyStore = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(simpleKeyStore != NULL, -1);
    xmlSecAssert2(*simpleKeyStore != NULL, -1);
    xmlSecAssert2(xmlSecKeyStoreCheckId(*simpleKeyStore, xmlSecSimpleKeysStoreId), -1);

    return(xmlSecSimpleKeysStoreSave(*simpleKeyStore, filename, type));
}
