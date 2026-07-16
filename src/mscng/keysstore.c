/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2018-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_mscng_keysstore
 * @brief Keys store implementation for Microsoft Cryptography API: Next Generation (CNG).
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

#define XMLSEC_MSCNG_APP_DEFAULT_CURRENT_USER_CERT_STORE_NAME   TEXT("MY")
#define XMLSEC_MSCNG_APP_DEFAULT_LOCAL_MACHINE_CERT_STORE_NAME  TEXT("ROOT")

/* CERT_STORE_PROV_SYSTEM is always CERT_STORE_PROV_SYSTEM_W and unconditionally
 * expects wchar_t* for pvPara.  In a non-Unicode (ANSI) build LPCTSTR is char*,
 * so use the TCHAR-correct variant to avoid silently passing the wrong type. */
#ifdef UNICODE
#define XMLSEC_MSCNG_CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_W
#else  /* UNICODE */
#define XMLSEC_MSCNG_CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_A
#endif /* UNICODE */

/******************************************************************************
 *
 * Helper: open a CERT_STORE_PROV_COLLECTION aggregating both the local
 * machine and current user system stores for the given store name (e.g. "MY").
 * Local machine is added at priority 1 (searched first), current user at 2.
 * Opening either individual store is treated as a soft failure – a warning is
 * logged but the other store is still tried.  Returns 0 on success or -1 if
 * neither store could be opened.
 *
  *****************************************************************************/
typedef struct _xmlSecMSCngCertStoreCtx {
    HCERTSTORE hCollection;
    HCERTSTORE hLocalMachine;
    HCERTSTORE hCurrentUser;
} xmlSecMSCngCertStoreCtx;


static int
xmlSecMSCngCertStoreCtxInitialize(xmlSecMSCngCertStoreCtx* ctx, LPCTSTR localMachineStoreName, LPCTSTR currentUserStoreName) {
    BOOL ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(localMachineStoreName != NULL, -1);
    xmlSecAssert2(currentUserStoreName != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCngCertStoreCtx));

    /* collection store – aggregates the two physical stores */
    ctx->hCollection = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    if(ctx->hCollection == NULL) {
        xmlSecMSCngLastError("CertOpenStore(CERT_STORE_PROV_COLLECTION)", NULL);
        return(-1);
    }

    /* local machine store (soft failure: may require elevation) */
    ctx->hLocalMachine = CertOpenStore(
        XMLSEC_MSCNG_CERT_STORE_PROV_SYSTEM,
        0,
        0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
        localMachineStoreName);
    if(ctx->hLocalMachine != NULL) {
        ret = CertAddStoreToCollection(ctx->hCollection, ctx->hLocalMachine,
            CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 1);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertAddStoreToCollection(LocalMachine)", NULL);
            /* non-fatal – continue without local machine store */
            CertCloseStore(ctx->hLocalMachine, 0);
            ctx->hLocalMachine = NULL;
        }
    }

    /* current user store (soft failure) */
    ctx->hCurrentUser = CertOpenStore(
        XMLSEC_MSCNG_CERT_STORE_PROV_SYSTEM,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
        currentUserStoreName);
    if(ctx->hCurrentUser != NULL) {
        ret = CertAddStoreToCollection(ctx->hCollection, ctx->hCurrentUser,
            CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 2);
        if(ret == FALSE) {
            xmlSecMSCngLastError("CertAddStoreToCollection(CurrentUser)", NULL);
            /* non-fatal */
            CertCloseStore(ctx->hCurrentUser, 0);
            ctx->hCurrentUser = NULL;
        }
    }

    /* fail only if both individual stores are unavailable */
    if(ctx->hLocalMachine == NULL && ctx->hCurrentUser == NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_DATA, NULL,
            "neither LocalMachine nor CurrentUser store could be opened");
        CertCloseStore(ctx->hCollection, 0);
        ctx->hCollection = NULL;
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCngCertStoreCtxFinalize(xmlSecMSCngCertStoreCtx* ctx) {
    if(ctx == NULL) {
        return;
    }
    /* close individual stores before the collection */
    if(ctx->hLocalMachine != NULL) {
        CertCloseStore(ctx->hLocalMachine, 0);
        ctx->hLocalMachine = NULL;
    }
    if(ctx->hCurrentUser != NULL) {
        CertCloseStore(ctx->hCurrentUser, 0);
        ctx->hCurrentUser = NULL;
    }
    if(ctx->hCollection != NULL) {
        CertCloseStore(ctx->hCollection, 0);
        ctx->hCollection = NULL;
    }
}

/******************************************************************************
 *
 * MSCng Keys Store. Uses Simple Keys Store under the hood
 *
  *****************************************************************************/
 typedef struct _xmlSecMSCngKeysStoreCtx {
    xmlSecKeyStorePtr       simpleKeyStore;
    xmlSecMSCngCertStoreCtx certStoreCtx;
} xmlSecMSCngKeysStoreCtx;

XMLSEC_KEY_STORE_DECLARE(MSCngKeysStore, xmlSecMSCngKeysStoreCtx)
#define xmlSecMSCngKeysStoreSize XMLSEC_KEY_STORE_SIZE(MSCngKeysStore)

static int
xmlSecMSCngKeysStoreInitialize(xmlSecKeyStorePtr store) {
    xmlSecMSCngKeysStoreCtx* ctx;
    LPCTSTR currentUserStoreName;
    LPCTSTR localMachineStoreName;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);

    ctx = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->simpleKeyStore == NULL, -1);

    ctx->simpleKeyStore = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
    if(ctx->simpleKeyStore == NULL) {
        xmlSecInternalError("xmlSecKeyStoreCreate", xmlSecKeyStoreGetName(store));
        return(-1);
    }

    currentUserStoreName = xmlSecMSCngAppGetCurrentUserCertStoreName();
    if(currentUserStoreName == NULL) {
        currentUserStoreName = XMLSEC_MSCNG_APP_DEFAULT_CURRENT_USER_CERT_STORE_NAME;
    }
    localMachineStoreName = xmlSecMSCngAppGetLocalMachineCertStoreName();
    if(localMachineStoreName == NULL) {
        localMachineStoreName = XMLSEC_MSCNG_APP_DEFAULT_LOCAL_MACHINE_CERT_STORE_NAME;
    }
    ret = xmlSecMSCngCertStoreCtxInitialize(&ctx->certStoreCtx, localMachineStoreName, currentUserStoreName);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngCertStoreCtxInitialize", xmlSecKeyStoreGetName(store));
        xmlSecKeyStoreDestroy(ctx->simpleKeyStore);
        ctx->simpleKeyStore = NULL;
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCngKeysStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecMSCngKeysStoreCtx* ctx;

    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId));

    ctx = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert((ctx != NULL) && (ctx->simpleKeyStore != NULL));

    xmlSecKeyStoreDestroy(ctx->simpleKeyStore);
    ctx->simpleKeyStore = NULL;
    xmlSecMSCngCertStoreCtxFinalize(&ctx->certStoreCtx);
}

static PCCERT_CONTEXT
xmlSecMSCngKeysStoreFindCert(xmlSecKeyStorePtr store, const xmlChar* name, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCngKeysStoreCtx* ctx;
    PCCERT_CONTEXT cert = NULL;
    LPTSTR lptName = NULL;
    LPWSTR lpwName = NULL;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), NULL);
    xmlSecAssert2(name != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->certStoreCtx.hCollection != NULL, NULL);

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
            ctx->certStoreCtx.hCollection,
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

            pCertCtxIter = CertEnumCertificatesInStore(ctx->certStoreCtx.hCollection, pCertCtxIter);
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
            ctx->certStoreCtx.hCollection,
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

    keyValue = xmlSecMSCngCertAdopt(certTmp, keyReq->keyType);
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
    xmlSecMSCngKeysStoreCtx* ctx;
    xmlSecKeyReqPtr keyReq = NULL;
    PCCERT_CONTEXT cert = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(((ctx != NULL) && (ctx->simpleKeyStore != NULL)), NULL);

    /* look for the key in the simple store */
    key = xmlSecKeyStoreFindKey(ctx->simpleKeyStore, name, keyInfoCtx);
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
    xmlSecMSCngKeysStoreCtx* ctx;
    xmlSecMSCngX509FindCertCtx findCertCtx;
    PCCERT_CONTEXT cert = NULL;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), NULL);
    xmlSecAssert2(x509Data != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->certStoreCtx.hCollection != NULL, NULL);

    /* init find certs */
    ret = xmlSecMSCngX509FindCertCtxInitializeFromValue(&findCertCtx, x509Data);
    if (ret < 0) {
        xmlSecInternalError("xmlSecMSCngX509FindCertCtxInitializeFromValue", NULL);
        xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    /* do we have a cert we can use? not an error if we don't! */
    cert = xmlSecMSCngX509FindCert(ctx->certStoreCtx.hCollection, &findCertCtx);
    if (cert == NULL) {
        xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    /* create a key */
    key = xmlSecMSCngKeysStoreCreateKeyFromCert(cert, &(keyInfoCtx->keyReq));
    if (key == NULL) {
        xmlSecInternalError("xmlSecMSCngKeysStoreCreateKeyFromCert", xmlSecKeyStoreGetName(store));
        CertFreeCertificateContext(cert);
        xmlSecMSCngX509FindCertCtxFinalize(&findCertCtx);
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
 * @brief The MSCng list based keys store klass.
 * @return MSCng list based keys store klass.
 */
xmlSecKeyStoreId
xmlSecMSCngKeysStoreGetKlass(void) {
    return(&xmlSecMSCngKeysStoreKlass);
}

/**
 * @brief Adds @p key to the @p store.
 * @param store the pointer to MSCng keys store.
 * @param key the pointer to key.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeysStoreAdoptKey(xmlSecKeyStorePtr store, xmlSecKeyPtr key) {
    xmlSecMSCngKeysStoreCtx* ctx;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);
    xmlSecAssert2((key != NULL), -1);

    ctx = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->simpleKeyStore != NULL, -1);
    xmlSecAssert2(xmlSecKeyStoreCheckId(ctx->simpleKeyStore, xmlSecSimpleKeysStoreId), -1);

    return(xmlSecSimpleKeysStoreAdoptKey(ctx->simpleKeyStore, key));
}

/**
 * @brief Reads keys from an XML file.
 * @param store the pointer to MSCng keys store.
 * @param uri the filename.
 * @param keysMngr the pointer to associated keys manager.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri, xmlSecKeysMngrPtr keysMngr) {
    return(xmlSecSimpleKeysStoreLoad_ex(store, uri, keysMngr, xmlSecMSCngKeysStoreAdoptKey));
}

/**
 * @brief Writes keys from @p store to an XML file.
 * @param store the pointer to MSCng keys store.
 * @param filename the filename.
 * @param type the saved keys type (public, private, ...).
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecMSCngKeysStoreSave(xmlSecKeyStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecMSCngKeysStoreCtx* ctx;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);
    xmlSecAssert2((filename != NULL), -1);

    ctx = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->simpleKeyStore != NULL, -1);
    xmlSecAssert2(xmlSecKeyStoreCheckId(ctx->simpleKeyStore, xmlSecSimpleKeysStoreId), -1);

    return(xmlSecSimpleKeysStoreSave(ctx->simpleKeyStore, filename, type));
}
