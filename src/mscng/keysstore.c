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
 * SECTION:keysstore
 * @Short_description: Keys store implementation for Microsoft Cryptography API: Next Generation (CNG).
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#include <ncrypt.h>

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
    xmlSecKeyStorePtr *ss;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);

    ss = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(*ss == NULL, -1);

    *ss = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
    if(*ss == NULL) {
        xmlSecInternalError("xmlSecKeyStoreCreate",
            xmlSecKeyStoreGetName(store));
        return(-1);
    }

    return(0);
}

static void
xmlSecMSCngKeysStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *ss;

    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId));

    ss = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert((ss != NULL) && (*ss != NULL));

    xmlSecKeyStoreDestroy(*ss);
}

static PCCERT_CONTEXT
xmlSecMSCngKeysStoreFindCert(xmlSecKeyStorePtr store, const xmlChar* name,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    LPCTSTR storeName;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    LPTSTR wcName = NULL;
    BOOL ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), NULL);
    xmlSecAssert2(name != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    storeName = xmlSecMSCngAppGetCertStoreName();
    if(storeName == NULL) {
        storeName = XMLSEC_MSCNG_APP_DEFAULT_CERT_STORE_NAME;
    }

    hStore = CertOpenSystemStore(0, storeName);
    if(hStore == NULL) {
        xmlSecMSCngLastError("CertOpenSystemStore",
                             xmlSecKeyStoreGetName(store));
        return(NULL);
    }

    /* convert name to unicode */
    wcName = xmlSecWin32ConvertUtf8ToTstr(name);
    if(wcName == NULL) {
        xmlSecInternalError("xmlSecWin32ConvertUtf8ToTstr(name)",
                            xmlSecKeyStoreGetName(store));
        CertCloseStore(hStore, 0);
        return(NULL);
    }

    /* find cert based on subject */
    pCertContext = xmlSecMSCngX509FindCertBySubject(
        hStore,
        wcName,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);

    if(pCertContext == NULL) {
        /* find cert based on friendly name */
        DWORD dwPropSize;
        PBYTE pbFriendlyName;
        PCCERT_CONTEXT pCertCtxIter = NULL;


        while (1) {
            pCertCtxIter = CertEnumCertificatesInStore(hStore, pCertCtxIter);
            if(pCertCtxIter == NULL) {
                break;
            }

            ret = CertGetCertificateContextProperty(pCertCtxIter,
                                                    CERT_FRIENDLY_NAME_PROP_ID,
                                                    NULL, &dwPropSize);
            if(ret != TRUE) {
                continue;
            }

            pbFriendlyName = xmlMalloc(dwPropSize);
            if(pbFriendlyName == NULL) {
                xmlSecMallocError(dwPropSize, xmlSecKeyStoreGetName(store));
                xmlFree(wcName);
                CertCloseStore(hStore, 0);
                return(NULL);
            }

            ret = CertGetCertificateContextProperty(pCertCtxIter,
                                                    CERT_FRIENDLY_NAME_PROP_ID,
                                                    pbFriendlyName,
                                                    &dwPropSize);
            if(ret != TRUE) {
                xmlFree(pbFriendlyName);
                continue;
            }

            if(lstrcmp(wcName, (LPCTSTR)pbFriendlyName) == 0) {
              pCertContext = pCertCtxIter;
              xmlFree(pbFriendlyName);
              break;
            }

            xmlFree(pbFriendlyName);
        }
    }

    if(pCertContext == NULL) {
        /* find cert based on part of the name */
        pCertContext = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR,
            wcName,
            NULL);
    }


    xmlFree(wcName);
    /* dwFlags=0 means close the store with memory remaining allocated for
     * contexts that have not been freed */
    CertCloseStore(hStore, 0);

    return(pCertContext);
}

static xmlSecKeyPtr
xmlSecMSCngKeysStoreFindKey(xmlSecKeyStorePtr store, const xmlChar* name,
        xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyStorePtr* ss;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyReqPtr keyReq = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CONTEXT pDuplicatedCertContext = NULL;
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ss = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(((ss != NULL) && (*ss != NULL)), NULL);

    /* look for the key in the simple store */
    key = xmlSecKeyStoreFindKey(*ss, name, keyInfoCtx);
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

    pCertContext = xmlSecMSCngKeysStoreFindCert(store, name, keyInfoCtx);
    if(pCertContext == NULL) {
        goto done;
    }

    /* set cert in x509 data */
    x509Data = xmlSecKeyDataCreate(xmlSecMSCngKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
            xmlSecKeyDataGetName(x509Data));
        goto done;
    }

    pDuplicatedCertContext = CertDuplicateCertificateContext(pCertContext);
    if(pDuplicatedCertContext == NULL) {
        xmlSecMSCngLastError("CertDuplicateCertificateContext",
            xmlSecKeyDataGetName(x509Data));
        goto done;
    }

    ret = xmlSecMSCngKeyDataX509AdoptCert(x509Data, pDuplicatedCertContext);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptCert",
            xmlSecKeyDataGetName(x509Data));
        goto done;
    }
    pDuplicatedCertContext = NULL;

    pDuplicatedCertContext = CertDuplicateCertificateContext(pCertContext);
    if(pDuplicatedCertContext == NULL) {
        xmlSecMSCngLastError("CertDuplicateCertificateContext",
            xmlSecKeyDataGetName(x509Data));
        goto done;
    }

    ret = xmlSecMSCngKeyDataX509AdoptKeyCert(x509Data, pDuplicatedCertContext);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCngKeyDataX509AdoptKeyCert",
            xmlSecKeyDataGetName(x509Data));
        goto done;
    }
    pDuplicatedCertContext = NULL;

    /* set cert in key data */
    data = xmlSecMSCngCertAdopt(pCertContext, keyReq->keyType);
    if(data == NULL) {
        xmlSecInternalError("xmlSecMSCngCertAdopt", NULL);
        goto done;
    }
    pCertContext = NULL;

    /* create key and add key data and x509 data to it */
    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        goto done;
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", xmlSecKeyDataGetName(data));
        goto done;
    }
    data = NULL;

    ret = xmlSecKeyAdoptData(key, x509Data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData",
            xmlSecKeyDataGetName(x509Data));
        goto done;
    }
    x509Data = NULL;

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
    if(pCertContext != NULL) {
        CertFreeCertificateContext(pCertContext);
    }

    if(pDuplicatedCertContext != NULL) {
        CertFreeCertificateContext(pDuplicatedCertContext);
    }

    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }

    if(x509Data != NULL) {
        xmlSecKeyDataDestroy(x509Data);
    }

    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }

    return(res);
}

static xmlSecKeyStoreKlass xmlSecMSCngKeysStoreKlass = {
    sizeof(xmlSecKeyStoreKlass),
    xmlSecMSCngKeysStoreSize,

    /* data */
    BAD_CAST "MSCng-keys-store",               /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecMSCngKeysStoreInitialize,             /* xmlSecKeyStoreInitializeMethod initialize; */
    xmlSecMSCngKeysStoreFinalize,               /* xmlSecKeyStoreFinalizeMethod finalize; */
    xmlSecMSCngKeysStoreFindKey,                /* xmlSecKeyStoreFindKeyMethod findKey; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
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
    xmlSecKeyStorePtr *ss;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);
    xmlSecAssert2((key != NULL), -1);

    ss = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(ss != NULL, -1);
    xmlSecAssert2(*ss != NULL, -1);
    xmlSecAssert2(xmlSecKeyStoreCheckId(*ss, xmlSecSimpleKeysStoreId), -1);

    return(xmlSecSimpleKeysStoreAdoptKey(*ss, key));
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
xmlSecMSCngKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri,
        xmlSecKeysMngrPtr keysMngr) {
    return(xmlSecSimpleKeysStoreLoad_ex(store, uri, keysMngr,
        xmlSecMSCngKeysStoreAdoptKey));
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
    xmlSecKeyStorePtr *ss;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecMSCngKeysStoreId), -1);
    xmlSecAssert2((filename != NULL), -1);

    ss = xmlSecMSCngKeysStoreGetCtx(store);
    xmlSecAssert2(ss != NULL, -1);
    xmlSecAssert2(*ss != NULL, -1);
    xmlSecAssert2(xmlSecKeyStoreCheckId(*ss, xmlSecSimpleKeysStoreId), -1);

    return(xmlSecSimpleKeysStoreSave(*ss, filename, type));
}
