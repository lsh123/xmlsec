/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:keysstore
 * @Short_description: Keys store implementation for NSS.
 * @Stability: Stable
 *
 * Nss keys store that uses Simple Keys Store under the hood. Uses the
 * Nss DB as a backing store for the finding keys, but the NSS DB is
 * not written to by the keys store.
 * So, if store->findkey is done and the key is not found in the simple
 * keys store, the NSS DB is looked up.
 * If store is called to adopt a key, that key is not written to the NSS
 * DB.
 * Thus, the NSS DB can be used to pre-load keys and becomes an alternate
 * source of keys for xmlsec
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <nss.h>
#include <cert.h>
#include <pk11func.h>
#include <keyhi.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/keysmngr.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/keysstore.h>
#include <xmlsec/nss/x509.h>
#include <xmlsec/nss/pkikeys.h>

#include "../cast_helpers.h"
/****************************************************************************
 *
 * Nss Keys Store. Uses Simple Keys Store under the hood
 *
 * xmlSecKeyStore +  xmlSecKeyStorePtr(Simple Keys Store ptr)
 *
 ***************************************************************************/
XMLSEC_KEY_STORE_DECLARE(NssKeysStore, xmlSecKeyStorePtr)
#define xmlSecNssKeysStoreSize XMLSEC_KEY_STORE_SIZE(NssKeysStore)

static int                      xmlSecNssKeysStoreInitialize    (xmlSecKeyStorePtr store);
static void                     xmlSecNssKeysStoreFinalize      (xmlSecKeyStorePtr store);
static xmlSecKeyPtr             xmlSecNssKeysStoreFindKey       (xmlSecKeyStorePtr store,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyStoreKlass xmlSecNssKeysStoreKlass = {
    sizeof(xmlSecKeyStoreKlass),
    xmlSecNssKeysStoreSize,

    /* data */
    BAD_CAST "NSS-keys-store",          /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecNssKeysStoreInitialize,       /* xmlSecKeyStoreInitializeMethod initialize; */
    xmlSecNssKeysStoreFinalize,         /* xmlSecKeyStoreFinalizeMethod finalize; */
    xmlSecNssKeysStoreFindKey,          /* xmlSecKeyStoreFindKeyMethod findKey; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/**
 * xmlSecNssKeysStoreGetKlass:
 *
 * The Nss list based keys store klass.
 *
 * Returns: Nss list based keys store klass.
 */
xmlSecKeyStoreId
xmlSecNssKeysStoreGetKlass(void) {
    return(&xmlSecNssKeysStoreKlass);
}

/**
 * xmlSecNssKeysStoreAdoptKey:
 * @store:              the pointer to Nss keys store.
 * @key:                the pointer to key.
 *
 * Adds @key to the @store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeysStoreAdoptKey(xmlSecKeyStorePtr store, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr *ss;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecNssKeysStoreId), -1);
    xmlSecAssert2((key != NULL), -1);

    ss = xmlSecNssKeysStoreGetCtx(store);
    xmlSecAssert2(((ss != NULL) && (*ss != NULL) &&
                   (xmlSecKeyStoreCheckId(*ss, xmlSecSimpleKeysStoreId))), -1);

    return (xmlSecSimpleKeysStoreAdoptKey(*ss, key));
}

/**
 * xmlSecNssKeysStoreLoad:
 * @store:              the pointer to Nss keys store.
 * @uri:                the filename.
 * @keysMngr:           the pointer to associated keys manager.
 *
 * Reads keys from an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri,
                            xmlSecKeysMngrPtr keysMngr ATTRIBUTE_UNUSED) {
    return(xmlSecSimpleKeysStoreLoad_ex(store, uri, keysMngr,
        xmlSecNssKeysStoreAdoptKey));
}

/**
 * xmlSecNssKeysStoreSave:
 * @store:              the pointer to Nss keys store.
 * @filename:           the filename.
 * @type:               the saved keys type (public, private, ...).
 *
 * Writes keys from @store to an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeysStoreSave(xmlSecKeyStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr *ss;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecNssKeysStoreId), -1);
    xmlSecAssert2((filename != NULL), -1);

    ss = xmlSecNssKeysStoreGetCtx(store);
    xmlSecAssert2(((ss != NULL) && (*ss != NULL) &&
                   (xmlSecKeyStoreCheckId(*ss, xmlSecSimpleKeysStoreId))), -1);

    return (xmlSecSimpleKeysStoreSave(*ss, filename, type));
}

static int
xmlSecNssKeysStoreInitialize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *ss;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecNssKeysStoreId), -1);

    ss = xmlSecNssKeysStoreGetCtx(store);
    xmlSecAssert2(((ss == NULL) || (*ss == NULL)), -1);

    *ss = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
    if(*ss == NULL) {
        xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId)",
                            xmlSecKeyStoreGetName(store));
        return(-1);
    }

    return(0);
}

static void
xmlSecNssKeysStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecKeyStorePtr *ss;

    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecNssKeysStoreId));

    ss = xmlSecNssKeysStoreGetCtx(store);
    xmlSecAssert((ss != NULL) && (*ss != NULL));

    xmlSecKeyStoreDestroy(*ss);
}

static xmlSecKeyPtr
xmlSecNssKeysStoreFindKey(xmlSecKeyStorePtr store, const xmlChar* name,
                          xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyStorePtr* ss;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr retval = NULL;
    xmlSecKeyReqPtr keyReq = NULL;
    CERTCertificate *cert = NULL;
    SECKEYPublicKey *pubkey = NULL;
    SECKEYPrivateKey *privkey = NULL;
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecNssKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ss = xmlSecNssKeysStoreGetCtx(store);
    xmlSecAssert2(((ss != NULL) && (*ss != NULL)), NULL);

    key = xmlSecKeyStoreFindKey(*ss, name, keyInfoCtx);
    if (key != NULL) {
        return (key);
    }

    /* Try to find the key in the NSS DB, and construct an xmlSecKey.
     * we must have a name to lookup keys in NSS DB.
     */
    if (name == NULL) {
        goto done;
    }

    /* what type of key are we looking for?
     * TBD: For now, we'll look only for public/private keys using the
     * name as a cert nickname. Later on, we can attempt to find
     * symmetric keys using PK11_FindFixedKey
     */
    keyReq = &(keyInfoCtx->keyReq);
    if (keyReq->keyType &
        (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate)) {
        cert = CERT_FindCertByNickname (CERT_GetDefaultCertDB(), (char *)name);
        if (cert == NULL) {
            goto done;
        }

        if (keyReq->keyType & xmlSecKeyDataTypePublic) {
            pubkey = CERT_ExtractPublicKey(cert);
            if (pubkey == NULL) {
                xmlSecNssError("CERT_ExtractPublicKey", NULL);
                goto done;
            }
        }

        if (keyReq->keyType & xmlSecKeyDataTypePrivate) {
            privkey = PK11_FindKeyByAnyCert(cert, NULL);
            if (privkey == NULL) {
                xmlSecNssError("PK11_FindKeyByAnyCert", NULL);
                goto done;
            }
        }

        data = xmlSecNssPKIAdoptKey(privkey, pubkey);
        if(data == NULL) {
            xmlSecInternalError("xmlSecNssPKIAdoptKey", NULL);
            goto done;
        }
        privkey = NULL;
        pubkey = NULL;

        key = xmlSecKeyCreate();
        if (key == NULL) {
            xmlSecInternalError("xmlSecKeyCreate", NULL);
            return (NULL);
        }

        x509Data = xmlSecKeyDataCreate(xmlSecNssKeyDataX509Id);
        if(x509Data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate",
                                xmlSecTransformKlassGetName(xmlSecNssKeyDataX509Id));
            goto done;
        }

        ret = xmlSecNssKeyDataX509AdoptKeyCert(x509Data, cert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecNssKeyDataX509AdoptKeyCert",
                                xmlSecKeyDataGetName(x509Data));
            goto done;
        }
        cert = CERT_DupCertificate(cert);
        if (cert == NULL) {
            xmlSecNssError("CERT_DupCertificate",
                           xmlSecKeyDataGetName(x509Data));
            goto done;
        }

        ret = xmlSecNssKeyDataX509AdoptCert(x509Data, cert);
        if (ret < 0) {
            xmlSecInternalError("xmlSecNssKeyDataX509AdoptCert",
                                xmlSecKeyDataGetName(x509Data));
            goto done;
        }
        cert = NULL;

        ret = xmlSecKeySetValue(key, data);
        if (ret < 0) {
            xmlSecInternalError("xmlSecKeySetValue",
                xmlSecKeyDataGetName(data));
            goto done;
        }
        data = NULL;

        ret = xmlSecKeyAdoptData(key, x509Data);
        if (ret < 0) {
            xmlSecInternalError("xmlSecKeyAdoptData",
                                xmlSecKeyDataGetName(x509Data));
            goto done;
        }
        x509Data = NULL;

        retval = key;
        key = NULL;
    }

done:
    if (cert != NULL) {
        CERT_DestroyCertificate(cert);
    }
    if (pubkey != NULL) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if (privkey != NULL) {
        SECKEY_DestroyPrivateKey(privkey);
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

    return (retval);
}
