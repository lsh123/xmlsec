/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * X509 certificates verification support functions for GnuTLS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:x509
 */

#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/gnutls/crypto.h>
#include <xmlsec/gnutls/x509.h>

#include "private.h"
#include "../cast_helpers.h"

/**************************************************************************
 *
 * Internal GnuTLS X509 store CTX
 *
 *************************************************************************/
typedef struct _xmlSecGnuTLSX509StoreCtx                xmlSecGnuTLSX509StoreCtx,
                                                        *xmlSecGnuTLSX509StoreCtxPtr;
struct _xmlSecGnuTLSX509StoreCtx {
    xmlSecPtrList certsTrusted;
    xmlSecPtrList certsUntrusted;
    xmlSecPtrList crls;
};

/****************************************************************************
 *
 * xmlSecGnuTLSKeyDataStoreX509Id:
 *
 ***************************************************************************/
XMLSEC_KEY_DATA_STORE_DECLARE(GnuTLSX509Store, xmlSecGnuTLSX509StoreCtx)
#define xmlSecGnuTLSX509StoreSize XMLSEC_KEY_DATA_STORE_SIZE(GnuTLSX509Store)

static int              xmlSecGnuTLSX509StoreInitialize                 (xmlSecKeyDataStorePtr store);
static void             xmlSecGnuTLSX509StoreFinalize                   (xmlSecKeyDataStorePtr store);

static xmlSecKeyDataStoreKlass xmlSecGnuTLSX509StoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass),
    xmlSecGnuTLSX509StoreSize,

    /* data */
    xmlSecNameX509Store,                        /* const xmlChar* name; */

    /* constructors/destructor */
    xmlSecGnuTLSX509StoreInitialize,            /* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecGnuTLSX509StoreFinalize,              /* xmlSecKeyDataStoreFinalizeMethod finalize; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

static gnutls_x509_crt_t xmlSecGnuTLSX509FindCert                       (xmlSecPtrListPtr certs,
                                                                         xmlSecGnuTLSX509FindCertCtxPtr findCertCtx);
static gnutls_x509_crt_t xmlSecGnuTLSX509FindSignedCert                 (xmlSecPtrListPtr certs,
                                                                         gnutls_x509_crt_t cert);
static gnutls_x509_crt_t xmlSecGnuTLSX509FindSignerCert                 (xmlSecPtrListPtr certs,
                                                                         gnutls_x509_crt_t cert);


/**
 * xmlSecGnuTLSX509StoreGetKlass:
 *
 * The GnuTLS X509 certificates key data store klass.
 *
 * Returns: pointer to GnuTLS X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId
xmlSecGnuTLSX509StoreGetKlass(void) {
    return(&xmlSecGnuTLSX509StoreKlass);
}

gnutls_x509_crt_t
xmlSecGnuTLSX509StoreFindCertByValue(xmlSecKeyDataStorePtr store, xmlSecKeyX509DataValuePtr x509Value) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    xmlSecGnuTLSX509FindCertCtx findCertCtx;
    int ret;
    gnutls_x509_crt_t res = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId), NULL);

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    ret = xmlSecGnuTLSX509FindCertCtxInitializeFromValue(&findCertCtx, x509Value);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSX509FindCertCtxInitializeFromValue", NULL);
        xmlSecGnuTLSX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    if(res == NULL) {
        res = xmlSecGnuTLSX509FindCert(&(ctx->certsTrusted), &findCertCtx);
    }
    if(res == NULL) {
        res = xmlSecGnuTLSX509FindCert(&(ctx->certsUntrusted), &findCertCtx);
    }

    /* done */
    xmlSecGnuTLSX509FindCertCtxFinalize(&findCertCtx);
    return(res);
}

xmlSecKeyPtr
xmlSecGnuTLSX509FindKeyByValue(xmlSecPtrListPtr keysList, xmlSecKeyX509DataValuePtr x509Value) {
    xmlSecGnuTLSX509FindCertCtx findCertCtx;
    xmlSecSize keysListSize, ii;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(keysList != NULL, NULL);
    xmlSecAssert2(x509Value != NULL, NULL);

    ret = xmlSecGnuTLSX509FindCertCtxInitializeFromValue(&findCertCtx, x509Value);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSX509FindCertCtxInitializeFromValue", NULL);
        xmlSecGnuTLSX509FindCertCtxFinalize(&findCertCtx);
        return(NULL);
    }

    keysListSize = xmlSecPtrListGetSize(keysList);
    for(ii = 0; ii < keysListSize; ++ii) {
        xmlSecKeyPtr key;
        xmlSecKeyDataPtr keyData;
        gnutls_x509_crt_t keyCert;

        /* get key's cert from x509 key data */
        key = (xmlSecKeyPtr)xmlSecPtrListGetItem(keysList, ii);
        if(key == NULL) {
            continue;
        }
        keyData = xmlSecKeyGetData(key, xmlSecGnuTLSKeyDataX509Id);
        if(keyData == NULL) {
            continue;
        }
        keyCert = xmlSecGnuTLSKeyDataX509GetKeyCert(keyData);
        if(keyCert == NULL) {
            continue;
        }

        /* does it match? */
        ret = xmlSecGnuTLSX509FindCertCtxMatch(&findCertCtx, keyCert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGnuTLSX509FindCertCtxMatch", NULL);
            xmlSecGnuTLSX509FindCertCtxFinalize(&findCertCtx);
            return(NULL);
        } else if(ret == 1) {
            res = key;
            break;
        }
    }

    /* done */
    xmlSecGnuTLSX509FindCertCtxFinalize(&findCertCtx);
    return(res);
}

static int
xmlSecGnuTLSX509CheckCrtTime(const gnutls_x509_crt_t cert, time_t ts) {
    time_t notValidBefore, notValidAfter;

    xmlSecAssert2(cert != NULL, -1);

    /* get expiration times */
    notValidBefore = gnutls_x509_crt_get_activation_time(cert);
    if(notValidBefore == (time_t)-1) {
        xmlSecGnuTLSError2("gnutls_x509_crt_get_activation_time", GNUTLS_E_SUCCESS, NULL,
            "cert activation time is invalid: %.lf",
            difftime(notValidBefore, (time_t)0));
        return(-1);
    }
    notValidAfter = gnutls_x509_crt_get_expiration_time(cert);
    if(notValidAfter == (time_t)-1) {
        xmlSecGnuTLSError2("gnutls_x509_crt_get_expiration_time", GNUTLS_E_SUCCESS, NULL,
            "cert expiration time is invalid: %.lf",
            difftime(notValidAfter, (time_t)0));
        return(-1);
    }

    /* check */
    if(ts < notValidBefore) {
        /* TODO: print cert subject */
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_NOT_YET_VALID, NULL, NULL);
        return(0);
    }
    if(ts > notValidAfter) {
        /* TODO: print cert subject */
        xmlSecOtherError(XMLSEC_ERRORS_R_CERT_HAS_EXPIRED, NULL, NULL);
        return(0);
    }

    /* good! */
    return(1);
}


static int
xmlSecGnuTLSX509CheckCrtsTime(const gnutls_x509_crt_t * cert_list, xmlSecSize cert_list_size, time_t ts) {
    xmlSecSize ii;
    int ret;

    xmlSecAssert2(cert_list != NULL, -1);

    for(ii = 0; ii < cert_list_size; ++ii) {
        const gnutls_x509_crt_t cert = cert_list[ii];
        if(cert == NULL) {
            continue;
        }

        ret = xmlSecGnuTLSX509CheckCrtTime(cert, ts);
        if(ret < 0) {
            xmlSecInternalError("", NULL);
            return(-1);
        } else if(ret == 0) {
            /* cert not valid yet or expired */
            return(0);
        }
    }

    /* GOOD! */
    return(1);
}

static int
xmlSecGnuTLSX509StoreGetTrustedCerts(xmlSecGnuTLSX509StoreCtxPtr ctx,
    gnutls_x509_crt_t** trusted, xmlSecSize* trusted_size
) {
    gnutls_x509_crt_t* res;
    xmlSecSize ii, res_size;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(trusted != NULL, -1);
    xmlSecAssert2(trusted_size != NULL, -1);

    /* get sizes */
    res_size = xmlSecPtrListGetSize(&(ctx->certsTrusted));
    if(res_size <= 0) {
        (*trusted) = NULL;
        (*trusted_size) = 0;
        return(0);
    }

    /* copy list */
    res = (gnutls_x509_crt_t *)xmlMalloc(sizeof(gnutls_x509_crt_t) * res_size);
    if(res == NULL) {
        xmlSecMallocError(sizeof(gnutls_x509_crt_t) * res_size, NULL);
        return(-1);
    }
    for(ii = 0; ii < res_size; ++ii) {
        res[ii] = xmlSecPtrListGetItem(&(ctx->certsTrusted), ii);
        if(res[ii] == NULL) {
            xmlSecInternalError("xmlSecPtrListGetItem(certsTrusted)", NULL);
            xmlFree(res);
            return(-1);
        }
    }

    /* done */
    (*trusted) = res;
    (*trusted_size) = res_size;
    return(0);
}


static int
xmlSecGnuTLSX509StoreGetCrls(xmlSecGnuTLSX509StoreCtxPtr ctx, xmlSecPtrListPtr extra_crls,
    gnutls_x509_crl_t** crls, xmlSecSize* crls_size
) {
    gnutls_x509_crl_t* res;
    xmlSecSize ii, res_size, res_pos = 0;
    xmlSecSize extra_crls_size, ctx_crls_size;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(extra_crls != NULL, -1);
    xmlSecAssert2(crls != NULL, -1);
    xmlSecAssert2(crls_size != NULL, -1);

    /* get sizes */
    extra_crls_size = xmlSecPtrListGetSize(extra_crls);
    ctx_crls_size = xmlSecPtrListGetSize(&(ctx->crls));
    res_size = extra_crls_size + ctx_crls_size;
    if(res_size <= 0) {
        (*crls) = NULL;
        (*crls_size) = 0;
        return(0);
    }

    /* copy lists */
    res = (gnutls_x509_crl_t *)xmlMalloc(sizeof(gnutls_x509_crl_t) * res_size);
    if(res == NULL) {
        xmlSecMallocError(sizeof(gnutls_x509_crl_t) * res_size, NULL);
        return(-1);
    }
    for(ii = 0; ii < extra_crls_size; ++ii, ++res_pos) {
        res[res_pos] = xmlSecPtrListGetItem(extra_crls, ii);
        if(res[res_pos] == NULL) {
            xmlSecInternalError("xmlSecPtrListGetItem(extra_crls)", NULL);
            xmlFree(res);
            return(-1);
        }
    }
    for(ii = 0; ii < ctx_crls_size; ++ii, ++res_pos) {
        res[res_pos] =  xmlSecPtrListGetItem(&(ctx->crls), ii);
        if(res[res_pos] == NULL) {
            xmlSecInternalError("xmlSecPtrListGetItem(crls)", NULL);
            xmlFree(res);
            return(-1);
        }
    }

    /* done */
    (*crls) = res;
    (*crls_size) = res_size;
    return(0);
}

static int
xmlSecGnuTLSX509StoreGetCertsChain(xmlSecGnuTLSX509StoreCtxPtr ctx, gnutls_x509_crt_t cert_to_verify,
    xmlSecPtrListPtr extra_certs,
    gnutls_x509_crt_t* certs_chain, xmlSecSize certs_chain_max_size, xmlSecSize* certs_chain_cur_size
) {
    gnutls_x509_crt_t cert, tmp;
    xmlSecSize ii, extra_certs_size, ctx_certs_size;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(extra_certs != NULL, -1);
    xmlSecAssert2(cert_to_verify != NULL, -1);
    xmlSecAssert2(certs_chain != NULL, -1);
    xmlSecAssert2(certs_chain_cur_size != NULL, -1);

    /* get sizes */
    extra_certs_size = xmlSecPtrListGetSize(extra_certs);
    ctx_certs_size = xmlSecPtrListGetSize(&(ctx->certsUntrusted));
    xmlSecAssert2((extra_certs_size + ctx_certs_size + 1) <= certs_chain_max_size, -1);

    /* construct the chain starting at cert_to_verify */
    for(cert = cert_to_verify, ii = 0; ((cert != 0) && (ii < certs_chain_max_size)); ++ii) {
        certs_chain[ii] = cert;

        /* find the cert that signed this one */
        tmp = xmlSecGnuTLSX509FindSignerCert(extra_certs, cert);
        if(tmp == NULL) {
            tmp = xmlSecGnuTLSX509FindSignerCert(&(ctx->certsUntrusted), cert);
        }
        cert = tmp;
    }

    (*certs_chain_cur_size) = ii;
    return(0);
}

/* returns 1 if verified, 0 if not, and < 0 value if an error occurs */
static int
xmlSecGnuTLSX509StoreVerifyCert(xmlSecGnuTLSX509StoreCtxPtr ctx,
    gnutls_x509_crt_t* certs_chain, xmlSecSize certs_chain_size,
    gnutls_x509_crt_t* trusted,  xmlSecSize trusted_size,
    gnutls_x509_crl_t* crls, xmlSecSize crls_size,
    const xmlSecKeyInfoCtx* keyInfoCtx
) {
    unsigned int certs_chain_len, trusted_len, crls_len;
    unsigned int flags = 0;
    unsigned int verify = 0;
    int err;
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(certs_chain != NULL, -1);
    xmlSecAssert2(certs_chain_size >= 1, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* do we even need to verify the cert? */
    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS) != 0) {
        return(1);
    }

    /* gnutls doesn't allow to specify "verification" timestamp so
     * we have to do it ourselves. Unfortunately it doesn't work
     * for CRLs yet: https://github.com/lsh123/xmlsec/issues/579
     */
    if(keyInfoCtx->certsVerificationTime > 0) {
        flags |= GNUTLS_VERIFY_DISABLE_TIME_CHECKS;
    }

    flags |= GNUTLS_VERIFY_ALLOW_UNSORTED_CHAIN;
    if((keyInfoCtx->flags & XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS) != 0) {
        /* legacy digests are still needed for tests */
        flags |= GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2;
        flags |= GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5;
#if GNUTLS_VERSION_NUMBER >= 0x030600
        flags |= GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1;
#endif /* GNUTLS_VERSION_NUMBER >= 0x030600 */
    }

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(certs_chain_size, certs_chain_len, return(1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(trusted_size, trusted_len, return(1), NULL);
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(crls_size, crls_len, return(1), NULL);
    err = gnutls_x509_crt_list_verify(
            certs_chain, certs_chain_len,
            trusted, trusted_len,
            crls, crls_len,
            flags,
            &verify);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_crt_list_verify", err, NULL);
        return(-1);
    }

    /* The certificate verification output will be put in verify and will be one or more of the
     * gnutls_certificate_status_t enumerated elements bitwise or'd. */
    if(verify != 0) {
        xmlSecOtherError2(XMLSEC_ERRORS_R_CERT_VERIFY_FAILED, NULL,
            "gnutls_x509_crt_list_verify: verification failed: status=%u", verify);
        return(0);
    }

    /* gnutls doesn't allow to specify "verification" timestamp so
     *  we have to do it ourselves */
    if(keyInfoCtx->certsVerificationTime > 0) {
        ret = xmlSecGnuTLSX509CheckCrtsTime(certs_chain, certs_chain_size, keyInfoCtx->certsVerificationTime);
        if(ret != 1) {
            xmlSecInternalError("xmlSecGnuTLSX509CheckCrtsTime", NULL);
            return(0);
        }
    }

    /* done! */
    return(1);
}

/**
 * xmlSecGnuTLSX509StoreVerifyKey:
 * @store:              the pointer to X509 key data store klass.
 * @key:                the pointer to key.
 * @keyInfoCtx:         the key info context for verification.
 *
 * Verifies @key with the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Adds @key to the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
int
xmlSecGnuTLSX509StoreVerifyKey(xmlSecKeyDataStorePtr store, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    xmlSecKeyDataPtr x509Data;
    gnutls_x509_crt_t key_cert;
    xmlSecPtrListPtr key_certs;
    xmlSecPtrListPtr key_crls;
    gnutls_x509_crt_t * certs_chain = NULL;
    xmlSecSize certs_chain_size = 0;
    xmlSecSize certs_chain_cur_size = 0;
    gnutls_x509_crt_t* trusted = NULL;
    xmlSecSize trusted_size = 0;
    gnutls_x509_crl_t* crls = NULL;
    xmlSecSize crls_size = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    /* retrieve X509 data and get key cert, other certs and crls */
    x509Data = xmlSecKeyGetData(key, xmlSecGnuTLSKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyGetData(xmlSecGnuTLSKeyDataX509Id)", xmlSecKeyDataStoreGetName(store));
        res = 0; /* key cannot be verified w/o key cert */
        goto done;
    }
    key_cert =  xmlSecGnuTLSKeyDataX509GetKeyCert(x509Data);
    if(key_cert == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataX509GetKeyCert", xmlSecKeyDataStoreGetName(store));
        res = 0; /* key cannot be verified w/o key cert */
        goto done;
    }
    key_certs = xmlSecGnuTLSKeyDataX509GetCerts(x509Data);
    if(key_certs == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataX509GetCerts", xmlSecKeyDataStoreGetName(store));
        goto done;
    }
    key_crls = xmlSecGnuTLSKeyDataX509GetCrls(x509Data);
    if(key_crls == NULL) {
        xmlSecInternalError("xmlSecGnuTLSKeyDataX509GetCrls", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* get trusted certs and crls lists */
    ret = xmlSecGnuTLSX509StoreGetTrustedCerts(ctx, &trusted, &trusted_size);
    if(ret< 0) {
        xmlSecInternalError("xmlSecGnuTLSX509StoreGetTrustedCerts", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    ret = xmlSecGnuTLSX509StoreGetCrls(ctx, key_crls, &crls, &crls_size);
    if(ret< 0) {
        xmlSecInternalError("xmlSecGnuTLSX509StoreGetCrls", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* prepare buffer for the certs chain */
    certs_chain_size = xmlSecPtrListGetSize(key_certs) + xmlSecPtrListGetSize(&(ctx->certsUntrusted)) + 1;
    if(certs_chain_size > 0) {
        certs_chain = (gnutls_x509_crt_t *)xmlMalloc(sizeof(gnutls_x509_crt_t) * certs_chain_size);
        if(certs_chain == NULL) {
            xmlSecMallocError(sizeof(gnutls_x509_crt_t) * certs_chain_size, xmlSecKeyDataStoreGetName(store));
            goto done;
        }
    }

    /* build the chain */
    ret = xmlSecGnuTLSX509StoreGetCertsChain(ctx, key_cert, key_certs, certs_chain, certs_chain_size, &certs_chain_cur_size);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListGetItem(certs)", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* try to verify */
    ret = xmlSecGnuTLSX509StoreVerifyCert(ctx,
        certs_chain, certs_chain_cur_size,
        trusted, trusted_size,
        crls, crls_size,
        keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSX509StoreVerifyCert(certs)", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* done! */
    if(ret == 1) {
        res = 1;
    } else {
        res = 0;
    }

done:
    /* cleanup */
    if(certs_chain != NULL) {
        xmlFree(certs_chain);
    }
    if(trusted != NULL) {
        xmlFree(trusted);
    }
    if(crls != NULL) {
        xmlFree(crls);
    }
    return(res);
}


/**
 * xmlSecGnuTLSX509StoreVerify:
 * @store:              the pointer to X509 key data store klass.
 * @certs:              the untrusted certificates.
 * @crls:               the crls.
 * @keyInfoCtx:         the pointer to &lt;dsig:KeyInfo/&gt; element processing context.
 *
 * Verifies @certs list.
 *
 * Returns: pointer to the first verified certificate from @certs.
 */
gnutls_x509_crt_t
xmlSecGnuTLSX509StoreVerify(xmlSecKeyDataStorePtr store,
                            xmlSecPtrListPtr certs,
                            xmlSecPtrListPtr crls,
                            const xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    gnutls_x509_crt_t res = NULL;
    xmlSecSize certs_size = 0;
    gnutls_x509_crt_t * certs_chain = NULL;
    xmlSecSize certs_chain_size = 0;
    gnutls_x509_crt_t * trusted = NULL;
    xmlSecSize trusted_size = 0;
    gnutls_x509_crl_t * all_crls = NULL;
    xmlSecSize all_crls_size = 0;
    xmlSecSize ii;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(crls != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    certs_size = xmlSecPtrListGetSize(certs);
    if(certs_size <= 0) {
        /* nothing to do */
        return(NULL);
    }

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* get trusted certs and crls lists */
    ret = xmlSecGnuTLSX509StoreGetTrustedCerts(ctx, &trusted, &trusted_size);
    if(ret< 0) {
        xmlSecInternalError("xmlSecGnuTLSX509StoreGetTrustedCerts", xmlSecKeyDataStoreGetName(store));
        goto done;
    }
    ret = xmlSecGnuTLSX509StoreGetCrls(ctx, crls, &all_crls, &all_crls_size);
    if(ret< 0) {
        xmlSecInternalError("xmlSecGnuTLSX509StoreGetCrls", xmlSecKeyDataStoreGetName(store));
        goto done;
    }

    /* prepare buffer for the certs chain */
    certs_chain_size = certs_size + xmlSecPtrListGetSize(&(ctx->certsUntrusted)) + 1;
    if(certs_chain_size > 0) {
        certs_chain = (gnutls_x509_crt_t *)xmlMalloc(sizeof(gnutls_x509_crt_t) * certs_chain_size);
        if(certs_chain == NULL) {
            xmlSecMallocError(sizeof(gnutls_x509_crt_t) * certs_chain_size, xmlSecKeyDataStoreGetName(store));
            goto done;
        }
    }

    /* we are going to build all possible cert chains and try to verify them */
    for(ii = 0; (ii < certs_size) && (res == NULL); ++ii) {
        gnutls_x509_crt_t cert;
        xmlSecSize certs_chain_cur_size = 0;

        cert = xmlSecPtrListGetItem(certs, ii);
        if(cert == NULL) {
            xmlSecInternalError("xmlSecPtrListGetItem(certs)", xmlSecKeyDataStoreGetName(store));
            goto done;
        }

        /* check if we are the "leaf" node in the certs chain */
        if(xmlSecGnuTLSX509FindSignedCert(certs, cert) != NULL) {
            continue;
        }

        /* build the chain */
        ret = xmlSecGnuTLSX509StoreGetCertsChain(ctx, cert, certs, certs_chain, certs_chain_size, &certs_chain_cur_size);
        if(ret < 0) {
            xmlSecInternalError("xmlSecPtrListGetItem(certs)", xmlSecKeyDataStoreGetName(store));
            goto done;
        }

        /* try to verify */
        ret = xmlSecGnuTLSX509StoreVerifyCert(ctx,
            certs_chain, certs_chain_cur_size,
            trusted, trusted_size,
            all_crls, all_crls_size,
            keyInfoCtx);
        if(ret < 0) {
            /* ignore all errors, don't stop, continue! */
            xmlSecInternalError("xmlSecGnuTLSX509StoreVerifyCert(certs)", xmlSecKeyDataStoreGetName(store));
            continue;
        } else if (ret != 1) {
            /* ignore if chain can't be verified, don't stop, continue! */
            continue;
        }

        /* DONE! */
        res = cert;
    }

done:
    /* cleanup */
    if(certs_chain != NULL) {
        xmlFree(certs_chain);
    }
    if(trusted != NULL) {
        xmlFree(trusted);
    }
    if(all_crls != NULL) {
        xmlFree(all_crls);
    }
    return(res);
}

/**
 * xmlSecGnuTLSX509StoreAdoptCert:
 * @store:              the pointer to X509 key data store klass.
 * @cert:               the pointer to GnuTLS X509 certificate.
 * @type:               the certificate type (trusted/untrusted).
 *
 * Adds trusted (root) or untrusted certificate to the store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSX509StoreAdoptCert(xmlSecKeyDataStorePtr store, gnutls_x509_crt_t cert, xmlSecKeyDataType type) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    if((type & xmlSecKeyDataTypeTrusted) != 0) {
        ret = xmlSecPtrListAdd(&(ctx->certsTrusted), cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecPtrListAdd(trusted)",
                                xmlSecKeyDataStoreGetName(store));
            return(-1);
        }
    } else {
        ret = xmlSecPtrListAdd(&(ctx->certsUntrusted), cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecPtrListAdd(untrusted)",
                                xmlSecKeyDataStoreGetName(store));
            return(-1);
        }
    }

    /* done */
    return(0);
}


/**
 * xmlSecGnuTLSX509StoreAdoptCrl:
 * @store:              the pointer to X509 key data store klass.
 * @crl:                the pointer to GnuTLS X509 CRL.
 *
 * Adds CRL to the store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecGnuTLSX509StoreAdoptCrl(xmlSecKeyDataStorePtr store, gnutls_x509_crl_t crl) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId), -1);
    xmlSecAssert2(crl != NULL, -1);

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

   ret = xmlSecPtrListAdd(&(ctx->crls), crl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListAdd(crls)", xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    /* done */
    return(0);
}


static int
xmlSecGnuTLSX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId), -1);

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecGnuTLSX509StoreCtx));

    ret = xmlSecPtrListInitialize(&(ctx->certsTrusted), xmlSecGnuTLSX509CrtListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(trusted)",
                            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    ret = xmlSecPtrListInitialize(&(ctx->certsUntrusted), xmlSecGnuTLSX509CrtListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(untrusted)",
                            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    ret = xmlSecPtrListInitialize(&(ctx->crls), xmlSecGnuTLSX509CrlListId);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize(crls)",
                            xmlSecKeyDataStoreGetName(store));
        return(-1);
    }

    return(0);
}

static void
xmlSecGnuTLSX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId));

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);

    xmlSecPtrListFinalize(&(ctx->certsTrusted));
    xmlSecPtrListFinalize(&(ctx->certsUntrusted));
    xmlSecPtrListFinalize(&(ctx->crls));

    memset(ctx, 0, sizeof(xmlSecGnuTLSX509StoreCtx));
}


/*****************************************************************************
 *
 * Low-level x509 functions
 *
 *****************************************************************************/
#define XMLSEC_GNUTLS_DN_ATTRS_SIZE             1024

int
xmlSecGnuTLSX509DnsEqual(const xmlChar * ll, const xmlChar * rr) {
    xmlSecGnuTLSDnAttr ll_attrs[XMLSEC_GNUTLS_DN_ATTRS_SIZE];
    xmlSecGnuTLSDnAttr rr_attrs[XMLSEC_GNUTLS_DN_ATTRS_SIZE];
    int ret;
    int res = -1;

    xmlSecAssert2(ll != NULL, -1);
    xmlSecAssert2(rr != NULL, -1);

    /* fast version first */
    if(xmlStrEqual(ll, rr)) {
        return(1);
    }

    /* prepare */
    xmlSecGnuTLSDnAttrsInitialize(ll_attrs, XMLSEC_GNUTLS_DN_ATTRS_SIZE);
    xmlSecGnuTLSDnAttrsInitialize(rr_attrs, XMLSEC_GNUTLS_DN_ATTRS_SIZE);

    /* parse */
    ret = xmlSecGnuTLSDnAttrsParse(ll, ll_attrs, XMLSEC_GNUTLS_DN_ATTRS_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSDnAttrsParse(ll)", NULL);
        goto done;
    }

    ret = xmlSecGnuTLSDnAttrsParse(rr, rr_attrs, XMLSEC_GNUTLS_DN_ATTRS_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGnuTLSDnAttrsParse(rr)", NULL);
        goto done;
    }

    /* compare */
    ret = xmlSecGnuTLSDnAttrsEqual(ll_attrs, XMLSEC_GNUTLS_DN_ATTRS_SIZE,
                                   rr_attrs, XMLSEC_GNUTLS_DN_ATTRS_SIZE);
    if(ret == 1) {
        res = 1;
    } else if(ret == 0) {
        res = 0;
    } else {
        xmlSecInternalError("xmlSecGnuTLSDnAttrsEqual", NULL);
        goto done;
    }

done:
    xmlSecGnuTLSDnAttrsDeinitialize(ll_attrs, XMLSEC_GNUTLS_DN_ATTRS_SIZE);
    xmlSecGnuTLSDnAttrsDeinitialize(rr_attrs, XMLSEC_GNUTLS_DN_ATTRS_SIZE);
    return(res);
}


/**
 * xmlSecGnuTLSX509CertCompareSKI:
 *
 * Returns 0 if SKI matches, 1 if SKI doesn't match and a negative value if an error occurs.
 */
int
xmlSecGnuTLSX509CertCompareSKI(gnutls_x509_crt_t cert, const xmlSecByte * ski, xmlSecSize skiSize) {
    xmlSecByte* buf = NULL;
    size_t bufSizeT = 0;
    xmlSecSize bufSize;
    unsigned int critical = 0;
    int err;
    int res = -1;

    xmlSecAssert2(cert != NULL, -1);
    xmlSecAssert2(ski != NULL, -1);
    xmlSecAssert2(skiSize > 0, -1);

    /* get ski size */
    err = gnutls_x509_crt_get_subject_key_id(cert, NULL, &bufSizeT, &critical);
    if((err != GNUTLS_E_SHORT_MEMORY_BUFFER) || (bufSizeT <= 0)) {
        xmlSecGnuTLSError("gnutls_x509_crt_get_subject_key_id", err, NULL);
        goto done;
    }
    XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(bufSizeT, bufSize, goto done, NULL);

    if(skiSize != bufSize) {
        /* doesn't match */
        res = 1;
        goto done;
    }

    /* allocate buffer */
    buf = (xmlSecByte *)xmlMalloc(bufSizeT + 1);
    if(buf == NULL) {
        xmlSecMallocError(bufSizeT + 1, NULL);
        goto done;
    }

    /* write ski out */
    err = gnutls_x509_crt_get_subject_key_id(cert, buf, &bufSizeT, &critical);
    if(err != GNUTLS_E_SUCCESS) {
        xmlSecGnuTLSError("gnutls_x509_crt_get_subject_key_id", err, NULL);
        goto done;
    }

    /* compare */
    if(memcmp(ski, buf, bufSize) != 0) {
        /* doesn't match */
        res = 1;
        goto done;
    }

    /* match! */
    res = 0;

done:
    /* cleanup */
    if(buf != NULL) {
        xmlFree(buf);
    }
    return(res);
}

static gnutls_x509_crt_t
xmlSecGnuTLSX509FindCert(xmlSecPtrListPtr certs, xmlSecGnuTLSX509FindCertCtxPtr findCertCtx) {
    xmlSecSize ii, sz;
    int ret;

    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(findCertCtx != NULL, NULL);

    /* todo: this is not the fastest way to search certs */
    sz = xmlSecPtrListGetSize(certs);
    for(ii = 0; (ii < sz); ++ii) {
        gnutls_x509_crt_t cert = xmlSecPtrListGetItem(certs, ii);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecPtrListGetItem", NULL, "pos=" XMLSEC_SIZE_FMT, ii);
            return(NULL);
        }


        /* returns 1 for match, 0 for no match, and a negative value if an error occurs */
        ret = xmlSecGnuTLSX509FindCertCtxMatch(findCertCtx, cert);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecGnuTLSX509FindCertCtxMatch", NULL, "pos=" XMLSEC_SIZE_FMT, ii);
            return(NULL);
        } else if(ret == 1) {
            return(cert);
        }
    }
    /* not found */
    return(NULL);
}

/* signed cert has issuer dn equal to our's subject dn */
static gnutls_x509_crt_t
xmlSecGnuTLSX509FindSignedCert(xmlSecPtrListPtr certs, gnutls_x509_crt_t cert) {
    gnutls_x509_crt_t res = NULL;
    xmlChar * subject = NULL;
    xmlSecSize ii, sz;

    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);

    /* get subject */
    subject = xmlSecGnuTLSX509CertGetSubjectDN(cert);
    if(subject == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertGetSubjectDN", NULL);
        goto done;
    }

    /* todo: this is not the fastest way to search certs */
    sz = xmlSecPtrListGetSize(certs);
    for(ii = 0; (ii < sz) && (res == NULL); ++ii) {
        gnutls_x509_crt_t tmp;
        xmlChar * issuer;

        tmp = xmlSecPtrListGetItem(certs, ii);
        if(tmp == NULL) {
            xmlSecInternalError2("xmlSecPtrListGetItem", NULL,
                "pos=" XMLSEC_SIZE_FMT, ii);
            goto done;
        }

        issuer = xmlSecGnuTLSX509CertGetIssuerDN(tmp);
        if(issuer == NULL) {
            xmlSecInternalError2("xmlSecGnuTLSX509CertGetIssuerDN", NULL,
                "pos=" XMLSEC_SIZE_FMT, ii);
            goto done;
        }

        /* are we done? */
        if(xmlSecGnuTLSX509DnsEqual(subject, issuer) == 1) {
            res = tmp;
        }
        xmlFree(issuer);
    }

done:
    if(subject != NULL) {
        xmlFree(subject);
    }
    return(res);
}

/* signer cert has subject dn equal to our's issuer dn */
static gnutls_x509_crt_t
xmlSecGnuTLSX509FindSignerCert(xmlSecPtrListPtr certs, gnutls_x509_crt_t cert) {
    gnutls_x509_crt_t res = NULL;
    xmlChar * issuer = NULL;
    xmlSecSize ii, sz;

    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(cert != NULL, NULL);

    /* get issuer */
    issuer = xmlSecGnuTLSX509CertGetIssuerDN(cert);
    if(issuer == NULL) {
        xmlSecInternalError("xmlSecGnuTLSX509CertGetIssuerDN", NULL);
        goto done;
    }

    /* todo: this is not the fastest way to search certs */
    sz = xmlSecPtrListGetSize(certs);
    for(ii = 0; (ii < sz) && (res == NULL); ++ii) {
        gnutls_x509_crt_t tmp;
        xmlChar * subject;

        tmp = xmlSecPtrListGetItem(certs, ii);
        if(tmp == NULL) {
            xmlSecInternalError2("xmlSecPtrListGetItem", NULL,
                "pos=" XMLSEC_SIZE_FMT, ii);
            goto done;
        }

        subject = xmlSecGnuTLSX509CertGetSubjectDN(tmp);
        if(subject == NULL) {
            xmlSecInternalError2("xmlSecGnuTLSX509CertGetSubjectDN", NULL,
                "pos=" XMLSEC_SIZE_FMT, ii);
            goto done;
        }

        /* are we done? */
        if((xmlSecGnuTLSX509DnsEqual(issuer, subject) == 1)) {
            res = tmp;
        }
        xmlFree(subject);
    }

done:
    if(issuer != NULL) {
        xmlFree(issuer);
    }
    return(res);
}

#endif /* XMLSEC_NO_X509 */
