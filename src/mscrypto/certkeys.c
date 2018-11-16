/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 * Copyright (C) 2003-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:certkeys
 * @Short_description: Certificate keys support functions for Microsoft Crypto API.
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <string.h>

#include <windows.h>
#include <wincrypt.h>

#ifndef XMLSEC_NO_GOST
#include "csp_oid.h"
#include "csp_calg.h"
#endif

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/bn.h>

#include <xmlsec/mscrypto/certkeys.h>
#include <xmlsec/mscrypto/crypto.h>
#include <xmlsec/mscrypto/x509.h>
#include "private.h"

// GOST CSP don't support keys duplicating, so we use NT4 analogs for these...
#ifndef XMLSEC_NO_GOST
#ifndef XMLSEC_MSCRYPTO_NT4
#define XMLSEC_MSCRYPTO_NT4
#endif
#endif


/**************************************************************************
 *
 * Internal MSCrypto PCCERT_CONTEXT key CTX
 *
 *************************************************************************/
typedef struct _xmlSecMSCryptoKeyDataCtx xmlSecMSCryptoKeyDataCtx,
                                                *xmlSecMSCryptoKeyDataCtxPtr;

#ifdef XMLSEC_MSCRYPTO_NT4
/*-
 * A wrapper of HCRYPTKEY, a reference counter is introduced, the function is
 * the same as CryptDuplicateKey. Because the CryptDuplicateKey is not support
 * by WINNT 4.0, the wrapper will enable the library work on WINNT 4.0
 */
struct _mscrypt_key {
        HCRYPTKEY hKey ;
        volatile LONG refcnt ;
} ;

/*-
 * A wrapper of HCRYPTPROV, a reference counter is introduced, the function is
 * the same as CryptContextAddRef. Because the CryptContextAddRef is not support
 * by WINNT 4.0, the wrapper will enable the library work on WINNT 4.0
 */
struct _mscrypt_prov {
        HCRYPTPROV hProv ;
    BOOL fCallerFreeProv ;
        volatile LONG refcnt ;
} ;
#endif /* XMLSEC_MSCRYPTO_NT4 */

/*
 * Since MSCrypto does not provide direct handles to private keys, we support
 * only private keys linked to a certificate context. The certificate context
 * also provides the public key. Only when no certificate context is used, and
 * a public key from xml document is provided, we need HCRYPTKEY.... The focus
 * now is however directed to certificates.  Wouter
 */
struct _xmlSecMSCryptoKeyDataCtx {
#ifndef XMLSEC_MSCRYPTO_NT4
    HCRYPTPROV                          hProv;
    BOOL                                fCallerFreeProv;
    HCRYPTKEY                           hKey;
#else /* XMLSEC_MSCRYPTO_NT4 */
    struct _mscrypt_prov*               p_prov ;
    struct _mscrypt_key*                p_key ;
#endif /* XMLSEC_MSCRYPTO_NT4 */
    PCCERT_CONTEXT                      pCert;
    const xmlSecMSCryptoProviderInfo  * providers;
    DWORD                               dwKeySpec;
    xmlSecKeyDataType   type;
};

#ifndef XMLSEC_MSCRYPTO_NT4

/******************************** Provider *****************************************/
#define xmlSecMSCryptoKeyDataCtxGetProvider(ctx)            (ctx)->hProv

static int
xmlSecMSCryptoKeyDataCtxCreateProvider(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert2(ctx != NULL, -1);

    ctx->hProv = 0;
    ctx->fCallerFreeProv = FALSE;
    return(0);
}

static void
xmlSecMSCryptoKeyDataCtxDestroyProvider(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    if ((ctx->hProv != 0) && (ctx->fCallerFreeProv)) {
        CryptReleaseContext(ctx->hProv, 0);
    }
    ctx->hProv = 0;
    ctx->fCallerFreeProv = FALSE;
}

static int
xmlSecMSCryptoKeyDataCtxSetProvider(xmlSecMSCryptoKeyDataCtxPtr ctx, HCRYPTPROV hProv, BOOL fCallerFreeProv)
{
    xmlSecAssert2(ctx != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyProvider(ctx);
    ctx->hProv               = hProv;
    ctx->fCallerFreeProv = fCallerFreeProv;
    return(0);
}

static int
xmlSecMSCryptoKeyDataCtxDuplicateProvider(xmlSecMSCryptoKeyDataCtxPtr ctxDst, xmlSecMSCryptoKeyDataCtxPtr ctxSrc) {
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxSrc != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyProvider(ctxDst);

    if(ctxSrc->hProv != 0) {
        if(!CryptContextAddRef(ctxSrc->hProv, NULL, 0)) {
                xmlSecMSCryptoError("CryptContextAddRef", NULL);
            return(-1);
        }

            ctxDst->hProv                   = ctxSrc->hProv;
            ctxDst->fCallerFreeProv = TRUE;
    }
    return(0);
}


/******************************** Key *****************************************/
#define xmlSecMSCryptoKeyDataCtxGetKey(ctx)            ((ctx)->hKey)

static int
xmlSecMSCryptoKeyDataCtxCreateKey(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert2(ctx != NULL, -1);

    ctx->hKey = 0;
    return(0);
}

static void
xmlSecMSCryptoKeyDataCtxDestroyKey(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    if (ctx->hKey != 0) {
            CryptDestroyKey(ctx->hKey);
    }
    ctx->hKey = 0;
}

static int
xmlSecMSCryptoKeyDataCtxSetKey(xmlSecMSCryptoKeyDataCtxPtr ctx, HCRYPTKEY hKey) {
    xmlSecAssert2(ctx != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyKey(ctx);
    ctx->hKey = hKey;
    return(0);
}

static int
xmlSecMSCryptoKeyDataCtxDuplicateKey(xmlSecMSCryptoKeyDataCtxPtr ctxDst, xmlSecMSCryptoKeyDataCtxPtr ctxSrc) {
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxSrc != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyKey(ctxDst);
    if (ctxSrc->hKey != 0) {
            if (!CryptDuplicateKey(ctxSrc->hKey, NULL, 0, &(ctxDst->hKey))) {
                xmlSecMSCryptoError("CryptDuplicateKey", NULL);
                return(-1);
            }
    }

    return(0);
}

#else /* XMLSEC_MSCRYPTO_NT4 */

/******************************** Provider *****************************************/
#define xmlSecMSCryptoKeyDataCtxGetProvider(ctx)            (((ctx)->p_prov) ? ((ctx)->p_prov->hProv) : 0)

static int
xmlSecMSCryptoKeyDataCtxCreateProvider(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert2(ctx != NULL, -1);

    ctx->p_prov = (struct _mscrypt_prov*)xmlMalloc(sizeof(struct _mscrypt_prov));
    if(ctx->p_prov == NULL) {
        xmlSecMallocError(sizeof(struct _mscrypt_prov), NULL);
        return(-1);
    }
    memset(ctx->p_prov, 0, sizeof(struct _mscrypt_prov));
    return(0);
}

static void
xmlSecMSCryptoKeyDataCtxDestroyProvider(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    if(ctx->p_prov != NULL) {
        if(InterlockedDecrement(&(ctx->p_prov->refcnt)) <= 0) {
            if((ctx->p_prov->hProv != 0) && (ctx->p_prov->fCallerFreeProv)) {
                CryptReleaseContext(ctx->p_prov->hProv, 0) ;
            }
            memset(ctx->p_prov, 0, sizeof(struct _mscrypt_prov));
            xmlFree(ctx->p_prov) ;
        }
        ctx->p_prov = NULL;
    }
}

static int
xmlSecMSCryptoKeyDataCtxSetProvider(xmlSecMSCryptoKeyDataCtxPtr ctx, HCRYPTPROV hProv, BOOL fCallerFreeProv)
{
    int ret;

    xmlSecAssert2(ctx != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyProvider(ctx);

    if((ctx->p_prov != NULL) && (ctx->p_prov->refcnt == 1)) {
        if((ctx->p_prov->hProv != 0) && (ctx->p_prov->fCallerFreeProv)) {
                CryptReleaseContext(ctx->p_prov->hProv, 0) ;
        }
        memset(ctx->p_prov, 0, sizeof(struct _mscrypt_prov));
    } else {
        xmlSecMSCryptoKeyDataCtxDestroyProvider(ctx);
        ret = xmlSecMSCryptoKeyDataCtxCreateProvider(ctx);
        if(ret != 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataCtxCreateProvider", NULL);
            return(-1);
        }
    }

    ctx->p_prov->hProv = hProv;
    ctx->p_prov->fCallerFreeProv = fCallerFreeProv;
    ctx->p_prov->refcnt = 1;
    return(0);
}

static int
xmlSecMSCryptoKeyDataCtxDuplicateProvider(xmlSecMSCryptoKeyDataCtxPtr ctxDst, xmlSecMSCryptoKeyDataCtxPtr ctxSrc) {
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxSrc != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyProvider(ctxDst);

    if (ctxSrc->p_prov != NULL) {
        ctxDst->p_prov = ctxSrc->p_prov;
        InterlockedIncrement(&(ctxDst->p_prov->refcnt));
    }

    return(0);
}

/********************************  Key  *****************************************/
#define xmlSecMSCryptoKeyDataCtxGetKey(ctx)            (((ctx)->p_key) ? ((ctx)->p_key->hKey) : 0)

static int
xmlSecMSCryptoKeyDataCtxCreateKey(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert2(ctx != NULL, -1);

    ctx->p_key = (struct _mscrypt_key*)xmlMalloc(sizeof(struct _mscrypt_key));
    if(ctx->p_key == NULL ) {
        xmlSecMallocError(sizeof(struct _mscrypt_key), NULL);
        return(-1);
    }
    memset(ctx->p_key, 0, sizeof(struct _mscrypt_key));
    return(0);
}

static void
xmlSecMSCryptoKeyDataCtxDestroyKey(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

        if(ctx->p_key != NULL) {
                if(InterlockedDecrement(&(ctx->p_key->refcnt)) <= 0) {
                        if(ctx->p_key->hKey != 0) {
                                CryptDestroyKey(ctx->p_key->hKey) ;
                        }
            memset(ctx->p_key, 0, sizeof(struct _mscrypt_key));
                        xmlFree(ctx->p_key) ;
                }
        ctx->p_key = NULL;
        }
}

static int
xmlSecMSCryptoKeyDataCtxSetKey(xmlSecMSCryptoKeyDataCtxPtr ctx, HCRYPTKEY hKey) {
    int ret;
    xmlSecAssert2(ctx != NULL, -1);

    if((ctx->p_key != NULL) && (ctx->p_key->refcnt == 1)) {
        if(ctx->p_key->hKey != 0) {
            CryptDestroyKey(ctx->p_key->hKey) ;
        }
        memset(ctx->p_key, 0, sizeof(struct _mscrypt_key));
    } else {
        xmlSecMSCryptoKeyDataCtxDestroyKey(ctx);
        ret = xmlSecMSCryptoKeyDataCtxCreateKey(ctx);
        if(ret != 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataCtxCreateKey", NULL);
            return(-1);
        }
    }
    ctx->p_key->hKey = hKey;
    ctx->p_key->refcnt = 1;
    return(0);
}

static int
xmlSecMSCryptoKeyDataCtxDuplicateKey(xmlSecMSCryptoKeyDataCtxPtr ctxDst, xmlSecMSCryptoKeyDataCtxPtr ctxSrc) {
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxSrc != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyKey(ctxDst);
    if (ctxSrc->p_key != NULL) {
        ctxDst->p_key = ctxSrc->p_key;
        InterlockedIncrement(&(ctxDst->p_key->refcnt));
    }

    return(0);
}

#endif /* XMLSEC_MSCRYPTO_NT4 */

/******************************** Cert *****************************************/
#define xmlSecMSCryptoKeyDataCtxGetCert(ctx)            ((ctx)->pCert)

static void
xmlSecMSCryptoKeyDataCtxCreateCert(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    ctx->pCert = NULL;
}

static void
xmlSecMSCryptoKeyDataCtxDestroyCert(xmlSecMSCryptoKeyDataCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);

    if(ctx->pCert != NULL) {
            CertFreeCertificateContext(ctx->pCert);
    }
    ctx->pCert = NULL;
}

static int
xmlSecMSCryptoKeyDataCtxSetCert(xmlSecMSCryptoKeyDataCtxPtr ctx, PCCERT_CONTEXT pCert) {
    xmlSecAssert2(ctx != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyCert(ctx);
    ctx->pCert = pCert;
    return(0);
}

static int
xmlSecMSCryptoKeyDataCtxDuplicateCert(xmlSecMSCryptoKeyDataCtxPtr ctxDst, xmlSecMSCryptoKeyDataCtxPtr ctxSrc) {
    xmlSecAssert2(ctxDst != NULL, -1);
    xmlSecAssert2(ctxSrc != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyCert(ctxDst);
    if(ctxSrc->pCert != NULL) {
            ctxDst->pCert = xmlSecMSCryptoCertDup(ctxSrc->pCert);
            if(ctxDst->pCert == NULL) {
                xmlSecInternalError("xmlSecMSCryptoPCCDup", NULL);
                return(-1);
            }
    }
    return(0);
}

/******************************************************************************
 *
 * xmlSecMSCryptoKeyDataCtx is located after xmlSecTransform
 *
 *****************************************************************************/
#define xmlSecMSCryptoKeyDataSize       \
    (sizeof(xmlSecKeyData) + sizeof(xmlSecMSCryptoKeyDataCtx))
#define xmlSecMSCryptoKeyDataGetCtx(data) \
    ((xmlSecMSCryptoKeyDataCtxPtr)(((xmlSecByte*)(data)) + sizeof(xmlSecKeyData)))

static int      xmlSecMSCryptoKeyDataDuplicate  (xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src);
static void             xmlSecMSCryptoKeyDataFinalize   (xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataGetSize    (xmlSecKeyDataPtr data);

/**
 * xmlSecMSCryptoKeyDataAdoptCert:
 * @data:               the pointer to MSCrypto pccert data.
 * @pCert:              the pointer to PCCERT key.
 *
 * Sets the value of key data.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
static int
xmlSecMSCryptoKeyDataAdoptCert(xmlSecKeyDataPtr data, PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    HCRYPTKEY hKey = 0;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), -1);
    xmlSecAssert2(pCert != NULL, -1);
    xmlSecAssert2(pCert->pCertInfo != NULL, -1);
    xmlSecAssert2((type & (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate)) != 0, -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    xmlSecMSCryptoKeyDataCtxDestroyProvider(ctx);
    xmlSecMSCryptoKeyDataCtxDestroyKey(ctx);
    xmlSecMSCryptoKeyDataCtxDestroyCert(ctx);

    ctx->type = type;

    /* Now we acquire a context for this key(pair). The context is needed
     * for the real crypto stuff in MS Crypto.
     */
    if((type & xmlSecKeyDataTypePrivate) != 0){
        HCRYPTPROV hProv = 0;
        BOOL fCallerFreeProv = FALSE;

        if (!CryptAcquireCertificatePrivateKey(pCert,
                    CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
                    NULL,
                    &hProv,
                    &(ctx->dwKeySpec),
                    &fCallerFreeProv)) {
                xmlSecMSCryptoError("CryptAcquireCertificatePrivateKey", NULL);
                return(-1);
        }
        ret = xmlSecMSCryptoKeyDataCtxSetProvider(ctx, hProv, fCallerFreeProv);
        if(ret != 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataCtxSetProvider", NULL);
            return(-1);
        }
    } else if((type & xmlSecKeyDataTypePublic) != 0){
        HCRYPTPROV hProv;

        hProv = xmlSecMSCryptoFindProvider(ctx->providers, NULL, CRYPT_VERIFYCONTEXT, FALSE);
        if (hProv == 0) {
            xmlSecInternalError("xmlSecMSCryptoFindProvider", NULL);
            return(-1);
        }
        ret = xmlSecMSCryptoKeyDataCtxSetProvider(ctx, hProv, TRUE);
        if(ret != 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataCtxSetProvider", NULL);
            return(-1);
        }
        ctx->dwKeySpec = 0;
    } else {
        xmlSecInvalidIntegerTypeError("keytype", type, "supported keytype", NULL);
        return(-1);
    }

    /* CryptImportPublicKeyInfo is only needed when a real key handle
     * is needed. The key handle is needed for de/encrypting and for
     * verifying of a signature, *not* for signing. We could call
     * CryptImportPublicKeyInfo in xmlSecMSCryptoKeyDataGetKey instead
     * so no unnecessary calls to CryptImportPublicKeyInfo are being
     * made. WK
     */
    if(!CryptImportPublicKeyInfo(xmlSecMSCryptoKeyDataCtxGetProvider(ctx),
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                &(pCert->pCertInfo->SubjectPublicKeyInfo),
                &hKey)) {
            xmlSecMSCryptoError("CryptImportPublicKeyInfo", NULL);
            return(-1);
    }

    ret = xmlSecMSCryptoKeyDataCtxSetKey(ctx, hKey);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataCtxSetKey", NULL);
        return(-1);
    }
    ret = xmlSecMSCryptoKeyDataCtxSetCert(ctx, pCert);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataCtxSetCert", NULL);
        return(-1);
    }
    return(0);
}

static int
xmlSecMSCryptoKeyDataAdoptKey(xmlSecKeyDataPtr data,
                              HCRYPTPROV hProv,
                              BOOL fCallerFreeProv,
                              HCRYPTKEY hKey,
                              DWORD dwKeySpec,
                              xmlSecKeyDataType type) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), -1);
    xmlSecAssert2(hKey != 0, -1);
    xmlSecAssert2(type & (xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate), -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    ret = xmlSecMSCryptoKeyDataCtxSetProvider(ctx, hProv, fCallerFreeProv);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataCtxSetProvider", NULL);
        return(-1);
    }
    ret = xmlSecMSCryptoKeyDataCtxSetKey(ctx, hKey);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataCtxSetKey", NULL);
        return(-1);
    }
    ret = xmlSecMSCryptoKeyDataCtxSetCert(ctx, NULL);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataCtxSetCert", NULL);
        return(-1);
    }

    ctx->dwKeySpec       = dwKeySpec;
    ctx->type            = type;

    return(0);
}

/**
 * xmlSecMSCryptoKeyDataGetKey:
 * @data:               the key data to retrieve certificate from.
 * @type:              type of key requested (public/private)
 *
 * Native MSCrypto key retrieval from xmlsec keydata. The
 * returned HKEY must not be destroyed by the caller.
 *
 * Returns: HKEY on success or NULL otherwise.
 */
HCRYPTKEY
xmlSecMSCryptoKeyDataGetKey(xmlSecKeyDataPtr data, xmlSecKeyDataType type) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);
    UNREFERENCED_PARAMETER(type);

    return(xmlSecMSCryptoKeyDataCtxGetKey(ctx));
}

/**
 * xmlSecMSCryptoKeyDataGetDecryptKey:
 * @data:       the key data pointer
 *
 * Native MSCrypto decrypt key retrieval from xmlsec keydata. The
 * returned HKEY must not be destroyed by the caller.
 *
 * Returns: HKEY on success or NULL otherwise.
 */
HCRYPTKEY
xmlSecMSCryptoKeyDataGetDecryptKey(xmlSecKeyDataPtr data) {
        xmlSecMSCryptoKeyDataCtxPtr ctx;
        HCRYPTKEY hKey;

        xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
        xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

        ctx = xmlSecMSCryptoKeyDataGetCtx(data);
        xmlSecAssert2(ctx != NULL, 0);

        if( !CryptGetUserKey(xmlSecMSCryptoKeyDataCtxGetProvider(ctx), AT_KEYEXCHANGE, &(hKey))) {
                xmlSecMSCryptoError("CryptGetUserKey", NULL);
                return(0);
        }
        return (hKey);
}

/**
 * xmlSecMSCryptoKeyDataGetCert:
 * @data:               the key data to retrieve certificate from.
 *
 * Native MSCrypto certificate retrieval from xmlsec keydata. The
 * returned PCCERT_CONTEXT must not be released by the caller.
 *
 * Returns: PCCERT_CONTEXT on success or NULL otherwise.
 */
PCCERT_CONTEXT
xmlSecMSCryptoKeyDataGetCert(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(xmlSecMSCryptoKeyDataCtxGetCert(ctx));
}

/**
 * xmlSecMSCryptoKeyDataGetMSCryptoProvider:
 * @data:              the key data
 *
 * Gets crypto provider handle
 *
 * Returns: the crypto provider handler or 0 if there is an error.
 */
HCRYPTPROV
xmlSecMSCryptoKeyDataGetMSCryptoProvider(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(xmlSecMSCryptoKeyDataCtxGetProvider(ctx));
}

/**
 * xmlSecMSCryptoKeyDataGetMSCryptoKeySpec:
 * @data:              the key data
 *
 * Gets key spec info.
 *
 * Returns: the key spec info from key data
 */
DWORD
xmlSecMSCryptoKeyDataGetMSCryptoKeySpec(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    return(ctx->dwKeySpec);
}

/**
 * xmlSecMSCryptoKeyDataGetMSCryptoProviderInfo:
 * @data:              the key data
 *
 * Gets key provider info.
 *
 * Returns: the key provider info.
 */
PCRYPT_KEY_PROV_INFO
xmlSecMSCryptoKeyDataGetMSCryptoProviderInfo(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    LPBYTE pInfoData = NULL;
    DWORD dwInfoDataLength = 0;

    xmlSecAssert2(data != NULL, NULL);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->pCert != NULL, NULL);

    if(!CertGetCertificateContextProperty(ctx->pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwInfoDataLength)) {
        xmlSecMSCryptoError("CertGetCertificateContextProperty", NULL);
        return NULL;
    }

    if(dwInfoDataLength > 0) {
        pInfoData = malloc(dwInfoDataLength * sizeof(BYTE));

        if(!CertGetCertificateContextProperty(ctx->pCert, CERT_KEY_PROV_INFO_PROP_ID, pInfoData, &dwInfoDataLength)) {
            xmlSecMSCryptoError("CertGetCertificateContextProperty", NULL);
            free(pInfoData);
            return NULL;
        }
    }

    return (PCRYPT_KEY_PROV_INFO)pInfoData;
}

static int
xmlSecMSCryptoKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecMSCryptoKeyDataCtxPtr ctxDst;
    xmlSecMSCryptoKeyDataCtxPtr ctxSrc;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecMSCryptoKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecMSCryptoKeyDataSize), -1);

    ctxDst = xmlSecMSCryptoKeyDataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);

    ctxSrc = xmlSecMSCryptoKeyDataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    if(xmlSecMSCryptoKeyDataCtxDuplicateProvider(ctxDst, ctxSrc) < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataCtxDuplicateProvider",
                                xmlSecKeyDataGetName(dst));
            return(-1);
    }

    if(xmlSecMSCryptoKeyDataCtxDuplicateKey(ctxDst, ctxSrc) < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataCtxDuplicateKey",
                                xmlSecKeyDataGetName(dst));
            return(-1);
    }

    if(xmlSecMSCryptoKeyDataCtxDuplicateCert(ctxDst, ctxSrc) < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataCtxDuplicateCert",
                                xmlSecKeyDataGetName(dst));
            return(-1);
    }

    ctxDst->dwKeySpec       = ctxSrc->dwKeySpec;
    ctxDst->providers       = ctxSrc->providers;
    ctxDst->type            = ctxSrc->type;

    return(0);
}

static int
xmlSecMSCryptoKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecMSCryptoKeyDataCtx));

    ret = xmlSecMSCryptoKeyDataCtxCreateProvider(ctx);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataCtxCreateProvider", NULL);
        return(-1);
    }
    ret = xmlSecMSCryptoKeyDataCtxCreateKey(ctx);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataCtxCreateKey", NULL);
        return(-1);
    }
    xmlSecMSCryptoKeyDataCtxCreateCert(ctx);
    return(0);
}

static void
xmlSecMSCryptoKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize));

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    xmlSecMSCryptoKeyDataCtxDestroyKey(ctx);
    xmlSecMSCryptoKeyDataCtxDestroyCert(ctx);
    xmlSecMSCryptoKeyDataCtxDestroyProvider(ctx);

    memset(ctx, 0, sizeof(xmlSecMSCryptoKeyDataCtx));
}

static int
xmlSecMSCryptoKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), 0);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);

    if(xmlSecMSCryptoKeyDataCtxGetCert(ctx) != NULL) {
        xmlSecAssert2(xmlSecMSCryptoKeyDataCtxGetCert(ctx)->pCertInfo != NULL, 0);
        return (CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    &(xmlSecMSCryptoKeyDataCtxGetCert(ctx)->pCertInfo->SubjectPublicKeyInfo)));
    } else if (xmlSecMSCryptoKeyDataCtxGetKey(ctx) != 0) {
        DWORD length = 0;
            DWORD lenlen = sizeof(DWORD);

        if (!CryptGetKeyParam(xmlSecMSCryptoKeyDataCtxGetKey(ctx), KP_KEYLEN, (BYTE *)&length, &lenlen, 0)) {
            xmlSecMSCryptoError("CertDuplicateCertificateContext", NULL);
            return(0);
        }
        return(length);
    }

    return (0);
}

static xmlSecKeyDataType
xmlSecMSCryptoKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);

    /* We could make a call to CryptFindCertificateKeyProvInfo here, to find out if
     * we *really* have a private key or not. However if the certificate is not
     * linked to a private key, the call takes an ridiculous amount of time.
     * the way it is now is better I think. WK.
     */
    return(ctx->type);
}

/**
 * xmlSecMSCryptoCertDup:
 * @pCert:              the pointer to cert.
 *
 * Duplicates the @pCert.
 *
 * Returns: pointer to newly created PCCERT_CONTEXT object or
 * NULL if an error occurs.
 */
PCCERT_CONTEXT xmlSecMSCryptoCertDup(PCCERT_CONTEXT pCert) {
    PCCERT_CONTEXT ret;

    xmlSecAssert2(pCert != NULL, NULL);

    ret = CertDuplicateCertificateContext(pCert);
    if(ret == NULL) {
        xmlSecMSCryptoError("CertDuplicateCertificateContext", NULL);
        return(NULL);
    }

    return(ret);
}


/**
 * xmlSecMSCryptoCertAdopt:
 * @pCert:              the pointer to cert.
 * @type:               the expected key type.
 *
 * Creates key data value from the cert.
 *
 * Returns: pointer to newly created xmlsec key or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecMSCryptoCertAdopt(PCCERT_CONTEXT pCert, xmlSecKeyDataType type) {
    xmlSecKeyDataPtr data = NULL;
    int ret;

    xmlSecAssert2(pCert != NULL, NULL);
    xmlSecAssert2(pCert->pCertInfo != NULL, NULL);
    xmlSecAssert2(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId != NULL, NULL);

#ifndef XMLSEC_NO_RSA
    if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA)) {
        data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataRsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataRsaId)", NULL);
            return(NULL);
        }
    }
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_DSA
    if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_X957_DSA /*szOID_DSALG_SIGN*/)) {
        data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataDsaId);
        if(data == NULL) {
                xmlSecInternalError("xmlSecKeyDataCreate(KeyDataDsaId)", NULL);
                return(NULL);
        }
    }
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_GOST
    if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,  szOID_MAGPRO_PUBKEY_SIGN_R3410_2001_CP) ||
        !strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,  szOID_MAGPRO_PUBKEY_SIGN_R3410_2001) ||
          !strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,  szOID_MAGPRO_PUBKEY_SIGN_R3410_94_CP)) {
        data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataGost2001Id);
        if(data == NULL) {
                xmlSecInternalError("xmlSecKeyDataCreate(KeyDataGost2001Id)", NULL);
                return(NULL);
        }
    }
#endif /* XMLSEC_NO_GOST*/
#ifndef XMLSEC_NO_GOST2012
    if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,  szOID_CP_GOST_R3410_12_256) ||
        !strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,  szOID_CP_GOST_R3411_12_256_R3410)) {
        data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataGost2012_256Id);
        if(data == NULL) {
                xmlSecInternalError("xmlSecKeyDataCreate(KeyDataGost2012_256Id)", NULL);
                return(NULL);
        }
    }
    if (!strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,  szOID_CP_GOST_R3410_12_512) ||
        !strcmp(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,  szOID_CP_GOST_R3411_12_512_R3410)) {
        data = xmlSecKeyDataCreate(xmlSecMSCryptoKeyDataGost2012_512Id);
        if(data == NULL) {
                xmlSecInternalError("xmlSecKeyDataCreate(KeyDataGost2012_512Id)", NULL);
                return(NULL);
        }
    }
#endif /* XMLSEC_NO_GOST2012 */

    if (NULL == data) {
        xmlSecInvalidStringTypeError("PCCERT_CONTEXT key type",
                pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                "unsupported keytype", NULL);
        return(NULL);
    }

    xmlSecAssert2(data != NULL, NULL);

    ret = xmlSecMSCryptoKeyDataAdoptCert(data, pCert, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoPCCDataAdoptPCC", NULL);
        xmlSecKeyDataDestroy(data);
        return(NULL);
    }
    return(data);
}


#ifndef XMLSEC_NO_RSA
/**************************************************************************
 *
 * <dsig:RSAKeyValue> processing
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue
 * The RSAKeyValue Element
 *
 * RSA key values have two fields: Modulus and Exponent.
 *
 * <RSAKeyValue>
 *   <Modulus>xA7SEU+e0yQH5rm9kbCDN9o3aPIo7HbP7tX6WOocLZAtNfyxSZDU16ksL6W
 *     jubafOqNEpcwR3RdFsT7bCqnXPBe5ELh5u4VEy19MzxkXRgrMvavzyBpVRgBUwUlV
 *        5foK5hhmbktQhyNdy/6LpQRhDUDsTvK+g9Ucj47es9AQJ3U=
 *   </Modulus>
 *   <Exponent>AQAB</Exponent>
 * </RSAKeyValue>
 *
 * Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are
 * represented in XML as octet strings as defined by the ds:CryptoBinary type.
 *
 * Schema Definition:
 *
 * <element name="RSAKeyValue" type="ds:RSAKeyValueType"/>
 * <complexType name="RSAKeyValueType">
 *   <sequence>
 *     <element name="Modulus" type="ds:CryptoBinary"/>
 *     <element name="Exponent" type="ds:CryptoBinary"/>
 *   </sequence>
 * </complexType>
 *
 * DTD Definition:
 *
 * <!ELEMENT RSAKeyValue (Modulus, Exponent) >
 * <!ELEMENT Modulus (#PCDATA) >
 * <!ELEMENT Exponent (#PCDATA) >
 *
 * ============================================================================
 *
 *
 *************************************************************************/

static int      xmlSecMSCryptoKeyDataRsaInitialize(xmlSecKeyDataPtr data);
static int      xmlSecMSCryptoKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src);
static void     xmlSecMSCryptoKeyDataRsaFinalize(xmlSecKeyDataPtr data);
static int      xmlSecMSCryptoKeyDataRsaXmlRead(xmlSecKeyDataId id,
                                                xmlSecKeyPtr key,
                                                xmlNodePtr node,
                                                xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecMSCryptoKeyDataRsaXmlWrite(xmlSecKeyDataId id,
                                                 xmlSecKeyPtr key,
                                                 xmlNodePtr node,
                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int      xmlSecMSCryptoKeyDataRsaGenerate(xmlSecKeyDataPtr data,
                                                 xmlSecSize sizeBits,
                                                 xmlSecKeyDataType type);

static xmlSecKeyDataType    xmlSecMSCryptoKeyDataRsaGetType(xmlSecKeyDataPtr data);
static xmlSecSize           xmlSecMSCryptoKeyDataRsaGetSize(xmlSecKeyDataPtr data);
static void                 xmlSecMSCryptoKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output);
static void                 xmlSecMSCryptoKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,                      /* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,                      /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCryptoKeyDataRsaInitialize,         /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataRsaDuplicate,          /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataRsaFinalize,           /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCryptoKeyDataRsaGenerate,           /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCryptoKeyDataRsaGetType,            /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoKeyDataRsaGetSize,            /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCryptoKeyDataRsaXmlRead,            /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCryptoKeyDataRsaXmlWrite,           /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataRsaDebugDump,          /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataRsaDebugXmlDump,       /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/* Ordered list of providers to search for algorithm implementation using
 * xmlSecMSCryptoFindProvider() function
 *
 * MUST END with { NULL, 0 } !!!
 */
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Rsa[] = {
    { XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV,                PROV_RSA_AES},
    { XMLSEC_CRYPTO_MS_ENH_RSA_AES_PROV_PROTOTYPE,      PROV_RSA_AES },
    { MS_STRONG_PROV,                                   PROV_RSA_FULL },
    { MS_ENHANCED_PROV,                                 PROV_RSA_FULL },
    { MS_DEF_PROV,                                      PROV_RSA_FULL },
    { NULL, 0 }
};

/**
 * xmlSecMSCryptoKeyDataRsaGetKlass:
 *
 * The MSCrypto RSA CertKey data klass.
 *
 * Returns: pointer to MSCrypto RSA key data klass.
 */
xmlSecKeyDataId
xmlSecMSCryptoKeyDataRsaGetKlass(void) {
    return(&xmlSecMSCryptoKeyDataRsaKlass);
}

static int
xmlSecMSCryptoKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), xmlSecKeyDataTypeUnknown);

    ret = xmlSecMSCryptoKeyDataInitialize(data);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataInitialize", NULL);
        return(-1);
    }

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    ctx->providers = xmlSecMSCryptoProviderInfo_Rsa;
    return(0);
}

static int
xmlSecMSCryptoKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataRsaId), -1);

    return(xmlSecMSCryptoKeyDataDuplicate(dst, src));
}

static void
xmlSecMSCryptoKeyDataRsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId));

    xmlSecMSCryptoKeyDataFinalize(data);
}

static int
xmlSecMSCryptoKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecBn modulus, exponent;
    xmlSecBuffer blob;
    unsigned int blobBufferLen;
    PUBLICKEYSTRUC* pubKeyStruc = NULL;
    RSAPUBKEY* pubKey = NULL;
    xmlSecByte* modulusBlob = NULL;
    xmlSecKeyDataPtr data = NULL;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    xmlNodePtr cur;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
                         xmlSecKeyDataKlassGetName(id),
                         "key already has a value");
        return(-1);
    }

    /* initialize buffers */
    ret = xmlSecBnInitialize(&modulus, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(modulus)",
                            xmlSecKeyDataKlassGetName(id));;
        return(-1);
    }

    ret = xmlSecBnInitialize(&exponent, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(exponent)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&modulus);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&blob, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(blob)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&modulus);
        xmlSecBnFinalize(&exponent);
        return(-1);
    }

    /* read xml */
    cur = xmlSecGetNextElementNode(node->children);

    /* first is Modulus node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeRSAModulus, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeRSAModulus,
                               xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecBnGetNodeValue(&modulus, cur, xmlSecBnBase64, 1);
    if((ret < 0) || (xmlSecBnGetSize(&modulus) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(modulus)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Exponent node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeRSAExponent, xmlSecDSigNs))) {    
        xmlSecInvalidNodeError(cur, xmlSecNodeRSAExponent, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBnGetNodeValue(&exponent, cur, xmlSecBnBase64, 1);
    if((ret < 0) || (xmlSecBnGetSize(&exponent) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(exponent)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeRSAPrivateExponent, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
         * MSCrypto does not support it. We just ignore it */
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* Now try to create the key */
    blobBufferLen = sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + xmlSecBnGetSize(&modulus);
    ret = xmlSecBufferSetSize(&blob, blobBufferLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize",
                             xmlSecKeyDataKlassGetName(id),
                             "size=%d", blobBufferLen);
        goto done;
    }

    /* Set the PUBLICKEYSTRUC */
    pubKeyStruc = (PUBLICKEYSTRUC *)xmlSecBufferGetData(&blob);
    pubKeyStruc->bType      = PUBLICKEYBLOB;
    pubKeyStruc->bVersion   = 0x02;
    pubKeyStruc->reserved   = 0;
    pubKeyStruc->aiKeyAlg   = CALG_RSA_KEYX | CALG_RSA_SIGN;

    /* Set the public key header */
    pubKey = (RSAPUBKEY*) (xmlSecBufferGetData(&blob) + sizeof(PUBLICKEYSTRUC));
    pubKey->magic           = 0x31415352;       /* == RSA1 public */
    pubKey->bitlen          = xmlSecBnGetSize(&modulus) * 8;    /* Number of bits in prime modulus */
    pubKey->pubexp          = 0;
    if(sizeof(pubKey->pubexp) < xmlSecBnGetSize(&exponent)) {
        xmlSecInvalidSizeLessThanError("exponent size",
                sizeof(pubKey->pubexp), xmlSecBnGetSize(&exponent),
                NULL);
        goto done;
    }
    xmlSecAssert2(xmlSecBnGetData(&exponent) != NULL, -1);
    memcpy(&(pubKey->pubexp), xmlSecBnGetData(&exponent), xmlSecBnGetSize(&exponent));

    modulusBlob = (xmlSecByte*) (xmlSecBufferGetData(&blob) + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY));
    xmlSecAssert2(xmlSecBnGetData(&modulus) != NULL, -1);
    memcpy(modulusBlob, xmlSecBnGetData(&modulus), xmlSecBnGetSize(&modulus));

    /* Now that we have the blob, import */
    hProv = xmlSecMSCryptoFindProvider(xmlSecMSCryptoProviderInfo_Rsa, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(hProv == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    if (!CryptImportKey(hProv, xmlSecBufferGetData(&blob), xmlSecBufferGetSize(&blob), 0, 0, &hKey)) {
        xmlSecMSCryptoError("CryptImportKey",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecMSCryptoKeyDataAdoptKey(data, hProv, TRUE, hKey, 0, xmlSecKeyDataTypePublic);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataAdoptKey",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    hProv = 0;
    hKey = 0;

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        goto done;
    }
    data = NULL;

    /* success */
    res = 0;

done:
    if (hProv == 0) {
        CryptReleaseContext(hProv, 0);
    }
    if (hKey != 0) {
        CryptDestroyKey(hKey);
    }
    if (data != 0) {
        xmlSecKeyDataDestroy(data);
    }

    xmlSecBnFinalize(&modulus);
    xmlSecBnFinalize(&exponent);
    xmlSecBufferFinalize(&blob);
    return(res);
}

static int
xmlSecMSCryptoKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    xmlSecBuffer buf;
    DWORD dwBlobLen;
    xmlSecByte* blob;
    PUBLICKEYSTRUC* pubKeyStruc;
    RSAPUBKEY *pubKey;
    xmlSecSize modulusLen, exponentLen;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataRsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecMSCryptoKeyDataRsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(xmlSecKeyGetValue(key));
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecMSCryptoKeyDataCtxGetKey(ctx) != 0, -1);

    if (!CryptExportKey(xmlSecMSCryptoKeyDataCtxGetKey(ctx), 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
        xmlSecMSCryptoError("CryptExportKey",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecBufferInitialize(&buf, dwBlobLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize",
                             xmlSecKeyDataKlassGetName(id),
                             "size=%ld", dwBlobLen);
        return(-1);
    }

    blob = xmlSecBufferGetData(&buf);
    if (!CryptExportKey(xmlSecMSCryptoKeyDataCtxGetKey(ctx), 0, PUBLICKEYBLOB, 0, blob, &dwBlobLen)) {
        xmlSecMSCryptoError("CryptExportKey",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    if (dwBlobLen < sizeof(PUBLICKEYSTRUC)) {
        xmlSecInvalidSizeLessThanError("Key blob", dwBlobLen, sizeof(PUBLICKEYSTRUC),
                xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* check PUBLICKEYSTRUC */
    pubKeyStruc = (PUBLICKEYSTRUC*)blob;
    if(pubKeyStruc->bVersion != 0x02) {
        xmlSecMSCryptoError2("CryptExportKey",
                             xmlSecKeyDataKlassGetName(id),
                             "pubKeyStruc->bVersion=%ld",
                             (long int)pubKeyStruc->bVersion);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    if(pubKeyStruc->bType != PUBLICKEYBLOB) {
        xmlSecMSCryptoError2("CryptExportKey",
                             xmlSecKeyDataKlassGetName(id),
                             "pubKeyStruc->bType=%ld",
                             (long int)pubKeyStruc->bType);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* check RSAPUBKEY */
    pubKey          = (RSAPUBKEY *)(blob + sizeof(PUBLICKEYSTRUC));
    if(pubKey->magic != 0x31415352) { /* RSA public key magic */
        xmlSecMSCryptoError2("CryptExportKey",
                             xmlSecKeyDataKlassGetName(id),
                             "pubKey->magic=0x%08lx",
                             (long int)pubKey->magic);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    modulusLen      = pubKey->bitlen / 8;

    if (dwBlobLen < sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + modulusLen) {
        xmlSecInvalidSizeLessThanError("Key blob",
                dwBlobLen, sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + modulusLen,
                xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    blob            += sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);

    /* first is Modulus node */
    cur = xmlSecAddChild(node, xmlSecNodeRSAModulus, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeRSAModulus)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    ret = xmlSecBnBlobSetNodeValue(blob, modulusLen, cur, xmlSecBnBase64, 1, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(NodeRSAModulus)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* next is Exponent node. */
    cur = xmlSecAddChild(node, xmlSecNodeRSAExponent, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeRSAExponent)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* Remove leading zero's (from least significant end) */
    blob        = (xmlSecByte*)(&(pubKey->pubexp));
    exponentLen = sizeof(pubKey->pubexp);
    while (exponentLen > 0 && blob[exponentLen - 1] == 0) {
        exponentLen--;
    }

    ret = xmlSecBnBlobSetNodeValue(blob, exponentLen, cur, xmlSecBnBase64, 1, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(NodeRSAExponent)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* next is PrivateExponent node: not supported in MSCrypto */

    /* done */
    xmlSecBufferFinalize(&buf);
    return(0);
}

static int
xmlSecMSCryptoKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits,
                                xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    DWORD dwKeySpec;
    DWORD dwSize;
    int res = -1;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* get provider */
    hProv = xmlSecMSCryptoFindProvider(ctx->providers, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(hProv == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider",
                            xmlSecKeyDataGetName(data));
        goto done;
    }

    dwKeySpec = AT_KEYEXCHANGE | AT_SIGNATURE;
    dwSize = ((sizeBits << 16) | CRYPT_EXPORTABLE);
    if (!CryptGenKey(hProv, CALG_RSA_SIGN, dwSize, &hKey)) {
        xmlSecMSCryptoError("CryptGenKey",
                            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecMSCryptoKeyDataAdoptKey(data, hProv, TRUE, hKey, dwKeySpec,
                                        xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataAdoptKey",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    hProv = 0;
    hKey = 0;

    /* success */
    res = 0;

done:
    if (hProv != 0) {
        CryptReleaseContext(hProv, 0);
    }

    if (hKey != 0) {
        CryptDestroyKey(hKey);
    }

    return(res);
}

static xmlSecKeyDataType
xmlSecMSCryptoKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    return(xmlSecMSCryptoKeyDataGetType(data));
}

static xmlSecSize
xmlSecMSCryptoKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId), 0);

    return (xmlSecMSCryptoKeyDataGetSize(data));
}

static void
xmlSecMSCryptoKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = %d\n",
            xmlSecMSCryptoKeyDataRsaGetSize(data));
}

static void xmlSecMSCryptoKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<RSAKeyValue size=\"%d\" />\n",
            xmlSecMSCryptoKeyDataRsaGetSize(data));
}

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_DSA
/**************************************************************************
 *
 * <dsig:DSAKeyValue> processing
 *
 *
 * The DSAKeyValue Element (http://www.w3.org/TR/xmldsig-core/#sec-DSAKeyValue)
 *
 * DSA keys and the DSA signature algorithm are specified in [DSS].
 * DSA public key values can have the following fields:
 *
 *   * P - a prime modulus meeting the [DSS] requirements
 *   * Q - an integer in the range 2**159 < Q < 2**160 which is a prime
 *         divisor of P-1
 *   * G - an integer with certain properties with respect to P and Q
 *   * Y - G**X mod P (where X is part of the private key and not made
 *         public)
 *   * J - (P - 1) / Q
 *   * seed - a DSA prime generation seed
 *   * pgenCounter - a DSA prime generation counter
 *
 * Parameter J is available for inclusion solely for efficiency as it is
 * calculatable from P and Q. Parameters seed and pgenCounter are used in the
 * DSA prime number generation algorithm specified in [DSS]. As such, they are
 * optional but must either both be present or both be absent. This prime
 * generation algorithm is designed to provide assurance that a weak prime is
 * not being used and it yields a P and Q value. Parameters P, Q, and G can be
 * public and common to a group of users. They might be known from application
 * context. As such, they are optional but P and Q must either both appear or
 * both be absent. If all of P, Q, seed, and pgenCounter are present,
 * implementations are not required to check if they are consistent and are
 * free to use either P and Q or seed and pgenCounter. All parameters are
 * encoded as base64 [MIME] values.
 *
 * Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are
 * represented in XML as octet strings as defined by the ds:CryptoBinary type.
 *
 * Schema Definition:
 *
 * <element name="DSAKeyValue" type="ds:DSAKeyValueType"/>
 * <complexType name="DSAKeyValueType">
 *   <sequence>
 *     <sequence minOccurs="0">
 *        <element name="P" type="ds:CryptoBinary"/>
 *        <element name="Q" type="ds:CryptoBinary"/>
 *     </sequence>
 *     <element name="G" type="ds:CryptoBinary" minOccurs="0"/>
 *     <element name="Y" type="ds:CryptoBinary"/>
 *     <element name="J" type="ds:CryptoBinary" minOccurs="0"/>
 *     <sequence minOccurs="0">
 *       <element name="Seed" type="ds:CryptoBinary"/>
 *       <element name="PgenCounter" type="ds:CryptoBinary"/>
 *     </sequence>
 *   </sequence>
 * </complexType>
 *
 * DTD Definition:
 *
 *  <!ELEMENT DSAKeyValue ((P, Q)?, G?, Y, J?, (Seed, PgenCounter)?) >
 *  <!ELEMENT P (#PCDATA) >
 *  <!ELEMENT Q (#PCDATA) >
 *  <!ELEMENT G (#PCDATA) >
 *  <!ELEMENT Y (#PCDATA) >
 *  <!ELEMENT J (#PCDATA) >
 *  <!ELEMENT Seed (#PCDATA) >
 *  <!ELEMENT PgenCounter (#PCDATA) >
 *
 * ============================================================================
 *
 * To support reading/writing private keys an X element added (before Y).
 * todo: The current implementation does not support Seed and PgenCounter!
 * by this the P, Q and G are *required*!
 *
 *************************************************************************/
static int              xmlSecMSCryptoKeyDataDsaInitialize(xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataDsaDuplicate(xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecMSCryptoKeyDataDsaFinalize(xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataDsaXmlRead (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataDsaXmlWrite(xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataDsaGenerate(xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecMSCryptoKeyDataDsaGetType(xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecMSCryptoKeyDataDsaGetSize(xmlSecKeyDataPtr data);
static void              xmlSecMSCryptoKeyDataDsaDebugDump(xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecMSCryptoKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefDSAKeyValue,              /* const xmlChar* href; */
    xmlSecNodeDSAKeyValue,              /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCryptoKeyDataDsaInitialize, /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataDsaDuplicate,  /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataDsaFinalize,   /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecMSCryptoKeyDataDsaGenerate,   /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCryptoKeyDataDsaGetType,    /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoKeyDataDsaGetSize,    /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                               /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecMSCryptoKeyDataDsaXmlRead,    /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecMSCryptoKeyDataDsaXmlWrite,   /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                               /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                               /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataDsaDebugDump,  /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataDsaDebugXmlDump,/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/* Ordered list of providers to search for algorithm implementation using
 * xmlSecMSCryptoFindProvider() function
 *
 * MUST END with { NULL, 0 } !!!
 */
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Dss[] = {
    { MS_DEF_DSS_PROV,              PROV_DSS },
    { NULL, 0 }
};


/**
 * xmlSecMSCryptoKeyDataDsaGetKlass:
 *
 * The DSA key data klass.
 *
 * Returns: pointer to DSA key data klass.
 */
xmlSecKeyDataId
xmlSecMSCryptoKeyDataDsaGetKlass(void) {
    return(&xmlSecMSCryptoKeyDataDsaKlass);
}


static int
xmlSecMSCryptoKeyDataDsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId), xmlSecKeyDataTypeUnknown);

    ret = xmlSecMSCryptoKeyDataInitialize(data);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataInitialize", NULL);
        return(-1);
    }

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    ctx->providers = xmlSecMSCryptoProviderInfo_Dss;
    return(0);
}

static int
xmlSecMSCryptoKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataDsaId), -1);

    return(xmlSecMSCryptoKeyDataDuplicate(dst, src));
}

static void
xmlSecMSCryptoKeyDataDsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId));

    xmlSecMSCryptoKeyDataFinalize(data);
}

static int
xmlSecMSCryptoKeyDataDsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                           xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data = NULL;
    xmlNodePtr cur;
    xmlSecBn p, q, g, y;
    xmlSecBuffer blob;
    unsigned int blobBufferLen;
    PUBLICKEYSTRUC *pubKeyStruc = NULL;
    DSSPUBKEY *pubKey = NULL;
    DSSSEED* seed = NULL;
    BYTE *buf = NULL;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    xmlSecSize i;
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecMSCryptoKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(xmlSecKeyGetValue(key) != NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_INVALID_KEY_DATA,
                         xmlSecKeyDataKlassGetName(id),
                         "key already has a value");
        return(-1);
    }

    /* initialize buffers */
    ret = xmlSecBnInitialize(&p, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(p)",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecBnInitialize(&q, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(q)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&p);
        return(-1);
    }

    ret = xmlSecBnInitialize(&g, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(g)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&p);
        xmlSecBnFinalize(&q);
        return(-1);
    }

    ret = xmlSecBnInitialize(&y, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnInitialize(y)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&p);
        xmlSecBnFinalize(&q);
        xmlSecBnFinalize(&g);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&blob, 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(blob)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBnFinalize(&p);
        xmlSecBnFinalize(&q);
        xmlSecBnFinalize(&g);
        xmlSecBnFinalize(&y);
        return(-1);
    }

    /* read xml */
    cur = xmlSecGetNextElementNode(node->children);

    /* first is P node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeDSAP, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAP, xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecBnGetNodeValue(&p, cur, xmlSecBnBase64, 1);
    if((ret < 0) || (xmlSecBnGetSize(&p) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(p)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is Q node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAQ, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAQ, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBnGetNodeValue(&q, cur, xmlSecBnBase64, 1);
    if((ret < 0) || (xmlSecBnGetSize(&q) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(q)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is G node. It is REQUIRED because we do not support Seed and PgenCounter*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAG, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAG, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBnGetNodeValue(&g, cur, xmlSecBnBase64, 1);
    if((ret < 0) || (xmlSecBnGetSize(&q) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(g)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAX, xmlSecNs))) {
        /* next is X node. It is REQUIRED for private key but
         * MSCrypto does not support it, we just ignore it */

        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* next is Y node. */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDSAY, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDSAY, xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    ret = xmlSecBnGetNodeValue(&y, cur, xmlSecBnBase64, 1);
    if((ret < 0) || (xmlSecBnGetSize(&y) == 0)) {
        xmlSecInternalError("xmlSecBnGetNodeValue(y)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* todo: add support for J */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAJ, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* todo: add support for seed */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSASeed, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* todo: add support for pgencounter */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeDSAPgenCounter, xmlSecDSigNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyDataKlassGetName(id))
        goto done;
    }

    /* we assume that sizeof(q) < 0x14, sizeof(g) <= sizeof(p) and sizeof(y) <= sizeof(p) */
    blobBufferLen = sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY) + 3 * xmlSecBnGetSize(&p) + 0x14 + sizeof(DSSSEED);
    ret = xmlSecBufferSetSize(&blob, blobBufferLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL, "size=%d", blobBufferLen);
        goto done;
    }

    /* Set PUBLICKEYSTRUC  */
    pubKeyStruc             = (PUBLICKEYSTRUC *)xmlSecBufferGetData(&blob);
    pubKeyStruc->bType      = PUBLICKEYBLOB;
    pubKeyStruc->bVersion   = 0x02;
    pubKeyStruc->reserved   = 0;
    pubKeyStruc->aiKeyAlg   = CALG_DSS_SIGN;

    /* Set the public key header */
    pubKey                  = (DSSPUBKEY *) (xmlSecBufferGetData(&blob) + sizeof(PUBLICKEYSTRUC));
    pubKey->magic           = 0x31535344;       /* == DSS1 pub key */
    pubKey->bitlen          = xmlSecBnGetSize(&p) * 8; /* Number of bits in prime modulus */

    /* copy the key data */
    buf                     = (BYTE*) (xmlSecBufferGetData(&blob) + sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY));

    /* set p */
    xmlSecAssert2(xmlSecBnGetData(&p) != NULL, -1);
    memcpy(buf, xmlSecBnGetData(&p), xmlSecBnGetSize(&p));
    buf += xmlSecBnGetSize(&p);

    /* set q */
    if(xmlSecBnGetSize(&q) > 0x14) {
        xmlSecInvalidSizeLessThanError("DSA key q",
                                       xmlSecBnGetSize(&q), 0x14, NULL);
        goto done;
    }
    xmlSecAssert2(xmlSecBnGetData(&q) != NULL, -1);
    memcpy(buf, xmlSecBnGetData(&q), xmlSecBnGetSize(&q));
    buf += xmlSecBnGetSize(&q);

    /* Pad with zeros */
    for(i = xmlSecBnGetSize(&q); i < 0x14; ++i) {
        *(buf++) = 0;
    }

    /* set generator */
    if(xmlSecBnGetSize(&g) > xmlSecBnGetSize(&p)) {
        xmlSecInvalidSizeMoreThanError("DSA key g",
                                       xmlSecBnGetSize(&g),
                                       xmlSecBnGetSize(&p),
                                       NULL);
        goto done;
    }
    xmlSecAssert2(xmlSecBnGetData(&g) != NULL, -1);
    memcpy(buf, xmlSecBnGetData(&g), xmlSecBnGetSize(&g));
    buf += xmlSecBnGetSize(&g);
    /* Pad with zeros */
    for(i = xmlSecBnGetSize(&g); i < xmlSecBnGetSize(&p); ++i) {
        *(buf++) = 0;
    }

    /* Public key */
    if(xmlSecBnGetSize(&y) > xmlSecBnGetSize(&p)) {
        xmlSecInvalidSizeMoreThanError("DSA key y",
                                       xmlSecBnGetSize(&y),
                                       xmlSecBnGetSize(&p),
                                       NULL);
        goto done;
    }
    xmlSecAssert2(xmlSecBnGetData(&y) != NULL, -1);
    memcpy(buf, xmlSecBnGetData(&y), xmlSecBnGetSize(&y));
    buf += xmlSecBnGetSize(&y);
    /* Pad with zeros */
    for(i = xmlSecBnGetSize(&y); i < xmlSecBnGetSize(&p); ++i) {
        *(buf++) = 0;
    }

    /* Set seed to 0xFFFFFFFFF */
    seed = (DSSSEED*)buf;
    memset(seed, 0, sizeof(*seed));
    seed->counter = 0xFFFFFFFF; /* SEED Counter set to 0xFFFFFFFF will cause seed to be ignored */

    hProv = xmlSecMSCryptoFindProvider(xmlSecMSCryptoProviderInfo_Dss, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(hProv == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* import the key blob */
    if (!CryptImportKey(hProv, xmlSecBufferGetData(&blob), xmlSecBufferGetSize(&blob), 0, 0, &hKey)) {
        xmlSecMSCryptoError("CryptImportKey",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecInternalError("xmlSecKeyDataCreate",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecMSCryptoKeyDataAdoptKey(data, hProv, TRUE, hKey, 0, xmlSecKeyDataTypePublic);
    if(ret < 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataAdoptKey",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    hProv = 0;
    hKey = 0;

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    data = NULL;

    /* success */
    res = 0;

done:
    if (hKey != 0) {
        CryptDestroyKey(hKey);
    }
    if (hProv != 0) {
        CryptReleaseContext(hProv, 0);
    }
    if (data != NULL) {
        xmlSecKeyDataDestroy(data);
    }

    xmlSecBufferFinalize(&blob);
    xmlSecBnFinalize(&p);
    xmlSecBnFinalize(&q);
    xmlSecBnFinalize(&g);
    xmlSecBnFinalize(&y);

    return(res);
}

static int
xmlSecMSCryptoKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    xmlSecBuffer buf;
    DWORD dwBlobLen;
    xmlSecByte* blob;
    PUBLICKEYSTRUC* pubKeyStruc;
    DSSPUBKEY *pubKey;
    xmlSecSize keyLen, len;
    xmlNodePtr cur;
    int ret;


    xmlSecAssert2(id == xmlSecMSCryptoKeyDataDsaId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(xmlSecKeyGetValue(key), xmlSecMSCryptoKeyDataDsaId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ctx = xmlSecMSCryptoKeyDataGetCtx(xmlSecKeyGetValue(key));
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(xmlSecMSCryptoKeyDataCtxGetKey(ctx) != 0, -1);

    if (!CryptExportKey(xmlSecMSCryptoKeyDataCtxGetKey(ctx), 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
        xmlSecInternalError("CryptExportKey",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    ret = xmlSecBufferInitialize(&buf, dwBlobLen);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize",
                             xmlSecKeyDataKlassGetName(id),
                             "size=%ld", dwBlobLen);
        return(-1);
    }

    blob = xmlSecBufferGetData(&buf);
    if (!CryptExportKey(xmlSecMSCryptoKeyDataCtxGetKey(ctx), 0, PUBLICKEYBLOB, 0, blob, &dwBlobLen)) {
        xmlSecMSCryptoError("CryptExportKey",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    if (dwBlobLen < sizeof(PUBLICKEYSTRUC)) {
        xmlSecInvalidSizeLessThanError("Key blob", dwBlobLen, sizeof(PUBLICKEYSTRUC),
                xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* check PUBLICKEYSTRUC */
    pubKeyStruc     = (PUBLICKEYSTRUC*)blob;
    if(pubKeyStruc->bVersion != 0x02) {
        xmlSecMSCryptoError2("CryptExportKey",
                             xmlSecKeyDataKlassGetName(id),
                             "pubKeyStruc->bVersion=%ld",
                             (long int)pubKeyStruc->bVersion);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    if(pubKeyStruc->bType != PUBLICKEYBLOB) {
        xmlSecMSCryptoError2("CryptExportKey",
                             xmlSecKeyDataKlassGetName(id),
                             "pubKeyStruc->bType=%ld",
                             (long int)pubKeyStruc->bType);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* check DSSPUBKEY */
    pubKey          = (DSSPUBKEY*)(blob + sizeof(PUBLICKEYSTRUC));
    if(pubKey->magic != 0x31535344) { /* DSS key magic */
        xmlSecMSCryptoError2("CryptExportKey",
                             xmlSecKeyDataKlassGetName(id),
                             "pubKey->magic=0x%08lx",
                             (long int)pubKey->magic);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    keyLen          = pubKey->bitlen / 8;

    /* we assume that sizeof(q) < 0x14, sizeof(g) <= sizeof(p) and sizeof(y) <= sizeof(p) */
    if (dwBlobLen < sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY) + 3 * keyLen + 0x14 + sizeof(DSSSEED)) {
        xmlSecInvalidSizeLessThanError("Key blob",
                dwBlobLen, sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY) + 3 * keyLen + 0x14 + sizeof(DSSSEED),
                xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    blob            += sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY);

    /* first is P node */
    cur = xmlSecAddChild(node, xmlSecNodeDSAP, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeDSAP)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    ret = xmlSecBnBlobSetNodeValue(blob, keyLen, cur, xmlSecBnBase64, 1, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(NodeDSAP)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    blob += keyLen;

    /* next is Q node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAQ, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeDSAQ)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* we think that the size of q is 0x14, skip trailing zeros */
    for(len = 0x14; len > 0 && blob[len - 1] == 0; --len);

    ret = xmlSecBnBlobSetNodeValue(blob, len, cur, xmlSecBnBase64, 1, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(NodeDSAQ)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    blob += 0x14;

    /* next is G node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAG, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeDSAG)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* skip trailing zeros */
    for(len = keyLen; len > 0 && blob[len - 1] == 0; --len);

    ret = xmlSecBnBlobSetNodeValue(blob, len, cur, xmlSecBnBase64, 1, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(NodeDSAG)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    blob += keyLen;

    /* next is X node: not supported in MSCrypto */

    /* next is Y node. */
    cur = xmlSecAddChild(node, xmlSecNodeDSAY, xmlSecDSigNs);
    if(cur == NULL) {
        xmlSecInternalError("xmlSecAddChild(NodeDSAY)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* skip trailing zeros */
    for(len = keyLen; len > 0 && blob[len - 1] == 0; --len);

    ret = xmlSecBnBlobSetNodeValue(blob, len, cur, xmlSecBnBase64, 1, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBnBlobSetNodeValue(NodeDSAY)",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    blob += keyLen;

    xmlSecBufferFinalize(&buf);
    return(0);
}

static int
xmlSecMSCryptoKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    DWORD dwKeySpec;
    DWORD dwSize;
    int res = -1;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecMSCryptoKeyDataSize), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);
    UNREFERENCED_PARAMETER(type);

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);

    hProv = xmlSecMSCryptoFindProvider(ctx->providers, NULL, CRYPT_VERIFYCONTEXT, TRUE);
    if(hProv == 0) {
        xmlSecInternalError("xmlSecMSCryptoFindProvider",
                            xmlSecKeyDataGetName(data));
        return(-1);
    }

    dwKeySpec = AT_SIGNATURE;
    dwSize = ((sizeBits << 16) | CRYPT_EXPORTABLE);
    if (!CryptGenKey(hProv, CALG_DSS_SIGN, dwSize, &hKey)) {
            xmlSecMSCryptoError("CryptGenKey",
                                xmlSecKeyDataGetName(data));
            goto done;
    }

    ret = xmlSecMSCryptoKeyDataAdoptKey(data, hProv, TRUE, hKey, dwKeySpec,
        xmlSecKeyDataTypePublic | xmlSecKeyDataTypePrivate);
    if(ret < 0) {
            xmlSecInternalError("xmlSecMSCryptoKeyDataAdoptKey",
                                xmlSecKeyDataGetName(data));
            goto done;
    }
    hProv = 0;
    hKey = 0;

    /* success */
    res = 0;

done:
    if (hProv != 0) {
        CryptReleaseContext(hProv, 0);
    }

    if (hKey != 0) {
            CryptDestroyKey(hKey);
    }

    return(res);
}

static xmlSecKeyDataType
xmlSecMSCryptoKeyDataDsaGetType(xmlSecKeyDataPtr data) {
    return(xmlSecMSCryptoKeyDataGetType(data));
}

static xmlSecSize
xmlSecMSCryptoKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId), 0);

    return xmlSecMSCryptoKeyDataGetSize(data);
}

static void
xmlSecMSCryptoKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = %d\n",
            xmlSecMSCryptoKeyDataDsaGetSize(data));
}

static void
xmlSecMSCryptoKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<DSAKeyValue size=\"%d\" />\n",
            xmlSecMSCryptoKeyDataDsaGetSize(data));
}

#endif /* XMLSEC_NO_DSA */


#ifndef XMLSEC_NO_GOST
/**************************************************************************
 *
 * GOST2001 xml key representation processing. Contain errors.
 *
 *************************************************************************/
static int              xmlSecMSCryptoKeyDataGost2001Initialize(xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataGost2001Duplicate(xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecMSCryptoKeyDataGost2001Finalize(xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataGost2001XmlRead    (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataGost2001XmlWrite(xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataGost2001Generate(xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecMSCryptoKeyDataGost2001GetType(xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecMSCryptoKeyDataGost2001GetSize(xmlSecKeyDataPtr data);
static void              xmlSecMSCryptoKeyDataGost2001DebugDump(xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecMSCryptoKeyDataGost2001DebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataGost2001Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoKeyDataSize,

    /* data */
    xmlSecNameGOST2001KeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGOST2001KeyValue,         /* const xmlChar* href; */
    xmlSecNodeGOST2001KeyValue,         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCryptoKeyDataGost2001Initialize,    /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataGost2001Duplicate,     /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataGost2001Finalize,      /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL, /* xmlSecMSCryptoKeyDataGost2001Generate,*/   /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCryptoKeyDataGost2001GetType,       /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoKeyDataGost2001GetSize,       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                               /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                               /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                               /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataGost2001DebugDump,     /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataGost2001DebugXmlDump,/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/* Ordered list of providers to search for algorithm implementation using
 * xmlSecMSCryptoFindProvider() function
 *
 * MUST END with { NULL, 0 } !!!
 */
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Gost[] = {
    { MAGPRO_CSP,                   PROV_MAGPRO_GOST },
    { CRYPTOPRO_CSP,                PROV_CRYPTOPRO_GOST },
    { NULL, 0 }
};

/**
 * xmlSecMSCryptoKeyDataGost2001GetKlass:
 *
 * The GOST2001 key data klass.
 *
 * Returns: pointer to GOST2001 key data klass.
 */
xmlSecKeyDataId
xmlSecMSCryptoKeyDataGost2001GetKlass(void) {
    return(&xmlSecMSCryptoKeyDataGost2001Klass);
}


static int
xmlSecMSCryptoKeyDataGost2001Initialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2001Id), xmlSecKeyDataTypeUnknown);

    ret = xmlSecMSCryptoKeyDataInitialize(data);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataInitialize", NULL);
        return(-1);
    }

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    ctx->providers = xmlSecMSCryptoProviderInfo_Gost;
    return(0);
}

static int
xmlSecMSCryptoKeyDataGost2001Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataGost2001Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataGost2001Id), -1);

    return(xmlSecMSCryptoKeyDataDuplicate(dst, src));
}

static void
xmlSecMSCryptoKeyDataGost2001Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2001Id));

    xmlSecMSCryptoKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecMSCryptoKeyDataGost2001GetType(xmlSecKeyDataPtr data) {
    return(xmlSecMSCryptoKeyDataGetType(data));
}

static xmlSecSize
xmlSecMSCryptoKeyDataGost2001GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2001Id), 0);

    return xmlSecMSCryptoKeyDataGetSize(data);
}

static void
xmlSecMSCryptoKeyDataGost2001DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2001Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = %d\n",
            xmlSecMSCryptoKeyDataGost2001GetSize(data));
}

static void
xmlSecMSCryptoKeyDataGost2001DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2001Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2001KeyValue size=\"%d\" />\n",
            xmlSecMSCryptoKeyDataGost2001GetSize(data));
}

#endif /* XMLSEC_NO_GOST */


#ifndef XMLSEC_NO_GOST2012

/**************************************************************************
 *
 * GOST2012 256 xml key representation processing.
 *
 *************************************************************************/
static int              xmlSecMSCryptoKeyDataGost2012_256Initialize(xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataGost2012_256Duplicate(xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecMSCryptoKeyDataGost2012_256Finalize(xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataGost2012_256XmlRead    (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataGost2012_256XmlWrite(xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataGost2012_256Generate(xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecMSCryptoKeyDataGost2012_256GetType(xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecMSCryptoKeyDataGost2012_256GetSize(xmlSecKeyDataPtr data);
static void              xmlSecMSCryptoKeyDataGost2012_256DebugDump(xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecMSCryptoKeyDataGost2012_256DebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataGost2012_256Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoKeyDataSize,

    /* data */
    xmlSecNameGostR3410_2012_256KeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGostR3410_2012_256KeyValue,         /* const xmlChar* href; */
    xmlSecNodeGostR3410_2012_256KeyValue,         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCryptoKeyDataGost2012_256Initialize,    /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataGost2012_256Duplicate,     /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataGost2012_256Finalize,      /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL, /* xmlSecMSCryptoKeyDataGost2001Generate,*/   /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCryptoKeyDataGost2012_256GetType,       /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoKeyDataGost2012_256GetSize,       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                               /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                               /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                               /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataGost2012_256DebugDump,     /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataGost2012_256DebugXmlDump,/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/* Ordered list of providers to search for algorithm implementation using
 * xmlSecMSCryptoFindProvider() function
 *
 * MUST END with { NULL, 0 } !!!
 */
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Gost2012_256[] = {
    { CRYPTOPRO_CSP_256,            PROV_GOST_2012_256 },
    { NULL, 0 }
};

/**
 * xmlSecMSCryptoKeyDataGost2001GetKlass:
 *
 * The GOST2012_256 key data klass.
 *
 * Returns: pointer to GOST2012_256 key data klass.
 */
xmlSecKeyDataId
xmlSecMSCryptoKeyDataGost2012_256GetKlass(void) {
    return(&xmlSecMSCryptoKeyDataGost2012_256Klass);
}


static int
xmlSecMSCryptoKeyDataGost2012_256Initialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_256Id), xmlSecKeyDataTypeUnknown);

    ret = xmlSecMSCryptoKeyDataInitialize(data);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataInitialize", NULL);
        return(-1);
    }

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    ctx->providers = xmlSecMSCryptoProviderInfo_Gost2012_256;
    return(0);
}

static int
xmlSecMSCryptoKeyDataGost2012_256Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataGost2012_256Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataGost2012_256Id), -1);

    return(xmlSecMSCryptoKeyDataDuplicate(dst, src));
}

static void
xmlSecMSCryptoKeyDataGost2012_256Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_256Id));

    xmlSecMSCryptoKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecMSCryptoKeyDataGost2012_256GetType(xmlSecKeyDataPtr data) {
    return(xmlSecMSCryptoKeyDataGetType(data));
}

static xmlSecSize
xmlSecMSCryptoKeyDataGost2012_256GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_256Id), 0);

    return xmlSecMSCryptoKeyDataGetSize(data);
}

static void
xmlSecMSCryptoKeyDataGost2012_256DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_256Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = %d\n",
            xmlSecMSCryptoKeyDataGost2012_256GetSize(data));
}

static void
xmlSecMSCryptoKeyDataGost2012_256DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_256Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2012_256KeyValue size=\"%d\" />\n",
            xmlSecMSCryptoKeyDataGost2012_256GetSize(data));
}


/**************************************************************************
 *
 * GOST2012 512 xml key representation processing.
 *
 *************************************************************************/
static int              xmlSecMSCryptoKeyDataGost2012_512Initialize(xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataGost2012_512Duplicate(xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecMSCryptoKeyDataGost2012_512Finalize(xmlSecKeyDataPtr data);
static int              xmlSecMSCryptoKeyDataGost2012_512XmlRead    (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataGost2012_512XmlWrite(xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecMSCryptoKeyDataGost2012_512Generate(xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecMSCryptoKeyDataGost2012_512GetType(xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecMSCryptoKeyDataGost2012_512GetSize(xmlSecKeyDataPtr data);
static void              xmlSecMSCryptoKeyDataGost2012_512DebugDump(xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecMSCryptoKeyDataGost2012_512DebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataKlass xmlSecMSCryptoKeyDataGost2012_512Klass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecMSCryptoKeyDataSize,

    /* data */
    xmlSecNameGostR3410_2012_512KeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefGostR3410_2012_512KeyValue,         /* const xmlChar* href; */
    xmlSecNodeGostR3410_2012_512KeyValue,         /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecMSCryptoKeyDataGost2012_512Initialize,    /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecMSCryptoKeyDataGost2012_512Duplicate,     /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecMSCryptoKeyDataGost2012_512Finalize,      /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL, /* xmlSecMSCryptoKeyDataGost2001Generate,*/   /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecMSCryptoKeyDataGost2012_512GetType,       /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecMSCryptoKeyDataGost2012_512GetSize,       /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                               /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                               /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                               /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecMSCryptoKeyDataGost2012_512DebugDump,     /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecMSCryptoKeyDataGost2012_512DebugXmlDump,/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/* Ordered list of providers to search for algorithm implementation using
 * xmlSecMSCryptoFindProvider() function
 *
 * MUST END with { NULL, 0 } !!!
 */
static xmlSecMSCryptoProviderInfo xmlSecMSCryptoProviderInfo_Gost2012_512[] = {
    { CRYPTOPRO_CSP_512,            PROV_GOST_2012_512 },
    { NULL, 0 }
};

/**
 * xmlSecMSCryptoKeyDataGost2001GetKlass:
 *
 * The GOST2012_512 key data klass.
 *
 * Returns: pointer to GOST2012_512 key data klass.
 */
xmlSecKeyDataId
xmlSecMSCryptoKeyDataGost2012_512GetKlass(void) {
    return(&xmlSecMSCryptoKeyDataGost2012_512Klass);
}


static int
xmlSecMSCryptoKeyDataGost2012_512Initialize(xmlSecKeyDataPtr data) {
    xmlSecMSCryptoKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_512Id), xmlSecKeyDataTypeUnknown);

    ret = xmlSecMSCryptoKeyDataInitialize(data);
    if(ret != 0) {
        xmlSecInternalError("xmlSecMSCryptoKeyDataInitialize", NULL);
        return(-1);
    }

    ctx = xmlSecMSCryptoKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    ctx->providers = xmlSecMSCryptoProviderInfo_Gost2012_512;
    return(0);
}

static int
xmlSecMSCryptoKeyDataGost2012_512Duplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecMSCryptoKeyDataGost2012_512Id), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecMSCryptoKeyDataGost2012_512Id), -1);

    return(xmlSecMSCryptoKeyDataDuplicate(dst, src));
}

static void
xmlSecMSCryptoKeyDataGost2012_512Finalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_512Id));

    xmlSecMSCryptoKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecMSCryptoKeyDataGost2012_512GetType(xmlSecKeyDataPtr data) {
    return(xmlSecMSCryptoKeyDataGetType(data));
}

static xmlSecSize
xmlSecMSCryptoKeyDataGost2012_512GetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_512Id), 0);

    return xmlSecMSCryptoKeyDataGetSize(data);
}

static void
xmlSecMSCryptoKeyDataGost2012_512DebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_512Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = %d\n",
            xmlSecMSCryptoKeyDataGost2012_512GetSize(data));
}

static void
xmlSecMSCryptoKeyDataGost2012_512DebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecMSCryptoKeyDataGost2012_512Id));
    xmlSecAssert(output != NULL);

    fprintf(output, "<GOST2012_512KeyValue size=\"%d\" />\n",
            xmlSecMSCryptoKeyDataGost2012_512GetSize(data));
}

#endif /* XMLSEC_NO_GOST2012 */
