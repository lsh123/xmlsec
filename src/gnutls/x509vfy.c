/**
 * XMLSec library
 *
 * X509 support
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2010 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>
#include <xmlsec/gnutls/x509.h>

#include "x509utils.h"

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
};

/****************************************************************************
 *
 * xmlSecGnuTLSKeyDataStoreX509Id:
 *
 * xmlSecGnuTLSX509StoreCtx is located after xmlSecTransform
 *
 ***************************************************************************/
#define xmlSecGnuTLSX509StoreGetCtx(store) \
    ((xmlSecGnuTLSX509StoreCtxPtr)(((xmlSecByte*)(store)) + \
                                    sizeof(xmlSecKeyDataStoreKlass)))
#define xmlSecGnuTLSX509StoreSize      \
    (sizeof(xmlSecKeyDataStoreKlass) + sizeof(xmlSecGnuTLSX509StoreCtx))

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
                                                                         const xmlChar *subjectName,
                                                                         const xmlChar *issuerName,
                                                                         const xmlChar *issuerSerial,
                                                                         const xmlChar *ski);
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

/**
 * xmlSecGnuTLSX509StoreFindCert:
 * @store:              the pointer to X509 key data store klass.
 * @subjectName:        the desired certificate name.
 * @issuerName:         the desired certificate issuer name.
 * @issuerSerial:       the desired certificate issuer serial number.
 * @ski:                the desired certificate SKI.
 * @keyInfoCtx:         the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Searches @store for a certificate that matches given criteria.
 *
 * Returns: pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */
gnutls_x509_crt_t
xmlSecGnuTLSX509StoreFindCert(xmlSecKeyDataStorePtr store,
                              const xmlChar *subjectName,
                              const xmlChar *issuerName,
                              const xmlChar *issuerSerial,
                              const xmlChar *ski,
                              const xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    gnutls_x509_crt_t res = NULL;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    if(res == NULL) {
        res = xmlSecGnuTLSX509FindCert(&(ctx->certsTrusted), subjectName, issuerName, issuerSerial, ski);
    }
    if(res == NULL) {
        res = xmlSecGnuTLSX509FindCert(&(ctx->certsUntrusted), subjectName, issuerName, issuerSerial, ski);
    }
    return(res);
}

/**
 * xmlSecGnuTLSX509StoreVerify:
 * @store:              the pointer to X509 key data store klass.
 * @certs:              the untrusted certificates stack.
 * @keyInfoCtx:         the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Verifies @certs list.
 *
 * Returns: pointer to the first verified certificate from @certs.
 */
gnutls_x509_crt_t
xmlSecGnuTLSX509StoreVerify(xmlSecKeyDataStorePtr store,
                            xmlSecPtrListPtr certs,
                            const xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecGnuTLSX509StoreCtxPtr ctx;
    gnutls_x509_crt_t res = NULL;
    xmlSecSize certs_size = 0;
    gnutls_x509_crt_t * cert_list = NULL;
    xmlSecSize cert_list_length;
    gnutls_x509_crt_t * ca_list = NULL;
    xmlSecSize ca_list_length;
    xmlSecSize ii;
    int err;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecGnuTLSX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    certs_size = xmlSecPtrListGetSize(certs);
    if(certs_size <= 0) {
        /* nothing to do */
        return(NULL);
    }

    ctx = xmlSecGnuTLSX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    /* Prepare */
    cert_list_length = certs_size + xmlSecPtrListGetSize(&(ctx->certsUntrusted));
    if(cert_list_length > 0) {
        cert_list = (gnutls_x509_crt_t *)xmlMalloc(sizeof(gnutls_x509_crt_t) * cert_list_length);
        if(cert_list == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        "xmlMalloc",
                        XMLSEC_ERRORS_R_MALLOC_FAILED,
                        "size=%d", (int)(sizeof(gnutls_x509_crt_t) * cert_list_length));
            goto done;
        }
    }
    ca_list_length = xmlSecPtrListGetSize(&(ctx->certsTrusted));
    if(ca_list_length > 0) {
        ca_list = (gnutls_x509_crt_t *)xmlMalloc(sizeof(gnutls_x509_crt_t) * ca_list_length);
        if(ca_list == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        "xmlMalloc",
                        XMLSEC_ERRORS_R_MALLOC_FAILED,
                        "size=%d", (int)(sizeof(gnutls_x509_crt_t) * ca_list_length));
            goto done;
        }
        for(ii = 0; ii < ca_list_length; ++ii) {
            ca_list[ii] = xmlSecPtrListGetItem(&(ctx->certsTrusted), ii);
            if(ca_list[ii] == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                            "xmlSecPtrListGetItem(certsTrusted)",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                goto done;
            }
        }
    }

    /* We are going to build all possible cert chains and try to verify them */
    for(ii = 0; (ii < certs_size) && (res == NULL); ++ii) {
        gnutls_x509_crt_t cert, cert2;
        xmlSecSize cert_list_cur_length = 0;
        unsigned int verify = 0;

        cert = xmlSecPtrListGetItem(certs, ii);
        if(cert == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        "xmlSecPtrListGetItem(certs)",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            goto done;
        }

        /* check if we are the "leaf" node in the certs chain */
        if(xmlSecGnuTLSX509FindSignedCert(certs, cert) != NULL) {
            continue;
        }

        /* build the chain */
        for(cert2 = cert, cert_list_cur_length = 0;
            (cert2 != NULL) && (cert_list_cur_length < cert_list_length);
            ++cert_list_cur_length)
        {
            gnutls_x509_crt_t tmp;

            /* store */
            cert_list[cert_list_cur_length] = cert2;

            /* find next */
            tmp = xmlSecGnuTLSX509FindSignerCert(certs, cert2);
            if(tmp == NULL) {
                tmp = xmlSecGnuTLSX509FindSignerCert(&(ctx->certsUntrusted), cert2);
            }
            cert2 = tmp;
        }

        /* try to verify */
        err = gnutls_x509_crt_list_verify(
                cert_list, (int)cert_list_cur_length, /* certs chain */
                ca_list, (int)ca_list_length, /* trusted cas */
                NULL, 0, /* crls */
                0, /* flags */
                &verify);
        if(err == GNUTLS_E_SUCCESS) {
            /* TODO: check the timestamp */
            res = cert;
        } else {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "gnutls_x509_crt_list_verify",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_GNUTLS_REPORT_ERROR(err));
            /* don't stop, continue! */
        }
    }

    /*
    for(ii = 0; ii < certs.size; ++ii) {
        cert = certs[ii];
        if(find(certs, where issuer = cert.subj)) {
            continue; // this is not the "leaf" of a certs chain!
        }
        // build chain
        for(cert2 = cert; ; ) {
            put cert2 into certsChain;
            cert2 = find(certs, where subject = cert2.issuer);
            if(cert2 == NULL) {
                cert2 = find(untrusted certs from store, where subject = cert2.issuer);
            }
        }
        if(gnutls_x509_crt_list_verify(certsChain, trusted certs from store)) {
            // we found it!
            cert is the key cert;

            // manually check certs time if specified 
        }
    }
    */

done:
    if(ca_list != NULL) {
        xmlFree(ca_list);
    }
    if(cert_list != NULL) {
        xmlFree(cert_list);
    }

    return(res);

#ifdef TODO
    STACK_OF(X509)* certs2 = NULL;
    X509 * res = NULL;
    X509 * cert;
    X509 * err_cert = NULL;
    char buf[256];
    int err = 0, depth;
    int i;
    int ret;

    /* dup certs */
    certs2 = sk_X509_dup(certs);
    if(certs2 == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                    "sk_X509_dup",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    /* add untrusted certs from the store */
    for(i = 0; i < sk_X509_num(ctx->certsUntrusted); ++i) {
        ret = sk_X509_push(certs2, sk_X509_value(ctx->certsUntrusted, i));
        if(ret < 1) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        "sk_X509_push",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            goto done;
        }
    }

    /* TODO: remove all revoked certs */

    /* get one cert after another and try to verify */
    for(i = 0; i < sk_X509_num(certs2); ++i) {
        cert = sk_X509_value(certs2, i);
        if(xmlSecGnuTLSX509FindNextChainCert(certs2, cert) == NULL) {
            X509_STORE_CTX xsc;

#if !defined(XMLSEC_OPENSSL_096) && !defined(XMLSEC_OPENSSL_097)
            X509_VERIFY_PARAM * vpm = NULL;
            unsigned long vpm_flags = 0;

            vpm = X509_VERIFY_PARAM_new();
            if(vpm == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                            "X509_VERIFY_PARAM_new",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                goto done;
            }
            vpm_flags = vpm->flags;
/*
            vpm_flags &= (~X509_V_FLAG_X509_STRICT);
*/

            X509_VERIFY_PARAM_set_depth(vpm, 9);
            X509_VERIFY_PARAM_set_flags(vpm, vpm_flags);
#endif /* !defined(XMLSEC_OPENSSL_096) && !defined(XMLSEC_OPENSSL_097) */


            X509_STORE_CTX_init (&xsc, ctx->xst, cert, certs2);

            if(keyInfoCtx->certsVerificationTime > 0) {
#if !defined(XMLSEC_OPENSSL_096) && !defined(XMLSEC_OPENSSL_097)
                vpm_flags |= X509_V_FLAG_USE_CHECK_TIME;
                X509_VERIFY_PARAM_set_time(vpm, keyInfoCtx->certsVerificationTime);
#endif /* !defined(XMLSEC_OPENSSL_096) && !defined(XMLSEC_OPENSSL_097) */
                X509_STORE_CTX_set_time(&xsc, 0, keyInfoCtx->certsVerificationTime);
            }

#if !defined(XMLSEC_OPENSSL_096) && !defined(XMLSEC_OPENSSL_097)
            X509_STORE_CTX_set0_param(&xsc, vpm);
#endif /* !defined(XMLSEC_OPENSSL_096) && !defined(XMLSEC_OPENSSL_097) */


            ret         = X509_verify_cert(&xsc);
            err_cert    = X509_STORE_CTX_get_current_cert(&xsc);
            err         = X509_STORE_CTX_get_error(&xsc);
            depth       = X509_STORE_CTX_get_error_depth(&xsc);

            X509_STORE_CTX_cleanup (&xsc);

            if(ret == 1) {
                res = cert;
                goto done;
            } else if(ret < 0) {
                const char* err_msg;

                buf[0] = '\0';
                X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof buf);
                err_msg = X509_verify_cert_error_string(err);
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                            "X509_verify_cert",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            "subj=%s;err=%d;msg=%s",
                            xmlSecErrorsSafeString(buf),
                            err,
                            xmlSecErrorsSafeString(err_msg));
                goto done;
            } else if(ret == 0) {
                const char* err_msg;

                buf[0] = '\0';
                X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof buf);
                err_msg = X509_verify_cert_error_string(err);
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                            "X509_verify_cert",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            "subj=%s;err=%d;msg=%s",
                            xmlSecErrorsSafeString(buf),
                            err,
                            xmlSecErrorsSafeString(err_msg));
            }
        }
    }

    /* if we came here then we found nothing. do we have any error? */
    if((err != 0) && (err_cert != NULL)) {
        const char* err_msg;

        err_msg = X509_verify_cert_error_string(err);
        switch (err) {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, sizeof buf);
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        NULL,
                        XMLSEC_ERRORS_R_CERT_ISSUER_FAILED,
                        "err=%d;msg=%s;issuer=%s",
                        err,
                        xmlSecErrorsSafeString(err_msg),
                        xmlSecErrorsSafeString(buf));
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        NULL,
                        XMLSEC_ERRORS_R_CERT_NOT_YET_VALID,
                        "err=%d;msg=%s", err,
                        xmlSecErrorsSafeString(err_msg));
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        NULL,
                        XMLSEC_ERRORS_R_CERT_HAS_EXPIRED,
                        "err=%d;msg=%s", err,
                        xmlSecErrorsSafeString(err_msg));
            break;
        default:
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        NULL,
                        XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
                        "err=%d;msg=%s", err,
                        xmlSecErrorsSafeString(err_msg));
        }
    }

done:
    if(certs2 != NULL) {
        sk_X509_free(certs2);
    }
    return(res);
#endif /* TODO */
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
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        "xmlSecPtrListAdd(trusted)",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    } else {
        ret = xmlSecPtrListAdd(&(ctx->certsUntrusted), cert);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        "xmlSecPtrListAdd(untrusted)",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
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
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                    "xmlSecPtrListInitialize(trusted)",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = xmlSecPtrListInitialize(&(ctx->certsUntrusted), xmlSecGnuTLSX509CrtListId);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                    "xmlSecPtrListInitialize(untrusted)",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
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

    memset(ctx, 0, sizeof(xmlSecGnuTLSX509StoreCtx));
}


/*****************************************************************************
 *
 * Low-level x509 functions
 *
 *****************************************************************************/
static gnutls_x509_crt_t
xmlSecGnuTLSX509FindCert(xmlSecPtrListPtr certs,
                         const xmlChar *subjectName,
                         const xmlChar *issuerName,
                         const xmlChar *issuerSerial,
                         const xmlChar *ski) {
    xmlSecSize ii, sz;

    xmlSecAssert2(certs != NULL, NULL);


    /* todo: this is not the fastest way to search certs */
    sz = xmlSecPtrListGetSize(certs);
    for(ii = 0; (ii < sz); ++ii) {
        gnutls_x509_crt_t cert = xmlSecPtrListGetItem(certs, ii);
        if(cert == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecPtrListGetItem",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "pos=%i", (int)ii);
            return(NULL);
        }

        if(subjectName != NULL) {
            xmlChar * tmp;

            tmp = xmlSecGnuTLSX509CertGetSubjectDN(cert);
            if(tmp == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecGnuTLSX509CertGetSubjectDN",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            "pos=%i", (int)ii);
                return(NULL);
            }

            if(xmlStrEqual(subjectName, tmp)) {
                xmlFree(tmp);
                return(cert);
            }
            xmlFree(tmp);
        } else if((issuerName != NULL) && (issuerSerial != NULL)) {
            xmlChar * tmp1;
            xmlChar * tmp2;

            tmp1 = xmlSecGnuTLSX509CertGetIssuerDN(cert);
            if(tmp1 == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecGnuTLSX509CertGetIssuerDN",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            "pos=%i", (int)ii);
                return(NULL);
            }

            tmp2 = xmlSecGnuTLSX509CertGetIssuerSerial(cert);
            if(tmp2 == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecGnuTLSX509CertGetIssuerSerial",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            "pos=%i", (int)ii);
                xmlFree(tmp1);
                return(NULL);
            }

            if(xmlStrEqual(issuerName, tmp1) && xmlStrEqual(issuerSerial, tmp2)) {
                xmlFree(tmp1);
                xmlFree(tmp2);
                return(cert);
            }
            xmlFree(tmp1);
            xmlFree(tmp2);
        } else if(ski != NULL) {
            xmlChar * tmp;

            tmp = xmlSecGnuTLSX509CertGetSKI(cert);
            if(tmp == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            NULL,
                            "xmlSecGnuTLSX509CertGetSKI",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            "pos=%i", (int)ii);
                return(NULL);
            }

            if(xmlStrEqual(ski, tmp)) {
                xmlFree(tmp);
                return(cert);
            }
            xmlFree(tmp);
        }
    }

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
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGnuTLSX509CertGetSubjectDN",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    /* todo: this is not the fastest way to search certs */
    sz = xmlSecPtrListGetSize(certs);
    for(ii = 0; (ii < sz) && (res == NULL); ++ii) {
        gnutls_x509_crt_t tmp;
        xmlChar * issuer;

        tmp = xmlSecPtrListGetItem(certs, ii);
        if(tmp == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecPtrListGetItem",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "pos=%i", (int)ii);
            goto done;
        }

        issuer = xmlSecGnuTLSX509CertGetIssuerDN(tmp);
        if(issuer == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecGnuTLSX509CertGetIssuerDN",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "pos=%i", (int)ii);
            goto done;
        }

        /* are we done? */
        if(xmlStrEqual(subject, issuer)) {
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
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGnuTLSX509CertGetIssuerDN",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    /* todo: this is not the fastest way to search certs */
    sz = xmlSecPtrListGetSize(certs);
    for(ii = 0; (ii < sz) && (res == NULL); ++ii) {
        gnutls_x509_crt_t tmp;
        xmlChar * subject;

        tmp = xmlSecPtrListGetItem(certs, ii);
        if(tmp == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecPtrListGetItem",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "pos=%i", (int)ii);
            goto done;
        }

        subject = xmlSecGnuTLSX509CertGetSubjectDN(tmp);
        if(subject == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecGnuTLSX509CertGetSubjectDN",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "pos=%i", (int)ii);
            goto done;
        }

        /* are we done? */
        if(xmlStrEqual(issuer, subject)) {
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


