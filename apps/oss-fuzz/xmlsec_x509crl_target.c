/*
 * xmlsec X509 store / CRL verification fuzz target.
 *
 * Threat model: certificates and CRLs are attacker-controlled in X509Data
 * elements of signatures, and CRL validation decides revocation. Production
 * coverage: src/openssl/x509vfy.c 487/1701 lines, 26/49 functions unreached
 * (VerifyCrl, FindBestCrl, VerifyCertAgainstRevoked, FilterCrlsByTime are
 * never called by the signature-verify harness); openssl/app.c 97/1359.
 *
 * Input container (cheap, mutator-friendly):
 *   byte 0      : format selector (Pem/Der) and cert trust-type bit
 *   bytes 1..2  : CRL blob length, big endian (clamped)
 *   bytes 3..   : certificate blob, then the CRL blob
 *
 * Harness shape (component API): load the blobs through xmlsec's own memory
 * loaders (src/openssl/app.c), then call the exported store entries
 * xmlSecOpenSSLX509StoreVerifyCrl() and xmlSecOpenSSLX509StoreVerify() with
 * typed OpenSSL objects. Expected bugs: memory safety and time/issuer
 * comparison logic in CRL chain checking.
 */
#include <stdint.h>
#include <stddef.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/x509.h>

#ifndef XMLSEC_NO_X509
static int g_initialized = 0;
static int g_init_failed = 0;

static void ignore_libxml_error(void* ctx, const char* msg, ...) {
    (void)ctx; (void)msg;
}

static void ignore_xmlsec_error(const char* file, int line, const char* func,
                                const char* errorObject, const char* errorSubject,
                                int reason, const char* msg) {
    (void)file; (void)line; (void)func;
    (void)errorObject; (void)errorSubject; (void)reason; (void)msg;
}

static int do_init(void) {
    xmlInitParser();
    if (xmlSecInit() < 0) {
        return -1;
    }
    if (xmlSecCheckVersion() != 1) {
        xmlSecShutdown();
        return -1;
    }
    if (xmlSecOpenSSLAppInit(NULL) < 0) {
        xmlSecShutdown();
        return -1;
    }
    if (xmlSecOpenSSLInit() < 0) {
        xmlSecOpenSSLShutdown();
        xmlSecOpenSSLAppShutdown();
        xmlSecShutdown();
        return -1;
    }
    xmlSetGenericErrorFunc(NULL, &ignore_libxml_error);
    xmlSecErrorsSetCallback(&ignore_xmlsec_error);
    return 0;
}

static X509_CRL* parse_crl(const uint8_t* data, size_t size, int der) {
    X509_CRL* crl = NULL;

    if (der) {
        const unsigned char* p = data;
        crl = d2i_X509_CRL(NULL, &p, (long)size);
    } else {
        BIO* bio = BIO_new_mem_buf(data, (int)size);
        if (bio != NULL) {
            crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
    }
    return crl;
}

static X509* parse_cert(const uint8_t* data, size_t size, int der) {
    X509* cert = NULL;

    if (der) {
        const unsigned char* p = data;
        cert = d2i_X509(NULL, &p, (long)size);
    } else {
        BIO* bio = BIO_new_mem_buf(data, (int)size);
        if (bio != NULL) {
            cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
    }
    return cert;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSecKeysMngrPtr mngr = NULL;
    xmlSecKeyDataStorePtr store = NULL;
    xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;
    xmlSecKeyDataType certType = xmlSecKeyDataTypeTrusted;
    xmlSecKeyDataFormat fmt;
    X509* cert = NULL;
    X509_CRL* crl = NULL;
    STACK_OF(X509)* certs = NULL;
    STACK_OF(X509_CRL)* crls = NULL;
    size_t crlLen, certLen;
    int der;

    if (!g_initialized) {
        g_init_failed = (do_init() < 0);
        g_initialized = 1;
    }
    /* byte 0 = selector, bytes 1..2 = crl length, then cert and crl blobs. */
    if (g_init_failed || size < 5 || size > 65536) {
        return 0;
    }
    der = (data[0] & 1) != 0;
    certType = ((data[0] & 2) != 0) ? xmlSecKeyDataTypeTrusted
                                    : xmlSecKeyDataTypeNone;
    fmt = der ? xmlSecKeyDataFormatDer : xmlSecKeyDataFormatPem;
    crlLen = ((size_t)data[1] << 8) | (size_t)data[2];
    if (crlLen > size - 3) {
        crlLen = size - 3;
    }
    certLen = size - 3 - crlLen;
    if (crlLen == 0 || certLen == 0) {
        return 0;
    }

    mngr = xmlSecKeysMngrCreate();
    if (mngr == NULL) {
        return 0;
    }
    if (xmlSecOpenSSLAppDefaultKeysMngrInit(mngr) < 0) {
        xmlSecKeysMngrDestroy(mngr);
        return 0;
    }
    store = xmlSecKeysMngrGetDataStore(mngr, xmlSecOpenSSLX509StoreId);

    /* xmlsec's own untrusted-input loaders (src/openssl/app.c). */
    (void)xmlSecOpenSSLAppKeysMngrCertLoadMemory(mngr, data + 3, certLen,
                                                 fmt, certType);
    (void)xmlSecOpenSSLAppKeysMngrCrlLoadMemory(mngr, data + 3 + certLen,
                                                crlLen, fmt);

    cert = parse_cert(data + 3, certLen, der);
    crl = parse_crl(data + 3 + certLen, crlLen, der);

    keyInfoCtx = xmlSecKeyInfoCtxCreate(mngr);
    if (keyInfoCtx == NULL) {
        if (cert != NULL) X509_free(cert);
        if (crl != NULL) X509_CRL_free(crl);
        xmlSecKeysMngrDestroy(mngr);
        return 0;
    }

    /* The dark entries: CRL validation against the store. */
    if (crl != NULL && store != NULL) {
        (void)xmlSecOpenSSLX509StoreVerifyCrl(store, crl, keyInfoCtx);
    }
    if (cert != NULL && crl != NULL && store != NULL) {
        certs = sk_X509_new_null();
        crls = sk_X509_CRL_new_null();
        if (certs != NULL && crls != NULL) {
            /* xmlSecOpenSSLX509StoreVerify() does not take ownership of the
             * stack items, so push the parsed objects directly. On a failed
             * push free the item here so the cleanup below does not double
             * free it. */
            if (sk_X509_push(certs, cert) < 0) {
                X509_free(cert);
                cert = NULL;
            }
            if (sk_X509_CRL_push(crls, crl) < 0) {
                X509_CRL_free(crl);
                crl = NULL;
            }
            (void)xmlSecOpenSSLX509StoreVerify(store, certs, crls, keyInfoCtx);
        }
    }

    if (certs != NULL) sk_X509_pop_free(certs, X509_free);
    if (crls != NULL) sk_X509_CRL_pop_free(crls, X509_CRL_free);
    if (cert != NULL) X509_free(cert);
    if (crl != NULL) X509_CRL_free(crl);
    xmlSecKeyInfoCtxDestroy(keyInfoCtx);
    xmlSecKeysMngrDestroy(mngr);
    return 0;
}

#else /* XMLSEC_NO_X509 */
/* X.509 support is disabled, so there is nothing to fuzz.
 * Provide a no-op entry point so the target still compiles and links when
 * built against a feature-disabled configuration. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    (void)data;
    (void)size;
    return 0;
}
#endif /* XMLSEC_NO_X509 */
