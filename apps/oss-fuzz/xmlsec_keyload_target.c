/*
 * xmlsec key and certificate loader fuzz target.
 *
 * The other targets all start from an XML document. This one starts from raw
 * key material, which is the other half of what xmlsec reads from untrusted
 * sources: PEM and DER private keys, PKCS#8, PKCS#12 bags and X509
 * certificates. Together those loaders are the largest cold area in the
 * library, roughly 7000 lines across openssl/app.c, openssl/evp.c,
 * openssl/x509.c, x509_helpers.c and openssl/kt_rsa.c.
 *
 * The first input byte picks the format, the rest is the key material, so a
 * mutator reaches a loader on its very first input. No XML wrapper and no
 * signature are needed to make progress.
 *
 * A fixed password is passed, the one the test suite uses, so the PKCS#12 and
 * encrypted-PKCS#8 key derivation paths run rather than stopping at the
 * password prompt.
 */
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#include <libxml/parser.h>
#include <libxml/xmlerror.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

/* The password the xmlsec test suite uses for its encrypted key material. */
#define FUZZ_KEY_PWD "secret123"

static const xmlSecKeyDataFormat g_formats[] = {
    xmlSecKeyDataFormatBinary,
    xmlSecKeyDataFormatPem,
    xmlSecKeyDataFormatDer,
    xmlSecKeyDataFormatPkcs8Pem,
    xmlSecKeyDataFormatPkcs8Der,
    xmlSecKeyDataFormatPkcs12,
    xmlSecKeyDataFormatCertPem,
    xmlSecKeyDataFormatCertDer
};
#define G_NFORMATS ((int)(sizeof(g_formats) / sizeof(g_formats[0])))

static int g_initialized = 0;
/* Set when do_init() fails, so a failed one-time init is not retried on
 * every input. */
static int g_init_failed = 0;

static void ignore_error(void* ctx, const char* msg, ...) {
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
        return -1;
    }
    if (xmlSecOpenSSLAppInit(NULL) < 0) {
        return -1;
    }
    if (xmlSecOpenSSLInit() < 0) {
        return -1;
    }

    xmlSetGenericErrorFunc(NULL, &ignore_error);
    xmlSecErrorsSetCallback(&ignore_xmlsec_error);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSecKeyDataFormat format;
    xmlSecKeyPtr key;

    if (!g_initialized) {
        g_init_failed = (do_init() < 0);
        g_initialized = 1;
    }
    if (g_init_failed || size < 2) {
        return 0;
    }

    format = g_formats[data[0] % G_NFORMATS];
    data++;
    size--;

    key = xmlSecOpenSSLAppKeyLoadMemory((const xmlSecByte*)data, (xmlSecSize)size,
                                        format, FUZZ_KEY_PWD, NULL, NULL);
    if (key != NULL) {
#ifndef XMLSEC_NO_X509
        /* A loaded key can carry a certificate chain, which is a separate
         * reader. Feed the same bytes to it. */
        (void)xmlSecOpenSSLAppKeyCertLoadMemory(key, (const xmlSecByte*)data,
                                                (xmlSecSize)size, format);
#endif /* XMLSEC_NO_X509 */
        xmlSecKeyDestroy(key);
    }

    return 0;
}
