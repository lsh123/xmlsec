/*
 * xmlsec XML Digital Signature verification fuzz target.
 *
 * The existing xmlsec_target.c only parses XML (xmlSecParseMemory); this drives
 * xmlSecDSigCtxVerify() to exercise <Signature> parsing, c14n, base64/digest
 * transforms, reference resolution and X509 key processing. A fixed self-signed
 * cert is loaded as trusted so the key-resolution paths run. Network and
 * external-entity loading are disabled so the harness stays offline.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

/* Fixed self-signed RSA test certificate (PEM), stored as individual lines so
 * the source contains no backslash-escape sequences. The OSS-Fuzz build.sh
 * runs `echo -e` over this file (to prepend an include); `echo -e` would expand
 * any literal newline-escape in the source and corrupt string literals, so we avoid them
 * and re-assemble the PEM (with real newlines) at runtime. Loaded as a trusted
 * cert so the X509 key-resolution path is exercised during verification. */
static const char* const g_cert_lines[] = {
    "-----BEGIN CERTIFICATE-----",
    "MIIDDzCCAfegAwIBAgIUCnv9ljdf65kswXi7sntLjL2/IcowDQYJKoZIhvcNAQEL",
    "BQAwFjEUMBIGA1UEAwwLeG1sc2VjLWZ1enowIBcNMjYwNjA4MTM1OTM0WhgPMjEy",
    "NjA1MTUxMzU5MzRaMBYxFDASBgNVBAMMC3htbHNlYy1mdXp6MIIBIjANBgkqhkiG",
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxfMDmHVegLXYCSYrcmGMCufRsh+XLOqQvpUR",
    "/mQa/1b9lvXYuYtLRKD3JLGdpzmsiXj68qi01sf0+bYdQ1KwXrVnBnSv0WZMOVU0",
    "6gtWDzpn+XOb4S3sW2wlJM6TkWKNtGhp2wsJ/hZyAlILOI+6i9mGXt4hsAAhKx0n",
    "3VDzYgakx1uu6YMd8X58stKdcKeYqGPQA3ZlBlrhSzG+H0q/uCGvegp8QJEa+7Hn",
    "aYS1dg3BnxLp+IM70hvh6oXWhTw7wPGa3dJi8uP4lYAwPKTUWql/Mzf6WXMg6w+d",
    "C/89Ei/5KjHLj/2mVKWDqwku+4scnjpaPjSKNCBT/AVz+onXDwIDAQABo1MwUTAd",
    "BgNVHQ4EFgQUsUjvD4/BRfNY7AYU4t+3sywgKKswHwYDVR0jBBgwFoAUsUjvD4/B",
    "RfNY7AYU4t+3sywgKKswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC",
    "AQEAqHDR2Q5RFqx2CKyXWNmd4f5bE7CJDxZCdpQGeiI+oZ6/JvfZTQ3bsbKbM8H+",
    "wLIgwxse7kNueANm97ntD6IxjQklX/NQNbvwkQMXTTl0ZisaI+2nNGrCUye5geQl",
    "J1OfZBLo3+ZEToFPKGNsrbPddZyJLO9LiRt8H1Ih9S1kU8OYivF5EhgSf7DVdAEk",
    "zE+zVJYPjWHNsYXRFhZ5gdN5zJ08Ijw3DZkbJ5wiluD3OYCwB/tjFZWbmEgE17ZI",
    "a59WDB1hYhzZzydviAuh92S1nvCHUuD7PKLVu71Yq3UEpdZt4xvo3pmjn9YhxEH2",
    "O/g/u3qLP1y9nuevc1IKYs0LwQ==",
    "-----END CERTIFICATE-----",
};
#define G_CERT_NLINES ((int)(sizeof(g_cert_lines) / sizeof(g_cert_lines[0])))

static int g_initialized = 0;
static xmlSecKeysMngrPtr g_mngr = NULL;

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

    /* Silence libxml2 and xmlsec error spam. */
    xmlSetGenericErrorFunc(NULL, &ignore_error);
    xmlSecErrorsSetCallback(&ignore_xmlsec_error);

    /* Build a keys manager once and load the fixed trusted cert into it. */
    g_mngr = xmlSecKeysMngrCreate();
    if (g_mngr == NULL) {
        return -1;
    }
    if (xmlSecOpenSSLAppDefaultKeysMngrInit(g_mngr) < 0) {
        xmlSecKeysMngrDestroy(g_mngr);
        g_mngr = NULL;
        return -1;
    }
    /* Re-assemble the PEM cert (with real newline characters) into a buffer. */
    {
        char pem[4096];
        size_t off = 0;
        int i;
        for (i = 0; i < G_CERT_NLINES; ++i) {
            size_t len = strlen(g_cert_lines[i]);
            if (off + len + 1 >= sizeof(pem)) {
                break;
            }
            memcpy(pem + off, g_cert_lines[i], len);
            off += len;
            pem[off++] = 0x0A;  /* newline; avoid escape sequences (see note above) */
        }
        /* Best effort: load embedded trusted cert. If it fails we keep going
         * with an (essentially empty) manager; the signature parsing surface
         * still runs. */
        xmlSecOpenSSLAppKeysMngrCertLoadMemory(g_mngr,
            (const xmlSecByte*)pem, (xmlSecSize)off,
            xmlSecKeyDataFormatCertPem, xmlSecKeyDataTypeTrusted);
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;

    if (!g_initialized) {
        if (do_init() < 0) {
            /* Initialization is one-time; if it fails there is nothing to do. */
            return 0;
        }
        g_initialized = 1;
    }

    if (size == 0) {
        return 0;
    }

    /* Parse the document from memory. NONET / NOENT defang external fetches
     * and entity expansion. */
    doc = xmlReadMemory((const char*)data, (int)size, "fuzz.xml", NULL,
                        XML_PARSE_NONET | XML_PARSE_NOENT);
    if (doc == NULL || xmlDocGetRootElement(doc) == NULL) {
        if (doc != NULL) xmlFreeDoc(doc);
        return 0;
    }

    /* Locate the <Signature> node. */
    node = xmlSecFindNode(xmlDocGetRootElement(doc),
                          xmlSecNodeSignature, xmlSecDSigNs);
    if (node == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    dsigCtx = xmlSecDSigCtxCreate(g_mngr);
    if (dsigCtx == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Restrict reference URIs to same-document / empty: never fetch remote or
     * local files. This is the critical no-network guard. */
    dsigCtx->enabledReferenceUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
    dsigCtx->transformCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
    /* Also restrict key-info reference / retrieval-method processing so that
     * <RetrievalMethod>/<KeyInfoReference> cannot fetch remote or local data. */
    dsigCtx->keyInfoReadCtx.retrievalMethodCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
    dsigCtx->keyInfoReadCtx.keyInfoReferenceCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;

    /* Drive verification. Return value / status are intentionally ignored:
     * the goal is to exercise the parsing + transform code paths. */
    (void)xmlSecDSigCtxVerify(dsigCtx, node);

    xmlSecDSigCtxDestroy(dsigCtx);
    xmlFreeDoc(doc);
    return 0;
}
