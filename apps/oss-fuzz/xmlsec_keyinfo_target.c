/*
 * xmlsec <dsig:KeyInfo /> reader fuzz target.
 *
 * xmlsec_target.c only parses XML (xmlSecParseMemory), and the dsig target
 * needs a whole well-formed signature before it reaches any key handling. This
 * target calls xmlSecKeyInfoNodeRead() on a <KeyInfo> element directly, which
 * is reachable from a very small document, so a mutator makes progress from the
 * first input.
 *
 * The code it drives is the largest cold area in the library: keysdata_helpers.c
 * (the KeyValue, X509Data and EncryptedKey structure readers), keyinfo.c,
 * x509_helpers.c and the OpenSSL key-data implementations.
 *
 * The keys manager is NULL on purpose. A manager only adds trusted-key lookup,
 * which needs key material this target does not supply, and it brings in
 * application-level initialisation that this target does not need. Structure
 * parsing, the part that reads attacker-supplied bytes, runs either way.
 *
 * External fetches are disabled, so the target stays offline.
 */
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/strings.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

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
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr node = NULL;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;

    if (!g_initialized) {
        g_init_failed = (do_init() < 0);
        g_initialized = 1;
    }
    /* Skip inputs that cannot be represented as the int length expected by
     * xmlReadMemory(). */
    if (g_init_failed || size == 0 || size > (size_t)INT_MAX) {
        return 0;
    }

    /* NONET and NOENT stop external fetches and entity expansion. */
    doc = xmlReadMemory((const char*)data, (int)size, "fuzz.xml", NULL,
                        XML_PARSE_NONET | XML_PARSE_NOENT);
    if (doc == NULL) {
        return 0;
    }
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Accept a bare <KeyInfo> document as well as one that contains it, so a
     * seed does not have to carry a signature wrapper. */
    if (xmlSecCheckNodeName(root, xmlSecNodeKeyInfo, xmlSecDSigNs)) {
        node = root;
    } else {
        node = xmlSecFindNode(root, xmlSecNodeKeyInfo, xmlSecDSigNs);
    }
    if (node == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    key = xmlSecKeyCreate();
    if (key == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    keyInfoCtx = xmlSecKeyInfoCtxCreate(NULL);
    if (keyInfoCtx == NULL) {
        xmlSecKeyDestroy(key);
        xmlFreeDoc(doc);
        return 0;
    }

    keyInfoCtx->mode = xmlSecKeyInfoModeRead;
    /* Accept any key so the first successfully read child element satisfies
     * the requirement (the reader then stops, skipping later siblings). */
    keyInfoCtx->keyReq.keyId = xmlSecKeyDataIdUnknown;
    keyInfoCtx->keyReq.keyType = xmlSecKeyDataTypeAny;
    keyInfoCtx->keyReq.keyUsage = xmlSecKeyUsageAny;
    /* <RetrievalMethod> and <KeyInfoReference> must not fetch remote or local
     * data. This is the no-network guard. */
    keyInfoCtx->retrievalMethodCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
    keyInfoCtx->keyInfoReferenceCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;

    /* The return value does not matter. The parsing paths are the target. */
    (void)xmlSecKeyInfoNodeRead(node, key, keyInfoCtx);

    xmlSecKeyInfoCtxDestroy(keyInfoCtx);
    xmlSecKeyDestroy(key);
    xmlFreeDoc(doc);
    return 0;
}
