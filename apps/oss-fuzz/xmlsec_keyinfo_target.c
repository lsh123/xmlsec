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
 * (the KeyValue and EncryptedKey structure readers), keyinfo.c and the OpenSSL
 * key-data implementations.
 *
 * An initialized, empty keys manager enables X509Data child processing without
 * trusting input certificates. A general-key pass accepts KeyValue classes;
 * a separate fresh AES pass preserves EncryptedKey's concrete extraction
 * requirement. No private keys or trust anchors are installed.
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
#include <xmlsec/keysmngr.h>
#include <xmlsec/parser.h>
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
        xmlSecShutdown();
        return -1;
    }
    if (xmlSecOpenSSLAppInit(NULL) < 0) {
        xmlSecShutdown();
        return -1;
    }
    if (xmlSecOpenSSLInit() < 0) {
        xmlSecOpenSSLAppShutdown();
        xmlSecShutdown();
        return -1;
    }

    xmlSetGenericErrorFunc(NULL, &ignore_error);
    xmlSecErrorsSetCallback(&ignore_xmlsec_error);

    g_mngr = xmlSecKeysMngrCreate();
    if (g_mngr == NULL) {
        goto fail;
    }
    if (xmlSecOpenSSLAppDefaultKeysMngrInit(g_mngr) < 0) {
        xmlSecKeysMngrDestroy(g_mngr);
        g_mngr = NULL;
        goto fail;
    }
    return 0;

fail:
    xmlSecOpenSSLShutdown();
    xmlSecOpenSSLAppShutdown();
    xmlSecShutdown();
    return -1;
}

static void read_keyinfo(xmlNodePtr node, xmlSecKeyDataId keyId) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;

    key = xmlSecKeyCreate();
    if (key == NULL) {
        return;
    }
    keyInfoCtx = xmlSecKeyInfoCtxCreate(g_mngr);
    if (keyInfoCtx == NULL) {
        xmlSecKeyDestroy(key);
        return;
    }

    keyInfoCtx->mode = xmlSecKeyInfoModeRead;
    keyInfoCtx->keyReq.keyId = keyId;
    keyInfoCtx->keyReq.keyType = xmlSecKeyDataTypeAny;
    keyInfoCtx->keyReq.keyUsage = xmlSecKeyUsageAny;
    keyInfoCtx->retrievalMethodCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
    keyInfoCtx->keyInfoReferenceCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;

    (void)xmlSecKeyInfoNodeRead(node, key, keyInfoCtx);

    xmlSecKeyInfoCtxDestroy(keyInfoCtx);
    xmlSecKeyDestroy(key);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const xmlChar* ids[] = { BAD_CAST "Id", NULL };
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr node = NULL;

    if (!g_initialized) {
        g_init_failed = (do_init() < 0);
        g_initialized = 1;
    }
    /* Skip inputs that cannot be represented as the int length expected by
     * xmlReadMemory(). */
    if (g_init_failed || size == 0 || size > (size_t)INT_MAX) {
        return 0;
    }

    /* NONET stops external fetches; NOENT enables general-entity substitution. */
    doc = xmlReadMemory((const char*)data, (int)size, "fuzz.xml", NULL,
        xmlSecParserGetDefaultOptions() | XML_PARSE_PEDANTIC | XML_PARSE_NONET);
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

    xmlSecAddIDs(doc, root, ids);
    read_keyinfo(node, xmlSecKeyDataIdUnknown);
#if !defined(XMLSEC_NO_AES) && !defined(XMLSEC_NO_XMLENC)
    read_keyinfo(node, xmlSecOpenSSLKeyDataAesId);
#endif
    xmlFreeDoc(doc);
    return 0;
}
