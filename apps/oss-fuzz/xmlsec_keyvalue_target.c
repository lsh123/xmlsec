/*
 * xmlsec KeyValue read/write fuzz target.
 *
 * Threat model: a KeyInfo/KeyValue element is attacker-controlled in any XML
 * Signature or XML Encryption document. xmlsec_keyinfo_fuzzer only calls
 * xmlSecKeyInfoNodeRead (unknown or AES key id) and never writes, so the
 * KeyValue writers in src/keysdata_helpers.c stay dark. This target reads the
 * untrusted KeyInfo and writes any key it obtains back through
 * xmlSecKeyInfoNodeWrite. It also generates a small symmetric key and writes
 * that, which reaches the binary KeyValue writers without a successful parse.
 *
 * Expected bugs: memory-safety in base64 decode, bignum import and XML
 * serialization of key material. External fetches stay disabled.
 */
#include <stdint.h>
#include <stddef.h>

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
#include <xmlsec/errors.h>
#include <xmlsec/strings.h>
#include <xmlsec/templates.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

static int g_initialized = 0;
static int g_init_failed = 0;
static xmlSecKeysMngrPtr g_mngr = NULL;

static void ignore_error(void* ctx, const char* msg, ...) {
    (void)ctx;
    (void)msg;
}

static void ignore_xmlsec_error(const char* file, int line, const char* func,
                                const char* errorObject, const char* errorSubject,
                                int reason, const char* msg) {
    (void)file;
    (void)line;
    (void)func;
    (void)errorObject;
    (void)errorSubject;
    (void)reason;
    (void)msg;
}

static int do_init(void) {
    int options;

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
    xmlSetGenericErrorFunc(NULL, &ignore_error);
    xmlSecErrorsSetCallback(&ignore_xmlsec_error);


    /* xmlReadMemory() below uses xmlSecParserGetDefaultOptions(), which
     * includes XML_PARSE_HUGE (see src/parser.c). Fuzz inputs are small, so
     * the relaxation is unnecessary; on libxml2 < 2.13.0 it disables the
     * parser depth limit, risking stack exhaustion on deeply nested fuzz
     * input. */
    options = xmlSecParserGetDefaultOptions();
    options &= ~XML_PARSE_HUGE;
    options |= XML_PARSE_PEDANTIC | XML_PARSE_NONET;
    xmlSecParserSetDefaultOptions(options);

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
static void write_key(xmlSecKeyPtr key) {
    xmlSecKeyInfoCtxPtr ctx;
    xmlDocPtr doc;
    xmlNodePtr node;
    xmlNodePtr keyInfoNode;

    if (key == NULL || xmlSecKeyGetValue(key) == NULL) {
        return;
    }
    doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        return;
    }
    node = xmlNewDocNode(doc, NULL, xmlSecNodeKeyInfo, NULL);
    if (node == NULL) {
        xmlFreeDoc(doc);
        return;
    }
    xmlDocSetRootElement(doc, node);
    xmlSetNs(node, xmlNewNs(node, xmlSecDSigNs, NULL));

    /* xmlSecKeyInfoNodeWrite() only writes into the child elements that
     * already exist under <KeyInfo>, so add the <KeyValue> element the
     * KeyValue writers are expected to fill in. */
    keyInfoNode = node;
    node = xmlSecTmplKeyInfoAddKeyValue(node);
    if (node == NULL) {
        xmlFreeDoc(doc);
        return;
    }

    ctx = xmlSecKeyInfoCtxCreate(g_mngr);
    if (ctx == NULL) {
        xmlFreeDoc(doc);
        return;
    }
    ctx->mode = xmlSecKeyInfoModeWrite;
    ctx->keyReq.keyId = xmlSecKeyDataIdUnknown;
    ctx->keyReq.keyType = xmlSecKeyDataTypeAny;
    ctx->keyReq.keyUsage = xmlSecKeyUsageAny;
    (void)xmlSecKeyInfoNodeWrite(keyInfoNode, key, ctx);
    xmlSecKeyInfoCtxDestroy(ctx);
    xmlFreeDoc(doc);
}

static void read_keyinfo(xmlNodePtr node, xmlSecKeyDataId keyId) {
    xmlSecKeyPtr key;
    xmlSecKeyInfoCtxPtr ctx;

    key = xmlSecKeyCreate();
    if (key == NULL) {
        return;
    }
    ctx = xmlSecKeyInfoCtxCreate(g_mngr);
    if (ctx == NULL) {
        xmlSecKeyDestroy(key);
        return;
    }
    ctx->mode = xmlSecKeyInfoModeRead;
    ctx->keyReq.keyId = keyId;
    ctx->keyReq.keyType = xmlSecKeyDataTypeAny;
    ctx->keyReq.keyUsage = xmlSecKeyUsageAny;
    ctx->retrievalMethodCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
    (void)xmlSecKeyInfoNodeRead(node, key, ctx);
    xmlSecKeyInfoCtxDestroy(ctx);
    write_key(key);
    xmlSecKeyDestroy(key);
}

static void write_generated_symmetric(uint8_t selector) {
    xmlSecKeyDataId id;
    xmlSecSize sizeBits;
    xmlSecKeyPtr key;

    /* Ids are function-call macros, not compile-time constants. */
    switch (selector % 4) {
    case 0: id = xmlSecOpenSSLKeyDataAesId; sizeBits = 128; break;
    case 1: id = xmlSecOpenSSLKeyDataAesId; sizeBits = 256; break;
    case 2: id = xmlSecOpenSSLKeyDataHmacId; sizeBits = 256; break;
    default: id = xmlSecOpenSSLKeyDataHmacId; sizeBits = 160; break;
    }
    key = xmlSecKeyGenerate(id, sizeBits, xmlSecKeyDataTypeSymmetric);
    if (key == NULL) {
        return;
    }
    write_key(key);
    xmlSecKeyDestroy(key);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr node = NULL;
    xmlSecKeyDataId ids[8];
    size_t nids = 0;
    size_t i;

    if (!g_initialized) {
        g_init_failed = (do_init() < 0);
        g_initialized = 1;
    }
    /* Bound the document so one input cannot stall the process. */
    if (g_init_failed || size < 2 || size > 65536) {
        return 0;
    }

    write_generated_symmetric(data[0]);

    /* Parse the whole buffer so corpus files are valid KeyInfo documents.
       data[0] still selects the generated symmetric key. */
    doc = xmlReadMemory((const char*)data, (int)size, "fuzz.xml", NULL, xmlSecParserGetDefaultOptions());
    if (doc == NULL) {
        return 0;
    }
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }
    if (xmlSecCheckNodeName(root, xmlSecNodeKeyInfo, xmlSecDSigNs)) {
        node = root;
    } else {
        node = xmlSecFindNode(root, xmlSecNodeKeyInfo, xmlSecDSigNs);
    }
    if (node == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    ids[nids++] = xmlSecKeyDataIdUnknown;
    ids[nids++] = xmlSecOpenSSLKeyDataRsaId;
#ifndef XMLSEC_NO_DSA
    ids[nids++] = xmlSecOpenSSLKeyDataDsaId;
#endif
#ifndef XMLSEC_NO_EC
    ids[nids++] = xmlSecOpenSSLKeyDataEcId;
#endif
#ifndef XMLSEC_NO_DH
    ids[nids++] = xmlSecOpenSSLKeyDataDhId;
#endif
    ids[nids++] = xmlSecOpenSSLKeyDataAesId;
    ids[nids++] = xmlSecOpenSSLKeyDataHmacId;
    for (i = 0; i < nids; i++) {
        read_keyinfo(node, ids[i]);
    }
    xmlFreeDoc(doc);
    return 0;
}

