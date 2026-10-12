/*
 * xmlsec XML Encryption decryption fuzz target.
 *
 * No existing target drives XML Encryption. This one calls
 * xmlSecEncCtxDecryptToBuffer() and xmlSecEncCtxDecrypt() on an
 * <EncryptedData> element, which exercises EncryptedData/CipherData parsing,
 * the transform chain, block cipher padding, AES/DES key wrap, RSA key
 * transport. Agreement/KDF fixtures are deferred until matching keys are loaded.
 *
 * The keys the xmlenc test documents name are loaded into the keys manager so
 * that decryption can succeed rather than stopping at key lookup. Network and
 * external data loading are disabled so the harness stays offline.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/parser.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

/* Named symmetric test keys from tests/merlin-xmlenc-five/keys.xml and
 * tests/keys/keys.xml. Explicit sizes preserve binary AES-GCM key material. */
static const struct {
    const char* name;
    const char* material;
    xmlSecSize size;
    int is_des;
} g_sym_keys[] = {
    { "bob", "abcdefghijklmnopqrstuvwx",         24, 1 },  /* tripledes, kw-tripledes */
    { "jeb", "abcdefghijklmnopqrstuvwx",         24, 0 },  /* aes192, kw-aes192 */
    { "job", "abcdefghijklmnop",                 16, 0 },  /* aes128, kw-aes128 */
    { "jed", "abcdefghijklmnopqrstuvwxyz012345", 32, 0 },  /* aes256, kw-aes256 */
    { "test-aes128",
        "\xd1\x77\xf2\xdc\x44\xbe\x15\xbb\xff\x39\xf5\xae\x40\x72\xaf\x3c",
        16, 0 },
    { "test-aes192",
        "\x96\x4f\x43\xc8\x0d\x3b\xc4\xbf\xe6\xe3\x97\xd4\x6f\xbc\xdb\x2e"
        "\x8c\xb7\x73\x48\x4b\x87\x0f\x34",
        24, 0 },
    { "test-aes256",
        "\x7e\x90\x8f\x40\xb0\x8c\x64\x2c\x3d\x5a\x2a\x47\xf2\x49\x35\x27"
        "\xbe\x42\xa9\x88\x16\x06\x16\xc9\x0c\xc1\x4f\x89\x44\xb4\x87\x31",
        32, 0 },
};
#define G_SYM_NKEYS ((int)(sizeof(g_sym_keys) / sizeof(g_sym_keys[0])))

/* Public test-suite key from tests/merlin-xmlenc-five/rsapriv.pem, named
 * merlin-rsa-key by tests/testEnc.sh. This is test material, not a production
 * secret. The PEM lines are reassembled with newlines at runtime. */
static const char* const g_key_lines[] = {
    "-----BEGIN RSA PRIVATE KEY-----",
    "MIICXQIBAAKBgQDkXTUsWzRVpUHjbDpWCfYDfXmQ/q4LkaioZoTpu4ut1Q3eQC5t",
    "gD14agJhgT8yzeY5S/YNlwCyuVkjuFyoyTHFX2IOPpz7jnh4KnQ+B1IH9fY/+kmk",
    "zHJgxSUDJsdUMPgGpKt5hnEn7ziXAWXLc2udFbnHwhi9TXXwRHGi9wZ4YwIDAQAB",
    "AoGBALNTnlXeqRI4W61DZ+v4ln/XIIeD9xiOoWrcVrNU2zL+g41ryQmkEqFkXcpD",
    "vGUg2xFTXTz+v0WZ1y39sIW6uKFRYUfaNsF6iVfGAyx1VWK/jgtPnCWDQy26Eby0",
    "BqpbZRy1a6MLYVEG/5bvZE01CDV4XttpTrNX91WWcYGduJxBAkEA6ED1ZOqIzBpu",
    "c2KAo+bWmroCH8+cSDk0gVq6bnRB+EEhRCmo/VgvndWLxfexdGmDIOAIisB06N5a",
    "GzBSCaEY/QJBAPu2cNvuuBNLwrlxPCwOEpIHYT4gJq8UMtg6O6N+u++nYCGhK6uo",
    "VCmrKY+UewyNIcsLZF0jsNI2qJjiU1vQxN8CQQDfQJnigMQwlfO3/Ga1po6Buu2R",
    "0IpkroB3G1R8GkrTrR+iGv2zUdKrwHsUOC2fPlFrB4+OeMOomRw6aG9jjDStAkB1",
    "ztiZhuvuVAoKIv5HnDqC0CNqIUAZtzlozDB3f+xT6SFr+/Plfn4Nlod4JMVGhZNo",
    "ZaeOlBLBAEX+cAcVtOs/AkBicZOAPv84ABmFfyhXhYaAuacaJLq//jg+t+URUOg+",
    "XZS9naRmawEQxOkZQVoMeKgvu05+V4MniFqdQBINIkr5",
    "-----END RSA PRIVATE KEY-----",
};
#define G_KEY_NLINES ((int)(sizeof(g_key_lines) / sizeof(g_key_lines[0])))

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

static int load_sym_keys(void) {
    int i;

    for (i = 0; i < G_SYM_NKEYS; ++i) {
        xmlSecKeyDataId id = g_sym_keys[i].is_des ?
            xmlSecOpenSSLKeyDataDesId :
            xmlSecOpenSSLKeyDataAesId;
        xmlSecKeyPtr key = xmlSecKeyReadMemory(id,
            (const xmlSecByte*)g_sym_keys[i].material,
            g_sym_keys[i].size);

        if (key == NULL) {
            return -1;
        }
        if (xmlSecKeySetName(key, (const xmlChar*)g_sym_keys[i].name) < 0 ||
            xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(g_mngr, key) < 0) {
            xmlSecKeyDestroy(key);
            return -1;
        }
    }
    return 0;
}

static int load_rsa_key(void) {
    char pem[4096];
    size_t off = 0;
    int i;
    xmlSecKeyPtr key = NULL;

    for (i = 0; i < G_KEY_NLINES; ++i) {
        size_t len = strlen(g_key_lines[i]);
        if (off + len + 1 >= sizeof(pem)) {
            return -1;
        }
        memcpy(pem + off, g_key_lines[i], len);
        off += len;
        pem[off++] = 0x0A;  /* newline; avoid escape sequences (see note above) */
    }

    key = xmlSecOpenSSLAppKeyLoadMemory((const xmlSecByte*)pem, (xmlSecSize)off,
                                       xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if (key == NULL) {
        return -1;
    }
    if (xmlSecKeySetName(key, (const xmlChar*)"merlin-rsa-key") < 0 ||
        xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(g_mngr, key) < 0) {
        xmlSecKeyDestroy(key);
        return -1;
    }
    return 0;
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

    /* Silence libxml2 and xmlsec error spam. */
    xmlSetGenericErrorFunc(NULL, &ignore_error);
    xmlSecErrorsSetCallback(&ignore_xmlsec_error);

    g_mngr = xmlSecKeysMngrCreate();
    if (g_mngr == NULL) {
        xmlSecOpenSSLShutdown();
        xmlSecOpenSSLAppShutdown();
        xmlSecShutdown();
        return -1;
    }
    if (xmlSecOpenSSLAppDefaultKeysMngrInit(g_mngr) < 0 ||
        load_sym_keys() < 0 || load_rsa_key() < 0) {
        xmlSecKeysMngrDestroy(g_mngr);
        g_mngr = NULL;
        xmlSecOpenSSLShutdown();
        xmlSecOpenSSLAppShutdown();
        xmlSecShutdown();
        return -1;
    }

    return 0;
}

/* Keep a decryption context from reaching the network or the file system.
 * <CipherReference> and <RetrievalMethod> both take a URI. */
static void restrict_uris(xmlSecEncCtxPtr encCtx) {
    encCtx->transformCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
    encCtx->keyInfoReadCtx.retrievalMethodCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
    encCtx->keyInfoReadCtx.keyInfoReferenceCtx.enabledUris =
        xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument;
}

/* xmlSecEncCtxDecrypt() replaces the encrypted node in its document, so it is
 * given the last turn. Both entry points are driven because they diverge on
 * how the decrypted octets are returned. */
static void decrypt_to_buffer(xmlDocPtr doc) {
    xmlSecEncCtxPtr encCtx = NULL;
    xmlNodePtr node = xmlSecFindNode(xmlDocGetRootElement(doc),
                                     xmlSecNodeEncryptedData, xmlSecEncNs);

    if (node == NULL) {
        return;
    }
    encCtx = xmlSecEncCtxCreate(g_mngr);
    if (encCtx == NULL) {
        return;
    }
    restrict_uris(encCtx);
    (void)xmlSecEncCtxDecryptToBuffer(encCtx, node);
    xmlSecEncCtxDestroy(encCtx);
}

static void decrypt_in_place(xmlDocPtr doc) {
    xmlSecEncCtxPtr encCtx = NULL;
    xmlNodePtr node = xmlSecFindNode(xmlDocGetRootElement(doc),
                                     xmlSecNodeEncryptedData, xmlSecEncNs);

    if (node == NULL) {
        return;
    }
    encCtx = xmlSecEncCtxCreate(g_mngr);
    if (encCtx == NULL) {
        return;
    }
    restrict_uris(encCtx);
    (void)xmlSecEncCtxDecrypt(encCtx, node);
    xmlSecEncCtxDestroy(encCtx);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlDocPtr doc = NULL;
    xmlDocPtr copy = NULL;

    if (!g_initialized) {
        g_init_failed = (do_init() < 0);
        g_initialized = 1;
    }
    /* Skip inputs that cannot be represented as the int length expected by
     * xmlReadMemory(). */
    if (g_init_failed || size == 0 || size > (size_t)INT_MAX) {
        return 0;
    }

    /* Parse the document from memory. NONET prevents external fetches. */
    doc = xmlReadMemory((const char*)data, (int)size, "fuzz.xml", NULL,
        xmlSecParserGetDefaultOptions() | XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if (doc == NULL || xmlDocGetRootElement(doc) == NULL) {
        if (doc != NULL) xmlFreeDoc(doc);
        return 0;
    }

    /* DecryptToBuffer runs on a copy because the in-place variant below
     * rewrites the tree it is given. */
    copy = xmlCopyDoc(doc, 1);
    if (copy != NULL) {
        decrypt_to_buffer(copy);
        xmlFreeDoc(copy);
    }

    decrypt_in_place(doc);

    xmlFreeDoc(doc);
    return 0;
}
