/*
 * xmlsec XML Encryption decryption fuzz target.
 *
 * No existing target drives XML Encryption. This one calls
 * xmlSecEncCtxDecryptToBuffer() and xmlSecEncCtxDecrypt() on an
 * <EncryptedData> element, which exercises EncryptedData/CipherData parsing,
 * the transform chain, block cipher padding, AES/DES key wrap, RSA key
 * transport and the ConcatKDF/AgreementMethod key derivation paths.
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
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

/* Symmetric keys used by the xmlenc test documents, which name them in
 * <KeyName>. The material is the plain ASCII prefix that
 * tests/merlin-xmlenc-five/keys.xml carries base64-encoded, so a document
 * wrapped to one of these keys really does decrypt. */
static const struct {
    const char* name;
    const char* material;   /* length selects the algorithm variant */
    int is_des;
} g_sym_keys[] = {
    { "bob", "abcdefghijklmnopqrstuvwx",         1 },  /* tripledes, kw-tripledes */
    { "jeb", "abcdefghijklmnopqrstuvwx",         0 },  /* aes192, kw-aes192 */
    { "job", "abcdefghijklmnop",                 0 },  /* aes128, kw-aes128 */
    { "jed", "abcdefghijklmnopqrstuvwxyz012345", 0 },  /* aes256, kw-aes256 */
};
#define G_SYM_NKEYS ((int)(sizeof(g_sym_keys) / sizeof(g_sym_keys[0])))

/* Fixed RSA test key (PEM), stored as individual lines so the source contains
 * no backslash-escape sequences; the PEM is re-assembled (with real newline
 * characters) at runtime. The rsa-1_5 and rsa-oaep documents were wrapped to a
 * different key, so key transport is driven down its failure paths, which is
 * where the padding handling lives. */
static const char* const g_key_lines[] = {
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDQBXL8JyfDOJhr",
    "K1019rmofPLqsMbIGielYOAwu5DjcICOXG5f2ew5oFySJPryWUTY2A3YbmLpX7/0",
    "7wVOdXyd8WgidrlIRsOaEnp0XeQ/VYV7ng6MDhM1efwGvvJdBysDwQAWkexaOPtK",
    "omu0mOExVHtrDO3LpS3GFtsdbLgDMph10ZFW6I9ZWurWded9osqZY39Monj9cEXt",
    "SapupJeP1wWLJUvzQNp6CYfNMhWpmvchuMG0HIIlqAm9i7AMNCLXbSIYvjAtOGOS",
    "ABjKwnZsBRr/2apET0E7j4Uo+T7Yb5alhYzxsXz+Ywjrji86em3yAjukQQdv+YGa",
    "WVsrsGIPAgMBAAECggEABwmhwdiGE3UfHJETaDeR2s3PXuB4LF2y9awsKYa1XvYR",
    "ab+RMS3FCVx2UhagmGf4vxu5uP0sqRfG/YxdZTG7jSrIcR7YvRJxaUCZL/kO0PqE",
    "HfiGjKp1PLWE/ao8HNv/OPNKNqx2wit0JPd1v8UxHGNVTmJAZHr3Uq2EE2zE+1nZ",
    "+F+ia87JX9UB3WgqW+5ZxneQ7U9s84dGaPRSvNFmOnUTlKp6P9QmH29tl8bSYFez",
    "LGAXsPNXcLRrmS88P9UkF+jAdik5rJUxGoiJ4SGmadZOPusVp4If9m3eH33BTzR8",
    "uUDcDWW9/z+/Jw3VLLdcOnOIdCo3gzRtYcKWXsHd8QKBgQD9iGMsVrQnpjkDiCul",
    "cZVJ9MLgTzGPjK/sQXxm4NnFN603wmWe7CRJK0Dnx7Q8mDkM6Ufq/30dxHgVnx13",
    "dO/qQoaonL0dAw8qdI3v80i0MScp51HqeJRWHp+3LsUBEvj2+Mz+Y2QlZviZKRoj",
    "9NfDxR4Yjt9lOKHhNOhWiOXxFQKBgQDSC65z78Md6wSE4qF7Kn+oc7OsPHEopika",
    "grSXPyuwI2icNj7DEYypphPs6vrlxdDn2zusO+p9LOBjm35zce1y+dqnnAvPBMpN",
    "4i++s7Dc8ALtB2F9FVPNuNQfYc9IPJire046bKhNjCFTlkeWl9P5FHy31QPqp2R9",
    "jTWzy+nnkwKBgF+lWGSdwRFEMDYY5P5hP0TLRcmBltzk4mlquxfEs+MnAf4LJHMz",
    "+uxvmOjX+jLx6nPofe01vWnBeNwPTvqF7wydVFe/6chMIyiNGA7x5Pe1o2S3k7u1",
    "CaEDpJVi24dwNORXMF63+Evz8M03KFlwQQXmE1iIbdat6sQfRZd/xd+RAoGAOsk2",
    "LBCAhVEPVLmxBC2iyNyI/r1z1jKa8mZ+cI4nhgaC8qVj72hr+9cVYItraP9yNlHv",
    "Y4bpW9tBed89BsZt9G3lOl+8FlZ64E1bm33jFBLAXuJf8IgVilAeXiIbx1XeTLAX",
    "9tYOTJXZhfFbW9RmaSHIvhKKJBRxVYo963I4pq0CgYBNukE2d/6dzIhsDC+Ndf9c",
    "uzyJVfihxoQRPJAR7C2RdyfUFLJPqEiqGWOUBm9f092WJT11mNZ1vtT9Lar2lg7b",
    "msfYIwZXfUbFerc0NY7Ak9mVhk7ZxFqtV38p9OvJgsh1BpMA7M/9HtaaZP6aTC/b",
    "0MODtheSMAnrJbLRlnBqHg==",
    "-----END PRIVATE KEY-----",
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

/* Load the named symmetric keys. Failures are ignored: a missing key only
 * makes the harness shallower, it does not make it wrong. */
static void load_sym_keys(void) {
    int i;

    for (i = 0; i < G_SYM_NKEYS; ++i) {
        xmlSecKeyDataId id = g_sym_keys[i].is_des ?
            xmlSecOpenSSLKeyDataDesId :
            xmlSecOpenSSLKeyDataAesId;
        xmlSecKeyPtr key = xmlSecKeyReadMemory(id,
            (const xmlSecByte*)g_sym_keys[i].material,
            (xmlSecSize)strlen(g_sym_keys[i].material));

        if (key == NULL) {
            continue;
        }
        if (xmlSecKeySetName(key, (const xmlChar*)g_sym_keys[i].name) < 0 ||
            xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(g_mngr, key) < 0) {
            xmlSecKeyDestroy(key);
        }
    }
}

static void load_rsa_key(void) {
    char pem[4096];
    size_t off = 0;
    int i;
    xmlSecKeyPtr key = NULL;

    for (i = 0; i < G_KEY_NLINES; ++i) {
        size_t len = strlen(g_key_lines[i]);
        if (off + len + 1 >= sizeof(pem)) {
            return;
        }
        memcpy(pem + off, g_key_lines[i], len);
        off += len;
        pem[off++] = 0x0A;  /* newline; avoid escape sequences (see note above) */
    }

    key = xmlSecOpenSSLAppKeyLoadMemory((const xmlSecByte*)pem, (xmlSecSize)off,
                                       xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if (key == NULL) {
        return;
    }
    if (xmlSecKeySetName(key, (const xmlChar*)"merlin-rsa-key") < 0 ||
        xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(g_mngr, key) < 0) {
        xmlSecKeyDestroy(key);
    }
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

    g_mngr = xmlSecKeysMngrCreate();
    if (g_mngr == NULL) {
        return -1;
    }
    if (xmlSecOpenSSLAppDefaultKeysMngrInit(g_mngr) < 0) {
        xmlSecKeysMngrDestroy(g_mngr);
        g_mngr = NULL;
        return -1;
    }

    load_sym_keys();
    load_rsa_key();
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

    /* Parse the document from memory. NONET prevents external fetches;
     * NOENT substitutes internal (general) entities at parse time. */
    doc = xmlReadMemory((const char*)data, (int)size, "fuzz.xml", NULL,
                        XML_PARSE_NONET | XML_PARSE_NOENT);
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
