/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library example: Encrypting data using a template file.
 * @details Encrypts binary data using a template file and an AES key from a binary file
 *
 * Usage:
 *
 * \code{.sh}
 *      ./encrypt1 <tmpl-file> <key-file>
 * \endcode
 *
 * Example:
 *
 * \code{.sh}
 *      ./encrypt1 encrypt1-tmpl.xml aeskey.bin > encrypt1-res.xml
 * \endcode
 *
 * The result can be decrypted using the decrypt1 example:
 *
 * \code{.sh}
 *      ./decrypt1 encrypt1-res.xml aeskey.bin
 * \endcode
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/crypto.h>
#include <xmlsec/dl.h>

int encrypt_file(const char* tmpl_file, const char* key_file,
                 const unsigned char* data, size_t dataSize);
int
main(int argc, char **argv) {
    static const char secret_data[] = "Big secret";
    int xmlsec_initialized = 0;
    int xmlsec_crypto_app_initialized = 0;
    int xmlsec_crypto_initialized = 0;
    int res = -1;

    assert(argv);

    if(argc != 3) {
        fprintf(stderr, "Error: wrong number of arguments.\n");
        fprintf(stderr, "Usage: %s <tmpl-file> <key-file>\n", argv[0]);
        return(1);
    }

    /* Init LibXML2 */
    xmlInitParser();
    LIBXML_TEST_VERSION

    /* Init XMLSec */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        goto done;
    }
    xmlsec_initialized = 1;

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        goto done;
    }

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                        "that you have it installed and check shared libraries path\n"
                        "(LD_LIBRARY_PATH and/or LTDL_LIBRARY_PATH) environment variables.\n");
        goto done;
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        goto done;
    }
    xmlsec_crypto_app_initialized = 1;

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        goto done;
    }
    xmlsec_crypto_initialized = 1;

    /* encrypt file */
    if(encrypt_file(argv[1], argv[2], BAD_CAST secret_data, strlen(secret_data)) < 0) {
        goto done;
    }

    /* success! */
    res = 0;

done:

    /* shutdown the crypto engine and the library, in the reverse order of
     * initialization, skipping the steps that did not succeed */
    if (xmlsec_crypto_initialized != 0) {
        xmlSecCryptoShutdown();
    }
    if (xmlsec_crypto_app_initialized != 0) {
        xmlSecCryptoAppShutdown();
    }
    if (xmlsec_initialized != 0) {
        xmlSecShutdown();
    }

    /* shutdown LibXML2 */
    xmlCleanupParser();

    return(res);
}

/**
 * @brief Encrypts binary data using an AES key and a template file.
 * @details Encrypts binary #data using template from #tmpl_file and AES key from
 * #key_file.
 * @param tmpl_file the encryption template file name.
 * @param key_file the AES key file.
 * @param data the binary data to encrypt.
 * @param dataSize the binary data size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
encrypt_file(const char* tmpl_file, const char* key_file,
             const unsigned char* data, size_t dataSize) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    assert(tmpl_file);
    assert(key_file);
    assert(data);

    /* load template */
#if LIBXML_VERSION >= 21300
    doc = xmlReadFile(tmpl_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET | XML_PARSE_NOENT | XML_PARSE_NO_XXE);
#else /* LIBXML_VERSION >= 21300 */
    doc = xmlReadFile(tmpl_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET | XML_PARSE_NOENT);
#endif /* LIBXML_VERSION >= 21300 */
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", tmpl_file);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", tmpl_file);
        goto done;
    }

    /* create encryption context, we don't need a keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr, "Error: failed to create encryption context\n");
        goto done;
    }

    /* load AES key */
    encCtx->encKey = xmlSecKeyReadBinaryFile(xmlSecKeyDataAesId, key_file);
    if(encCtx->encKey == NULL) {
        fprintf(stderr, "Error: failed to load AES key from binary file \"%s\"\n", key_file);
        goto done;
    }

    /* set the key name to the file name; this is only an example */
    if(xmlSecKeySetName(encCtx->encKey, BAD_CAST key_file) < 0) {
        fprintf(stderr, "Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* encrypt the data */
    if(xmlSecEncCtxBinaryEncrypt(encCtx, node, data, dataSize) < 0) {
        fprintf(stderr, "Error: encryption failed\n");
        goto done;
    }

    /* print encrypted data with the document to stdout */
    if(xmlDocDump(stdout, doc) < 0) {
        fprintf(stderr, "Error: failed to write the encrypted document to stdout\n");
        goto done;
    }
    fprintf(stdout, "\n");

    /* success */
    res = 0;

done:

    /* cleanup */
    if(encCtx != NULL) {
        xmlSecEncCtxDestroy(encCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(res);
}
