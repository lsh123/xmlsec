/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library example: Decrypting an encrypted file using a single key.
 * @details Decrypts encrypted XML file using a single DES key from a binary file
 *
 * Usage:
 *
 * \code{.sh}
 *      ./decrypt1 <xml-enc> <des-key-file>
 * \endcode
 *
 * Example:
 *
 * \code{.sh}
 *      ./decrypt1 encrypt1-res.xml deskey.bin
 *      ./decrypt1 encrypt2-res.xml deskey.bin
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

int decrypt_file(const char* enc_file, const char* key_file);

int
main(int argc, char **argv) {
    int xmlsec_initialized = 0;
    int res = -1;

    assert(argv);

    if(argc != 3) {
        fprintf(stderr, "Error: wrong number of arguments.\n");
        fprintf(stderr, "Usage: %s <enc-file> <key-file>\n", argv[0]);
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

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        goto done;
    }
    xmlsec_initialized = 1;

    /* decrypt file */
    if(decrypt_file(argv[1], argv[2]) < 0) {
        goto done;
    }
    res = 0;

done:
    /* shutdown xmlsec-crypto library and xmlsec itself */
    if (xmlsec_initialized != 0) {
        xmlSecCryptoShutdown();
        xmlSecCryptoAppShutdown();
        xmlSecShutdown();
    }

    /* shutdown LibXML2 */
    xmlCleanupParser();

    return(res);
}

/**
 * @brief Decrypts an encrypted XML file using a DES key.
 * @details Decrypts the XML file #enc_file using DES key from #key_file and
 * prints results to stdout.
 * @param enc_file the encrypted XML file name.
 * @param key_file the DES key file.
 * @return 0 on success or a negative value if an error occurs.
 */
int
decrypt_file(const char* enc_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    assert(enc_file);
    assert(key_file);

    /* load encrypted file */
    doc = xmlReadFile(enc_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET | XML_PARSE_NOENT);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", enc_file);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", enc_file);
        goto done;
    }

    /* create encryption context, we don't need keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
        goto done;
    }

    /* load DES key */
    encCtx->encKey = xmlSecKeyReadBinaryFile(xmlSecKeyDataDesId, key_file);
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load DES key from binary file \"%s\"\n", key_file);
        goto done;
    }

    /* set the key name to the file name; this is only an example */
    if(xmlSecKeySetName(encCtx->encKey, BAD_CAST key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* decrypt the data */
    if((xmlSecEncCtxDecrypt(encCtx, node) < 0) || (encCtx->result == NULL)) {
        fprintf(stderr,"Error: decryption failed\n");
        goto done;
    }

    /* print decrypted data to stdout */
    if(encCtx->resultReplaced != 0) {
        fprintf(stdout, "Decrypted XML data:\n");
        if(xmlDocDump(stdout, doc) < 0) {
            fprintf(stderr, "Error: failed to write the decrypted document to stdout\n");
            goto done;
        }
    } else {
        fprintf(stdout, "Decrypted binary data (" XMLSEC_SIZE_FMT " bytes):\n",
            xmlSecBufferGetSize(encCtx->result));
        if(xmlSecBufferGetData(encCtx->result) != NULL) {
            if(fwrite(xmlSecBufferGetData(encCtx->result),
                      1,
                      xmlSecBufferGetSize(encCtx->result),
                      stdout) != xmlSecBufferGetSize(encCtx->result)) {
                fprintf(stderr, "Error: failed to write the decrypted data to stdout\n");
                goto done;
            }
        }
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
