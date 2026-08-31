/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library example: Decrypting an encrypted file using a custom keys manager.
 * @details Decrypts encrypted XML file using a custom files based keys manager.
 * We assume that key's name in <dsig:KeyName/> element is just
 * key's file name in the current folder.
 *
 * Usage:
 *
 * \code{.sh}
 *      ./decrypt3 <xml-enc>
 * \endcode
 *
 * Example:
 *
 * \code{.sh}
 *      ./decrypt3 encrypt1-res.xml
 *      ./decrypt3 encrypt2-res.xml
 * \endcode
 */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/crypto.h>

xmlSecKeyStoreId  files_keys_store_get_klass(void);
xmlSecKeysMngrPtr create_files_keys_mngr(void);
int decrypt_file(xmlSecKeysMngrPtr mngr, const char* enc_file);

int
main(int argc, char **argv) {
    int xmlsec_initialized = 0;
    xmlSecKeysMngrPtr mngr = NULL;
    int res = -1;
#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

    assert(argv);

    if(argc != 2) {
        fprintf(stderr, "Error: wrong number of arguments.\n");
        fprintf(stderr, "Usage: %s <enc-file>\n", argv[0]);
        return(1);
    }

    /* Init LibXML2 */
    xmlInitParser();
    LIBXML_TEST_VERSION

    /* Init LibXSLT */
#ifndef XMLSEC_NO_XSLT
    /* disable all XSLT file and network access */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

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

    /* create keys manager and load keys */
    mngr = create_files_keys_mngr();
    if(mngr == NULL) {
        goto done;
    }

    /* decrypt file */
    if(decrypt_file(mngr, argv[1]) < 0) {
        goto done;
    }

    /* success! */
    res = 0;

done:
    /* destroy keys manager */
    if(mngr != NULL) {
        xmlSecKeysMngrDestroy(mngr);
    }

    /* shutdown xmlsec-crypto library and xmlsec itself */
    if (xmlsec_initialized != 0) {
        xmlSecCryptoShutdown();
        xmlSecCryptoAppShutdown();
        xmlSecShutdown();
    }

    /* shutdown LibXSLT / LibXML2 */
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    return(res);
}

/**
 * @brief Decrypts an encrypted XML file using a keys manager.
 * @details Decrypts the XML file #enc_file using keys from the keys manager and
 * prints results to stdout.
 * @param mngr the pointer to keys manager.
 * @param enc_file the encrypted XML file name.
 * @return 0 on success or a negative value if an error occurs.
 */
int
decrypt_file(xmlSecKeysMngrPtr mngr, const char* enc_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    assert(mngr);
    assert(enc_file);

    /* load template */
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

    /* create encryption context */
    encCtx = xmlSecEncCtxCreate(mngr);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
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

/**
 * @brief Creates a files-based keys manager.
 * @details Creates a files based keys manager: we assume that key name is
 * the key file name.
 * @return pointer to newly created keys manager or NULL if an error occurs.
 */
xmlSecKeysMngrPtr
create_files_keys_mngr(void) {
    xmlSecKeyStorePtr keysStore;
    xmlSecKeysMngrPtr mngr;

    /* create a file-based keys store */
    keysStore = xmlSecKeyStoreCreate(files_keys_store_get_klass());
    if(keysStore == NULL) {
        fprintf(stderr, "Error: failed to create keys store.\n");
        return(NULL);
    }

    /* create keys manager */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
        fprintf(stderr, "Error: failed to create keys manager.\n");
        xmlSecKeyStoreDestroy(keysStore);
        return(NULL);
    }

    /* add store to keys manager, from now on keys manager destroys the store if needed */
    if(xmlSecKeysMngrAdoptKeysStore(mngr, keysStore) < 0) {
        fprintf(stderr, "Error: failed to add keys store to keys manager.\n");
        xmlSecKeyStoreDestroy(keysStore);
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    /* initialize crypto library specific data in keys manager */
    if(xmlSecCryptoKeysMngrInit(mngr) < 0) {
        fprintf(stderr, "Error: failed to initialize crypto data in keys manager.\n");
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    /* set the get key callback */
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(mngr);
}

/******************************************************************************
 *
 * Files Keys Store: we assume that key's name (content of the
 * <xenc:KeyName/> element) is a name of the file with a key (in the
 * current folder).
 * Attention: this is probably not a good solution for high traffic systems.
 *
  *****************************************************************************/
static xmlSecKeyPtr             files_keys_store_find_key       (xmlSecKeyStorePtr store,
                                                                 const xmlChar* name,
                                                                 xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyStoreKlass files_keys_store_klass = {
    sizeof(xmlSecKeyStoreKlass),
    sizeof(xmlSecKeyStore),
    BAD_CAST "files-based-keys-store",  /* const xmlChar* name; */
    NULL,                               /* xmlSecKeyStoreInitializeMethod initialize; */
    NULL,                               /* xmlSecKeyStoreFinalizeMethod finalize; */
    files_keys_store_find_key,          /* xmlSecKeyStoreFindKeyMethod findKey; */
    NULL,                               /* xmlSecKeyStoreFindKeyFromX509DataMethod findKeyFromX509Data; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
};

/**
 * @brief Gets the files-based keys store klass.
 * @details Returns the file-based keys store klass; it assumes that the key
 * name is the key file name.
 * @return the file-based keys store klass.
 */
xmlSecKeyStoreId
files_keys_store_get_klass(void) {
    return(&files_keys_store_klass);
}

/**
 * @brief Finds a key in the files-based keys store.
 * @details Looks up a key in #store. The caller is responsible for destroying
 * the returned key with #xmlSecKeyDestroy.
 * @param store the pointer to the files-based keys store.
 * @param name the desired key name.
 * @param keyInfoCtx the pointer to <dsig:KeyInfo/> node processing context.
 * @return pointer to key or NULL if key not found or an error occurs.
 */
static xmlSecKeyPtr
files_keys_store_find_key(xmlSecKeyStorePtr store, const xmlChar* name, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyPtr key;
    const xmlChar* p;

    assert(store);
    assert(keyInfoCtx);

    /* it is possible that the key name or desired key type is missing,
     * and there is nothing we can do in that case */
    if((name == NULL) || (keyInfoCtx->keyReq.keyId == xmlSecKeyDataIdUnknown)){
        return(NULL);
    }

    /* we do not want to open files outside the current folder;
     * to prevent that, limit the characters in the key name to letters, digits,
     * '.', '-' or '_'.
     */
    for(p = name; (*p) != '\0'; ++p) {
        if(!isalnum((*p)) && ((*p) != '.') && ((*p) != '-') && ((*p) != '_')) {
            return(NULL);
        }
    }

    if((keyInfoCtx->keyReq.keyId == xmlSecKeyDataDsaId) || (keyInfoCtx->keyReq.keyId == xmlSecKeyDataRsaId)) {
        /* load key from a pem file, if key is not found then it's an error */
        key = xmlSecCryptoAppKeyLoadEx((const char*)name, xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
        if(key == NULL) {
            fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", name);
            return(NULL);
        }
    } else {
        /* otherwise it's a binary key, if key is not found then it's an error */
        key = xmlSecKeyReadBinaryFile(keyInfoCtx->keyReq.keyId, (const char*)name);
        if(key == NULL) {
            fprintf(stderr,"Error: failed to load key from binary file \"%s\"\n", name);
            return(NULL);
        }
    }

    /* set key name */
    if(xmlSecKeySetName(key, name) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", (const char*)name);
        xmlSecKeyDestroy(key);
        return(NULL);
    }

    return(key);
}
