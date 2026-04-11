/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library example: Encrypting an XML file with a dynamically created template.
 * @details Encrypts an XML file using a dynamically created template and a DES key
 * from a binary file.
 *
 * Usage:
 *
 * \code{.sh}
 *      ./encrypt2 <xml-doc> <des-key-file>
 * \endcode
 *
 * Example:
 *
 * \code{.sh}
 *      ./encrypt2 encrypt2-doc.xml deskey.bin > encrypt2-res.xml
 * \endcode
 *
 * The result can be decrypted using the decrypt1 example:
 *
 * \code{.sh}
 *      ./decrypt1 encrypt2-res.xml deskey.bin
 * \endcode
 */
#include <stdlib.h>
#include <string.h>
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
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

int encrypt_file(const char* xml_file, const char* key_file);
xmlNodePtr create_encryption_template(xmlDocPtr doc);

int
main(int argc, char **argv) {
#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

    assert(argv);

    if(argc != 3) {
        fprintf(stderr, "Error: wrong number of arguments.\n");
        fprintf(stderr, "Usage: %s <xml-file> <key-file>\n", argv[0]);
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
        return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return(-1);
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
        return(-1);
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return(-1);
    }

    if(encrypt_file(argv[1], argv[2]) < 0) {
        return(-1);
    }

    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();

    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();

    /* Shutdown XMLSec */
    xmlSecShutdown();

    /* Shutdown LibXSLT / LibXML2*/
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    return(0);
}

/**
 * @brief Creates encryption template to encrypt the XML file.
 * @param doc the XML document.
 * @return pointer to the <enc:EncryptedData/> node or NULL if an error occurs.
 */
xmlNodePtr
create_encryption_template(xmlDocPtr doc) {
    xmlNodePtr encDataNode = NULL;
    xmlNodePtr keyInfoNode = NULL;

    assert(doc);

    /* add <enc:EncryptedData/> node to encrypt XML file and replace its content with encryption result */
    encDataNode = xmlSecTmplEncDataCreate(doc, xmlSecTransformDes3CbcId, NULL, xmlSecTypeEncElement, NULL, NULL);
    if(encDataNode == NULL) {
        fprintf(stderr, "Error: failed to create encryption template\n");
        return(NULL);
    }

    /* add <enc:CipherValue/> node */
    if(xmlSecTmplEncDataEnsureCipherValue(encDataNode) == NULL) {
        fprintf(stderr, "Error: failed to add CipherValue node\n");
        return(NULL);
    }

    /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
    keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encDataNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        return(NULL);
    }
    if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
        fprintf(stderr, "Error: failed to add key name\n");
        return(NULL);
    }

    /* done */
    return(encDataNode);
}

/**
 * @brief Encrypts an XML file using a dynamically created template and DES key.
 * @details Encrypts #xml_file using a dynamically created template and the DES key
 * from #key_file.
 * @param xml_file the encryption template file name.
 * @param key_file the Triple DES key file.
 * @return 0 on success or a negative value if an error occurs.
 */
int
encrypt_file(const char* xml_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr encDataNode = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    assert(xml_file);
    assert(key_file);

    /* load template */
    doc = xmlReadFile(xml_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET | XML_PARSE_NOENT);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
        goto done;
    }

    /* create encryption template */
    encDataNode = create_encryption_template(doc);
    if(encDataNode == NULL) {
            fprintf(stderr,"Error: failed to create encryption context\n");
        goto done;
    }

    /* create encryption context, we don't need keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
        goto done;
    }

    /* load DES key, assuming that there is no password */
    encCtx->encKey = xmlSecKeyReadBinaryFile(xmlSecKeyDataDesId, key_file);
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load des key from binary file \"%s\"\n", key_file);
        goto done;
    }

    /* set the key name to the file name; this is only an example */
    if(xmlSecKeySetName(encCtx->encKey, BAD_CAST key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* encrypt the data */
    if(xmlSecEncCtxXmlEncrypt(encCtx, encDataNode, xmlDocGetRootElement(doc)) < 0) {
        fprintf(stderr,"Error: encryption failed\n");
        goto done;
    }

    /* the template is inserted into the document */
    encDataNode = NULL;

    /* print encrypted data with document to stdout */
    xmlDocDump(stdout, doc);

    /* success */
    res = 0;

done:

    /* cleanup */
    if(encCtx != NULL) {
        xmlSecEncCtxDestroy(encCtx);
    }

    if(encDataNode != NULL) {
        xmlFreeNode(encDataNode);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(res);
}
