/**
 * XML Security Library example: Encrypting XML file with a dynamicaly created template.
 *
 * Encrypts XML file using a dynamicaly created template file and an AES key
 * from a binary file
 *
 * Usage:
 *      ./encrypt2 <xml-doc> <aes-key-file>
 *
 * Example:
 *      ./encrypt2 encrypt2-doc.xml aeskey.bin > encrypt2-res.xml
 *
 * The result could be decrypted with decrypt1 example:
 *      ./decrypt1 encrypt2-res.xml aeskey.bin
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
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

    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    /* Do not substitute (external) entities and do not load external DTDs:
     * enabling entity expansion is XXE-prone for untrusted input. */
    xmlLoadExtDtdDefaultValue = 0;
    xmlSubstituteEntitiesDefault(0);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
#endif /* XMLSEC_NO_XSLT */

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

    /* Init xmlsec library */
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

    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    return(0);
}

/**
 * encrypt_file:
 * @xml_file:           the encryption template file name.
 * @key_file:           the AES key file.
 *
 * Encrypts #xml_file using a dynamicaly created template and AES key from
 * #key_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
encrypt_file(const char* xml_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr encDataNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    assert(xml_file);
    assert(key_file);

    /* load template */
    doc = xmlParseFile(xml_file);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
        goto done;
    }

    /* create encryption template to encrypt XML file and replace
     * its content with encryption result */
    encDataNode = xmlSecTmplEncDataCreate(doc, xmlSecTransformAes128CbcId,
                                NULL, xmlSecTypeEncElement, NULL, NULL);
    if(encDataNode == NULL) {
        fprintf(stderr, "Error: failed to create encryption template\n");
        goto done;
    }

    /* we want to put encrypted data in the <enc:CipherValue/> node */
    if(xmlSecTmplEncDataEnsureCipherValue(encDataNode) == NULL) {
        fprintf(stderr, "Error: failed to add CipherValue node\n");
        goto done;
    }

    /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
    keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encDataNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        goto done;
    }

    if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
        fprintf(stderr, "Error: failed to add key name\n");
        goto done;
    }

    /* create encryption context, we don't need keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
        goto done;
    }

    /* load AES key, assuming that there is not password */
    encCtx->encKey = xmlSecKeyReadBinaryFile(xmlSecKeyDataAesId, key_file);
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load aes key from binary file \"%s\"\n", key_file);
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(encCtx->encKey, BAD_CAST key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* encrypt the data */
    if(xmlSecEncCtxXmlEncrypt(encCtx, encDataNode, xmlDocGetRootElement(doc)) < 0) {
        fprintf(stderr,"Error: encryption failed\n");
        goto done;
    }

    /* we template is inserted in the doc */
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

