/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library example: Verifying a file signed with an X509 certificate
 * @details Verifies a file signed with an X509 certificate.
 *
 * This example was developed and tested with the OpenSSL crypto library. The
 * certificates management policies for another crypto library may break it.
 *
 * Usage:
 *
 * \code{.sh}
 *      verify4 <signed-file> <id-attribute-to-verify> <trusted-cert-pem-file1> [<trusted-cert-pem-file2> [...]]
 * \endcode
 *
 * Example:
 *
 * \code{.sh}
 *      ./verify4 sign4-res.xml "data" ca2cert.pem cacert.pem
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
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

xmlSecKeysMngrPtr load_trusted_certs(char** files, int files_size);
int verify_file(xmlSecKeysMngrPtr mngr, const char* xml_file, const char* id_attr);
int verify_signature_results(xmlSecDSigCtxPtr dsigCtx, const char* id_attr);

int
main(int argc, char **argv) {
    int xmlsec_initialized = 0;
#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */
    xmlSecKeysMngrPtr mngr = NULL;
    int res = -1;

    assert(argv);

    if(argc < 4) {
        fprintf(stderr, "Error: wrong number of arguments.\n");
        fprintf(stderr, "Usage: %s <xml-file> <id-attribute-to-verify> <cert-file1> [<cert-file2> [...]]\n", argv[0]);
        return(1);
    }

    /* Init LibXML2 */
    xmlInitParser();
    LIBXML_TEST_VERSION

    /* Init LibXSLT */
#ifndef XMLSEC_NO_XSLT
    /* disable all XSLT file and network access */
    xsltSecPrefs = xsltNewSecurityPrefs();
    if(xsltSecPrefs == NULL) {
        fprintf(stderr, "Error: failed to create the xslt security prefs\n");
        goto xslt_cleanup;
    }
    if(xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid) < 0) {
        fprintf(stderr, "Error: failed to set XSLT security pref READ_FILE\n");
        goto xslt_cleanup;
    }
    if(xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid) < 0) {
        fprintf(stderr, "Error: failed to set XSLT security pref WRITE_FILE\n");
        goto xslt_cleanup;
    }
    if(xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid) < 0) {
        fprintf(stderr, "Error: failed to set XSLT security pref CREATE_DIRECTORY\n");
        goto xslt_cleanup;
    }
    if(xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid) < 0) {
        fprintf(stderr, "Error: failed to set XSLT security pref READ_NETWORK\n");
        goto xslt_cleanup;
    }
    if(xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid) < 0) {
        fprintf(stderr, "Error: failed to set XSLT security pref WRITE_NETWORK\n");
        goto xslt_cleanup;
    }
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

    /* Init XMLSec */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        goto xslt_cleanup;
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

    /* create keys manager and load trusted certificates */
    mngr = load_trusted_certs(&(argv[3]), argc - 3);
    if(mngr == NULL) {
        goto done;
    }

    /* verify file */
    if(verify_file(mngr, argv[1], argv[2]) < 0) {
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

xslt_cleanup:
    /* Shutdown LibXSLT / LibXML2 */
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    return(res);
}

/**
 * @brief Creates a keys manager and loads trusted X.509 certificates.
 * @details Creates a simple keys manager and loads trusted certificates from PEM #files.
 * The caller is responsible for destroying returned keys manager using
 * #xmlSecKeysMngrDestroy.
 * @param files the list of filenames.
 * @param files_size the number of filenames in #files.
 * @return the pointer to newly created keys manager or NULL if an error
 * occurs.
 */
xmlSecKeysMngrPtr
load_trusted_certs(char** files, int files_size) {
    xmlSecKeysMngrPtr mngr;
    int i;

    assert(files);
    assert(files_size > 0);

    /* create and initialize keys manager, we use a simple list based
     * keys manager, implement your own xmlSecKeysStore klass if you need
     * something more sophisticated
     */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
        fprintf(stderr, "Error: failed to create keys manager.\n");
        return(NULL);
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        fprintf(stderr, "Error: failed to initialize keys manager.\n");
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    for(i = 0; i < files_size; ++i) {
        assert(files[i]);

        /* load trusted cert */
        if(xmlSecCryptoAppKeysMngrCertLoad(mngr, files[i], xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
            fprintf(stderr,"Error: failed to load PEM certificate from \"%s\"\n", files[i]);
            xmlSecKeysMngrDestroy(mngr);
            return(NULL);
        }
    }

    return(mngr);
}

/**
 * @brief Verifies XML signature in #xml_file.
 * @param mngr the pointer to keys manager.
 * @param xml_file the signed XML file name.
 * @param id_attr the expected ID attribute for the signed node
 * @return 0 on success or a negative value if an error occurs.
 */
int
verify_file(xmlSecKeysMngrPtr mngr, const char* xml_file, const char* id_attr) {
    const xmlChar* id_attributes[] = { BAD_CAST "id", BAD_CAST "ID", NULL };
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    assert(mngr);
    assert(xml_file);
    assert(id_attr);

    /* load file */
#if LIBXML_VERSION >= 21300
    doc = xmlReadFile(xml_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET | XML_PARSE_NOENT | XML_PARSE_NO_XXE);
#else /* LIBXML_VERSION >= 21300 */
    doc = xmlReadFile(xml_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET | XML_PARSE_NOENT);
#endif /* LIBXML_VERSION >= 21300 */
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
        goto done;
    }

    /* add ID attributes to the doc context since we don't have DTDs */
    xmlSecAddIDs(doc, NULL, id_attributes);

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", xml_file);
        goto done;
    }

    /* create signature context */
    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature verification failed\n");
        goto done;
    }

    /* verify results and print outcome to stdout */
    if(verify_signature_results(dsigCtx, id_attr) == 0) {
        fprintf(stdout, "Signature is OK\n");
    } else {
        fprintf(stdout, "Signature is INVALID\n");
        goto done;
    }

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(res);
}

/**
 * @brief Verifies XML signature results match expected data.
 * @details Verifies XML signature results to ensure that signature was applied
 * to the expected data.
 * @param dsigCtx the XMLDSig context
 * @param id_attr the expected ID attribute for the signed node
 * @return 0 on success or a negative value if an error occurs.
 */
int
verify_signature_results(xmlSecDSigCtxPtr dsigCtx, const char* id_attr) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    xmlSecTransformPtr transform;
    char uri[1024];

    assert(dsigCtx);
    assert(id_attr);

    /* check that signature verification succeeded */
    if(dsigCtx->status != xmlSecDSigStatusSucceeded) {
        fprintf(stderr,"Error: Signature verification result is not SUCCESS\n");
        return(-1);
    }

    /* in this example we expect exactly ONE reference with URI "#<id-attribute>" and no unexpected transforms */
    if(xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) != 1) {
        fprintf(stderr,"Error: Exactly one Reference is expected\n");
        return(-1);
    }
    dsigRefCtx = (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), 0);
    if((dsigRefCtx == NULL) || (dsigRefCtx->status != xmlSecDSigStatusSucceeded)) {
        fprintf(stderr,"Error: Reference verification result is not SUCCESS\n");
        return(-1);
    }

    /* check URI */
    if (strlen(id_attr) + 2 > sizeof(uri)) {
        fprintf(stderr, "Error: id attribute is too long\n");
        return(-1);
    }
    sprintf(uri, "#%s", id_attr);

    if(!xmlStrEqual(dsigRefCtx->uri, BAD_CAST uri)) {
        fprintf(stderr,"Error: Reference URI value doesn't match expected one\n");
        return(-1);
    }

    /* check transforms: all transforms should be inserted by XMLSec */
    transform = dsigRefCtx->transformCtx.first;
    while(transform != NULL) {
        if((transform->flags & XMLSEC_TRANSFORM_FLAGS_USER_SPECIFIED) != 0) {
            fprintf(stderr,"Error: Found unexpected Transform name '%s'\n", transform->id->name);
            return(-1);
        }
        transform = transform->next;
    }

    /* all good! */
    return(0);
}
