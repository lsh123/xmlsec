/**
 * XML Security Library example: Verifying a file using a single key.
 *
 * Verifies a file using a key from PEM file.
 *
 * Usage:
 *      verify1 <signed-file> <pem-key>
 *
 * Example:
 *      ./verify1 sign1-res.xml rsapub.pem
 *      ./verify1 sign2-res.xml rsapub.pem
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
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

int verify_file(const char* xml_file, const char* key_file);
int verify_signature_results(xmlSecDSigCtxPtr dsigCtx);

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
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

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

    if(verify_file(argv[1], argv[2]) < 0) {
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
 * verify_file:
 * @xml_file:           the signed XML file name.
 * @key_file:           the PEM public key file name.
 *
 * Verifies XML signature in #xml_file using public key from #key_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
verify_file(const char* xml_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    assert(xml_file);
    assert(key_file);

    /* load file */
    doc = xmlReadFile(xml_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", xml_file);
        goto done;
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load public key */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadEx(key_file, xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load public pem key from \"%s\"\n", key_file);
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, BAD_CAST key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature verificaton failed\n");
        goto done;
    }

    /* verif results and print outcome to stdout */
    if(verify_signature_results(dsigCtx) == 0) {
        fprintf(stdout, "Signature is OK\n");
    } else {
        fprintf(stdout, "Signature is INVALID\n");
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
 * verify_signature_results:
 * @dsigCtx:            the XMLDSig context
 *
 * Verifies XML signature results to ensure that signature was applied
 * to the expected data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
verify_signature_results(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    xmlSecTransformPtr transform;

    assert(dsigCtx);

    /* check that signature verification succeeded */
    if(dsigCtx->status != xmlSecDSigStatusSucceeded) {
        fprintf(stderr,"Error: Signature verificaton result is not SUCCESS\n");
        return(-1);
    }

    /* in this example we expect exactly ONE reference with URI="" and
    *  exactly ONE enveloped signature transform (i.e. the whole document is signed)*/
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
    if(!xmlStrEqual(dsigRefCtx->uri, BAD_CAST "")) {
        fprintf(stderr,"Error: Reference URI value doesn't match expected one\n");
        return(-1);
    }

    /* check transforms: we expect only one "enveloped signature" transform */
    transform = dsigRefCtx->transformCtx.first;
    if((transform == NULL) || (!xmlStrEqual(transform->id->name, xmlSecNameEnveloped))) {
        fprintf(stderr,"Error: First Transform name '%s' doesn't match expected '%s'\n", (transform != NULL ? transform->id->name : BAD_CAST "NULL"), xmlSecNameEnveloped);
        return(-1);
    }

    /* all other transforms should be inserted by XMLSec */
    transform = transform->next;
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

