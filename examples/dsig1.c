/** 
 * XML Security Library example: Signing a template file.
 * 
 * Signs a template file using a key from PEM file
 * 
 * Usage: 
 *	dsig1 <xml-tmpl> <pem-key> 
 * Example:
 *	./dsig1 ./dsig1-tmpl.xml rsakey.pem > dsig1-res.xml
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/xmldsig.h>

#ifdef XMLSEC_CRYPTO_OPENSSL
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/symbols.h>
#else /* XMLSEC_CRYPTO_OPENSSL */
#ifdef XMLSEC_CRYPTO_GNUTLS
#include <xmlsec/gnutls/app.h>
#include <xmlsec/gnutls/symbols.h>
#else /* XMLSEC_CRYPTO_GNUTLS */
#ifdef XMLSEC_CRYPTO_NSS
#include <xmlsec/nss/app.h>
#include <xmlsec/nss/symbols.h>
#else /* XMLSEC_CRYPTO_NSS */
#error No Crypto library defined
#endif /* XMLSEC_CRYPTO_GNUTLS */
#endif /* XMLSEC_CRYPTO_NSS */
#endif /* XMLSEC_CRYPTO_OPENSSL */

static int sign_file(const char* tmpl_file, const char* key_file);

int 
main(int argc, char **argv) {
    assert(argv);

    if(argc != 3) {
	fprintf(stderr, "Error: wrong number of arguments.\n");
	fprintf(stderr, "Usage: %s <tmpl-file> <key-file>\n", argv[0]);
	return(1);
    }

    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */
        	
    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
	fprintf(stderr, "Error: xmlsec initialization failed.\n");
	return(-1);
    }

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

    if(sign_file(argv[1], argv[2]) < 0) {
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
    xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();
    
    return(0);
}

static int 
sign_file(const char* tmpl_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;
    
    assert(tmpl_file);
    assert(key_file);

    /* load template */
    doc = xmlParseFile(tmpl_file);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
	fprintf(stderr, "Error: unable to parse file \"%s\"\n", tmpl_file);
	goto done;	
    }
    
    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
	fprintf(stderr, "Error: start node not found in \"%s\"\n", tmpl_file);
	goto done;	
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
	goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecCryptoAppPemKeyLoad(key_file, NULL, NULL, 1);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
	goto done;
    }

    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature failed\n");
	goto done;
    }
        
    /* print signed document to stdout */
    xmlDocDump(stdout, doc);
    
    /* success */
    res = 0;

done:    
    if(dsigCtx != NULL) {
	xmlSecDSigCtxDestroy(dsigCtx);
    }
    
    if(doc != NULL) {
	xmlFreeDoc(doc); 
    }
    return(res);
}

