/** 
 * XML Security examples
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xmlerror.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h> 
#include <xmlsec/keysmngr.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/x509.h>
#include <xmlsec/x509mngr.h>


int url_decode(char *buf, size_t size);

int main(int argc, char **argv) {
    xmlSecSimpleKeyMngrPtr keyMgr = NULL; 
    xmlSecSimpleX509MngrPtr x509Mngr = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    xmlSecKeysReadContext keysReadCtx;
    xmlBufferPtr buffer = NULL;
    xmlDocPtr doc = NULL;
    xmlSecDSigResultPtr result = NULL;
    X509_LOOKUP *lookup = NULL;
    unsigned char buf[1024];
    int ret = -1;
    int rnd_seed = 0;
    xmlSecKeyPtr key;
    int res = -1;
    
    printf("Content-type: text/plain\n");
    printf("\n");
    
    /** 
     * Init OpenSSL
     */    
    OpenSSL_add_all_algorithms();
    while (RAND_status() != 1) {
	RAND_seed(&rnd_seed, sizeof(rnd_seed));
    }
    
    /*
     * Init libxml
     */     
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlGenericErrorContext = stdout;
    
    /*
     * Init xmlsec
     */
    xmlSecInit();    

    /** 
     * Create Keys managers
     */
    keyMgr = xmlSecSimpleKeyMngrCreate();    
    if(keyMgr == NULL) {
	fprintf(stdout, "Error: failed to create keys manager\n");
	goto done;	
    }
    /* HMAC */    
    key = xmlSecKeyCreate(xmlSecHmacKey, xmlSecKeyOriginDefault);
    if(key == NULL) {
	fprintf(stderr, "Error: failed to create hmac key\n"); 
	goto done;  
    }        
    ret = xmlSecHmacKeyGenerate(key, (unsigned char*)"secret", 6);
    if(ret < 0) {
	xmlSecKeyDestroy(key, 1); 
	fprintf(stderr, "Error: failed to set hmac key params\n"); 
	goto done;  
    }

    ret = xmlSecSimpleKeyMngrAddKey(keyMgr, key);
    if(ret < 0) {
	xmlSecKeyDestroy(key, 1);
	fprintf(stdout, "Error: failed to add hmac key\n"); 
	goto done;
    }

    x509Mngr = xmlSecSimpleX509MngrCreate();
    if(x509Mngr == NULL) {
	fprintf(stdout, "Error: failed to create x509 manager\n");
	return(-1);
    }
    /* read Merlin's ca */
    ret = xmlSecSimpleX509MngrAddTrustedCert(x509Mngr, "/etc/httpd/conf/ssl.crt/merlin.crt"); 
    if(ret < 0) {
	fprintf(stdout, "Error: failed to read Merlin's CA\n");
	return(-1);
    }
    /* read Aleksey's ca */
    ret = xmlSecSimpleX509MngrAddTrustedCert(x509Mngr, "/etc/httpd/conf/ssl.crt/aleksey.crt"); 
    if(ret < 0) {
	fprintf(stdout, "Error: failed to read Aleksey's CA\n");
	return(-1);
    }
    /* read root ca */
    lookup = X509_STORE_add_lookup(x509Mngr->xst, X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
	fprintf(stdout, "Error: failed to create hash lookup\n");
	return(-1);
    }    
    X509_LOOKUP_add_dir(lookup, "/etc/httpd/conf/ssl.crt", X509_FILETYPE_DEFAULT);
    
    /**
     * Create Signature Context 
     */
    memset(&keysReadCtx, 0, sizeof(keysReadCtx));

    keysReadCtx.allowedOrigins = xmlSecKeyOriginAll; /* by default all keys are accepted */
    keysReadCtx.maxRetrievals = 1;
    keysReadCtx.findKeyCallback = xmlSecSimpleKeyMngrFindKey;
    keysReadCtx.findKeyContext = keyMgr;
    keysReadCtx.x509.context = x509Mngr; 
    keysReadCtx.x509.verifyCallback = (xmlSecX509VerifyCallback)xmlSecSimpleX509MngrVerify;
    keysReadCtx.x509.addCRLCallback = (xmlSecX509AddCRLCallback)xmlSecSimpleX509MngrAddCRL;
    
    dsigCtx = xmlSecDSigCtxCreate(&keysReadCtx);
    if(dsigCtx == NULL) {
    	fprintf(stdout,"Error: failed to create dsig context\n");
	goto done; 
    }
                
    /* 
     * build an XML tree from a the file; we need to add default
     * attributes and resolve all character and entities references
     */
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    buffer = xmlBufferCreate();
    if(buffer == NULL) {
    	fprintf(stdout,"Error: failed to create buffer\n");
	goto done; 	
    }
    
    while(!feof(stdin)) {
	ret = fread(buf, 1, sizeof(buf), stdin);
	if(ret < 0) {
	    fprintf(stdout,"Error: read failed\n");
	    goto done; 	
	}
	xmlBufferAdd(buffer, buf, ret);
    }
    /* is the document subbmitted from the form? */
    if(strncmp((char*)xmlBufferContent(buffer), "_xmldoc=", 8) == 0) {
	xmlBufferShrink(buffer, 8);
	buffer->use = url_decode(xmlBufferContent(buffer), xmlBufferLength(buffer)); 
    }
        
    /** 
     * Load doc 
     */
    doc = xmlParseMemory(xmlBufferContent(buffer), xmlBufferLength(buffer));
    if (doc == NULL) {
	fprintf(stdout, "Error: unable to parse xml document (syntax error)\n");
	goto done;
    }
    
    /*
     * Check the document is of the right kind
     */    
    if(xmlDocGetRootElement(doc) == NULL) {
        fprintf(stdout,"Error: empty document\n");
	goto done;
    }

    /**
     * Verify It!
     */ 
    ret = xmlSecDSigValidate(dsigCtx, xmlDocGetRootElement(doc), &result);
    if(ret < 0) {
    	fprintf(stdout,"Error: verification failed\n");
	goto done; 
    }     
    
    /*
     * Print out result     
     */
    res = 0;
    xmlSecDSigResultDebugDump(stdout, result); 

done:
    
    /*
     * Cleanup
     */
    if(result != NULL) {
	xmlSecDSigResultDestroy(result);
    }
    if(dsigCtx != NULL) { 
	xmlSecDSigCtxDestroy(dsigCtx);
    }    
    if(doc != NULL) {
	xmlFreeDoc(doc); 
    }
    if(buffer != NULL) {
	xmlBufferFree(buffer);
    }
    
    if(x509Mngr != NULL) {
	xmlSecSimpleX509MngrDestroy(x509Mngr);
    }
    if(keyMgr != NULL) {
	xmlSecSimpleKeyMngrDestroy(keyMgr);
    }
    
    xmlSecShutdown();
    
    /* 
     * Shutdown libxml
     */
    xmlCleanupParser();
    
    /* 
     * Shutdown OpenSSL
     */
    RAND_cleanup();
    ERR_clear_error();
    X509_TRUST_cleanup();

    return((ret >= 0) ? 0 : 1);
}

/* not the best way to do it */
#define toHex(c) ( ( ('0' <= (c)) && ((c) <= '9') ) ? (c) - '0' : \
		 ( ( ('A' <= (c)) && ((c) <= 'F') ) ? (c) - 'A' + 10 : 0 ) )        
		 
int url_decode(char *buf, size_t size) {
    char *p1, *p2;
    
    p1 = p2 = buf;
    while(p1 - buf < size) {
	if(((*p1) == '%') && ((p1 - buf) <= (size - 3))) {
	    *(p2++) = (char)(toHex(p1[1]) * 16 + toHex(p1[2]));
	    p1 += 3;	    
	} else if((*p1) == '+') {
	    *(p2++) = ' ';
	    p1++;	    
	} else {
	    *(p2++) = *(p1++);
	}
    }
    return(p2 - buf);
}

