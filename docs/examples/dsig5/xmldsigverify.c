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


int url_decode(char *buf, size_t size);

int main(int argc, char **argv) {
    xmlSecKeysMngrPtr keysMngr = NULL; 
    xmlSecDSigCtxPtr dsigCtx = NULL;
    xmlBufferPtr buffer = NULL;
    xmlDocPtr doc = NULL;
    xmlSecDSigResultPtr result = NULL;
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
    keysMngr = xmlSecSimpleKeysMngrCreate();    
    if(keysMngr == NULL) {
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
	xmlSecKeyDestroy(key); 
	fprintf(stderr, "Error: failed to set hmac key params\n"); 
	goto done;  
    }

    ret = xmlSecSimpleKeysMngrAddKey(keysMngr, key);
    if(ret < 0) {
	xmlSecKeyDestroy(key);
	fprintf(stdout, "Error: failed to add hmac key\n"); 
	goto done;
    }

    /* read Merlin's ca */
    ret = xmlSecSimpleKeysMngrLoadPemCert(keysMngr, "/etc/httpd/conf/ssl.crt/merlin.crt", 1); 
    if(ret < 0) {
	fprintf(stdout, "Error: failed to read Merlin's CA\n");
	return(-1);
    }
    /* read Aleksey's ca */
    ret = xmlSecSimpleKeysMngrLoadPemCert(keysMngr, "/etc/httpd/conf/ssl.crt/aleksey.crt", 1); 
    if(ret < 0) {
	fprintf(stdout, "Error: failed to read Aleksey's CA\n");
	return(-1);
    }

    /* read root ca */
    ret = xmlSecSimpleKeysMngrAddCertsDir(keysMngr, "/etc/httpd/conf/ssl.crt");
    if(ret < 0) {
	fprintf(stdout, "Error: failed to add certs dir lookup\n");
	return(-1);
    }    
    
    dsigCtx = xmlSecDSigCtxCreate(keysMngr);
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
    ret = xmlSecDSigValidate(dsigCtx, NULL, NULL, xmlDocGetRootElement(doc), &result);
    if(ret < 0) {
    	fprintf(stdout,"Error: verification failed\n");
	goto done; 
    }     
    
    /*
     * Print out result     
     */
    res = 0;
    xmlSecDSigResultDebugDump(result, stdout); 

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
    if(keysMngr != NULL) {
	xmlSecSimpleKeysMngrDestroy(keysMngr);
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

