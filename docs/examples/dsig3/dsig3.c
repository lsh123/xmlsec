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

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h> 
#include <xmlsec/keysmngr.h>
#include <xmlsec/xmltree.h>


int main(int argc, char **argv) {
    xmlSecSimpleKeyMngrPtr keyMgr = NULL; 
    xmlSecDSigCtxPtr dsigCtx = NULL;
    xmlSecKeysReadContext keysReadCtx;
    xmlDocPtr doc = NULL;
    xmlSecDSigResultPtr result = NULL;
    int ret = -1;
    int rnd_seed = 0;
    xmlNodePtr signNode;
            
    if(argc < 1) {
	fprintf(stderr, "Error: missed required parameter. Usage: %s <xml-file>\n", argv[0]);
	return(1);
    }
    
    /** 
     * Init OpenSSL
     */    
    while (RAND_status() != 1) {
	RAND_seed(&rnd_seed, sizeof(rnd_seed));
    }
    
    /*
     * Init libxml
     */     
    xmlInitParser();
    LIBXML_TEST_VERSION

    /*
     * Init xmlsec
     */
    xmlSecInit();    

    /** 
     * Create Keys managers
     */
    keyMgr = xmlSecSimpleKeyMngrCreate();    
    if(keyMgr == NULL) {
	fprintf(stderr, "Error: failed to create keys manager\n");
	goto done;	
    }

    /**
     * Create Signature Context 
     */
    memset(&keysReadCtx, 0, sizeof(keysReadCtx));

    keysReadCtx.allowedOrigins = xmlSecKeyOriginAll; /* by default all keys are accepted */
    keysReadCtx.findKeyCallback = xmlSecSimpleKeyMngrFindKey;
    keysReadCtx.findKeyContext = keyMgr;
    
    dsigCtx = xmlSecDSigCtxCreate(&keysReadCtx);
    if(dsigCtx == NULL) {
    	fprintf(stderr,"Error: failed to create dsig context\n");
	goto done; 
    }
                

    /* 
     * build an XML tree from a the file; we need to add default
     * attributes and resolve all character and entities references
     */
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    /** 
     * Load doc 
     */
    doc = xmlParseFile(argv[1]);
    if (doc == NULL) {
	fprintf(stderr, "Error	: unable to parse file \"%s\"\n", argv[1]);
	goto done;
    }
    
    /*
     * Check the document is of the right kind
     */    
    if(xmlDocGetRootElement(doc) == NULL) {
        fprintf(stderr,"Error: empty document for file \"%s\"\n", argv[1]);
	goto done;
    }

    /**
     * Verify It!
     */ 
    signNode = xmlSecFindNode(xmlDocGetRootElement(doc), 
			      BAD_CAST "Signature", xmlSecDSigNs);
    if(signNode == NULL) {
        fprintf(stderr,"Error: failed to find Signature node\n");
	goto done;
    }    
     
    ret = xmlSecDSigValidate(dsigCtx, signNode, &result);
    if(ret < 0) {
    	fprintf(stderr,"Error: verification failed\n");
	goto done; 
    }     
    
    /*
     * Print out result     
     */
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

    return((ret >= 0) ? 0 : 1);
}

