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

xmlNodePtr addSignature(xmlDocPtr doc);

int main(int argc, char **argv) {
    xmlSecKeysMngrPtr keysMngr = NULL; 
    xmlSecDSigCtxPtr dsigCtx = NULL;
    xmlDocPtr doc = NULL;
    xmlSecDSigResultPtr result = NULL;
    xmlNodePtr signatureNode;
    xmlChar* string;
    int ret = -1;
    int rnd_seed = 0;
    int len; 
        
    if(argc < 2) {
	fprintf(stderr, "Error: missed required parameter. Usage: %s <key-file> <xml-file>\n", argv[0]);
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
    keysMngr = xmlSecSimpleKeysMngrCreate();    
    if(keysMngr == NULL) {
	fprintf(stderr, "Error: failed to create keys manager\n");
	goto done;	
    }

    /** 
     * load key
     */
    if(xmlSecSimpleKeysMngrLoadPemKey(keysMngr, argv[1], NULL, NULL, 1) == NULL) {
	fprintf(stderr, "Error: failed to load key from \"%s\"\n", argv[1]);
	goto done;
    }
    
    dsigCtx = xmlSecDSigCtxCreate(keysMngr);
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
    doc = xmlParseFile(argv[2]);
    if (doc == NULL) {
	fprintf(stderr, "Error	: unable to parse file \"%s\"\n", argv[2]);
	goto done;
    }
    
    /*
     * Check the document is of the right kind
     */    
    if(xmlDocGetRootElement(doc) == NULL) {
        fprintf(stderr,"Error: empty document for file \"%s\"\n", argv[2]);
	goto done;
    }    
    
    /**
     * Add Signature
     */ 
    signatureNode = addSignature(doc);
    if(signatureNode == NULL) {
        fprintf(stderr,"Error: failed to add signature\n");
	goto done;
    }
									
    /**
     * Sign It!
     */ 
    ret = xmlSecDSigGenerate(dsigCtx, NULL, NULL, signatureNode, &result);
    if(ret < 0) {
    	fprintf(stderr,"Error: signature failed\n");
	goto done; 
    }     
    
    /*
     * Print out the document
     */
    xmlDocDumpMemoryEnc(doc, &string, &len, NULL);
    if(string == NULL) {
	fprintf(stderr,"Error: failed to dump document to memory\n");
	goto done;
    }
    fwrite(string, len, 1, stdout);
    xmlFree(string);
    
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

    return((ret >= 0) ? 0 : 1);
}

xmlNodePtr addSignature(xmlDocPtr doc) {
    xmlNodePtr signatureNode;
    xmlNodePtr signedInfoNode;
    xmlNodePtr keyInfoNode;
    xmlNodePtr referenceNode;
    xmlNodePtr cur;

    /**
     * Create Signature node 
     */
    signatureNode = xmlSecSignatureCreate("my-signature");
    if(signatureNode == NULL) {
    	fprintf(stderr,"Error: failed to create signature\n");
	return(NULL);
    }


    /**
     * Add SignedInfo and set c14n and signature methods
     */
    signedInfoNode = xmlSecSignatureAddSignedInfo(signatureNode, NULL);
    if(signedInfoNode == NULL) {
    	fprintf(stderr,"Error: failed to add SignedInfo\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }

    cur = xmlSecSignedInfoAddC14NMethod(signedInfoNode, xmlSecC14NInclusive);
    if(cur == NULL) {
    	fprintf(stderr,"Error: failed to add C14N method\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }

    cur = xmlSecSignedInfoAddSignMethod(signedInfoNode, xmlSecSignDsaSha1);
    if(cur == NULL) {
    	fprintf(stderr,"Error: failed to add sign method\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }

    /** 
     * Create Reference node with SHA1 as digest method and one
     * C14N transform to include comments in the digest
     */
    referenceNode = xmlSecSignedInfoAddReference(signedInfoNode,
					"my-reference",
					"#xpointer(id('SomeData'))",
					NULL);
    if(referenceNode == NULL) {
    	fprintf(stderr,"Error: failed to add Reference\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }

    cur = xmlSecReferenceAddDigestMethod(referenceNode, xmlSecDigestSha1);
    if(cur == NULL) {
    	fprintf(stderr,"Error: failed to add digest method\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }
    
    cur = xmlSecReferenceAddTransform(referenceNode, 
				      xmlSecC14NExclusiveWithComments);
    if(cur == NULL) {
    	fprintf(stderr,"Error: failed to add c14n transform\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }

    /**
     * Add KeyInfo node: for test purposes we will put
     * DSA key in the signature
     */
    keyInfoNode = xmlSecSignatureAddKeyInfo(signatureNode, NULL);  
    if(keyInfoNode == NULL) {
    	fprintf(stderr,"Error: failed to add KeyInfo\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }
    
    cur = xmlSecKeyInfoAddKeyValue(keyInfoNode);
    if(cur == NULL) { 
    	fprintf(stderr,"Error: failed to add KeyValue node\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }

    /**
     * Add the signature to the end of the document
     */    
    if(xmlAddChild(xmlDocGetRootElement(doc), signatureNode) == NULL) {
    	fprintf(stderr,"Error: failed to add Signature\n");
	xmlSecSignatureDestroy(signatureNode);
	return(NULL);
    }

    return(signatureNode);
}

