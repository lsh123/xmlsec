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
#include <libxslt/xslt.h>

#include <xmlsec/xmlenc.h> 
#include <xmlsec/keysmngr.h>


int		initEverything				(void);
void		shutdownEverything			(void);
int 		decrypt					(const char *filename);


xmlSecKeysMngrPtr keysMngr = NULL; 
xmlSecEncCtxPtr ctx;

int main(int argc, char **argv) {
    int ret = -1;
    xmlSecKeyPtr key;
            
    /** 
     * Init OpenSSL, libxml and xmlsec
     */
    ret = initEverything();
    if(ret < 0) {
	fprintf(stderr, "Error: initialization failed\n");
	return(1);
    }
    
    if(argc < 3) {
	fprintf(stderr, "Error: missed required parameter. Usage: %s <private-key-file> <encrypted-doc>\n", argv[0]);
	goto done;
    }

    /** 
     * load key
     */
    key = xmlSecSimpleKeysMngrLoadPemKey(keysMngr, argv[1], NULL, NULL, 1);
    if(key == NULL) {
	fprintf(stderr, "Error: failed to load key from \"%s\"\n", argv[1]);
	goto done;
    }
    key->name = xmlStrdup(BAD_CAST "test-rsa-key");

    /** 
     * Decrypt file
     */    
    ret = decrypt(argv[2]);
    if(ret < 0) {
	fprintf(stderr, "Error: failed to decrypt file \"%s\"\n", argv[2]);
	goto done;	
    }
        
done:
    /*
     * Cleanup: shutdown xmlsec, libxml, openssl
     */
    shutdownEverything();    
    return((ret >= 0) ? 0 : 1);
}

int 
decrypt(const char *filename) {
    xmlDocPtr doc = NULL;
    xmlSecEncResultPtr result = NULL;
    int ret;


    /*
     * build an XML tree from a the file; we need to add default
     * attributes and resolve all character and entities references
     */
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    doc = xmlParseFile(filename);
    if (doc == NULL) {
	fprintf(stderr, "Error: unable to parse file \"%s\"\n", filename);
	goto done;    
    }
    
    /*
     * Check the document is of the right kind
     */    
    if(xmlDocGetRootElement(doc) == NULL) {
	fprintf(stderr,"Error: empty document for file \"%s\"\n", filename);
	goto done;    
    }
    
    /** 
     * Decrypt
     */
    ret = xmlSecDecrypt(ctx, NULL, NULL, xmlDocGetRootElement(doc), &result);
    if(ret < 0) {
	fprintf(stderr, "Error: decryption failed\n");
	goto done;    
    }
    
    /**
     * And print result to stdout
     */			     
     ret = fwrite(xmlBufferContent(result->buffer),  
    		  xmlBufferLength(result->buffer), 
		  1, stdout);     
done:        
    if(result != NULL) {
	xmlSecEncResultDestroy(result);
    }    
    
    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(0);
}


int initEverything(void) {
    int rnd_seed = 0;
            
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
	return(-1);	
    }
  
    /**
     * Create enc context
     */
    ctx = xmlSecEncCtxCreate(keysMngr);
    if(ctx == NULL) {
	fprintf(stderr, "Error: template failed to create context\n");
	return(-1);
    }
    
    return(0);
}

void shutdownEverything(void) {

    /* destroy context and key manager */
    if(ctx != NULL) {
	xmlSecEncCtxDestroy(ctx);
    }
    
    
    if(keysMngr != NULL) {
	xmlSecSimpleKeysMngrDestroy(keysMngr);
    }
    
    /**
     * Shutdown xmlsec
     */
    xmlSecShutdown();

    /**
     * Shutdown libxslt
     */    
    xsltCleanupGlobals();            
    
    /* 
     * Shutdown libxml
     */
    xmlCleanupParser();
    
    /* 
     * Shutdown OpenSSL
     */
    RAND_cleanup();
    ERR_clear_error();
}

