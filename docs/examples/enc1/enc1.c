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
int 		encrypt					(void);
int		generateAesKey				(void);

xmlSecKeysMngrPtr keysMngr = NULL; 
xmlSecEncCtxPtr ctx = NULL;

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
    
    if(argc < 2) {
	fprintf(stderr, "Error: missed required parameter. Usage: %s <public-key-file>\n", argv[0]);
	goto done;
    }

    /** 
     * load key
     */
    key = xmlSecSimpleKeysMngrLoadPemKey(keysMngr, argv[1], NULL, NULL, 0);
    if(key == NULL) {
	fprintf(stderr, "Error: failed to load key from \"%s\"\n", argv[1]);
	goto done;
    }
    key->name = xmlStrdup(BAD_CAST "test-rsa-key");

    ret = generateAesKey();
    if(ret < 0) {
	 fprintf(stderr, "Error: failed to generate random aes key\n");
	 goto done;
    }
    
    /** 
     * Encrypt file
     */    
    ret = encrypt();
    if(ret < 0) {
	fprintf(stderr, "Error: failed to encrypt data\n");
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
encrypt(void) {
    static const char buf[] = "big secret";
    xmlNodePtr encKey = NULL;
    xmlNodePtr encData = NULL;
    xmlSecEncResultPtr result = NULL;
    xmlNodePtr cur;
    xmlDocPtr doc = NULL;
    int ret;
    
    /**
     * Create the EncryptedData node
     */
    encData = xmlSecEncDataCreate(NULL, NULL, NULL, NULL);
    if(encData == NULL) {
	fprintf(stderr, "Error: template creation failed\n");
	goto done;    
    }

    /**
     * Set the encryption method
     */
    cur = xmlSecEncDataAddEncMethod(encData, xmlSecEncAes128Cbc);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add Enc Method\n");
	goto done;    
    }

    /**
     * Add EncryptionProperties node just for fun
     */
    cur = xmlSecEncDataAddEncProperty(encData, BAD_CAST "Classified", NULL);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add KeyInfo\n");
	goto done;    
    }
    xmlSetProp(cur, BAD_CAST "Level", BAD_CAST "Top secret: destroy before reading");

    /** 
     * The encrypted data should be saved in CipherValue node 
     */
    cur = xmlSecEncDataAddCipherValue(encData);    
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add CipherValue\n");
	goto done;    
    }

    /**
     * Add key info node 
     */
    cur = xmlSecEncDataAddKeyInfo(encData);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add KeyInfo\n");
	goto done;    
    }

    /**
     * The session AES key will be RSA encrypted and included
     * in the message
     */
    encKey = xmlSecKeyInfoAddEncryptedKey(cur, NULL, NULL, NULL);
    if(encKey == NULL) {
	fprintf(stderr, "Error: failed to add EncryptedKey\n");
	goto done;    
    }
    
    /**
     * Set the encryption method for encrypting the key
     */
    cur = xmlSecEncDataAddEncMethod(encKey, xmlSecEncRsaOaep);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add EncryptedKey Enc Method\n");
	goto done;    
    }
    
    /**
     * The encrypted key should be stored in XML document
     */
    cur = xmlSecEncDataAddCipherValue(encKey);    
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add EncryptedKey CipherValue\n");
	goto done;    
    }

    /**
     * Now specify the key used to encrypt session key
     */
    cur = xmlSecEncDataAddKeyInfo(encKey);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add EncryptedKey KeyInfo\n");
	goto done;    
    }

    cur = xmlSecKeyInfoAddKeyName(cur);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add EncryptedKey KeyName\n");
	goto done;    
    }

    /**
     * Create doc
     */
    doc = xmlNewDoc(NULL);
    if(doc == NULL) {
	fprintf(stderr, "Error: failed to create document\n");
	goto done;    
    }
    xmlDocSetRootElement(doc, encData);
     
    /**
     * Finally encrypt everything
     */
    ret = xmlSecEncryptMemory(ctx, NULL, NULL, encData, (const unsigned char*)buf,
			     strlen(buf), &result);
    if(ret < 0) {
	fprintf(stderr, "Error: memory encryption failed\n");
	goto done;    
    }
    
    /**
     * And print result to stdout
     */			     
    xmlDocDump(stdout, doc);
    
done:        
    if(result != NULL) {
	xmlSecEncResultDestroy(result);
    }    
    
    if(encData != NULL) {
	xmlSecEncDataDestroy(encData);
    }
    
    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(0);
}

int
generateAesKey(void) {
    xmlSecKeyPtr key;    
    int ret;

    /* AES 128 */    
    key = xmlSecKeyCreate(xmlSecAesKey, xmlSecKeyOriginDefault);
    if(key == NULL) {
	fprintf(stderr, "Error: failed to create aes 128 key\n"); 
	return(-1);
    }        
    ret = xmlSecAesKeyGenerate(key, NULL, 128);
    if(ret < 0) {
	xmlSecKeyDestroy(key);  
	fprintf(stderr, "Error: failed to create aes 128 key\n"); 
	return(-1);
    }    
    key->name = xmlStrdup(BAD_CAST "test-aes128");
    ret = xmlSecSimpleKeysMngrAddKey(keysMngr, key);
    if(ret < 0) {
	xmlSecKeyDestroy(key);
	fprintf(stderr, "Error: failed to add aes 128 key\n"); 
	return(-1);
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
     * We encrypt using our keys only
     */
    keysMngr->allowedOrigins = xmlSecKeyOriginKeyManager | xmlSecKeyOriginKeyName;
      
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

