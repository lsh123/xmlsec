/** 
 * XML Security Library example: Decrypting an encrypted file using a custom keys manager.
 * 
 * Decrypts encrypted XML file using a custom files based keys manager.
 * We assume that key's name in <dsig:KeyName/> element is just 
 * file name thay contains the key.
 * 
 * Usage: 
 *	enc5 <xml-enc> 
 *
 * Example:
 *	./enc5 enc1-res.xml
 *	./enc5 enc2-res.xml
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
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
#include <xmlsec/xmlenc.h>
#include <xmlsec/crypto.h>

xmlSecKeyStoreId  files_keys_store_get_klass(void);
xmlSecKeysMngrPtr create_files_keys_mngr(void);
int decrypt_file(xmlSecKeysMngrPtr mngr, const char* enc_file);

int 
main(int argc, char **argv) {
    xmlSecKeysMngrPtr mngr;

    assert(argv);

    if(argc != 2) {
	fprintf(stderr, "Error: wrong number of arguments.\n");
	fprintf(stderr, "Usage: %s <enc-file>\n", argv[0]);
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

    /* create keys manager and load keys */
    mngr = create_files_keys_mngr();
    if(mngr == NULL) {
	return(-1);
    }

    if(decrypt_file(mngr, argv[1]) < 0) {
	xmlSecKeysMngrDestroy(mngr);	
	return(-1);
    }    

    /* destroy keys manager */
    xmlSecKeysMngrDestroy(mngr);
    
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

/**
 * decrypt_file:
 * @mngr:		the pointer to keys manager.
 * @enc_file:		the encrypted XML  file name.
 *
 * Decrypts the XML file #enc_file using DES key from #key_file and 
 * prints results to stdout.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
decrypt_file(xmlSecKeysMngrPtr mngr, const char* enc_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;
    
    assert(mngr);
    assert(enc_file);

    /* load template */
    doc = xmlParseFile(enc_file);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
	fprintf(stderr, "Error: unable to parse file \"%s\"\n", enc_file);
	goto done;	
    }
    
    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    if(node == NULL) {
	fprintf(stderr, "Error: start node not found in \"%s\"\n", enc_file);
	goto done;	
    }

    /* create encryption context */
    encCtx = xmlSecEncCtxCreate(mngr);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
	goto done;
    }

    /* decrypt the data */
    if((xmlSecEncCtxDecrypt(encCtx, node) < 0) || (encCtx->result == NULL)) {
        fprintf(stderr,"Error: decryption failed\n");
	goto done;
    }
        
    /* print decrypted data to stdout */
    if(encCtx->resultReplaced != 0) {
	fprintf(stdout, "Decrypted XML data:\n");
	xmlDocDump(stdout, doc);
    } else {
	fprintf(stdout, "Decrypted binary data (%d bytes):\n", xmlSecBufferGetSize(encCtx->result));
	if(xmlSecBufferGetData(encCtx->result) != NULL) {
	    fwrite(xmlSecBufferGetData(encCtx->result), 
	          1, 
	          xmlSecBufferGetSize(encCtx->result),
	          stdout);
	}
    }
    fprintf(stdout, "\n");
        
    /* success */
    res = 0;

done:    
    /* cleanup */
    if(encCtx != NULL) {
	xmlSecEncCtxDestroy(encCtx);
    }
    
    if(doc != NULL) {
	xmlFreeDoc(doc); 
    }
    return(res);
}

/**
 * create_files_keys_mngr:
 *  
 * Creates a files based keys manager: we assume that key name is 
 * the key file name,
 *
 * Returns pointer to newly created keys manager or NULL if an error occurs.
 */
xmlSecKeysMngrPtr 
create_files_keys_mngr(void) {
    xmlSecKeyStorePtr keysStore;
    xmlSecKeysMngrPtr mngr;

    /* create files based keys store */
    keysStore = xmlSecKeyStoreCreate(files_keys_store_get_klass());
    if(keysStore == NULL) {
	fprintf(stderr, "Error: failed to create keys store.\n");
	return(NULL);
    }
    
    /* create keys manager */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
	fprintf(stderr, "Error: failed to create keys manager.\n");
	xmlSecKeyStoreDestroy(keysStore);
	return(NULL);
    }

    /* add store to keys manager, from now on keys manager destroys the store if needed */
    if(xmlSecKeysMngrAdoptKeysStore(mngr, keysStore) < 0) {
	fprintf(stderr, "Error: failed to add keys store to keys manager.\n");
	xmlSecKeyStoreDestroy(keysStore);
	xmlSecKeysMngrDestroy(mngr);
	return(NULL);
    }
    
    /* initialize crypto library specific data in keys manager */
    if(xmlSecCryptoKeysMngrInit(mngr) < 0) {
	fprintf(stderr, "Error: failed to initialize crypto data in keys manager.\n");
	xmlSecKeysMngrDestroy(mngr);
	return(NULL);
    }

    /* set the get key callback */    
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(mngr);
}

/****************************************************************************
 *
 * Files Keys Store: we assume that key's name (content of the 
 * <dsig:KeyName/> element is a name of the file with a key.
 * Attention: this probably not a good solution for high traffic systems.
 * 
 ***************************************************************************/
static int			files_keys_store_find_key	(xmlSecKeyStorePtr store,
								 xmlSecKeyPtr key,
								 const xmlChar* name,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static xmlSecKeyStoreKlass files_keys_store_klass = {
    sizeof(xmlSecKeyStoreKlass),
    sizeof(xmlSecKeyStore),
    BAD_CAST "files-based-keys-store",	/* const xmlChar* name; */         
    NULL,				/* xmlSecKeyStoreInitializeMethod initialize; */
    NULL,				/* xmlSecKeyStoreFinalizeMethod finalize; */
    files_keys_store_find_key,		/* xmlSecKeyStoreFindMethod find; */

    /* reserved for the future */
    NULL,				/* void* reserved0; */
    NULL,				/* void* reserved1; */
};

/**
 * files_keys_store_get_klass:
 * 
 * The files based keys store klass: we assume that key name is the
 * key file name,
 *
 * Returns files based keys store klass.
 */
xmlSecKeyStoreId 
files_keys_store_get_klass(void) {
    return(&files_keys_store_klass);
}

/**
 * files_keys_store_find_key:
 * @store:		the pointer to simple keys store.
 * @name:		the desired key name.
 * @keyInfoCtx:		the pointer to <dsig:KeyInfo/> node processing context.
 *  
 * Lookups key in the @store.
 *
 * Returns pointer to key or NULL if key not found or an error occurs.
 */
static int
files_keys_store_find_key(xmlSecKeyStorePtr store,  xmlSecKeyPtr key, 
			const xmlChar* name, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecPtrListPtr list;
    xmlSecKeyPtr tmpKey = NULL;
    size_t pos, size;
    int ret;
    
    assert(store);
    assert(key);
    assert(keyInfoCtx);

    /* it's possible to do not have the key name or desired key type 
     * but we could do nothing in this case */
    if((name == NULL) || (keyInfoCtx->keyReq.keyId == xmlSecKeyDataIdUnknown)){
	return(0);
    }
    
    if((keyInfoCtx->keyReq.keyId == xmlSecKeyDataDsaId) || (keyInfoCtx->keyReq.keyId == xmlSecKeyDataRsaId)) {
	/* load key from a pem file, if key is not found then it's an error (is it?) */
	tmpKey = xmlSecCryptoAppPemKeyLoad(name, NULL, NULL, 0);
	if(tmpKey == NULL) {
    	    fprintf(stderr,"Error: failed to load public pem key from \"%s\"\n", name);
	    return(-1);
	}
    } else {
	/* otherwise it's a binary key, if key is not found then it's an error (is it?) */
	tmpKey = xmlSecKeyReadBinaryFile(keyInfoCtx->keyReq.keyId, name);
	if(tmpKey == NULL) {
    	    fprintf(stderr,"Error: failed to load key from binary file \"%s\"\n", name);
	    return(-1);
	}
    }

    /* erase any current information in the key because we don't care
     * about the data in the <dsig:KeyInfo/> other than key name
     */
    xmlSecKeyEmpty(key);
    
    /* and copy the key from keys storage */
    ret = xmlSecKeyCopy(key, tmpKey);
    if(ret < 0) {
	fprintf(stderr, "Error: failed to copy key \"%s\"\n", name);
	xmlSecKeyDestroy(tmpKey);
	return(-1);
    }
    
    /* destroy our key */
    xmlSecKeyDestroy(tmpKey);

    /* set key name */
    if(xmlSecKeySetName(key, name) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", name);
        return(-1);	
    }

    return(0);
}

