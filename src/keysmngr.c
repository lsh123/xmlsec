/** 
 * XMLSec library
 *
 * Simple Keys Manager
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/keysmngr.h>


/**
 * Simple Keys Manager
 */

#define XMLSEC_SIMPLEKEYMNGR_DEFAULT			16

typedef struct _xmlSecSimpleKeysMngrData {
     xmlSecKeyPtr			*keys;
     size_t				curSize;
     size_t				maxSize;
} xmlSecSimpleKeysData, *xmlSecSimpleKeysDataPtr;

static xmlSecSimpleKeysDataPtr	xmlSecSimpleKeysDataCreate	(void);
static void			xmlSecSimpleKeysDataDestroy	(xmlSecSimpleKeysDataPtr keysData);

/**
 * xmlSecSimpleKeysMngrCreate
 *
 *
 *
 */
xmlSecKeysMngrPtr	
xmlSecSimpleKeysMngrCreate(void) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrCreate";
    xmlSecKeysMngrPtr mngr;
        
    mngr = (xmlSecKeysMngrPtr)xmlMalloc(sizeof(xmlSecKeysMngr));
    if(mngr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate xmlSecKeysMngr\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(mngr, 0, sizeof(xmlSecKeysMngr));
    mngr->getKey = xmlSecKeysMngrGetKey;
    /* set "smart" defaults */
    mngr->allowedOrigins = xmlSecKeyOriginAll;
    mngr->maxRetrievalsLevel = 1;
    mngr->maxEncKeysLevel = 1;

    /* keys */
    mngr->keysData = xmlSecSimpleKeysDataCreate();       
    if(mngr->keysData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to creates keys data\n",
	    func);	
#endif 	    
	xmlSecSimpleKeysMngrDestroy(mngr);
	return(NULL);
    }   
    mngr->findKey = xmlSecSimpleKeysMngrFindKey;    

#ifndef XMLSEC_NO_X509
    mngr->x509Data = xmlSecX509StoreCreate();
    if(mngr->x509Data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to creates x509 data\n",
	    func);	
#endif 	    
	xmlSecSimpleKeysMngrDestroy(mngr);
	return(NULL);
    }   
    mngr->findX509 = xmlSecSimpleKeysMngrX509Find;
    mngr->verifyX509 = xmlSecSimpleKeysMngrX509Verify;
#endif /* XMLSEC_NO_X509 */            
        
    return(mngr);
}

/**
 * xmlSecSimpleKeysMngrDestroy
 *
 *
 *
 */
void
xmlSecSimpleKeysMngrDestroy(xmlSecKeysMngrPtr mngr) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrDestroy";
    
    if(mngr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr is null\n",
	    func);	
#endif 	    
	return;    
    }
    if(mngr->keysData != NULL) {
	xmlSecSimpleKeysDataDestroy((xmlSecSimpleKeysDataPtr)(mngr->keysData));
    }
#ifndef XMLSEC_NO_X509
    if(mngr->x509Data != NULL) {
	xmlSecX509StoreDestroy((xmlSecX509StorePtr)(mngr->x509Data));
    }
#endif /* XMLSEC_NO_X509 */    
    memset(mngr, 0, sizeof(xmlSecKeysMngr));
    xmlFree(mngr);
}

/**
 * xmlSecSimpleKeysMngrFindKey
 * @context:
 * @id:
 * @type:
 * @name:
 *
 * Lookups the first key that does match the given criteria
 */
xmlSecKeyPtr 		
xmlSecSimpleKeysMngrFindKey(xmlSecKeysMngrPtr mngr, void *context ATTRIBUTE_UNUSED,
			    const xmlChar *name, xmlSecKeyId id, xmlSecKeyType type, 
			    xmlSecKeyUsage usage ATTRIBUTE_UNUSED) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrFindKey";
    xmlSecSimpleKeysDataPtr keysData;
    xmlSecKeyPtr key;
    size_t i;
    
    
    if((mngr == NULL) || (mngr->keysData == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr or keys data is null\n",
	    func);	
#endif 	    
	return(NULL);    
    }
    keysData = (xmlSecSimpleKeysDataPtr)((mngr)->keysData);
    
    for(i = 0; i < keysData->curSize; ++i) {
	if(xmlSecVerifyKey(keysData->keys[i], name, id, type) == 1) {
	    key = xmlSecKeyDuplicate(keysData->keys[i], xmlSecKeyOriginKeyManager);
	    if(key == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to duplicate the key\n",
		    func);	
#endif 	    
		return(NULL);    
	    }
	    return(key);
	}
    }
        
    return(NULL);
}


/**
 * xmlSecSimpleKeysMngrAddKey:
 * @mngr:
 * @key:
 *
 * Adds new key to the key manager
 */
int	
xmlSecSimpleKeysMngrAddKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrAddKey";
    xmlSecSimpleKeysDataPtr keysData;

    if((mngr == NULL) || (mngr->keysData == NULL) || (key == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr or key is null\n",
	    func);	
#endif 	    
	return(-1);    
    }

    keysData = (xmlSecSimpleKeysDataPtr)((mngr)->keysData);
    
    if(keysData->maxSize == 0) {
	keysData->keys = (xmlSecKeyPtr *) xmlMalloc(XMLSEC_SIMPLEKEYMNGR_DEFAULT *
					    sizeof(xmlSecKeyPtr));
	if(keysData->keys == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to allocate %d keys pointers\n",
		func, XMLSEC_SIMPLEKEYMNGR_DEFAULT);	
#endif 	    
	    return(-1);
	}
	memset(keysData->keys, 0, XMLSEC_SIMPLEKEYMNGR_DEFAULT * sizeof(xmlSecKeyPtr)); 
	keysData->maxSize = XMLSEC_SIMPLEKEYMNGR_DEFAULT;
    } else if(keysData->curSize == keysData->maxSize) {
	xmlSecKeyPtr *newKeys;
	size_t newMax;
	
	newMax = keysData->maxSize * 2;
	newKeys = (xmlSecKeyPtr *) xmlRealloc(keysData->keys, newMax * sizeof(xmlSecKeyPtr));
	if(newKeys == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to allocate %d keys pointers\n",
		func, newMax);	
#endif 	    
	    return(-1);	
	}
	keysData->maxSize = newMax;
	keysData->keys = newKeys;
    }
    
    keysData->keys[(keysData->curSize)++] = key;
    return(0);
}

/**
 * xmlSecSimpleKeysMngrLoad
 * @mngr:
 * @uri:
 *
 */
int
xmlSecSimpleKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char *uri, int strict) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrLoad";
    xmlSecKeysMngr keysMngr;
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlSecKeyPtr key;
    int ret;
    
    if((mngr == NULL) || (uri == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr or uri is null\n",
	    func);	
#endif 	    
	return(-1); 
    }
    
    doc = xmlParseFile(uri);
    if(doc == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to load keys from \"%s\"\n", 
	    func, uri);	
#endif
	return(-1);
    }
    
    root = xmlDocGetRootElement(doc);
    if(!xmlSecCheckNodeName(root, BAD_CAST "Keys", xmlSecNs)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bad root node\n", 
	    func);	
#endif
	xmlFreeDoc(doc);
	return(-1);
    }
    
    memcpy(&keysMngr, mngr, sizeof(keysMngr));
    keysMngr.allowedOrigins = xmlSecKeyOriginAll;
    cur = xmlSecGetNextElementNode(root->children);
    while(xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecDSigNs)) {  
	key = xmlSecKeyInfoNodeRead(cur, &keysMngr, NULL, xmlSecKeyIdUnknown,
				    xmlSecKeyTypeAny, xmlSecKeyUsageAny);
	if(key == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read KeyInfo\n", 
		func);	
#endif
	    if(strict) {
		xmlFreeDoc(doc);
		return(-1);	
	    }
	} else {
	    ret = xmlSecSimpleKeysMngrAddKey(mngr, key);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to add key\n", 
		    func);	
#endif
		xmlSecKeyDestroy(key);
		xmlFreeDoc(doc);
		return(-1);	
	    }
	}
        cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: unexpected node found\n", 
	    func);	
#endif
	xmlFreeDoc(doc);
	return(-1);	    
    }
    
    xmlFreeDoc(doc);
    return(0);
}

/**
 * xmlSecSimpleKeysMngrSave
 * @mngr:
 * @filename:
 * @type:
 */
int
xmlSecSimpleKeysMngrSave(const xmlSecKeysMngrPtr mngr, 
			const char *filename, xmlSecKeyType type) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrSave";
    xmlSecSimpleKeysDataPtr keysData;  
    xmlSecKeysMngr keysMngr;
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    int ret;
    size_t i;
    
    if((mngr == NULL) || (mngr->keysData == NULL) || (filename == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr or filename is null\n",
	    func);	
#endif 	    
	return(-1);    
    }
    keysData = (xmlSecSimpleKeysDataPtr)((mngr)->keysData);

    memset(&keysMngr, 0, sizeof(keysMngr));
    keysMngr.allowedOrigins = xmlSecKeyOriginKeyValue;
    
    /* create doc */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create new doc\n",
	    func);	
#endif
	return(-1);
    }
    
    /* create root node "Keys" */
    root = xmlNewDocNode(doc, NULL, BAD_CAST "Keys", NULL); 
    if(root == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create root doc node\n",
	    func);	
#endif
	xmlFreeDoc(doc);
	return(-1);
    }
    xmlDocSetRootElement(doc, root);
    if(xmlNewNs(root, xmlSecNs, NULL) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to add ns to node\n",
	    func);	
#endif
	xmlFreeDoc(doc); 
	return(-1);
    }
    for(i = 0; i < keysData->curSize; ++i) {
	cur = xmlSecAddChild(root, BAD_CAST "KeyInfo", xmlSecDSigNs);
	if(cur == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to ad KeyInfo node\n",
		func);	
#endif
	    xmlFreeDoc(doc); 
	    return(-1);
	}
	
	if(xmlSecAddChild(cur, BAD_CAST "KeyName", xmlSecDSigNs) == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add KeyName node\n",
		func);	
#endif
	    xmlFreeDoc(doc); 
	    return(-1);
	}

	if(xmlSecAddChild(cur, BAD_CAST "KeyValue", xmlSecDSigNs) == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add KeyValue node\n",
		func);	
#endif
	    xmlFreeDoc(doc); 
	    return(-1);
	}

#ifndef XMLSEC_NO_X509
	if((keysData->keys[i]->x509Data != NULL)){
	    if(xmlSecAddChild(cur, BAD_CAST "X509Data", xmlSecDSigNs) == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to add KeyValue node\n",
		    func);	
#endif
		xmlFreeDoc(doc); 
		return(-1);
	    }
	}
#endif /* XMLSEC_NO_X509 */	     

	ret = xmlSecKeyInfoNodeWrite(cur, &keysMngr, NULL, keysData->keys[i], type);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to write KeyInfo node\n",
		func);	
#endif
	    xmlFreeDoc(doc); 
	    return(-1);
	}		
    }    

    /* now write result */
    ret = xmlSaveFormatFile(filename, doc, 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to write file \"%s\"\n", 
	    func, filename);	
#endif
	xmlFreeDoc(doc); 
	return(-1);
    }	   
    
    xmlFreeDoc(doc);
    return(0);
}


/**
 * xmlSecSimpleKeysMngrLoadPemKey
 * @mngr:
 * @keyfile:
 * @keyPwd:
 * @keyPwdCallback:
 * @certfile:
 *
 */
xmlSecKeyPtr
xmlSecSimpleKeysMngrLoadPemKey(xmlSecKeysMngrPtr mngr, 
			const char *keyfile, const char *keyPwd,
			pem_password_cb *keyPwdCallback, int privateKey) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrLoadPemKey";
    xmlSecKeyPtr key = NULL;
    EVP_PKEY *pKey = NULL;    
    FILE *f;
    int ret;
    
    if((mngr == NULL) || (keyfile == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr or key file is null\n",
	    func);	
#endif 	    
	return(NULL);    
    }
    
    f = fopen(keyfile, "r");
    if(f == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to open file \"%s\"\n",
	    func, keyfile);	
#endif 	    
	return(NULL);    
    }
    
    if(privateKey) {
	pKey = PEM_read_PrivateKey(f, NULL, keyPwdCallback, (void*)keyPwd);
    } else {	
        pKey = PEM_read_PUBKEY(f, NULL, keyPwdCallback, (void*)keyPwd);
    }
    if(pKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to read key file \"%s\"\n",
	    func, keyfile);	
#endif 	    
	fclose(f);
	return(NULL);    
    }
    fclose(f);

    switch(pKey->type) {	
#ifndef XMLSEC_NO_RSA    
    case EVP_PKEY_RSA:
	key = xmlSecKeyCreate(xmlSecRsaKey, xmlSecKeyOriginX509);
	if(key == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create RSA key\n",
		func);	
#endif
	    EVP_PKEY_free(pKey);
	    return(NULL);	    
	}
	
	ret = xmlSecRsaKeyGenerate(key, pKey->pkey.rsa);
	if(ret < 0) {	
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to set RSA key\n",
		func);	
#endif
	    xmlSecKeyDestroy(key);
	    EVP_PKEY_free(pKey);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_RSA */	
#ifndef XMLSEC_NO_DSA	
    case EVP_PKEY_DSA:
	key = xmlSecKeyCreate(xmlSecDsaKey, xmlSecKeyOriginX509);
	if(key == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create DSA key\n",
		func);	
#endif
	    EVP_PKEY_free(pKey);
	    return(NULL);	    
	}
	
	ret = xmlSecDsaKeyGenerate(key, pKey->pkey.dsa);
	if(ret < 0) {	
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to set DSA key\n",
		func);	
#endif
	    xmlSecKeyDestroy(key);
	    EVP_PKEY_free(pKey);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_DSA */	
    default:	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: the key type %d is not supported\n",
	    func, pKey->type);	
#endif
	EVP_PKEY_free(pKey);
	return(NULL);
    }
    EVP_PKEY_free(pKey);
    
    ret = xmlSecSimpleKeysMngrAddKey(mngr, key);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to add key to the keymanager\n",
	    func);	
#endif 	    
	xmlSecKeyDestroy(key);
	return(NULL);
    }
    
    return(key);
}

/**
 * Keys Data
 */
static xmlSecSimpleKeysDataPtr	
xmlSecSimpleKeysDataCreate(void) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysDataCreate";    
    xmlSecSimpleKeysDataPtr keysData;
        
    keysData = (xmlSecSimpleKeysDataPtr)xmlMalloc(sizeof(xmlSecSimpleKeysData));
    if(keysData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate xmlSecSimpleKeysData\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(keysData, 0, sizeof(xmlSecSimpleKeysData));
    return(keysData);
}

static void
xmlSecSimpleKeysDataDestroy(xmlSecSimpleKeysDataPtr keysData) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysDataDestroy";    

    if(keysData == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: keysData is null\n",
	    func);	
#endif 	    
	return;
    }

    if(keysData->keys != NULL) {
	size_t i;
	
	for(i = 0; i < keysData->curSize; ++i) {
	    if(keysData->keys[i] != NULL) {
		xmlSecKeyDestroy(keysData->keys[i]);
	    }
	}
	memset(keysData->keys, 0, keysData->maxSize * sizeof(xmlSecKeyPtr));
	xmlFree(keysData->keys);
    }
    memset(keysData, 0, sizeof(xmlSecSimpleKeysData));
    xmlFree(keysData);
}


#ifndef XMLSEC_NO_X509						 
xmlSecX509DataPtr
xmlSecSimpleKeysMngrX509Find(xmlSecKeysMngrPtr mngr, void *context ATTRIBUTE_UNUSED,
			    xmlChar *subjectName, xmlChar *issuerName, 
			    xmlChar *issuerSerial, xmlChar *ski, 
			    xmlSecX509DataPtr cert) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrX509Find";
    
    if(mngr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr is null\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    if(mngr->x509Data != NULL) {
	return(xmlSecX509StoreFind((xmlSecX509StorePtr)mngr->x509Data, 
				    subjectName, issuerName, issuerSerial, ski,
				    cert));
				
    }        
    return(NULL);
}

int	
xmlSecSimpleKeysMngrX509Verify(xmlSecKeysMngrPtr mngr, void *context ATTRIBUTE_UNUSED, 
			       xmlSecX509DataPtr cert) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrX509Verify";

    if(mngr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    if(mngr->x509Data != NULL) {
	return(xmlSecX509StoreVerify((xmlSecX509StorePtr)mngr->x509Data, cert));
    }        
    return(0);
}

int
xmlSecSimpleKeysMngrLoadPemCert(xmlSecKeysMngrPtr mngr, const char *filename,
				int trusted) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrLoadPemCert";

    if((mngr == NULL) || (mngr->x509Data == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr or x509 data is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    return(xmlSecX509StoreLoadPemCert((xmlSecX509StorePtr)mngr->x509Data, filename, trusted));
}

int	
xmlSecSimpleKeysMngrAddCertsDir(xmlSecKeysMngrPtr mngr, const char *path) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrAddCertsDir";

    if((mngr == NULL) || (mngr->x509Data == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr or x509 data is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    return(xmlSecX509StoreAddCertsDir((xmlSecX509StorePtr)mngr->x509Data, path));
}

int	
xmlSecSimpleKeysMngrLoadPkcs12(xmlSecKeysMngrPtr mngr, const char* name,
			    const char *filename, const char *pwd) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecSimpleKeysMngrLoadPkcs12";
    xmlSecKeyPtr key;
    int ret;
    
    if((mngr == NULL) || (filename == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr or filename is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    key = xmlSecPKCS12ReadKey(filename, pwd);
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read key from file \"%s\"\n",
	    func, filename);	
#endif 	    
	return(-1);
    }
    
    if(name != NULL) {
	key->name = xmlStrdup(BAD_CAST name); 
    }
    
    ret = xmlSecSimpleKeysMngrAddKey(mngr, key);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to add key to the keymanager\n",
	    func);	
#endif 	    
	xmlSecKeyDestroy(key);
	return(-1);
    }
    
    return(0);
}

#endif /* XMLSEC_NO_X509 */
