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
#include <xmlsec/errors.h>


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
    xmlSecKeysMngrPtr mngr;
        
    mngr = (xmlSecKeysMngrPtr)xmlMalloc(sizeof(xmlSecKeysMngr));    
    if(mngr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);
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
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSimpleKeysDataCreate");
	xmlSecSimpleKeysMngrDestroy(mngr);
	return(NULL);
    }   
    mngr->findKey = xmlSecSimpleKeysMngrFindKey;    

#ifndef XMLSEC_NO_X509
    mngr->x509Data = xmlSecX509StoreCreate();
    if(mngr->x509Data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509StoreCreate");
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
    xmlSecAssert(mngr != NULL);    

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
    xmlSecSimpleKeysDataPtr keysData;
    xmlSecKeyPtr key;
    size_t i;

    xmlSecAssert2(mngr != NULL, NULL);
    xmlSecAssert2(mngr->keysData != NULL, NULL);

    keysData = (xmlSecSimpleKeysDataPtr)((mngr)->keysData);    
    for(i = 0; i < keysData->curSize; ++i) {
	if(xmlSecVerifyKey(keysData->keys[i], name, id, type) == 1) {
	    key = xmlSecKeyDuplicate(keysData->keys[i], xmlSecKeyOriginKeyManager);
	    if(key == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecKeyDuplicate");
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
    xmlSecSimpleKeysDataPtr keysData;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(mngr->keysData != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    keysData = (xmlSecSimpleKeysDataPtr)((mngr)->keysData);
        
    if(keysData->maxSize == 0) {
	keysData->keys = (xmlSecKeyPtr *) xmlMalloc(XMLSEC_SIMPLEKEYMNGR_DEFAULT *
					    sizeof(xmlSecKeyPtr));
	if(keysData->keys == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			"%d bytes", XMLSEC_SIMPLEKEYMNGR_DEFAULT * sizeof(xmlSecKeyPtr));
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
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			"%d bytes", newMax * sizeof(xmlSecKeyPtr));
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

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);
    
    doc = xmlParseFile(uri);
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlParseFile");
	return(-1);
    }
    
    root = xmlDocGetRootElement(doc);
    if(!xmlSecCheckNodeName(root, BAD_CAST "Keys", xmlSecNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Keys");
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
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyInfoNodeRead");
	    if(strict) {
		xmlFreeDoc(doc);
		return(-1);	
	    }
	} else {
	    ret = xmlSecSimpleKeysMngrAddKey(mngr, key);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecSimpleKeysMngrAddKey - %d", ret);
		xmlSecKeyDestroy(key);
		xmlFreeDoc(doc);
		return(-1);	
	    }
	}
        cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*) cur->name : "NULL");
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
    xmlSecSimpleKeysDataPtr keysData;  
    xmlSecKeysMngr keysMngr;
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    int ret;
    size_t i;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(mngr->keysData != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    keysData = (xmlSecSimpleKeysDataPtr)((mngr)->keysData);
    memset(&keysMngr, 0, sizeof(keysMngr));
    keysMngr.allowedOrigins = xmlSecKeyOriginKeyValue;
    
    /* create doc */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewDoc");
	return(-1);
    }
    
    /* create root node "Keys" */
    root = xmlNewDocNode(doc, NULL, BAD_CAST "Keys", NULL); 
    if(root == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewDocNode");
	xmlFreeDoc(doc);
	return(-1);
    }
    xmlDocSetRootElement(doc, root);
    if(xmlNewNs(root, xmlSecNs, NULL) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewNs");
	xmlFreeDoc(doc); 
	return(-1);
    }
    for(i = 0; i < keysData->curSize; ++i) {
	cur = xmlSecAddChild(root, BAD_CAST "KeyInfo", xmlSecDSigNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyInfo\")");
	    xmlFreeDoc(doc); 
	    return(-1);
	}
	
	if(xmlSecAddChild(cur, BAD_CAST "KeyName", xmlSecDSigNs) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyName\")");
	    xmlFreeDoc(doc); 
	    return(-1);
	}

	if(xmlSecAddChild(cur, BAD_CAST "KeyValue", xmlSecDSigNs) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyValue\")");
	    xmlFreeDoc(doc); 
	    return(-1);
	}

#ifndef XMLSEC_NO_X509
	if((keysData->keys[i]->x509Data != NULL)){
	    if(xmlSecAddChild(cur, BAD_CAST "X509Data", xmlSecDSigNs) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecAddChild(\"X509Data\")");
		xmlFreeDoc(doc); 
		return(-1);
	    }
	}
#endif /* XMLSEC_NO_X509 */	     

	ret = xmlSecKeyInfoNodeWrite(cur, &keysMngr, NULL, keysData->keys[i], type);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyInfoNodeWrite - %d", ret);
	    xmlFreeDoc(doc); 
	    return(-1);
	}		
    }    

    /* now write result */
    ret = xmlSaveFormatFile(filename, doc, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlSaveFormatFile(\"%s\") - %d", filename, ret);
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
    xmlSecKeyPtr key = NULL;
    EVP_PKEY *pKey = NULL;    
    FILE *f;
    int ret;

    xmlSecAssert2(mngr != NULL, NULL);
    xmlSecAssert2(keyfile != NULL, NULL);
    
    f = fopen(keyfile, "r");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "fopen(\"%s\")", keyfile);
	return(NULL);    
    }
    
    if(privateKey) {
	pKey = PEM_read_PrivateKey(f, NULL, keyPwdCallback, (void*)keyPwd);
    } else {	
        pKey = PEM_read_PUBKEY(f, NULL, keyPwdCallback, (void*)keyPwd);
    }
    if(pKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    (privateKey) ? "PEM_read_PrivateKey" : "PEM_read_PUBKEY");
	fclose(f);
	return(NULL);    
    }
    fclose(f);

    switch(pKey->type) {	
#ifndef XMLSEC_NO_RSA    
    case EVP_PKEY_RSA:
	key = xmlSecKeyCreate(xmlSecRsaKey, xmlSecKeyOriginX509);
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyCreate(xmlSecRsaKey)");
	    EVP_PKEY_free(pKey);
	    return(NULL);	    
	}
	
	ret = xmlSecRsaKeyGenerate(key, pKey->pkey.rsa);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecRsaKeyGenerate - %d", ret);
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
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyCreate(xmlSecDsaKey)");
	    EVP_PKEY_free(pKey);
	    return(NULL);	    
	}
	
	ret = xmlSecDsaKeyGenerate(key, pKey->pkey.dsa);
	if(ret < 0) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDsaKeyGenerate - %d", ret);
	    xmlSecKeyDestroy(key);
	    EVP_PKEY_free(pKey);
	    return(NULL);	    
	}
	break;
#endif /* XMLSEC_NO_DSA */	
    default:	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    "key type %d", pKey->type);
	EVP_PKEY_free(pKey);
	return(NULL);
    }
    EVP_PKEY_free(pKey);
    
    ret = xmlSecSimpleKeysMngrAddKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSimpleKeysMngrAddKey - %d", ret);
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
    xmlSecSimpleKeysDataPtr keysData;
        
    keysData = (xmlSecSimpleKeysDataPtr)xmlMalloc(sizeof(xmlSecSimpleKeysData));
    if(keysData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);    
	return(NULL);
    }
    memset(keysData, 0, sizeof(xmlSecSimpleKeysData));
    return(keysData);
}

static void
xmlSecSimpleKeysDataDestroy(xmlSecSimpleKeysDataPtr keysData) {
    xmlSecAssert(keysData != NULL);

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
    xmlSecAssert2(mngr != NULL, NULL);
    
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
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);
    
    if(mngr->x509Data != NULL) {
	return(xmlSecX509StoreVerify((xmlSecX509StorePtr)mngr->x509Data, cert));
    }        
    return(0);
}

int
xmlSecSimpleKeysMngrLoadPemCert(xmlSecKeysMngrPtr mngr, const char *filename,
				int trusted) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(mngr->x509Data != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    return(xmlSecX509StoreLoadPemCert((xmlSecX509StorePtr)mngr->x509Data, filename, trusted));
}

int	
xmlSecSimpleKeysMngrAddCertsDir(xmlSecKeysMngrPtr mngr, const char *path) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(mngr->x509Data != NULL, -1);
    xmlSecAssert2(path != NULL, -1);
    
    return(xmlSecX509StoreAddCertsDir((xmlSecX509StorePtr)mngr->x509Data, path));
}

int	
xmlSecSimpleKeysMngrLoadPkcs12(xmlSecKeysMngrPtr mngr, const char* name,
			    const char *filename, const char *pwd) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    
    key = xmlSecPKCS12ReadKey(filename, pwd);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecPKCS12ReadKey(\"%s\")", filename);
	return(-1);
    }
    
    if(name != NULL) {
	key->name = xmlStrdup(BAD_CAST name); 
    }
    
    ret = xmlSecSimpleKeysMngrAddKey(mngr, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecSimpleKeysMngrAddKey - %d", ret);
	xmlSecKeyDestroy(key);
	return(-1);
    }
    
    return(0);
}

#endif /* XMLSEC_NO_X509 */
