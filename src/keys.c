/** 
 * XMLSec library
 *
 * Keys
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/x509.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>


xmlSecKeyId xmlSecAllKeyIds[100];

/**
 * xmlSecKeyInit
 * 
 * Initializes the keys list
 */
void		
xmlSecKeysInit(void) {
    int i = 0;

#ifndef XMLSEC_NO_HMAC    
    xmlSecAllKeyIds[i++] = xmlSecHmacKey;
#endif /* XMLSEC_NO_HMAC */    

#ifndef XMLSEC_NO_DSA
    xmlSecAllKeyIds[i++] = xmlSecDsaKey;
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_RSA
    xmlSecAllKeyIds[i++] = xmlSecRsaKey;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_DES    
    xmlSecAllKeyIds[i++] = xmlSecDesKey;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES    
    xmlSecAllKeyIds[i++] = xmlSecAesKey;
#endif /* XMLSEC_NO_AES */

    /* MUST be the last in the list */  
    xmlSecAllKeyIds[i++] = xmlSecKeyIdUnknown;
}

/**
 * xmlSecKeyCreate
 * @id:
 * @origin:
 *
 * Creates new key (wrapper for xmlSecKey::create method)
 *
 */
xmlSecKeyPtr	
xmlSecKeyCreate(xmlSecKeyId id, xmlSecKeyOrigin origin)  {
    xmlSecKeyPtr key;
    
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->create != NULL, NULL);
    
    key = id->create(id);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->create");
	return(NULL);	
    }
    key->origin = origin;
    return(key);
}

/**
 * xmlSecKeyDestroy
 * @key:
 * @forceDestroy:
 *
 * Destroys the key. If the key origin has a KeyManager marker 
 * the key is *not* destroyed unless @forceDestroy is not zero
 */
void
xmlSecKeyDestroy(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);    
    xmlSecAssert(key->id != NULL);    
    xmlSecAssert(key->id->destroy != NULL);    

    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return;
    }
    
    if(key->name != NULL) {
	xmlFree(key->name); 
	key->name = NULL;
    }
#ifndef XMLSEC_NO_X509
    if(key->x509Data != NULL) {	
	xmlSecX509DataDestroy(key->x509Data);
    }
#endif /* XMLSEC_NO_X509 */    
    key->id->destroy(key);
}

xmlSecKeyPtr	
xmlSecKeyDuplicate(xmlSecKeyPtr key,  xmlSecKeyOrigin origin) {
    xmlSecKeyPtr newKey;

    xmlSecAssert2(key != NULL, NULL);
    xmlSecAssert2(key->id != NULL, NULL);
    xmlSecAssert2(key->id->duplicate != NULL, NULL);
    
    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return(NULL);	
    }
    
    newKey = key->id->duplicate(key);
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->duplicate");
	return(NULL);	
    }
    
    newKey->origin = origin;
    if(key->name != NULL) {
	newKey->name = xmlStrdup(key->name);
    }

#ifndef XMLSEC_NO_X509
    /* dup x509 certs */
    if(key->x509Data != NULL) {
	newKey->x509Data = xmlSecX509DataDup(key->x509Data);
    }
#endif /* XMLSEC_NO_X509 */    
    return(newKey);
}

/**
 * xmlSecKeyReadXml
 * @node:
 * 
 * Reads the key form XML doc
 */
xmlSecKeyPtr	
xmlSecKeyReadXml(xmlSecKeyId id, xmlNodePtr node) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->read != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);

    key = xmlSecKeyCreate(id, xmlSecKeyOriginDefault);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyCreate");
	return(NULL);    
    }

    ret = (id->read)(key, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->read - %d", ret);
	xmlSecKeyDestroy(key);
	return(NULL);    
    }
    
    return(key);
}

/**
 * xmlSecKeyWriteXml
 * @key:
 * @type:
 * @parent:
 * 
 * Writes the key into XML node and adds it to the list of @parent children
 * (if parent is not null).
 */
int
xmlSecKeyWriteXml(xmlSecKeyPtr key, xmlSecKeyType type, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->id != NULL, -1);
    xmlSecAssert2(key->id->write != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return(-1);
    }
    
    /* write key */
    ret = key->id->write(key, type, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->write - %d", ret);
	return(-1);	    
    }
    return(0);    
}

xmlSecKeyPtr	
xmlSecKeyReadBin(xmlSecKeyId id, const unsigned char *buf, size_t size) {
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->readBin != NULL, NULL);
    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);
    
    key = xmlSecKeyCreate(id, xmlSecKeyOriginDefault);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyCreate");
	return(NULL);    
    }

    ret = (id->readBin)(key, buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->readBin - %d", ret);
	xmlSecKeyDestroy(key);
	return(NULL);    
    }
    
    return(key);
}

int
xmlSecKeyWriteBin(xmlSecKeyPtr key, xmlSecKeyType type,
		 unsigned char **buf, size_t *size) {
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->id != NULL, -1);
    xmlSecAssert2(key->id->readBin != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);

    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return(-1);
    }

    /* write key */
    ret = key->id->writeBin(key, type, buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->writeBin - %d", ret);
	return(-1);	    
    }
    return(0);    
}

int
xmlSecVerifyKey(xmlSecKeyPtr key, const xmlChar *name, xmlSecKeyId id, xmlSecKeyType type) {
    xmlSecAssert2(key != NULL, -1);

    if((id != xmlSecKeyIdUnknown) && (id != key->id)) {
	return(0);
    }
    if((type != xmlSecKeyTypeAny) && (key->type != type) && (key->type != xmlSecKeyTypePrivate)) {
	 return(0);
    }
    if((name != NULL) && (!xmlStrEqual(key->name, name))) {
	return(0);
    }
    return(1);
}

/** 
 * xmlSecKeyDebugDump
 *
 *
 *
 */
void
xmlSecKeyDebugDump(xmlSecKeyPtr key, FILE *output) {
    xmlSecAssert(key != NULL);
    xmlSecAssert(output != NULL);
    
    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    NULL);
	return;
    }
    fprintf(output, "== KEY\n");
    fprintf(output, "=== method: %s\n", 
	    (key->id->keyValueNodeName != NULL) ? 
	    (char*)(key->id->keyValueNodeName) : "NULL"); 
    fprintf(output, "=== key name: %s\n", 
	    (key->name != NULL) ? 
	    (char*)(key->name) : "NULL"); 
    fprintf(output, "=== key type: %s\n", 
	    (key->type == xmlSecKeyTypePrivate) ? 
	    "Private" : "Public"); 
    fprintf(output, "=== key origin:");
    if(key->origin & xmlSecKeyOriginKeyManager) {
	fprintf(output, " KeyManager");
    }
    if(key->origin & xmlSecKeyOriginKeyName) {
	fprintf(output, " KeyName");
    }
    if(key->origin & xmlSecKeyOriginKeyValue) {
	fprintf(output, " KeyValue");
    }
    if(key->origin & xmlSecKeyOriginRetrievalDocument) {
	fprintf(output, " RetrievalDocument");
    }
    if(key->origin & xmlSecKeyOriginRetrievalRemote) {
	fprintf(output, " RetrievalRemote");
    }
    if(key->origin & xmlSecKeyOriginX509) {
	fprintf(output, " x509");
    }
    if(key->origin & xmlSecKeyOriginEncryptedKey) {
	fprintf(output, " EncKey");
    }
    if(key->origin & xmlSecKeyOriginPGP) {
	fprintf(output, " PGP");
    }
    fprintf(output, "\n");
#ifndef XMLSEC_NO_X509
    if(key->x509Data != NULL) {
	xmlSecX509DataDebugDump(key->x509Data, output);
    }
#endif /* XMLSEC_NO_X509 */    
}

#ifndef XMLSEC_NO_X509
int		
xmlSecKeyReadPemCert(xmlSecKeyPtr key,  const char *filename) {
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    if(key->x509Data == NULL) {
	key->x509Data = xmlSecX509DataCreate();
	if(key->x509Data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecX509DataCreate");
	    return(-1);
	}
    }    
    
    ret = xmlSecX509DataReadPemCert(key->x509Data, filename);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecX509DataReadPemCert(%s) - %d", filename, ret);
	return(-1);
    }
    
    return(0);
}
#endif /* XMLSEC_NO_X509 */


xmlSecKeyPtr 		
xmlSecKeysMngrGetKey(xmlNodePtr keyInfoNode, xmlSecKeysMngrPtr mngr, void *context,
		xmlSecKeyId keyId, xmlSecKeyType keyType, xmlSecKeyUsage keyUsage) {
    xmlSecKeyPtr key = NULL;
        
    xmlSecAssert2(mngr != NULL, NULL);

    if((key == NULL) && (keyInfoNode != NULL)) {
	key = xmlSecKeyInfoNodeRead(keyInfoNode, mngr, context,
			keyId, keyType, keyUsage);
    }
    
    if((key == NULL) && (mngr->allowedOrigins & xmlSecKeyOriginKeyManager) && 
			(mngr->findKey != NULL)) {
	key = mngr->findKey(mngr, context, NULL, keyId, keyType, keyUsage);
    }
    
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    NULL);
	return(NULL);    
    }
    
    return(key);
}


