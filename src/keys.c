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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyCreate";
    xmlSecKeyPtr key;
    
    if((id == xmlSecKeyIdUnknown) || (id->create == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id or create method is not defined\n",
	    func);	
#endif
	return(NULL);	
    }
    
    key = id->create(id);
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key creation failed\n",
	    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyDestroy";
    
    if((!xmlSecKeyIsValid(key)) || (key->id->destroy == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or destroy method is not defined\n",
	    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyDuplicate";
    xmlSecKeyPtr newKey;
    
    if(!xmlSecKeyIsValid(key) || (key->id->duplicate == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bad key: unable to duplicate\n",
	    func);	
#endif
	return(NULL);	
    }
    
    newKey = key->id->duplicate(key);
    if(newKey == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key duplication failed\n",
	    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyReadXml";
    xmlSecKeyPtr key;
    int ret;
    
    if(node == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: node is null\n",
	    func);	
#endif
	return(NULL);
    }

    if(id->read == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XML read not implemented for key \"%s\"\n",
	    func, id->keyValueNodeName);	
#endif
	return(NULL);	    	
    }

    key = xmlSecKeyCreate(id, xmlSecKeyOriginDefault);
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create key\n",
	    func);	
#endif
	return(NULL);    
    }

    
    
    ret = (id->read)(key, node);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read key\n",
	    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyWriteXml";
    int ret;
    
    if((!xmlSecKeyIsValid(key)) || (node == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or parent is null\n",
	    func);	
#endif
	return(-1);
    }
    
    if(key->id->write == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XML write not implemented for key \"%s\"\n",
	    func, key->id->keyValueNodeName);	
#endif
	return(-1);	    	
    }
    
    /* write key */
    ret = key->id->write(key, type, node);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to write key\n",
	    func);	
#endif
	return(-1);	    
    }
    return(0);    
}

xmlSecKeyPtr	
xmlSecKeyReadBin(xmlSecKeyId id, const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyReadBin";
    xmlSecKeyPtr key;
    int ret;
    
    if((buf == NULL) || (size == 0)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: buffer or size is null\n",
	    func);	
#endif
	return(NULL);
    }

    if(id->readBin == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bin read not implemented for key \"%s\"\n",
	    func, id->keyValueNodeName);	
#endif
	return(NULL);	    	
    }

    key = xmlSecKeyCreate(id, xmlSecKeyOriginDefault);
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create key\n",
	    func);	
#endif
	return(NULL);    
    }

    
    
    ret = (id->readBin)(key, buf, size);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read key\n",
	    func);	
#endif
	xmlSecKeyDestroy(key);
	return(NULL);    
    }
    
    return(key);
}

int
xmlSecKeyWriteBin(xmlSecKeyPtr key, xmlSecKeyType type,
		 unsigned char **buf, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyWriteBin";
    int ret;
    
    if((!xmlSecKeyIsValid(key)) || (buf == NULL) || (size == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is invalid or buffer or size is null\n",
	    func);	
#endif
	return(-1);
    }

    if(key->id->writeBin == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: bin write not implemented for key \"%s\"\n",
	    func, key->id->keyValueNodeName);	
#endif
	return(-1);	    	
    }
    
    
    /* write key */
    ret = key->id->writeBin(key, type, buf, size);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to write key\n",
	    func);	
#endif
	return(-1);	    
    }
    return(0);    
}

int
xmlSecVerifyKey(xmlSecKeyPtr key, const xmlChar *name, xmlSecKeyId id, xmlSecKeyType type) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecVerifyKey";
	
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is null\n", 
	    func);	
#endif
	return(-1);
    }

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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyDebugDump";
    
    if((output == NULL) || !xmlSecKeyIsValid(key)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key or output file is null\n", 
	    func);	
#endif
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeyReadPemCert";
    int ret;

    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: key is null\n", 
	    func);	
#endif
	return(-1);
    }
    
    if(key->x509Data == NULL) {
	key->x509Data = xmlSecX509DataCreate();
	if(key->x509Data == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create x509 data\n", 
		func);	
#endif
	    return(-1);
	}
    }    
    
    ret = xmlSecX509DataReadPemCert(key->x509Data, filename);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read pem cert\n", 
	    func);	
#endif
	return(-1);
    }
    
    return(0);
}
#endif /* XMLSEC_NO_X509 */


xmlSecKeyPtr 		
xmlSecKeysMngrGetKey(xmlNodePtr keyInfoNode, xmlSecKeysMngrPtr mngr, void *context,
		xmlSecKeyId keyId, xmlSecKeyType keyType, xmlSecKeyUsage keyUsage) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecKeysMngrGetKey";
    xmlSecKeyPtr key = NULL;
        
    if(mngr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: mngr is null\n",
	    func);	
#endif 	    
	return(NULL);    
    }
    
    if((key == NULL) && (keyInfoNode != NULL)) {
	key = xmlSecKeyInfoNodeRead(keyInfoNode, mngr, context,
			keyId, keyType, keyUsage);
    }
    
    if((key == NULL) && (mngr->allowedOrigins & xmlSecKeyOriginKeyManager) && 
			(mngr->findKey != NULL)) {
	key = mngr->findKey(mngr, context, NULL, keyId, keyType, keyUsage);
    }
    
    if(key == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to find key\n",
	    func);	
#endif 	    
	return(NULL);    
    }
    
    return(key);
}


