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



/*************************************************************************
 *
 * KeyValue ids
 *
 ************************************************************************/
#define XMLSEC_KEYIDS_SIZE 	100

static xmlSecKeyValueId xmlSecKeyValueIdsAll[XMLSEC_KEYIDS_SIZE] = { xmlSecKeyValueIdUnknown };
static int xmlSecKeyValueIdsPos = 0;

int 
xmlSecKeyValueIdsRegister(xmlSecKeyValueId id) {
    xmlSecAssert2(id != xmlSecKeyValueIdUnknown, -1);
    
    if(xmlSecKeyValueIdsPos + 1 >= XMLSEC_KEYIDS_SIZE) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "%d", xmlSecKeyValueIdsPos);
	return(-1);	
    }
    
    xmlSecKeyValueIdsAll[xmlSecKeyValueIdsPos++] = id;
    xmlSecKeyValueIdsAll[xmlSecKeyValueIdsPos] = xmlSecKeyValueIdUnknown; /* MUST be the last in the list */  

    return(0);
}

int 
xmlSecKeyValueIdsRegisterDefault(void) {
    /* all keys are registered in crypto engine */
    return(0);
}

void 
xmlSecKeyValueIdsUnregisterAll(void) {
    memset(xmlSecKeyValueIdsAll, 0, sizeof(xmlSecKeyValueIdsAll));
    xmlSecKeyValueIdsPos = 0;
}

xmlSecKeyValueId 
xmlSecKeyValueIdsFindByNode(xmlSecKeyValueId desiredKeyId, xmlNodePtr cur) {
    xmlSecKeyValueId keyId;
    int i;

    xmlSecAssert2(cur != NULL, xmlSecKeyValueIdUnknown);
    
    for(i = 0; i < xmlSecKeyValueIdsPos; ++i) {
	keyId = xmlSecKeyValueIdsAll[i];
	if((desiredKeyId != xmlSecKeyValueIdUnknown) && (desiredKeyId != keyId)) {
	    continue;
	}
	if(xmlSecCheckNodeName(cur, keyId->keyValueNodeName, keyId->keyValueNodeNs)) {
	    return(keyId);
	}
    }
    /* todo: print an error? */
    return(xmlSecKeyValueIdUnknown);
}

/*************************************************************************
 *
 * KeyValue 
 *
 ************************************************************************/
/**
 * xmlSecKeyValueCreate:
 * @id: the key id.
 * @origin: the key origins.
 *
 * Creates new key of the specified type @id.
 *
 * Returns the pointer to newly allocated #xmlSecKeyValue structure
 * or NULL if an error occurs.
 */
xmlSecKeyValuePtr	
xmlSecKeyValueCreate(xmlSecKeyValueId id, xmlSecKeyOrigin origin)  {
    xmlSecKeyValuePtr key;
    
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
 * xmlSecKeyValueDestroy:
 * @key: the pointer to the #xmlSecKeyValue structure.
 *
 * Destroys the key and frees all allocated memory. 
 */
void
xmlSecKeyValueDestroy(xmlSecKeyValuePtr key) {
    xmlSecAssert(key != NULL);    
    xmlSecAssert(key->id != NULL);    
    xmlSecAssert(key->id->destroy != NULL);    

    if(!xmlSecKeyValueIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
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

/**
 * xmlSecKeyValueDuplicate:
 * @key: the pointer to the #xmlSecKeyValue structure.
 * @origin: the key origins.
 *
 * Creates a duplicate of the given @key.
 *
 * Returns the pointer to newly allocated #xmlSecKeyValue structure
 * or NULL if an error occurs.
 */
xmlSecKeyValuePtr	
xmlSecKeyValueDuplicate(xmlSecKeyValuePtr key,  xmlSecKeyOrigin origin) {
    xmlSecKeyValuePtr newKey;

    xmlSecAssert2(key != NULL, NULL);
    xmlSecAssert2(key->id != NULL, NULL);
    xmlSecAssert2(key->id->duplicate != NULL, NULL);
    
    if(!xmlSecKeyValueIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
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

xmlSecKeyValuePtr
xmlSecKeyValueGenerate(xmlSecKeyValueId id, int keySize, xmlSecKeyOrigin origin, const char* name) {
    xmlSecKeyValuePtr key;
    int ret;
    
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->generate != NULL, NULL);
    
    key = xmlSecKeyValueCreate(id, origin);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCreate");
	return(NULL);	
    }
    
    ret = id->generate(key, keySize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->generate");
	xmlSecKeyValueDestroy(key);
	return(NULL);	
    }	

    if(name != NULL) {
	key->name = xmlStrdup(BAD_CAST name);
    }						    
    return(key);
}

int
xmlSecKeyValueSet(xmlSecKeyValuePtr key,  void* data, int dataSize) {
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->id != NULL, -1);
    xmlSecAssert2(key->id->setValue != NULL, -1);
    
    if(!xmlSecKeyValueIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return(-1);	
    }
    
    ret = key->id->setValue(key, data, dataSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->setValue");
	return(-1);	
    }	
    return(0);
}

/**
 * xmlSecKeyValueReadXml:
 * @id: the key id.
 * @node: the pointer to key value node.
 * 
 * Reads the key from XML node.
 *
 * Returns the pointer to newly allocated #xmlSecKeyValue structure
 * or NULL if an error occurs.
 */
xmlSecKeyValuePtr	
xmlSecKeyValueReadXml(xmlSecKeyValueId id, xmlNodePtr node) {
    xmlSecKeyValuePtr key;
    int ret;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->read != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);

    key = xmlSecKeyValueCreate(id, xmlSecKeyOriginDefault);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyValueCreate");
	return(NULL);    
    }

    ret = (id->read)(key, node);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->read - %d", ret);
	xmlSecKeyValueDestroy(key);
	return(NULL);    
    }
    
    return(key);
}

/**
 * xmlSecKeyValueWriteXml:
 * @key: the pointer to the #xmlSecKeyValue structure.
 * @type: the key type to write (public/private).
 * @node: the parent XML node. 
 * 
 * Writes the key in the XML node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecKeyValueWriteXml(xmlSecKeyValuePtr key, xmlSecKeyValueType type, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->id != NULL, -1);
    xmlSecAssert2(key->id->write != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    
    if(!xmlSecKeyValueIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
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

/**
 * xmlSecKeyValueReadBin:
 * @id: the key id.
 * @buf: the pointer to key binary data buffer.
 * @size: the size of the binary key data @buf.
 * 
 * Reads the key from binary data.
 *
 * Returns the pointer to newly allocated #xmlSecKeyValue structure
 * or NULL if an error occurs.
 */
xmlSecKeyValuePtr	
xmlSecKeyValueReadBin(xmlSecKeyValueId id, const unsigned char *buf, size_t size) {
    xmlSecKeyValuePtr key;
    int ret;

    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->readBin != NULL, NULL);
    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(size > 0, NULL);
    
    key = xmlSecKeyValueCreate(id, xmlSecKeyOriginDefault);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyValueCreate");
	return(NULL);    
    }

    ret = (id->readBin)(key, buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->readBin - %d", ret);
	xmlSecKeyValueDestroy(key);
	return(NULL);    
    }
    
    return(key);
}

/**
 * xmlSecKeyValueWriteBin:
 * @key: the pointer to the #xmlSecKeyValue structure.
 * @type: the key type to write (public/private).
 * @buf: the pointer to pointer to the binary data buffer.
 * @size: the pointer to the returned buffer size.
 * 
 * Writes the key in the binary buffer. The caller is responsible
 * for freeing the returned buffer using xmlFree() function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecKeyValueWriteBin(xmlSecKeyValuePtr key, xmlSecKeyValueType type,
		 unsigned char **buf, size_t *size) {
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->id != NULL, -1);
    xmlSecAssert2(key->id->readBin != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size != NULL, -1);

    if(!xmlSecKeyValueIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
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

/**
 * xmlSecKeyValueCheck:
 * @key: the pointer to the #xmlSecKeyValue structure.
 * @name: the pointer to key name (may be NULL).
 * @id: the key id (may be "any").
 * @type: the key type to write (public/private).
 * 
 * Checks whether the @key matches the given criteria
 * (key name is equal to @name, key id is equal to @id,
 * key type is @type).
 *
 * Returns 1 if the key satisfies the given criteria or 0 otherwise.
 */
int
xmlSecKeyValueCheck(xmlSecKeyValuePtr key, const xmlChar *name, xmlSecKeyValueId id, 
		xmlSecKeyValueType type) {
    xmlSecAssert2(key != NULL, -1);

    if((id != xmlSecKeyValueIdUnknown) && (id != key->id)) {
	return(0);
    }
    if((type != xmlSecKeyValueTypeAny) && (key->type != type) && (key->type != xmlSecKeyValueTypePrivate)) {
	 return(0);
    }
    if((name != NULL) && (!xmlStrEqual(key->name, name))) {
	return(0);
    }
    return(1);
}

/** 
 * xmlSecKeyValueDebugDump:
 * @key: the pointer to the #xmlSecKeyValue structure.
 * @output: the destination #FILE pointer.
 *
 * Prints the information about the @key to the @output.
 */
void
xmlSecKeyValueDebugDump(xmlSecKeyValuePtr key, FILE *output) {
    xmlSecAssert(key != NULL);
    xmlSecAssert(output != NULL);
    
    if(!xmlSecKeyValueIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return;
    }
    fprintf(output, "== KEY VALUE\n");
    fprintf(output, "=== method: %s\n", 
	    (key->id->keyValueNodeName != NULL) ? 
	    (char*)(key->id->keyValueNodeName) : "NULL"); 
    fprintf(output, "=== key name: %s\n", 
	    (key->name != NULL) ? 
	    (char*)(key->name) : "NULL"); 
    fprintf(output, "=== key type: %s\n", 
	    (key->type == xmlSecKeyValueTypePrivate) ? 
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

/** 
 * xmlSecKeyValueDebugXmlDump:
 * @key: the pointer to the #xmlSecKeyValue structure.
 * @output: the destination #FILE pointer.
 *
 * Prints the information about the @key to the @output in XML format.
 */
void
xmlSecKeyValueDebugXmlDump(xmlSecKeyValuePtr key, FILE *output) {
    xmlSecAssert(key != NULL);
    xmlSecAssert(output != NULL);
    
    if(!xmlSecKeyValueIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    " ");
	return;
    }
    fprintf(output, "<KeyInfo>\n");
    if(key->id->keyValueNodeName != NULL) {
        fprintf(output, "<KeyMethod>%s</KeyMethod>\n", 
		key->id->keyValueNodeName); 
    }
    if(key->name != NULL) {
	fprintf(output, "<KeyName>%s</KeyName>\n", 
	        key->name);
    }
    fprintf(output, "<KeyType>%s</KeyType>\n", 
	    (key->type == xmlSecKeyValueTypePrivate) ? 
	    "Private" : "Public"); 
    fprintf(output, "<KeyOrigins>\n");
    if(key->origin & xmlSecKeyOriginKeyManager) {
	fprintf(output, "<KeyOrigin>KeyManager</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginKeyName) {
	fprintf(output, "<KeyOrigin>KeyName</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginKeyValue) {
	fprintf(output, "<KeyOrigin>KeyValue</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginRetrievalDocument) {
	fprintf(output, "<KeyOrigin>RetrievalDocument</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginRetrievalRemote) {
	fprintf(output, "<KeyOrigin>RetrievalRemote</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginX509) {
	fprintf(output, "<KeyOrigin>x509</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginEncryptedKey) {
	fprintf(output, "<KeyOrigin>EncKey</KeyOrigin>\n");
    }
    if(key->origin & xmlSecKeyOriginPGP) {
	fprintf(output, "<KeyOrigin>PGP</KeyOrigin>\n");
    }
    fprintf(output, "</KeyOrigins>\n");
#ifndef XMLSEC_NO_X509
    if(key->x509Data != NULL) {
	xmlSecX509DataDebugXmlDump(key->x509Data, output);
    }
#endif /* XMLSEC_NO_X509 */   
    fprintf(output, "</KeyInfo>\n"); 
}



/**
 * xmlSecKeysMngrGetKey:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @mngr: the keys manager.
 * @context: the pointer to application specific data.
 * @keyId: the required key Id (or NULL for "any").
 * @keyType: the required key (may be "any").
 * @keyUsage: the required key usage.
 * 
 * Reads the <dsig:KeyInfo> node @keyInfoNode and extracts the key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
xmlSecKeyValuePtr 		
xmlSecKeysMngrGetKey(xmlNodePtr keyInfoNode, xmlSecKeysMngrPtr mngr, void *context,
		xmlSecKeyValueId keyId, xmlSecKeyValueType keyType, xmlSecKeyUsage keyUsage,
		time_t certsVerificationTime) {
    xmlSecKeyValuePtr key = NULL;
        
    xmlSecAssert2(mngr != NULL, NULL);

    if((key == NULL) && (keyInfoNode != NULL)) {
	key = xmlSecKeyInfoNodeRead(keyInfoNode, mngr, context,
			keyId, keyType, keyUsage, certsVerificationTime);
    }
    
    if((key == NULL) && (mngr->allowedOrigins & xmlSecKeyOriginKeyManager) && 
			(mngr->findKey != NULL)) {
	key = mngr->findKey(mngr, context, NULL, keyId, keyType, keyUsage);
    }
    
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    " ");
	return(NULL);    
    }
    
    return(key);
}

#ifndef XMLSEC_NO_X509
/**
 * xmlSecKeyValueReadPemCert:
 * @key: the pointer to the #xmlSecKeyValue structure.
 * @filename: the PEM cert file name.
 *
 * Reads the cert from a PEM file and assigns the cert
 * to the key.
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
int		
xmlSecKeyValueReadPemCert(xmlSecKeyValuePtr key,  const char *filename) {
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

