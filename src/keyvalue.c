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
#include <xmlsec/keyvalue.h>
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
 *
 * Creates new key of the specified type @id.
 *
 * Returns the pointer to newly allocated #xmlSecKeyValue structure
 * or NULL if an error occurs.
 */
xmlSecKeyValuePtr	
xmlSecKeyValueCreate(xmlSecKeyValueId id)  {
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
    
    key->id->destroy(key);
}

/**
 * xmlSecKeyValueDuplicate:
 * @key: the pointer to the #xmlSecKeyValue structure.
 *
 * Creates a duplicate of the given @key.
 *
 * Returns the pointer to newly allocated #xmlSecKeyValue structure
 * or NULL if an error occurs.
 */
xmlSecKeyValuePtr	
xmlSecKeyValueDuplicate(xmlSecKeyValuePtr key) {
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
    
    return(newKey);
}

xmlSecKeyValuePtr
xmlSecKeyValueGenerate(xmlSecKeyValueId id, int keySize) {
    xmlSecKeyValuePtr key;
    int ret;
    
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->generate != NULL, NULL);
    
    key = xmlSecKeyValueCreate(id);
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

int
xmlSecKeyValueCheck(xmlSecKeyValuePtr key, xmlSecKeyValueId keyId, xmlSecKeyValueType keyType) {
    xmlSecAssert2(key != NULL, -1);

    if((keyId != xmlSecKeyValueIdUnknown) && (keyId != key->id)) {
	return(0);
    }
    if((keyType != xmlSecKeyValueTypeAny) && 
       (key->type != xmlSecKeyValueTypeAny) && 
       (key->type != keyType) && 
       (key->type != xmlSecKeyValueTypePrivate)) {
	 return(0);
    }
    return(1);
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

    key = xmlSecKeyValueCreate(id);
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
    
    key = xmlSecKeyValueCreate(id);
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
    fprintf(output, "=== key type: %s\n", 
	    (key->type == xmlSecKeyValueTypePrivate) ? 
	    "Private" : "Public"); 
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
    fprintf(output, "<KeyType>%s</KeyType>\n", 
	    (key->type == xmlSecKeyValueTypePrivate) ? 
	    "Private" : "Public"); 
    fprintf(output, "</KeyInfo>\n"); 
}

