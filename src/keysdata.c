/** 
 * XMLSec library
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
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>


/**************************************************************************
 *
 * Global xmlSecKeyDataIds list functions
 *
 *************************************************************************/
static xmlSecKeyDataId xmlSecAllKeyDataIds[100];

int 
xmlSecKeyDataIdsInit(void) {
    int ret;
    
    memset(xmlSecAllKeyDataIds, 0, sizeof(xmlSecAllKeyDataIds));
    xmlSecAllKeyDataIds[0] = xmlSecKeyDataIdUnknown;
    
    ret = xmlSecKeyDataIdsRegisterDefault();
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataIdsRegisterDefault - %d", ret);
        return(-1);
    }
    
    return(0);
}

int 
xmlSecKeyDataIdsRegisterDefault(void) {
    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataNameId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataIdsRegister(xmlSecKeyDataNameId)");
        return(-1);	
    }

    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataValueId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataIdsRegister(xmlSecKeyDataValueId)");
        return(-1);	
    }

    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataRetrievalMethodId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataIdsRegister(xmlSecKeyDataRetrievalMethodId)");
        return(-1);	
    }

    if(xmlSecKeyDataIdsRegister(xmlSecKeyDataEncryptedKeyId) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataIdsRegister(xmlSecKeyDataEncryptedKeyId)");
        return(-1);	
    }
    return(0);
}

int 
xmlSecKeyDataIdsRegister(xmlSecKeyDataId id) {
    unsigned int i;
    
    xmlSecAssert2(id != NULL, -1);
    
    for(i = 0; i < sizeof(xmlSecAllKeyDataIds) / sizeof(xmlSecAllKeyDataIds[0]) - 1; ++i) {
	if(xmlSecAllKeyDataIds[i] == xmlSecKeyDataIdUnknown) {
	    xmlSecAllKeyDataIds[i++] = id;
	    xmlSecAllKeyDataIds[i++] = xmlSecKeyDataIdUnknown;
	    
	    return(0);
	}
    }
    
    xmlSecError(XMLSEC_ERRORS_HERE,
		XMLSEC_ERRORS_R_XMLSEC_FAILED,
		"no more key slots available; increase xmlSecAllKeyDataIds table size");
    return(-1);    
}

void
xmlSecKeyDataIdsClear(void) {
    memset(xmlSecAllKeyDataIds, 0, sizeof(xmlSecAllKeyDataIds));
    xmlSecAllKeyDataIds[0] = xmlSecKeyDataIdUnknown;
}

size_t 	
xmlSecKeyDataIdsGetSize(void) {
    size_t res = 0;
    size_t i;
            
    for(i = 0; xmlSecAllKeyDataIds[i] != xmlSecKeyDataIdUnknown; ++i) {
	++res;
    }
    
    return(res);
}

xmlSecKeyDataId	
xmlSecKeyDataIdsGetId(size_t pos) {
    /* todo: add checks !!! */
    return(xmlSecAllKeyDataIds[pos]);
}

xmlSecKeyDataId	
xmlSecKeyDataIdsFindByNode(const xmlChar* nodeName, const xmlChar* nodeNs, xmlSecKeyDataUsage usage) {
    unsigned int i;

    xmlSecAssert2(nodeName != NULL, xmlSecKeyDataIdUnknown);
    for(i = 0; xmlSecAllKeyDataIds[i] != xmlSecKeyDataIdUnknown; ++i) {
	if(((usage & xmlSecAllKeyDataIds[i]->usage) != 0) &&
	   xmlStrEqual(nodeName, xmlSecAllKeyDataIds[i]->dataNodeName) &&
	   xmlStrEqual(nodeNs, xmlSecAllKeyDataIds[i]->dataNodeNs)) {
	    
	   return(xmlSecAllKeyDataIds[i]);	   
	}
    }
    
    return(xmlSecKeyDataIdUnknown);
}

xmlSecKeyDataId	
xmlSecKeyDataIdsFindByHref(const xmlChar* href, xmlSecKeyDataUsage usage) {
    unsigned int i;

    xmlSecAssert2(href != NULL, xmlSecKeyDataIdUnknown);
    for(i = 0; xmlSecAllKeyDataIds[i] != xmlSecKeyDataIdUnknown; ++i) {
	if(((usage & xmlSecAllKeyDataIds[i]->usage) != 0) &&
	   xmlStrEqual(href, xmlSecAllKeyDataIds[i]->href)) {
	   
	   return(xmlSecAllKeyDataIds[i]);	   
	}
    }
    
    return(xmlSecKeyDataIdUnknown);
}

xmlSecKeyDataId	
xmlSecKeyDataIdsFindByName(const xmlChar* name, xmlSecKeyDataUsage usage) {
    unsigned int i;

    xmlSecAssert2(name != NULL, xmlSecKeyDataIdUnknown);
    for(i = 0; xmlSecAllKeyDataIds[i] != xmlSecKeyDataIdUnknown; ++i) {
	if(((usage & xmlSecAllKeyDataIds[i]->usage) != 0) &&
	   xmlStrEqual(name, xmlSecAllKeyDataIds[i]->name)) {
	   
	   return(xmlSecAllKeyDataIds[i]);	   
	}
    }
    
    return(xmlSecKeyDataIdUnknown);
}

/**************************************************************************
 *
 * xmlSecKeyData functions
 *
 *************************************************************************/
/**
 * xmlSecKeyDataCreate:
 * @id: the data id.
 *
 * Creates new data of the specified type @id.
 *
 * Returns the pointer to newly allocated #xmlSecKeyData structure
 * or NULL if an error occurs.
 */
xmlSecKeyDataPtr	
xmlSecKeyDataCreate(xmlSecKeyDataId id)  {
    xmlSecKeyDataPtr data;
    int ret;
        
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->objSize > 0, NULL);
        
    /* Allocate a new xmlSecKeyData and fill the fields. */
    data = (xmlSecKeyDataPtr)xmlMalloc(id->objSize);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", id->objSize); 
	return(NULL);
    }
    memset(data, 0, id->objSize);    
    data->id = id;

    if(id->initialize != NULL) {
	ret = (id->initialize)(data);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"id->initialize");
	    xmlSecKeyDataDestroy(data);
	    return(NULL);
	}
    }
    
    return(data);
}

/**
 * xmlSecKeyDataDuplicate:
 * @data: the pointer to the #xmlSecKeyData structure.
 *
 * Creates a duplicate of the given @data.
 *
 * Returns the pointer to newly allocated #xmlSecKeyData structure
 * or NULL if an error occurs.
 */
xmlSecKeyDataPtr	
xmlSecKeyDataDuplicate(xmlSecKeyDataPtr data) {
    xmlSecKeyDataPtr newData;
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(data->id->duplicate != NULL, NULL);

    newData = xmlSecKeyDataCreate(data->id);
    if(newData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataCreate"); 
	return(NULL);
    }

    ret = (data->id->duplicate)(newData, data);
    if(newData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->duplicate");
	xmlSecKeyDataDestroy(newData);
	return(NULL);	
    }
    
    return(newData);
}

/**
 * xmlSecKeyDataDestroy:
 * @data: the pointer to the #xmlSecKeyData structure.
 *
 * Destroys the data and frees all allocated memory. 
 */
void
xmlSecKeyDataDestroy(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));    
    xmlSecAssert(data->id->objSize > 0);

    
    if(data->id->finalize != NULL) { 
	(data->id->finalize)(data);
    }
    memset(data, 0, data->id->objSize);
    xmlFree(data);
}


/**
 * xmlSecKeyDataXmlRead:
 * @id: the data id.
 * @key: the key.
 * @node: the pointer to data value node.
 * @keyInfoCtx: the keys mngr.
 * 
 * Reads the data from XML node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(id->xmlRead != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    return((id->xmlRead)(id, key, node, keyInfoCtx));
}

/**
 * xmlSecKeyDataXmlWrite:
 * @id: the data id.
 * @key: the key.
 * @node: the pointer to data value node.
 * @keyInfoCtx: the keys mngr.
 * 
 * Reads the data from XML node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(id->xmlWrite != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    return((id->xmlWrite)(id, key, node, keyInfoCtx));
}

/** 
 * xmlSecKeyDataBinRead:
 * @id: the data id.
 * @key: the key.
 * @buf: the input buffer.
 * @bufSize: the buffer size.
 * @keyInfoCtx: the <dsig:KeyInfo> node processing context
 *
 * Reads the data from binary buffer @buf.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key, const unsigned char* buf, size_t bufSize, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(id->binRead != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    return((id->binRead)(id, key, buf, bufSize, keyInfoCtx));
}

/** 
 * xmlSecKeyDataWriteBin:
 * @id: the data id.
 * @key: the key.
 * @buf: the output buffer.
 * @bufSize: the buffer size.
 * @keyInfoCtx: the <dsig:KeyInfo> node processing context
 *
 * Writes the data to a binary buffer. 
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, unsigned char** buf, size_t* bufSize, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id != NULL, -1);
    xmlSecAssert2(id->binWrite != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    return((id->binWrite)(id, key, buf, bufSize, keyInfoCtx));
}

/** 
 * xmlSecKeyDataGenerate:
 * @data: the data.
 * @sizeBits: the key data specific size.
 *
 * KeyData specific destroy method.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecKeyDataGenerate(xmlSecKeyDataPtr data, size_t sizeBits) {
    int ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(data->id->generate != NULL, -1);
    
    /* write data */
    ret = data->id->generate(data, sizeBits);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->generate - %d", ret);
	return(-1);	    
    }
    return(0);    
}

xmlSecKeyDataType	
xmlSecKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(data->id->getType != NULL, xmlSecKeyDataTypeUnknown);
    
    return(data->id->getType(data));
}

size_t
xmlSecKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(data->id->getSize != NULL, 0);
    
    return(data->id->getSize(data));
}

const xmlChar*
xmlSecKeyDataGetIdentifier(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(data->id->getIdentifier != NULL, NULL);
    
    return(data->id->getIdentifier(data));
}

/** 
 * xmlSecKeyDataDebugDump:
 * @data: the data.
 * @output: the FILE to print debug info (should be open for writing).
 *
 * Prints key data debug info.
 */
void
xmlSecKeyDataDebugDump(xmlSecKeyDataPtr data, FILE *output) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->debugDump != NULL);
    xmlSecAssert(output != NULL);
    
    data->id->debugDump(data, output);
}

/** 
 * xmlSecKeyDataDebugXmlDump:
 * @data: the data.
 * @output: the FILE to print debug info (should be open for writing).
 *
 * Prints key data debug info in XML format.
 */ 
void 
xmlSecKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE *output) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->debugXmlDump != NULL);
    xmlSecAssert(output != NULL);
    
    data->id->debugXmlDump(data, output);
}

/**************************************************************************
 *
 * xmlSecKeyDataBinary methods
 *
 *************************************************************************/
int
xmlSecKeyDataBinaryValueInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
        
    /* create buffer */
    xmlSecAssert2(data->reserved0 == NULL, -1);
    data->reserved0 = xmlBufferCreate();
    if(data->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlBufferCreate");
	return(-1);
    }
    
    return(0);    
}

int
xmlSecKeyDataBinaryValueDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlBufferPtr buffer;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(src);
    xmlSecAssert2(buffer != NULL, -1);
    
    /* copy data */
    ret = xmlSecKeyDataBinaryValueSetBuffer(dst,
		    xmlBufferContent(buffer),
		    xmlBufferLength(buffer));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataBinaryValueSetBuffer");
	return(-1);
    }

    return(0);
}

void 
xmlSecKeyDataBinaryValueFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    
    /* destroy buffer */
    if(data->reserved0 != NULL) {
	/* zero buffer before destroying */
	xmlBufferEmpty((xmlBufferPtr)(data->reserved0));
	xmlBufferFree((xmlBufferPtr)(data->reserved0));
	data->reserved0 = NULL;
    }
}

int 
xmlSecKeyDataBinaryValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlChar* str;
    size_t len;
    xmlSecKeyDataPtr data;
    int ret;
    
    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    str = xmlNodeGetContent(node);
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    " ");
	return(-1);
    }

    /* usual trick: decode into the same buffer */
    ret = xmlSecBase64Decode(str, (unsigned char*)str, xmlStrlen(str));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode");
	xmlFree(str);
	return(-1);
    }
    len = ret;

    /* check do we have a key already */
    data = xmlSecKeyGetValue(key);
    if(data != NULL) {
	xmlBufferPtr buffer;
	
	if(!xmlSecKeyDataCheckId(data, id)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY_DATA,
			"key already has a value of different type");
	    xmlFree(str);
	    return(-1);	
	}
	
	buffer = xmlSecKeyDataBinaryValueGetBuffer(data);	
	if((buffer != NULL) && ((size_t)xmlBufferLength(buffer) != len)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY_DATA,
			"key already has a value of different size");
	    xmlFree(str);
	    return(-1);		
	}
	if((buffer != NULL) && (len > 0) && (memcmp(xmlBufferContent(buffer), str, len) != 0)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY_DATA,
			"key already has a different value");
	    xmlFree(str);
	    return(-1);		
	}
	if(buffer != NULL) {
	    /* we already have exactly the same key */
    	    xmlFree(str);
	    return(0);
	}
	
	/* we have binary key value with empty buffer */
    }

    
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataCreate");
	xmlFree(str);
	return(-1);
    }
        
    ret = xmlSecKeyDataBinaryValueSetBuffer(data, (unsigned char*)str, len);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataBinaryValueSetBuffer(size=%d)", len);
	xmlSecKeyDataDestroy(data);
	xmlFree(str);
	return(-1);
    }
    xmlFree(str);

    if((xmlSecKeyDataGetType(data) & keyInfoCtx->keyType) == 0) {
	xmlSecKeyDataDestroy(data);
	return(0);
    }
    
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeySetValue");
	xmlSecKeyDataDestroy(data);
	return(-1);
    }

    return(0);
}

int 
xmlSecKeyDataBinaryValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlBufferPtr buffer;
    xmlChar* str;
    
    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(key->value->id == id, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if((xmlSecKeyDataGetType(key->value) & keyInfoCtx->keyType) == 0) {
	/* we can have only private key */
	return(0);
    }

    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);

    str = xmlSecBase64Encode(xmlBufferContent(buffer),
			     xmlBufferLength(buffer),
			     keyInfoCtx->base64LineSize);
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Encode");
	return(-1);
    }    
    xmlNodeSetContent(node, str);
    xmlFree(str);
    return(0);
}

int 
xmlSecKeyDataBinaryValueBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key, const unsigned char* buf, size_t bufSize, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataPtr data;
    int ret;
    
    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* check do we have a key already */
    data = xmlSecKeyGetValue(key);
    if(data != NULL) {
	xmlBufferPtr buffer;
	
	if(!xmlSecKeyDataCheckId(data, id)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY_DATA,
			"key already has a value of different type");
	    return(-1);	
	}
	
	buffer = xmlSecKeyDataBinaryValueGetBuffer(data);	
	if((buffer != NULL) && ((size_t)xmlBufferLength(buffer) != bufSize)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY_DATA,
			"key already has a value of different size");
	    return(-1);		
	}
	if((buffer != NULL) && (bufSize > 0) && (memcmp(xmlBufferContent(buffer), buf, bufSize) != 0)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_KEY_DATA,
			"key already has a different value");
	    return(-1);		
	}
	if(buffer != NULL) {
	    /* we already have exactly the same key */
	    return(0);
	}
	
	/* we have binary key value with empty buffer */
    }
    
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataCreate");
	return(-1);
    }
        
    ret = xmlSecKeyDataBinaryValueSetBuffer(data, buf, bufSize);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataBinaryValueSetBuffer(size=%d)", bufSize);
	xmlSecKeyDataDestroy(data);
	return(-1);
    }

    if((xmlSecKeyDataGetType(data) & keyInfoCtx->keyType) == 0) {
	xmlSecKeyDataDestroy(data);
	return(0);
    }
    
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeySetValue");
	xmlSecKeyDataDestroy(data);
	return(-1);
    }

    return(0);
}

int 
xmlSecKeyDataBinaryValueBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, unsigned char** buf, size_t* bufSize, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlBufferPtr buffer;

    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);
    xmlSecAssert2(key->value->id == id, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if((xmlSecKeyDataGetType(key->value) & keyInfoCtx->keyType) == 0) {
	/* we can have only private key */
	return(0);
    }

    buffer = xmlSecKeyDataBinaryValueGetBuffer(key->value);
    xmlSecAssert2(buffer != NULL, -1);

    (*bufSize) = xmlBufferLength(buffer);
    (*buf) = (unsigned char*) xmlMalloc((*bufSize));
    if((*buf) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", (*bufSize));
	return(-1);
    }
    memcpy((*buf), xmlBufferContent(buffer), (*bufSize));    
    return(0);
}

void 
xmlSecKeyDataBinaryValueDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlBufferPtr buffer;
    
    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->dataNodeName != NULL);
    xmlSecAssert(output != NULL);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert(buffer != NULL);

    /* print only size, everything else is sensitive */    
    fprintf(output, "=== %s: size=%d\n", data->id->dataNodeName, 
					 xmlSecKeyDataGetSize(data));
}

void 
xmlSecKeyDataBinaryValueDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlBufferPtr buffer;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(data->id->dataNodeName != NULL);
    xmlSecAssert(output != NULL);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert(buffer != NULL);
    
    /* print only size, everything else is sensitive */    
    fprintf(output, "<%s size=\"%d\" />\n", data->id->dataNodeName, 
					    xmlSecKeyDataGetSize(data));
}

size_t
xmlSecKeyDataBinaryValueGetSize(xmlSecKeyDataPtr data) {
    xmlBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), 0);
    xmlSecAssert2(data->reserved0 != NULL, 0);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, 0);

    /* return size in bits */    
    return(8 * xmlBufferLength(buffer));    
}

xmlBufferPtr 
xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(data->reserved0 != NULL, NULL);
    
    return((xmlBufferPtr)data->reserved0);    
}

int
xmlSecKeyDataBinaryValueSetBuffer(xmlSecKeyDataPtr data, const unsigned char* buf, size_t bufSize) {
    xmlBufferPtr buffer;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);

    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);

    /* we might have private key here, so erasy the memory! */
    xmlBufferEmpty(buffer);
    xmlBufferAdd(buffer, buf, bufSize);
    return(0);
}

/***********************************************************************
 *
 * Keys Data list
 *
 **********************************************************************/
static const struct _xmlSecPtrListKlass xmlSecKeyDataPtrListKlass = {
    (xmlSecPtrDuplicateItemMethod)xmlSecKeyDataDuplicate, 	/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecKeyDataDestroy,		/* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecKeyDataDebugDump,	/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecKeyDataDebugXmlDump,	/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId 
xmlSecKeyDataPtrListGetKlass(void) {
    return(&xmlSecKeyDataPtrListKlass);
}

/**************************************************************************
 *
 * xmlSecKeyDataStore functions
 *
 *************************************************************************/
/**
 * xmlSecKeyDataStoreCreate:
 * @id: the store id.
 *
 * Creates new store of the specified type @id.
 *
 * Returns the pointer to newly allocated #xmlSecKeyDataStore structure
 * or NULL if an error occurs.
 */
xmlSecKeyDataStorePtr	
xmlSecKeyDataStoreCreate(xmlSecKeyDataStoreId id)  {
    xmlSecKeyDataStorePtr store;
    int ret;
        
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->objSize > 0, NULL);
        
    /* Allocate a new xmlSecKeyDataStore and fill the fields. */
    store = (xmlSecKeyDataStorePtr)xmlMalloc(id->objSize);
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", id->objSize); 
	return(NULL);
    }
    memset(store, 0, id->objSize);    
    store->id = id;

    if(id->initialize != NULL) {
	ret = (id->initialize)(store);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"id->initialize");
	    xmlSecKeyDataStoreDestroy(store);
	    return(NULL);
	}
    }
    
    return(store);
}

/**
 * xmlSecKeyDataStoreDestroy:
 * @store: the pointer to the #xmlSecKeyDataStore structure.
 *
 * Destroys the store and frees all allocated memory. 
 */
void
xmlSecKeyDataStoreDestroy(xmlSecKeyDataStorePtr store) {
    xmlSecAssert(xmlSecKeyDataStoreIsValid(store));    
    xmlSecAssert2(store->id->objSize > 0, NULL);
    
    if(store->id->finalize != NULL) {  
        (store->id->finalize)(store);
    }
    memset(store, 0, store->id->objSize);
    xmlFree(store);
}

int 
xmlSecKeyDataStoreFind(xmlSecKeyDataStorePtr store, xmlSecKeyPtr key, 
		       const xmlChar** params, size_t paramsSize,
		       xmlSecKeyInfoCtxPtr keyInfoCtx) {
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataStoreIsValid(store), -1);    
    xmlSecAssert2(store->id->find != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    ret = store->id->find(store, key, params, paramsSize, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->find");
	return(-1);	
    }
    return(ret);
}

/***********************************************************************
 *
 * Keys Data Store list
 *
 **********************************************************************/
static const struct _xmlSecPtrListKlass xmlSecKeyDataStorePtrListKlass = {
    NULL, 							/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecKeyDataStoreDestroy,	/* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,							/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,							/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

xmlSecPtrListId 
xmlSecKeyDataStorePtrListGetKlass(void) {
    return(&xmlSecKeyDataStorePtrListKlass);
}


