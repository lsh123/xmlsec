/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Keys.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>

/**************************************************************************
 *
 * xmlSecKeyReq - what key are we looking for?
 *
 *************************************************************************/
/** 
 * xmlSecKeyReqInitialize:
 * @keyReq:		the pointer to key requirements object.
 *
 * Initialize key requirements object. Caller is responsible for
 * cleaning it with #xmlSecKeyReqFinalize function.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecKeyReqInitialize(xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(keyReq != NULL, -1);
    
    memset(keyReq, 0, sizeof(xmlSecKeyReq));
    
    keyReq->keyUsage	= xmlSecKeyUsageAny;	/* by default you can do whatever you want with the key */
    return(0);
}

/**
 * xmlSecKeyReqFinalize:
 * @keyReq:		the pointer to key requirements object.
 *
 * Cleans the key requirements object initialized with #xmlSecKeyReqInitialize
 * function.
 */
void
xmlSecKeyReqFinalize(xmlSecKeyReqPtr keyReq) {
    xmlSecAssert(keyReq != NULL);
    
    xmlSecKeyReqReset(keyReq);
}

/** 
 * xmlSecKeyReqReset:
 * @keyReq:		the pointer to key requirements object.
 *
 * Resets key requirements object for new key search.
 */
void 
xmlSecKeyReqReset(xmlSecKeyReqPtr keyReq) {
    xmlSecAssert(keyReq != NULL);

    memset(keyReq, 0, sizeof(xmlSecKeyReq));
}

/**
 * xmlSecKeyReqCopy:
 * @dst:		the pointer to destination object.
 * @src:		the pointer to source object.
 *
 * Copies key requirements from @src object to @dst object.
 * 
 * Returns 0 on success and a negative value if an error occurs.
 */
int 
xmlSecKeyReqCopy(xmlSecKeyReqPtr dst, xmlSecKeyReqPtr src) {
    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(src != NULL, -1);

    memcpy(dst, src, sizeof(xmlSecKeyReq));
    return(0);
}

/**
 * xmlSecKeyReqMatchKey:
 * @keyReq:		the pointer to key requirements object.
 * @key:		the pointer to key.
 *
 * Checks whether @key matches key requirements @keyReq.
 *
 * Returns 1 if key matches requirements, 0 if not and a negative value
 * if an error occurs.
 */
int 
xmlSecKeyReqMatchKey(xmlSecKeyReqPtr keyReq, xmlSecKeyPtr key) {
    xmlSecAssert2(keyReq != NULL, -1);
    xmlSecAssert2(xmlSecKeyIsValid(key), -1);

    if((keyReq->keyType != xmlSecKeyDataTypeUnknown) && ((xmlSecKeyGetType(key) & keyReq->keyType) == 0)) {
	 return(0);
    }
    if((keyReq->keyUsage != xmlSecKeyDataUsageUnknown) && ((keyReq->keyUsage & key->usage) == 0)) {
	return(0);
    }

    return(xmlSecKeyReqMatchKeyValue(keyReq, xmlSecKeyGetValue(key)));
}

/**
 * xmlSecKeyReqMatchKeyValue:
 * @keyReq:		the pointer to key requirements.
 * @value:		the pointer to key value.
 *
 * Checks whether @keyValue matches key requirements @keyReq.
 *
 * Returns 1 if key value matches requirements, 0 if not and a negative value
 * if an error occurs.
 */
int 
xmlSecKeyReqMatchKeyValue(xmlSecKeyReqPtr keyReq, xmlSecKeyDataPtr value) {
    xmlSecAssert2(keyReq != NULL, -1);
    xmlSecAssert2(value != NULL, -1);
    
    if((keyReq->keyId != xmlSecKeyDataIdUnknown) && 
       (!xmlSecKeyDataCheckId(value, keyReq->keyId))) {

	return(0);
    }
    if((keyReq->keyBitsSize > 0) && 
       (xmlSecKeyDataGetSize(value) > 0) && 
       (xmlSecKeyDataGetSize(value) < keyReq->keyBitsSize)) {
	
	return(0);
    }
    return(1);
}

/**
 * xmlSecKeyCreate:
 *
 * Allocates and initializes new key. Caller is responsible for 
 * freeing returned object with #xmlSecKeyDestroy function.
 *
 * Returns the pointer to newly allocated @xmlSecKey structure
 * or NULL if an error occurs.
 */
xmlSecKeyPtr	
xmlSecKeyCreate(void)  {
    xmlSecKeyPtr key;
    
    /* Allocate a new xmlSecKey and fill the fields. */
    key = (xmlSecKeyPtr)xmlMalloc(sizeof(xmlSecKey));
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecKey)=%d", 
		    sizeof(xmlSecKey));
	return(NULL);
    }
    memset(key, 0, sizeof(xmlSecKey));    
    key->usage = xmlSecKeyUsageAny;	
    return(key);
}

/**
 * xmlSecKeyEmpty:
 * @key:		the pointer to key.
 *
 * Clears the @key data.
 */
void
xmlSecKeyEmpty(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);    
    
    if(key->value != NULL) {
	xmlSecKeyDataDestroy(key->value);
    }
    if(key->name != NULL) {
	xmlFree(key->name);
    }
    if(key->dataList != NULL) {
	xmlSecPtrListDestroy(key->dataList);
    }
    
    memset(key, 0, sizeof(xmlSecKey));
}

/**
 * xmlSecKeyDestroy:
 * @key: 		the pointer to key.
 *
 * Destroys the key created using #xmlSecKeyCreate function. 
 */
void
xmlSecKeyDestroy(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);    

    xmlSecKeyEmpty(key);
    xmlFree(key);
}

/** 
 * xmlSecKeyCopy:
 * @keyDst:		the destination key.
 * @keySrc:		the source key.
 *
 * Copies key data from @keySrc to @keyDst.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecKeyCopy(xmlSecKeyPtr keyDst, xmlSecKeyPtr keySrc) {
    xmlSecAssert2(keyDst != NULL, -1);    
    xmlSecAssert2(keySrc != NULL, -1);    
    
    /* empty destination */
    xmlSecKeyEmpty(keyDst);

    /* copy everything */    
    if(keySrc->name != NULL) {
	keyDst->name = xmlStrdup(keySrc->name);
	if(keyDst->name == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			NULL,
		        XMLSEC_ERRORS_R_STRDUP_FAILED,
			"len=%d", xmlStrlen(keySrc->name));
	    return(-1);	
        }
    }

    if(keySrc->value != NULL) {
	keyDst->value = xmlSecKeyDataDuplicate(keySrc->value);
	if(keyDst->value == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyDataDuplicate",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);	
        }
    }
    
    if(keySrc->dataList != NULL) {
	keyDst->dataList = xmlSecPtrListDuplicate(keySrc->dataList);
	if(keyDst->dataList == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecPtrListDuplicate",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
        }
    }
    
    keyDst->usage 	   = keySrc->usage;
    keyDst->notValidBefore = keySrc->notValidBefore;
    keyDst->notValidAfter  = keySrc->notValidAfter;
    return(0);
}

/**
 * xmlSecKeyDuplicate:
 * @key: 		the pointer to the #xmlSecKey structure.
 *
 * Creates a duplicate of the given @key.
 *
 * Returns the pointer to newly allocated #xmlSecKey structure
 * or NULL if an error occurs.
 */
xmlSecKeyPtr	
xmlSecKeyDuplicate(xmlSecKeyPtr key) {
    xmlSecKeyPtr newKey;
    int ret;
    
    xmlSecAssert2(key != NULL, NULL);
    
    newKey = xmlSecKeyCreate();
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    ret = xmlSecKeyCopy(newKey, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyCopy",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDestroy(newKey);
	return(NULL);	
    }
    
    return(newKey);
}

/**
 * xmlSecKeyMatch:
 * @key: 		the pointer to key.
 * @name: 		the pointer to key name (may be NULL).
 * @keyReq:		the pointer to key requirements.
 * 
 * Checks whether the @key matches the given criteria.
 *
 * Returns 1 if the key satisfies the given criteria or 0 otherwise.
 */
int
xmlSecKeyMatch(xmlSecKeyPtr key, const xmlChar *name, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecKeyIsValid(key), -1);
    xmlSecAssert2(keyReq != NULL, -1);
    
    if((name != NULL) && (!xmlStrEqual(xmlSecKeyGetName(key), name))) {
	return(0);
    }
    return(xmlSecKeyReqMatchKey(keyReq, key));
}

/** 
 * xmlSecKeyGetType:
 * @key:		the pointer to key.
 *
 * Gets @key type.
 *
 * Returns key type.
 */
xmlSecKeyDataType 
xmlSecKeyGetType(xmlSecKeyPtr key) {
    xmlSecKeyDataPtr data;
    
    xmlSecAssert2(key != NULL, xmlSecKeyDataTypeUnknown);

    data = xmlSecKeyGetValue(key);
    if(data == NULL) {
	return(xmlSecKeyDataTypeUnknown);
    }
    return(xmlSecKeyDataGetType(data));
}

/** 
 * xmlSecKeyGetName:
 * @key:		the pointer to key.
 *
 * Gets key name (see also #xmlSecKeySetName function).
 *
 * Returns key name.
 */
const xmlChar*	
xmlSecKeyGetName(xmlSecKeyPtr key) {
    xmlSecAssert2(key != NULL, NULL);

    return(key->name);
}

/** 
 * xmlSecKeySetName:
 * @key:		the pointer to key.
 * @name:		the new key name.
 *
 * Sets key name (see also #xmlSecKeyGetName function).
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecKeySetName(xmlSecKeyPtr key, const xmlChar* name) {
    xmlSecAssert2(key != NULL, -1);

    if(key->name != NULL) {
	xmlFree(key->name);
	key->name = NULL;
    }
    
    if(name != NULL) {
	key->name = xmlStrdup(name);
	if(key->name == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			NULL,
		        XMLSEC_ERRORS_R_STRDUP_FAILED,
			"len=%d", xmlStrlen(name));
	    return(-1);	    
	}	
    }
    
    return(0);
}

/** 
 * xmlSecKeyGetValue:
 * @key:		the pointer to key.
 *
 * Gets key value (see also #xmlSecKeySetValue function).
 *
 * Returns key value (crypto material).
 */
xmlSecKeyDataPtr 
xmlSecKeyGetValue(xmlSecKeyPtr key) {
    xmlSecAssert2(key != NULL, NULL);

    return(key->value);
}

/** 
 * xmlSecKeySetValue:
 * @key:		the pointer to key.
 * @value:		the new value.
 *
 * Sets key value (see also #xmlSecKeyGetValue function).
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecKeySetValue(xmlSecKeyPtr key, xmlSecKeyDataPtr value) {
    xmlSecAssert2(key != NULL, -1);

    if(key->value != NULL) {
	xmlSecKeyDataDestroy(key->value);
	key->value = NULL;
    }
    key->value = value;
    
    return(0);
}

/** 
 * xmlSecKeyGetData:
 * @key:		the pointer to key.
 * @dataId:		the requested data klass.
 *
 * Gets key's data.
 *
 * Returns additional data associated with the @key (see also 
 * #xmlSecKeyAdoptData function).
 */
xmlSecKeyDataPtr 
xmlSecKeyGetData(xmlSecKeyPtr key, xmlSecKeyDataId dataId) {
    
    xmlSecAssert2(key != NULL, NULL);
    xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, NULL);

    /* special cases */
    if(dataId == xmlSecKeyDataValueId) {
	return(key->value);
    } else if(key->dataList != NULL) {
	xmlSecKeyDataPtr tmp;
	xmlSecSize pos, size;
	
	size = xmlSecPtrListGetSize(key->dataList);
	for(pos = 0; pos < size; ++pos) {
	    tmp = (xmlSecKeyDataPtr)xmlSecPtrListGetItem(key->dataList, pos);
	    if((tmp != NULL) && (tmp->id == dataId)) {	
		return(tmp);
	    }
	}
    }
    return(NULL);
}

/**
 * xmlSecKeyEnsureData:
 * @key:		the pointer to key.
 * @dataId:		the requested data klass.
 * 
 * If necessary, creates key data of @dataId klass and adds to @key.
 *
 * Returns pointer to key data or NULL if an error occurs.
 */
xmlSecKeyDataPtr 
xmlSecKeyEnsureData(xmlSecKeyPtr key, xmlSecKeyDataId dataId) {
    xmlSecKeyDataPtr data;
    int ret;
        
    xmlSecAssert2(key != NULL, NULL);
    xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, NULL);

    data = xmlSecKeyGetData(key, dataId);
    if(data != NULL) {
	return(data);
    }
    
    data = xmlSecKeyDataCreate(dataId);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "dataId=%s", 
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)));
	return(NULL);
    }
	
    ret = xmlSecKeyAdoptData(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyAdoptData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "dataId=%s", 
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)));
	xmlSecKeyDataDestroy(data);
	return(NULL);
    }
    
    return(data);
}

/**
 * xmlSecKeyAdoptData:
 * @key:		the pointer to key.
 * @data:		the pointer to key data.
 *
 * Adds @data to the @key. The @data object will be destroyed
 * by @key.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecKeyAdoptData(xmlSecKeyPtr key, xmlSecKeyDataPtr data) {
    xmlSecKeyDataPtr tmp;
    xmlSecSize pos, size;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);

    /* special cases */
    if(data->id == xmlSecKeyDataValueId) {
	if(key->value != NULL) {
	    xmlSecKeyDataDestroy(key->value);
	}
	key->value = data;
	return(0);
    }
    
    if(key->dataList == NULL) {
	key->dataList = xmlSecPtrListCreate(xmlSecKeyDataListId);
	if(key->dataList == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecPtrListCreate",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }

	
    size = xmlSecPtrListGetSize(key->dataList);
    for(pos = 0; pos < size; ++pos) {
	tmp = (xmlSecKeyDataPtr)xmlSecPtrListGetItem(key->dataList, pos);
	if((tmp != NULL) && (tmp->id == data->id)) {	
	    return(xmlSecPtrListSet(key->dataList, data, pos));
	}
    }
    
    return(xmlSecPtrListAdd(key->dataList, data));
}

/** 
 * xmlSecKeyDebugDump:
 * @key:		the pointer to key.
 * @output: 		the pointer to output FILE.
 *
 * Prints the information about the @key to the @output.
 */
void
xmlSecKeyDebugDump(xmlSecKeyPtr key, FILE *output) {
    xmlSecAssert(xmlSecKeyIsValid(key));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "== KEY\n");
    fprintf(output, "=== method: %s\n", 
	    (key->value->id->dataNodeName != NULL) ? 
	    (char*)(key->value->id->dataNodeName) : "NULL"); 

    fprintf(output, "=== key type: ");
    if((xmlSecKeyGetType(key) & xmlSecKeyDataTypeSymmetric) != 0) {
	fprintf(output, "Symmetric\n");
    } else if((xmlSecKeyGetType(key) & xmlSecKeyDataTypePrivate) != 0) {
	fprintf(output, "Private\n");
    } else if((xmlSecKeyGetType(key) & xmlSecKeyDataTypePublic) != 0) {
	fprintf(output, "Public\n");
    } else {
	fprintf(output, "Unknown\n");
    } 

    if(key->name != NULL) {
	fprintf(output, "=== key name: %s\n", key->name);
    }
    fprintf(output, "=== key usage: %d\n", key->usage);
    if(key->notValidBefore < key->notValidAfter) {
        fprintf(output, "=== key not valid before: %ld\n", (unsigned long)key->notValidBefore);
	fprintf(output, "=== key not valid after: %ld\n", (unsigned long)key->notValidAfter);
    }
    if(key->value != NULL) {
	xmlSecKeyDataDebugDump(key->value, output);
    }
    if(key->dataList != NULL) {
	xmlSecPtrListDebugDump(key->dataList, output);
    }
}

/** 
 * xmlSecKeyDebugXmlDump:
 * @key:		the pointer to key.
 * @output: 		the pointer to output FILE.
 *
 * Prints the information about the @key to the @output in XML format.
 */
void
xmlSecKeyDebugXmlDump(xmlSecKeyPtr key, FILE *output) {
    xmlSecAssert(xmlSecKeyIsValid(key));
    xmlSecAssert(output != NULL);
    
    fprintf(output, "<KeyInfo>\n");
    if(key->value->id->dataNodeName != NULL) {
        fprintf(output, "<KeyMethod>%s</KeyMethod>\n", 
		key->value->id->dataNodeName); 
    }

    fprintf(output, "<KeyType>");
    if((xmlSecKeyGetType(key) & xmlSecKeyDataTypeSymmetric) != 0) {
	fprintf(output, "Symmetric\n");
    } else if((xmlSecKeyGetType(key) & xmlSecKeyDataTypePrivate) != 0) {
	fprintf(output, "Private\n");
    } else if((xmlSecKeyGetType(key) & xmlSecKeyDataTypePublic) != 0) {
	fprintf(output, "Public\n");
    } else {
	fprintf(output, "Unknown\n");
    } 
    fprintf(output, "</KeyType>\n");

    if(key->name != NULL) {
	fprintf(output, "<KeyName>%s</KeyName>\n", key->name);
    }
    if(key->notValidBefore < key->notValidAfter) {
        fprintf(output, "<KeyValidity notValidBefore=\"%ld\" notValidAfter=\"%ld\"/>\n",
		(unsigned long)key->notValidBefore, 
		(unsigned long)key->notValidAfter);
    }

    if(key->value != NULL) {
	xmlSecKeyDataDebugXmlDump(key->value, output);
    }
    if(key->dataList != NULL) {
	xmlSecPtrListDebugXmlDump(key->dataList, output);
    }

    fprintf(output, "</KeyInfo>\n"); 
}

/** 
 * xmlSecKeyGenerate:
 * @dataId:		the requested key klass (rsa, dsa, aes, ...).
 * @sizeBits:		the new key size (in bits!).
 * @type:		the new key type (session, permanent, ...).
 *
 * Generates new key of requested klass @dataId and @type.
 *
 * Returns pointer to newly created key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecKeyGenerate(xmlSecKeyDataId dataId, xmlSecSize sizeBits, xmlSecKeyDataType type) {
    xmlSecKeyPtr key;
    xmlSecKeyDataPtr data;
    int ret;

    xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, NULL);
    
    data = xmlSecKeyDataCreate(dataId);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);    
    }

    ret = xmlSecKeyDataGenerate(data, sizeBits, type);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeyDataGenerate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d;type=%d", sizeBits, type);
	xmlSecKeyDataDestroy(data);
	return(NULL);    
    }
        
    key = xmlSecKeyCreate();
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeyCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	return(NULL);    
    }
    
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeySetValue",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDataDestroy(data);
	xmlSecKeyDestroy(key);
	return(NULL);    
    }
    
    return(key);
}

/** 
 * xmlSecKeyGenerateByName:
 * @name:		the requested key klass name (rsa, dsa, aes, ...).
 * @sizeBits:		the new key size (in bits!).
 * @type:		the new key type (session, permanent, ...).
 *
 * Generates new key of requested @klass and @type.
 *
 * Returns pointer to newly created key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecKeyGenerateByName(const xmlChar* name, xmlSecSize sizeBits, xmlSecKeyDataType type) {
    xmlSecKeyDataId dataId;

    xmlSecAssert2(name != NULL, NULL);
    
    dataId = xmlSecKeyDataIdListFindByName(xmlSecKeyDataIdsGet(), name, xmlSecKeyDataUsageAny);
    if(dataId == xmlSecKeyDataIdUnknown) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(name),
		    XMLSEC_ERRORS_R_KEY_DATA_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);    
    }
    
    return(xmlSecKeyGenerate(dataId, sizeBits, type));
}

/**
 * xmlSecKeyReadBuffer:
 * @dataId:		the key value data klass.
 * @buffer:		the buffer that contains the binary data.
 *
 * Reads the key value of klass @dataId from a buffer.
 *
 * Returns pointer to newly created key or NULL if an error occurs.
 */
xmlSecKeyPtr 
xmlSecKeyReadBuffer(xmlSecKeyDataId dataId, xmlSecBuffer* buffer) {
    xmlSecKeyInfoCtx keyInfoCtx;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, NULL);
    xmlSecAssert2(buffer != NULL, NULL);

    /* create key data */
    key = xmlSecKeyCreate();
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeyCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);    
    }

    ret = xmlSecKeyInfoCtxInitialize(&keyInfoCtx, NULL);    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeyInfoCtxInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDestroy(key);
	return(NULL);    
    }
    
    keyInfoCtx.keyReq.keyType = xmlSecKeyDataTypeAny;
    ret = xmlSecKeyDataBinRead(dataId, key, 
			xmlSecBufferGetData(buffer),
			xmlSecBufferGetSize(buffer),
			&keyInfoCtx);	
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeyDataBinRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
	xmlSecKeyDestroy(key);
	return(NULL);    
    }
    xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
    
    return(key);
}

/**
 * xmlSecKeyReadBinaryFile:
 * @dataId:		the key value data klass.
 * @filename:		the key binary filename.
 *
 * Reads the key value of klass @dataId from a binary file @filename.
 *
 * Returns pointer to newly created key or NULL if an error occurs.
 */
xmlSecKeyPtr 
xmlSecKeyReadBinaryFile(xmlSecKeyDataId dataId, const char* filename) {
    xmlSecKeyPtr key;
    xmlSecBuffer buffer;
    int ret;
    
    xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, NULL);
    xmlSecAssert2(filename != NULL, NULL);

    /* read file to buffer */
    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecBufferReadFile",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s", 
		    xmlSecErrorsSafeString(filename));
	xmlSecBufferFinalize(&buffer);
	return(NULL);
    }

    key = xmlSecKeyReadBuffer(dataId, &buffer);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeyReadBuffer",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "filename=%s", 
		    xmlSecErrorsSafeString(filename));
	xmlSecBufferFinalize(&buffer);
	return(NULL);	
    }

    xmlSecBufferFinalize(&buffer);
    return (key);
}

/**
 * xmlSecKeyReadMemory:
 * @dataId:		the key value data klass.
 * @data:		the memory containing the key
 * @dataSize: 		the size of the memory block
 *
 * Reads the key value of klass @dataId from a memory block @data.
 *
 * Returns pointer to newly created key or NULL if an error occurs.
 */
xmlSecKeyPtr 
xmlSecKeyReadMemory(xmlSecKeyDataId dataId, const xmlSecByte* data, xmlSecSize dataSize) {
    xmlSecBuffer buffer;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, NULL);
    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

    /* read file to buffer */
    ret = xmlSecBufferInitialize(&buffer, 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }

    if (xmlSecBufferAppend(&buffer, data, dataSize) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecBufferAppend",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferFinalize(&buffer);
	return(NULL);	
    }

    key = xmlSecKeyReadBuffer(dataId, &buffer);
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeyReadBuffer",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferFinalize(&buffer);
	return(NULL);	
    }

    xmlSecBufferFinalize(&buffer);
    return (key);
}

/**
 * xmlSecKeysMngrGetKey:
 * @keyInfoNode: 	the pointer to <dsig:KeyInfo/> node.
 * @keyInfoCtx: 	the pointer to <dsig:KeyInfo/> node processing context.	
 * 
 * Reads the <dsig:KeyInfo/> node @keyInfoNode and extracts the key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
xmlSecKeyPtr 		
xmlSecKeysMngrGetKey(xmlNodePtr keyInfoNode, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyPtr key;
    int ret;
    
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    
    /* first try to read data from <dsig:KeyInfo/> node */
    key = xmlSecKeyCreate();
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecKeyCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    if(keyInfoNode != NULL) {
	ret = xmlSecKeyInfoNodeRead(keyInfoNode, key, keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyInfoNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(keyInfoNode)));
	    xmlSecKeyDestroy(key);
	    return(NULL);
	}

	if((xmlSecKeyGetValue(key) != NULL) &&
           (xmlSecKeyMatch(key, NULL, &(keyInfoCtx->keyReq)) != 0)) {
            return(key);
        }
    }	
    xmlSecKeyDestroy(key);
    
    /* if we have keys manager, try it */
    if(keyInfoCtx->keysMngr != NULL) {
	key = xmlSecKeysMngrFindKey(keyInfoCtx->keysMngr, NULL, keyInfoCtx);
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeysMngrFindKey",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(NULL);
	}
	if(xmlSecKeyGetValue(key) != NULL) {
	    return(key);
	}
	xmlSecKeyDestroy(key);
    }
    
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		NULL,
		XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		XMLSEC_ERRORS_NO_MESSAGE);    
    return(NULL);
}

/***********************************************************************
 *
 * Keys list
 *
 **********************************************************************/
static xmlSecPtrListKlass xmlSecKeyPtrListKlass = {
    BAD_CAST "keys-list",
    (xmlSecPtrDuplicateItemMethod)xmlSecKeyDuplicate, 	/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecKeyDestroy,	/* xmlSecPtrDestroyItemMethod destroyItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecKeyDebugDump,	/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    (xmlSecPtrDebugDumpItemMethod)xmlSecKeyDebugXmlDump,/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

/**
 * xmlSecKeyPtrListGetKlass: 
 *
 * The keys list klass.
 *
 * Returns keys list id.
 */
xmlSecPtrListId 
xmlSecKeyPtrListGetKlass(void) {
    return(&xmlSecKeyPtrListKlass);
}

