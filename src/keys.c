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
int 
xmlSecKeyReqInitialize(xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(keyReq != NULL, -1);
    
    memset(keyReq, 0, sizeof(xmlSecKeyReq));
    
    keyReq->keyUsage	= xmlSecKeyUsageAny;	/* by default you can do whatever you want with the key */
    return(0);
}

void
xmlSecKeyReqFinalize(xmlSecKeyReqPtr keyReq) {
    xmlSecAssert(keyReq != NULL);

    memset(keyReq, 0, sizeof(xmlSecKeyReq));
}

int 
xmlSecKeyReqCopy(xmlSecKeyReqPtr dst, xmlSecKeyReqPtr src) {
    xmlSecAssert2(dst != NULL, -1);
    xmlSecAssert2(src != NULL, -1);

    memcpy(dst, src, sizeof(xmlSecKeyReq));
    return(0);
}

int 
xmlSecKeyReqMatchKey(xmlSecKeyReqPtr keyReq, xmlSecKeyPtr key) {
    xmlSecAssert2(keyReq != NULL, -1);
    xmlSecAssert2(xmlSecKeyIsValid(key), -1);

    if((xmlSecKeyGetType(key) & keyReq->keyType) == 0) {
	 return(0);
    }
    if((keyReq->keyUsage & key->usage) == 0) {
	return(0);
    }

    return(xmlSecKeyReqMatchKeyValue(keyReq, xmlSecKeyGetValue(key)));
}

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
 * Creates new key of the specified type @id.
 *
 * Returns the pointer to newly allocated #xmlSecKey structure
 * or NULL if an error occurs.
 */
xmlSecKeyPtr	
xmlSecKeyCreate(void)  {
    xmlSecKeyPtr key;
    
    /* Allocate a new xmlSecKey and fill the fields. */
    key = (xmlSecKeyPtr)xmlMalloc(sizeof(xmlSecKey));
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecKey",
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecKey)=%d", 
		    sizeof(xmlSecKey));
	return(NULL);
    }
    memset(key, 0, sizeof(xmlSecKey));    
    key->usage = xmlSecKeyUsageAny;	
    return(key);
}

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
 * @key: the pointer to the #xmlSecKey structure.
 *
 * Destroys the key and frees all allocated memory. 
 */
void
xmlSecKeyDestroy(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);    

    xmlSecKeyEmpty(key);
    xmlFree(key);
}

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
			"xmlSecKey",
			"xmlStrdup",
		        XMLSEC_ERRORS_R_MALLOC_FAILED,
			"len=%d", xmlStrlen(keySrc->name));
	    return(-1);	
        }
    }

    if(keySrc->value != NULL) {
	keyDst->value = xmlSecKeyDataDuplicate(keySrc->value);
	if(keyDst->value == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			"xmlSecKey",
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
			"xmlSecKey",
			"xmlSecPtrListDuplicate",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
        }
    }
    
    keyDst->usage = keySrc->usage;
    return(0);
}

/**
 * xmlSecKeyDuplicate:
 * @key: the pointer to the #xmlSecKey structure.
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
		    "xmlSecKey",
		    "xmlSecKeyCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);	
    }
    
    ret = xmlSecKeyCopy(newKey, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecKey",
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
 * @key: the pointer to the #xmlSecKey structure.
 * @name: the pointer to key name (may be NULL).
 * 
 * Checks whether the @key matches the given criteria
 * (key name is equal to @name, key id is equal to @id,
 * key type is @type).
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

const xmlChar*	
xmlSecKeyGetName(xmlSecKeyPtr key) {
    xmlSecAssert2(key != NULL, NULL);

    return(key->name);
}

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
			"xmlSecKey",
			"xmlStrdup",
		        XMLSEC_ERRORS_R_MALLOC_FAILED,
			"%d", xmlStrlen(name));
	    return(-1);	    
	}	
    }
    
    return(0);
}

xmlSecKeyDataPtr 
xmlSecKeyGetValue(xmlSecKeyPtr key) {
    xmlSecAssert2(key != NULL, NULL);

    return(key->value);
}

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

xmlSecKeyDataPtr 
xmlSecKeyGetData(xmlSecKeyPtr key, xmlSecKeyDataId dataId) {
    
    xmlSecAssert2(key != NULL, NULL);
    xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, NULL);

    /* special cases */
    if(dataId == xmlSecKeyDataValueId) {
	return(key->value);
    } else if(key->dataList != NULL) {
	xmlSecKeyDataPtr tmp;
	size_t pos, size;
	
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
		    "xmlSecKey",
		    "xmlSecKeyDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s", 
		    dataId->name);
	return(NULL);
    }
	
    ret = xmlSecKeyAdoptData(key, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecKey",
		    "xmlSecKeyAdoptData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%s",
		    dataId->name);
	xmlSecKeyDataDestroy(data);
	return(NULL);
    }
    
    return(data);
}

int 
xmlSecKeyAdoptData(xmlSecKeyPtr key, xmlSecKeyDataPtr data) {
    xmlSecKeyDataPtr tmp;
    size_t pos, size;
    
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
			"xmlSecKey",
			"xmlSecPtrListCreate",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataListId");
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
 * @key: the pointer to the #xmlSecKey structure.
 * @output: the destination #FILE pointer.
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
	fprintf(output, "=== keys name: %s\n", key->name);
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
 * @key: the pointer to the #xmlSecKey structure.
 * @output: the destination #FILE pointer.
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

    if(key->value != NULL) {
	xmlSecKeyDataDebugXmlDump(key->value, output);
    }
    if(key->dataList != NULL) {
	xmlSecPtrListDebugXmlDump(key->dataList, output);
    }

    fprintf(output, "</KeyInfo>\n"); 
}

xmlSecKeyPtr
xmlSecKeyGenerate(const xmlChar* klass, const xmlChar* name, size_t sizeBits, xmlSecKeyDataType type) {
    xmlSecKeyPtr key;
    xmlSecKeyDataPtr data;
    xmlSecKeyDataId dataId;
    int ret;
    
    xmlSecAssert2(klass != NULL, NULL);
    
    dataId = xmlSecKeyDataIdListFindByName(xmlSecKeyDataIdsGet(), klass, xmlSecKeyDataUsageAny);
    if(dataId == xmlSecKeyDataIdUnknown) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecKey",
		    "xmlSecKeyDataIdListFindByName",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "klass=%s", klass);
	return(NULL);    
    }
    
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
    
    ret = xmlSecKeySetName(key, name);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(dataId)),
		    "xmlSecKeySetName",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecKeyDestroy(key);
	return(NULL);    
    }
    
    return(key);
}

/**
 * xmlSecKeysMngrGetKey:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @keyInfoCtx: 
 * 
 * Reads the <dsig:KeyInfo> node @keyInfoNode and extracts the key.
 *
 * Returns the pointer to key or NULL if the key is not found or 
 * an error occurs.
 */
xmlSecKeyPtr 		
xmlSecKeysMngrGetKey(xmlNodePtr keyInfoNode, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyPtr key = NULL;
    int ret;
    
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

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
			xmlSecNodeGetName(keyInfoNode),
			"xmlSecKeyInfoNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyDestroy(key);
	    return(NULL);
	}
	if(xmlSecKeyGetValue(key) != NULL) {
	    return(key);
	}
    }	
    
    if(keyInfoCtx->keysMngr != NULL) {
	ret = xmlSecKeysMngrFindKey(keyInfoCtx->keysMngr, key, NULL, keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeysMngrFindKey",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyDestroy(key);
	    return(NULL);
	}
	if(xmlSecKeyGetValue(key) != NULL) {
	    return(key);
	}
    }
    
    xmlSecKeyDestroy(key);
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

xmlSecPtrListId 
xmlSecKeyPtrListGetKlass(void) {
    return(&xmlSecKeyPtrListKlass);
}

