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
#include <errno.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/errors.h>

/****************************************************************************
 *
 * Keys Manager
 *
 ***************************************************************************/
xmlSecKeysMngrPtr 
xmlSecKeysMngrCreate(void) {
    xmlSecKeysMngrPtr mngr;

    /* Allocate a new xmlSecKeysMngr and fill the fields. */
    mngr = (xmlSecKeysMngrPtr)xmlMalloc(sizeof(xmlSecKeysMngr));
    if(mngr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecKeysMngr)=%d", 
		    sizeof(xmlSecKeysMngr));
	return(NULL);
    }
    memset(mngr, 0, sizeof(xmlSecKeysMngr));    
    return(mngr);    
}

void
xmlSecKeysMngrDestroy(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert(mngr != NULL);

    /* destroy keys store */
    if(mngr->keysStore != NULL) {
	xmlSecKeyDataStoreDestroy(mngr->keysStore);
    }
    
    /* destroy other data stores */
    if(mngr->storesList != NULL) {
	xmlSecPtrListDestroy(mngr->storesList);
    }

    memset(mngr, 0, sizeof(xmlSecKeysMngr));    
    xmlFree(mngr);    
}

int
xmlSecKeysMngrFindKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key, const xmlChar* name, 
		     xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr store;
    const xmlChar* params[1];
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    
    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
	/* no store. is it an error? */
	return(0);
    }
    
    params[0] = name;
    ret = xmlSecKeyDataStoreFind(store, key, params, 1, keyInfoCtx);
    if(ret < 0) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataStoreFind");
	return(-1);
    }
    
    return(0);    
}

int	
xmlSecKeysMngrFindKeyData(xmlSecKeysMngrPtr mngr, xmlSecKeyDataStoreId storeId,
			xmlSecKeyPtr key, const xmlChar** params, size_t paramsSize,
			xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr store;
    int ret;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(storeId != xmlSecKeyDataStoreIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    
    store = xmlSecKeysMngrGetDataStore(mngr, storeId);
    if(store == NULL) {
	/* no store. is it an error? */
	return(0);
    }
    
    ret = xmlSecKeyDataStoreFind(store, key, params, paramsSize, keyInfoCtx);
    if(ret < 0) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataStoreFind");
	return(-1);
    }
    
    return(0);    
}

int
xmlSecKeysMngrAdoptKeysStore(xmlSecKeysMngrPtr mngr, xmlSecKeyDataStorePtr store) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataStoreIsValid(store), -1);
    
    if(mngr->keysStore != NULL) {
	xmlSecKeyDataStoreDestroy(mngr->keysStore);
    }
    mngr->keysStore = store;
    
    return(0);
}

xmlSecKeyDataStorePtr
xmlSecKeysMngrGetKeysStore(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, NULL);
    
    return(mngr->keysStore);
}

int
xmlSecKeysMngrAdoptDataStore(xmlSecKeysMngrPtr mngr, xmlSecKeyDataStorePtr store) {
    xmlSecKeyDataStorePtr keysStore;
    xmlSecKeyDataStorePtr tmp;
    size_t pos, size;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataStoreIsValid(store), -1);

    /* special case */
    keysStore = xmlSecKeysMngrGetKeysStore(mngr);
    if((keysStore != NULL) && (keysStore->id == store->id)) {
	return(xmlSecKeysMngrAdoptKeysStore(mngr, store));
    }

    if(mngr->storesList == NULL) {
	mngr->storesList = xmlSecPtrListCreate(xmlSecKeyDataStorePtrListId);
	if(mngr->storesList == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecPtrListCreate(xmlSecKeyDataStorePtrListId)");
	    return(-1);
	}
    }

    size = xmlSecPtrListGetSize(mngr->storesList);
    for(pos = 0; pos < size; ++pos) {
	tmp = (xmlSecKeyDataStorePtr)xmlSecPtrListGetItem(mngr->storesList, pos);
	if((tmp != NULL) && (tmp->id == store->id)) {	
	    return(xmlSecPtrListSet(mngr->storesList, store, pos));
	}
    }
    
    return(xmlSecPtrListAdd(mngr->storesList, store));
}

xmlSecKeyDataStorePtr 
xmlSecKeysMngrGetDataStore(xmlSecKeysMngrPtr mngr, xmlSecKeyDataStoreId id) {
    xmlSecKeyDataStorePtr keysStore;
    
    xmlSecAssert2(mngr != NULL, NULL);
    xmlSecAssert2(id != xmlSecKeyDataStoreIdUnknown, NULL);

    /* special case */
    keysStore = xmlSecKeysMngrGetKeysStore(mngr);
    if((keysStore != NULL) && (keysStore->id == id)) {
	return(keysStore);
    } else if(mngr->storesList != NULL) {
	xmlSecKeyDataStorePtr tmp;
	size_t pos, size;
	
	size = xmlSecPtrListGetSize(mngr->storesList);
	for(pos = 0; pos < size; ++pos) {
	    tmp = (xmlSecKeyDataStorePtr)xmlSecPtrListGetItem(mngr->storesList, pos);
	    if((tmp != NULL) && (tmp->id == id)) {	
		return(tmp);
	    }
	}
    }
    
    return(NULL);
}

/****************************************************************************
 *
 * Simple Keys Store
 *
 ***************************************************************************/
static int			xmlSecSimpleKeysStoreInitialize	(xmlSecKeyDataStorePtr store);
static void			xmlSecSimpleKeysStoreFinalize	(xmlSecKeyDataStorePtr store);
static int			xmlSecSimpleKeysStoreFind	(xmlSecKeyDataStorePtr store,
								 xmlSecKeyPtr key,
								 const xmlChar** params,
								 size_t paramsSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataStoreKlass xmlSecSimpleKeysStoreKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    BAD_CAST "simple-keys-store",	/* const xmlChar* name; */ 
        
    /* constructors/destructor */
    xmlSecSimpleKeysStoreInitialize,	/* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecSimpleKeysStoreFinalize,	/* xmlSecKeyDataStoreFinalizeMethod finalize; */
    xmlSecSimpleKeysStoreFind,		/* xmlSecKeyDataStoreFindMethod find; */
};

/*
 * mapping: 
 * xmlSecKeysDataStore::reserved0 --> xmlSecKeyPtrList
 */
#define xmlSecSimpleKeysStoreGetList(store) ((xmlSecPtrListPtr)(store)->reserved0)
 
xmlSecKeyDataStoreId 
xmlSecSimpleKeysStoreGetKlass(void) {
    return(&xmlSecSimpleKeysStoreKlass);
}

int 
xmlSecSimpleKeysStoreAdoptKey(xmlSecKeyDataStorePtr store, xmlSecKeyPtr key) {
    xmlSecPtrListPtr list;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);
    xmlSecAssert2(key != NULL, -1);

    list = xmlSecSimpleKeysStoreGetList(store);
    if(list == NULL) {
	list = xmlSecPtrListCreate(xmlSecKeyPtrListId);
	if(list == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecPtrListCreate(xmlSecKeyPtrListId)");
	    return(-1);
	}
	store->reserved0 = list;
    }

    ret = xmlSecPtrListAdd(list, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecPtrListAdd");
	return(-1);
    }

    return(0);
}

xmlSecKeyPtr 
xmlSecSimpleKeysStoreFindKey(xmlSecKeyDataStorePtr store, const xmlChar* name, 
			    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecPtrListPtr list;
    xmlSecKeyPtr key;
    size_t pos, size;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecSimpleKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    list = xmlSecSimpleKeysStoreGetList(store);
    if(list == NULL) {
	/* we have nothing in the list */
	return(NULL);
    }
    
    size = xmlSecPtrListGetSize(list);
    for(pos = 0; pos < size; ++pos) {
	key = (xmlSecKeyPtr)xmlSecPtrListGetItem(list, pos);
	if((key != NULL) && (xmlSecKeyVerify(key, name, keyInfoCtx->keyId, keyInfoCtx->keyType) == 1)) {
	    return(key);
	}
    }
    return(NULL);
}

int
xmlSecSimpleKeysStoreLoad(xmlSecKeyDataStorePtr store, const char *uri) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlSecKeyPtr key;
    xmlSecKeyInfoCtx keyInfoCtx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);
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
    
    memset(&keyInfoCtx, 0, sizeof(keyInfoCtx));
    keyInfoCtx.keyId 		= xmlSecKeyDataIdUnknown;
    keyInfoCtx.keyType		= xmlSecKeyDataTypeAny;
    keyInfoCtx.keyUsage 	= xmlSecKeyDataUsageAny;
    keyInfoCtx.retrievalsLevel 	= 0;
    keyInfoCtx.encKeysLevel 	= 1;
    
    cur = xmlSecGetNextElementNode(root->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecDSigNs)) {  
	key = xmlSecKeyCreate();
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyCreate");
	    xmlFreeDoc(doc);
	    return(-1);
	}

	ret = xmlSecKeyInfoNodeRead(cur, key, &keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyInfoNodeRead");
	    xmlSecKeyDestroy(key);
	    xmlFreeDoc(doc);
	    return(-1);
	}
	
	ret = xmlSecSimpleKeysStoreAdoptKey(store, key);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecSimpleKeysStoreAdoptKey");
	    xmlSecKeyDestroy(key);
	    xmlFreeDoc(doc);
	    return(-1);
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

int
xmlSecSimpleKeysStoreSave(xmlSecKeyDataStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecKeyInfoCtx keyInfoCtx;
    xmlSecPtrListPtr list;
    xmlSecKeyPtr key;
    size_t i, keysSize;    
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlSecKeyDataId dataId;
    xmlSecKeyDataPtr data;
    size_t idsSize, j;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);
    xmlSecAssert2(filename != NULL, -1);    

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
    
    
    memset(&keyInfoCtx, 0, sizeof(keyInfoCtx));
    keyInfoCtx.keyId 		= xmlSecKeyDataIdUnknown;
    keyInfoCtx.keyType		= type;
    keyInfoCtx.keyUsage 	= xmlSecKeyDataUsageAny;
    keyInfoCtx.retrievalsLevel 	= 0;
    keyInfoCtx.encKeysLevel 	= 1;

    list = xmlSecSimpleKeysStoreGetList(store);
    if(list != NULL) {
        keysSize = xmlSecPtrListGetSize(list);
	idsSize = xmlSecKeyDataIdsGetSize();
	for(i = 0; i < keysSize; ++i) {
	    key = (xmlSecKeyPtr)xmlSecPtrListGetItem(list, i);
	    xmlSecAssert2(key != NULL, -1);
	    
    	    cur = xmlSecAddChild(root, BAD_CAST "KeyInfo", xmlSecDSigNs);
	    if(cur == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecAddChild(\"KeyInfo\")");
	        xmlFreeDoc(doc); 
		return(-1);
	    }

	    /* special data key name */
	    if(xmlSecKeyGetName(key) != NULL) {
    		if(xmlSecAddChild(cur, BAD_CAST "KeyName", xmlSecDSigNs) == NULL) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecAddChild(\"KeyName\")");
		    xmlFreeDoc(doc); 
		    return(-1);
		}
	    }
    
	    /* create nodes for other keys data */
	    for(j = 0; j < idsSize; ++j) {
		dataId = xmlSecKeyDataIdsGetId(j);
		if(dataId == xmlSecKeyDataIdUnknown) {
		    break;
		}
		if(dataId->dataNodeName == NULL) {
		    continue;
		}
	    
		data = xmlSecKeyGetData(key, dataId);
		if(data == NULL) {
		    continue;
		}

	        if(xmlSecAddChild(cur, dataId->dataNodeName, dataId->dataNodeNs) == NULL) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"xmlSecAddChild(\"%s\")", dataId->dataNodeName);
		    xmlFreeDoc(doc); 
		    return(-1);
		}
	    }

	    /* finally write key in the node */
	    ret = xmlSecKeyInfoNodeWrite(cur, key, &keyInfoCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecKeyInfoNodeWrite - %d", ret);
		xmlFreeDoc(doc); 
		return(-1);
	    }		
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

static int
xmlSecSimpleKeysStoreInitialize(xmlSecKeyDataStorePtr store) {
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);

    return(0);    
}

static void
xmlSecSimpleKeysStoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecPtrListPtr list;
    
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecSimpleKeysStoreId));
    

    list = xmlSecSimpleKeysStoreGetList(store);
    if(list != NULL) {
	xmlSecPtrListDestroy(list);
	store->reserved0 = NULL;
    }
}

static int
xmlSecSimpleKeysStoreFind(xmlSecKeyDataStorePtr store,  xmlSecKeyPtr key, 
			const xmlChar** params, size_t paramsSize,
			xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyPtr storedKey;
    const xmlChar* name = NULL;
    int ret;
    
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    xmlSecAssert2((paramsSize == 0) || (paramsSize == 1), -1);

    /* get name (it might be NULL) */
    if(paramsSize > 0) {	
	name = params[0];
    }
    
    storedKey = xmlSecSimpleKeysStoreFindKey(store, name, keyInfoCtx);
    if(storedKey == NULL) {
	/* found nothing */
	/* todo: add key info ctx parameter to report error/bail out in this case */
	return(0);
    }
    
    /* erase any current information in the key */
    xmlSecKeyEmpty(key);
    
    /* and copy the key from keys storage */
    ret = xmlSecKeyCopy(key, storedKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyCopy");
	return(-1);
    }
    
    return(0);
}

