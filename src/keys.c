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
#include <xmlsec/strings.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/x509.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>

/*********************************************************************
 *
 * Keys store
 *
 *********************************************************************/
xmlSecObjKlassPtr
xmlSecKeysStoreKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecKeysStoreKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecKeysStoreKlass),
	    "xmlSecKeysStore",
	    NULL, 				/* xmlSecObjKlassInitMethod */
	    NULL,				/* xmlSecObjKlassFinalizeMethod */
	    
    	    /* obj info */
	    sizeof(xmlSecKeysStore),
	    NULL,				/* xmlSecObjKlassConstructorMethod */
	    NULL,				/* xmlSecObjKlassDuplicatorMethod */
	    NULL,				/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecObjKlassId); 
    } 
    return(klass);   
}

xmlSecKeyPtr 	
xmlSecKeysStoreFind(xmlSecKeysStorePtr store, xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(store);
    xmlSecKeysStoreKlassPtr storeKlass = xmlSecKeysStoreKlassCast(klass);

    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(storeKlass != NULL, NULL);

    if(storeKlass->find != NULL) {
	return(storeKlass->find(store, keysMngrCtx)); 
    }
    return(NULL);
}


/*********************************************************************
 *
 * Simple Keys store
 *
 *********************************************************************/
static void		xmlSecSimpleKeysStoreKlassInit	(xmlSecObjKlassPtr klass);
static int		xmlSecSimpleKeysStoreConstructor(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr obj);
static int		xmlSecSimpleKeysStoreDuplicator	(xmlSecObjKlassPtr klass, 
						         xmlSecObjPtr dst, 
							 xmlSecObjPtr src);
static void		xmlSecSimpleKeysStoreDestructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst);
static void		xmlSecSimpleKeysStoreDebugDump	(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static void		xmlSecSimpleKeysStoreDebugXmlDump(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static xmlSecKeyPtr 	xmlSecSimpleKeysStoreFindKey	(xmlSecKeysStorePtr keysStore, 
							 xmlSecKeysMngrCtxPtr keysMngrCtx);

xmlSecObjKlassPtr
xmlSecSimpleKeysStoreKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecSimpleKeysStoreKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecSimpleKeysStoreKlass),
	    "xmlSecSimpleKeysStore",
	    xmlSecSimpleKeysStoreKlassInit, 	/* xmlSecObjKlassInitMethod */
	    NULL,				/* xmlSecObjKlassFinalizeMethod */
	    
    	    /* obj info */
	    sizeof(xmlSecSimpleKeysStore),
	    xmlSecSimpleKeysStoreConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecSimpleKeysStoreDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecSimpleKeysStoreDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecKeysStoreKlassId); 
    } 
    return(klass);   
}

/**
 * xmlSecSimpleKeysStoreAddKey:
 * @store: the pointer to the simple keys manager.
 * @key: the pointer to the #xmlSecValue structure.
 *
 * Adds new key to the key manager
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSimpleKeysStoreAddKey(xmlSecSimpleKeysStorePtr store, xmlSecKeyPtr key) {
    int ret;
    
    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(store->keys != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    ret = xmlSecListFind(store->keys, key);
    if(ret >= 0) {
	/* todo: change error code */
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecListFind - key already present");
	return(-1);		    
    }
    
    ret = xmlSecListAppend(store->keys, key);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecListAppend - %d", ret);
	return(-1);		    
    }
    return(0);
}

/**
 * xmlSecSimpleKeysStoreLoad:
 * @mngr: the pointer to the simple keys manager.
 * @uri: the keys file uri.
 * @strict: the flag which determines whether we stop after first error or not.
 *
 * Reads the XML keys files into simple keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSimpleKeysStoreLoad(xmlSecSimpleKeysStorePtr store, const char *uri, int strict) {
    xmlSecKeysMngrPtr keysMngr = NULL;
    xmlSecKeysMngrCtxPtr keysMngrCtx = NULL;
    xmlDocPtr doc = NULL;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlSecKeyPtr key;
    int res = -1;
    int ret;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);
    
    doc = xmlParseFile(uri);
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlParseFile");
	goto done;
    }
    
    root = xmlDocGetRootElement(doc);
    if(!xmlSecCheckNodeName(root, BAD_CAST "Keys", xmlSecNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "Keys");
	goto done;
    }

    keysMngr = (xmlSecKeysMngrPtr)xmlSecObjNew(xmlSecKeysMngrKlassId);
    if(keysMngr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjNew(xmlSecKeysMngrKlassId)");
	goto done;
    }    
    
    keysMngrCtx = xmlSecKeysMngrCtxCreate(keysMngr);
    if(keysMngrCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrCtxCreate");
	goto done;
    }    
    keysMngrCtx->allowedOrigins = xmlSecKeyOriginAll;

    cur = xmlSecGetNextElementNode(root->children);
    while(xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecNsDSig)) {  
	key = xmlSecKeyInfoNodeRead(cur, keysMngrCtx);
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyInfoNodeRead");
	    if(strict) {
		goto done;
	    }
	} else {
	    ret = xmlSecSimpleKeysStoreAddKey(store, key);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecSimpleKeysStoreAddKey - %d", ret);
		xmlSecKeyDestroy(key);
		goto done;
	    }
	}
        cur = xmlSecGetNextElementNode(cur->next);
    }
    
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*) cur->name : "NULL");
    	goto done;
    }
    res = 0;
    
done:
    if(keysMngrCtx != NULL) {    
        xmlSecObjDelete(xmlSecObjCast(keysMngrCtx));
    }
    if(keysMngr != NULL) {    
        xmlSecObjDelete(xmlSecObjCast(keysMngr));
    }
    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(res);
}

/**
 * xmlSecSimpleKeysStoreSave:
 * @store: the pointer to the simple keys manager.
 * @filename: the destination filename.
 * @type: the keys type (private/public).
 *
 * Writes all the keys from the simple keys manager to 
 * an XML file @filename.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSimpleKeysStoreSave(xmlSecSimpleKeysStorePtr store, const char *filename) {
    xmlSecKeysMngrPtr keysMngr = NULL;
    xmlSecKeysMngrCtxPtr keysMngrCtx = NULL;
    xmlDocPtr doc = NULL;
    xmlSecKeyPtr key;
    xmlNodePtr root;
    xmlNodePtr cur;
    int res = -1;
    int ret;
    size_t i;

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(store->keys != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    /* create doc */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewDoc");
	goto done;
    }
    
    /* create root node "Keys" */
    root = xmlNewDocNode(doc, NULL, BAD_CAST "Keys", NULL); 
    if(root == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewDocNode");
	goto done;
    }
    xmlDocSetRootElement(doc, root);
    if(xmlNewNs(root, xmlSecNs, NULL) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlNewNs");
	goto done;
    }

    keysMngr = (xmlSecKeysMngrPtr)xmlSecObjNew(xmlSecKeysMngrKlassId);
    if(keysMngr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjNew(xmlSecKeysMngrKlassId)");
	goto done;
    }    

    keysMngrCtx = xmlSecKeysMngrCtxCreate(keysMngr);
    if(keysMngrCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrCtxCreate");
	goto done;
    }    
    keysMngrCtx->allowedOrigins = xmlSecKeyOriginAll;

    for(i = 0; i < xmlSecListGetSize(store->keys); ++i) {
	key = xmlSecListGetData(store->keys, i);
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecListGetData(%d)", i);
	    goto done;
	}

	cur = xmlSecAddChild(root, BAD_CAST "KeyInfo", xmlSecNsDSig);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyInfo\")");
	    goto done;
	}
	
	if(xmlSecAddChild(cur, BAD_CAST "KeyName", xmlSecNsDSig) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyName\")");
	    goto done;
	}

	if(xmlSecAddChild(cur, BAD_CAST "KeyValue", xmlSecNsDSig) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyValue\")");
	    goto done;
	}

#ifndef XMLSEC_NO_X509
	if((key->x509Data != NULL)){
	    if(xmlSecAddChild(cur, BAD_CAST "X509Data", xmlSecNsDSig) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecAddChild(\"X509Data\")");
		goto done;
	    }
	}
#endif /* XMLSEC_NO_X509 */	     

	ret = xmlSecKeyInfoNodeWrite(cur, keysMngrCtx, key, xmlSecKeyValueTypeAny);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyInfoNodeWrite - %d", ret);
	    goto done;
	}		
    }    

    /* now write result */
    ret = xmlSaveFormatFile(filename, doc, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlSaveFormatFile(\"%s\") - %d", filename, ret);
	goto done;
    }	   
    res = 0;
    
done:    
    if(keysMngrCtx != NULL) {
        xmlSecObjDelete(xmlSecObjCast(keysMngrCtx));
    }
    if(keysMngr != NULL) {    
        xmlSecObjDelete(xmlSecObjCast(keysMngr));
    }
    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(res);
}

static void
xmlSecSimpleKeysStoreKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecKeysStoreKlassPtr keysMngrKlass = (xmlSecKeysStoreKlassPtr)klass;

    xmlSecAssert(keysMngrKlass != NULL);

    klass->debugDump 		= xmlSecSimpleKeysStoreDebugDump;
    klass->debugXmlDump 	= xmlSecSimpleKeysStoreDebugXmlDump;
    keysMngrKlass->find		= xmlSecSimpleKeysStoreFindKey;
}

static int
xmlSecSimpleKeysStoreConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecSimpleKeysStorePtr store = xmlSecSimpleKeysStoreCast(obj);

    xmlSecAssert2(store != NULL, -1);
    xmlSecAssert2(store->keys == NULL, -1);
    
    store->keys = xmlSecListNew();
    if(store		->keys == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecListNew()");
	return(-1);		    
    }

    return(0);
}

static int
xmlSecSimpleKeysStoreDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecSimpleKeysStorePtr keysMngrDst = xmlSecSimpleKeysStoreCast(dst);
    xmlSecSimpleKeysStorePtr keysMngrSrc = xmlSecSimpleKeysStoreCast(src);
    xmlSecObjPtr tmp;
    
    xmlSecAssert2(keysMngrDst != NULL, -1);
    xmlSecAssert2(keysMngrSrc != NULL, -1);
    xmlSecAssert2(keysMngrSrc->keys != NULL, -1);
    xmlSecAssert2(keysMngrDst->keys == NULL, -1);
    
    tmp = xmlSecObjDuplicate(xmlSecObjCast(keysMngrSrc->keys));
    keysMngrDst->keys = xmlSecListCast(tmp);
    if(keysMngrDst->keys == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjDuplicate(xmlSecObjCast(keysMngrSrc->keys))");
	return(-1);		    
    }
    return(0);
}

static void
xmlSecSimpleKeysStoreDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecSimpleKeysStorePtr store = xmlSecSimpleKeysStoreCast(obj);

    xmlSecAssert(store != NULL);
    
    if(store->keys != NULL) {
	xmlSecPtr tmp;
	size_t i;
	
	while((i = xmlSecListGetSize(store->keys)) > 0) {
	    tmp = xmlSecListGetData(store->keys, i - 1);
	    xmlSecListRemove(store->keys, i - 1);
	    xmlSecAssert(tmp != NULL);
		
	    xmlSecKeyDestroy((xmlSecKeyPtr)tmp);
	}
        xmlSecObjDelete(xmlSecObjCast(store->keys));
    }
}
    
static void
xmlSecSimpleKeysStoreDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecSimpleKeysStorePtr store = xmlSecSimpleKeysStoreCast(obj);

    xmlSecAssert(output != NULL);
    xmlSecAssert(store != NULL);
    xmlSecAssert(store->keys != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "simple keys manager:\n");
    xmlSecObjDebugDump(xmlSecObjCast(store->keys), output, level + 1);
}

static void
xmlSecSimpleKeysStoreDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecSimpleKeysStorePtr store = xmlSecSimpleKeysStoreCast(obj);
	    
    xmlSecAssert(output != NULL);
    xmlSecAssert(store != NULL);
    xmlSecAssert(store->keys != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<SimpleKeysStore>\n");
    xmlSecObjDebugXmlDump(xmlSecObjCast(store->keys), output, level + 1);
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "</SimpleKeysStore>\n");
}

static xmlSecKeyPtr 		
xmlSecSimpleKeysStoreFindKey(xmlSecKeysStorePtr keysStore, xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecSimpleKeysStorePtr store = xmlSecSimpleKeysStoreCast(keysStore);
    xmlSecKeyPtr tmp;
    xmlSecKeyPtr key = NULL;
    size_t i;

    xmlSecAssert2(keysStore != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(store != NULL, NULL);
    xmlSecAssert2(store->keys != NULL, NULL);

    for(i = 0; i < xmlSecListGetSize(store->keys); ++i) {
	tmp = xmlSecListGetData(store->keys, i);
	if(tmp == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecListGetData(%d)", i);
	    return(NULL);    
	}

	if(xmlSecKeyCheck(tmp, keysMngrCtx->keyName, 
			       keysMngrCtx->keyId, 
			       keysMngrCtx->keyType) == 1) {
	    key = xmlSecKeyDuplicate(tmp);
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

/***************************************************************************
 *
 * xmlSecKey
 *
 **************************************************************************/
xmlSecKeyPtr
xmlSecKeyCreate(xmlSecKeyValuePtr value, const xmlChar* name)  {
    xmlSecKeyPtr key;

    /*
     * Allocate a new xmlSecKey and fill the fields.
     */
    key = (xmlSecKeyPtr) xmlMalloc(sizeof(xmlSecKey));
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecKey)=%d", 
		    sizeof(xmlSecKey));
	return(NULL);
    }
    memset(key, 0, sizeof(xmlSecKey));

    /* dup value */    
    if(value != NULL) {
	key->value = xmlSecKeyValueDuplicate(value);
	if(key->value == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyValueDuplicate");
	    xmlSecKeyDestroy(key);
	    return(NULL);	
	}
    }
    /* dup name */    
    if(name != NULL) {
	key->name = xmlStrdup(name);
	if(key->name == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "xmlStrdup(\"%s\")", name);
	    xmlSecKeyDestroy(key);
	    return(NULL);	
	}
    }
    
    return(key);    
}

void
xmlSecKeyDestroy(xmlSecKeyPtr key) {
    xmlSecAssert(key != NULL);

    if(key->value != NULL) {
	xmlSecKeyValueDestroy(key->value);
    }
    if(key->name != NULL) {
	xmlFree(key->name);
    }

    if(key->x509Data != NULL) {
	xmlSecObjDelete(xmlSecObjCast(key->x509Data));
    }
    if(key->pgpData != NULL) {
	xmlSecObjDelete(xmlSecObjCast(key->pgpData));
    }

    memset(key, 0, sizeof(xmlSecKey));
    xmlFree(key);    
}

xmlSecKeyPtr
xmlSecKeyDuplicate(xmlSecKeyPtr key) {
    xmlSecKeyPtr newKey = NULL;
    
    xmlSecAssert2(key != NULL, NULL);
    
    newKey = xmlSecKeyCreate(key->value, key->name);
    if(newKey == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyCreate");
	return(NULL);	
    }

    /* dup x509 */    
    if(key->x509Data != NULL) {
	newKey->x509Data = (xmlSecX509DataPtr)xmlSecObjDuplicate(xmlSecObjCast(key->x509Data));
	if(newKey->x509Data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjDuplicate(x509Data)");
	    xmlSecKeyDestroy(newKey);
	    return(NULL);	
	}
    }

    /* dup pgp */    
    if(key->pgpData != NULL) {
	newKey->pgpData = (xmlSecPgpDataPtr)xmlSecObjDuplicate(xmlSecObjCast(key->pgpData));
	if(newKey->pgpData == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjDuplicate(pgpData)");
	    xmlSecKeyDestroy(newKey);
	    return(NULL);	
	}
    }
    return(newKey);
}

/**
 * xmlSecKeyCheck:
 * @key: the pointer to the #xmlSecKey structure.
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
xmlSecKeyCheck(xmlSecKeyPtr key, const xmlChar *name, xmlSecKeyValueId id, 
		xmlSecKeyValueType type) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(key->value != NULL, -1);

    /* todo: name is not an empty string */
    if((name != NULL) && (!xmlStrEqual(key->name, name))) {
	return(0);
    }
    
    return(xmlSecKeyValueCheck(key->value, id, type));
}

void
xmlSecKeyDebugDump(xmlSecKeyPtr key, FILE *output) {
    int level = 0;
    
    xmlSecAssert(key != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "== KEY\n");
    fprintf(output, "=== key name: %s\n", 
	    (key->name != NULL) ? 
	    (char*)(key->name) : "NULL"); 
    if(key->value != NULL) {
	xmlSecKeyValueDebugDump(key->value, output);
    }	    
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

    if(key->x509Data != NULL) {
	xmlSecObjDebugDump(xmlSecObjCast(key->x509Data), output, level + 1);
    }
    if(key->pgpData != NULL) {
	xmlSecObjDebugDump(xmlSecObjCast(key->pgpData), output, level + 1);
    }	
}

void
xmlSecKeyDebugXmlDump(xmlSecKeyPtr key, FILE *output) {
    int level = 0;
    
    xmlSecAssert(key != NULL);
    xmlSecAssert(output != NULL);
    
    fprintf(output, "<KeyInfo>\n");
    if(key->name != NULL) {
	fprintf(output, "<KeyName>%s</KeyName>\n", 
	        key->name);
    }
    if(key->value != NULL) {
	xmlSecKeyValueDebugXmlDump(key->value, output);
    }	    
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
    
    if(key->x509Data != NULL) {
	xmlSecObjDebugXmlDump(xmlSecObjCast(key->x509Data), output, level + 1);
    }
    if(key->pgpData != NULL) {
	xmlSecObjDebugXmlDump(xmlSecObjCast(key->pgpData), output, level + 1);
    }	
    fprintf(output, "</KeyInfo>\n"); 
}




