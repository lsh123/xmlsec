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
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/errors.h>

static void		xmlSecKeysMngrKlassInit		(xmlSecObjKlassPtr klass);
static xmlSecKeyPtr 	xmlSecKeysMngrGetKeyImp		(xmlSecKeysMngrPtr keysMngr, 
							 xmlSecKeysMngrCtxPtr keysMngrCtx, 
		    					 xmlNodePtr keyInfoNode);
static void		xmlSecSimpleKeysMngrKlassInit	(xmlSecObjKlassPtr klass);
static int		xmlSecSimpleKeysMngrConstructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr obj);
static int		xmlSecSimpleKeysMngrDuplicator	(xmlSecObjKlassPtr klass, 
						         xmlSecObjPtr dst, 
							 xmlSecObjPtr src);
static void		xmlSecSimpleKeysMngrDestructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst);
static void		xmlSecSimpleKeysMngrDebugDump	(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static void		xmlSecSimpleKeysMngrDebugXmlDump(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static xmlSecKeyPtr 	xmlSecSimpleKeysMngrFindKey	(xmlSecKeysMngrPtr km, 
							 xmlSecKeysMngrCtxPtr keysMngrCtx);


/*********************************************************************
 *
 * Keys Manager
 *
 *********************************************************************/
xmlSecObjKlassPtr
xmlSecKeysMngrKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecKeysMngrKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecKeysMngrKlass),
	    "xmlSecKeysMngr",
	    xmlSecKeysMngrKlassInit, 	/* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecKeysMngr),
	    NULL,			/* xmlSecObjKlassConstructorMethod */
	    NULL,			/* xmlSecObjKlassDuplicatorMethod */
	    NULL,			/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecObjKlassId); 
    } 
    return(klass);   
}

xmlSecKeyPtr 	
xmlSecKeysMngrGetKey(xmlSecKeysMngrPtr keysMngr, xmlSecKeysMngrCtxPtr keysMngrCtx, 
		     xmlNodePtr keyInfoNode) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(keysMngr);
    xmlSecKeysMngrKlassPtr keysMngrKlass = xmlSecKeysMngrKlassCast(klass);

    xmlSecAssert2(keysMngr != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(keyInfoNode != NULL, NULL);
    xmlSecAssert2(keysMngrKlass != NULL, NULL);
    
    if(keysMngrKlass->getKey != NULL) {
	return(keysMngrKlass->getKey(keysMngr, keysMngrCtx, keyInfoNode)); 
    }
    return(NULL);
}

xmlSecKeyPtr 	
xmlSecKeysMngrFindKey(xmlSecKeysMngrPtr keysMngr, xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(keysMngr);
    xmlSecKeysMngrKlassPtr keysMngrKlass = xmlSecKeysMngrKlassCast(klass);

    xmlSecAssert2(keysMngr != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(keysMngrKlass != NULL, NULL);

    if(keysMngrKlass->findKey != NULL) {
	return(keysMngrKlass->findKey(keysMngr, keysMngrCtx)); 
    }
    return(NULL);
}

static void
xmlSecKeysMngrKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecKeysMngrKlassPtr keysMngrKlass = (xmlSecKeysMngrKlassPtr)klass;

    xmlSecAssert(keysMngrKlass != NULL);
    
    keysMngrKlass->getKey = xmlSecKeysMngrGetKeyImp;
}

static xmlSecKeyPtr 	
xmlSecKeysMngrGetKeyImp(xmlSecKeysMngrPtr keysMngr, xmlSecKeysMngrCtxPtr keysMngrCtx, 
		    	xmlNodePtr keyInfoNode) {
    xmlSecKeyPtr key = NULL;

    xmlSecAssert2(keysMngr != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(keyInfoNode != NULL, NULL);

    if((key == NULL) && (keyInfoNode != NULL)) {
	key = xmlSecKeyInfoNodeRead(keyInfoNode, keysMngrCtx);
    }
    
    if((key == NULL) && (keysMngrCtx->allowedOrigins & xmlSecKeyOriginKeyManager)) {
	if(keysMngrCtx->keyName != NULL) {
	    xmlFree(keysMngrCtx->keyName);
	    keysMngrCtx->keyName = NULL;
	}
	key = xmlSecKeysMngrFindKey(keysMngr, keysMngrCtx);
    }
    
    if(key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    " ");
	return(NULL);    
    }
    
    return(key);
}



/*********************************************************************
 *
 * Simple Keys Manager
 *
 *********************************************************************/
xmlSecObjKlassPtr
xmlSecSimpleKeysMngrKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecSimpleKeysMngrKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecSimpleKeysMngrKlass),
	    "xmlSecSimpleKeysMngr",
	    xmlSecSimpleKeysMngrKlassInit, 	/* xmlSecObjKlassInitMethod */
	    NULL,				/* xmlSecObjKlassFinalizeMethod */
	    
    	    /* obj info */
	    sizeof(xmlSecSimpleKeysMngr),
	    xmlSecSimpleKeysMngrConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecSimpleKeysMngrDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecSimpleKeysMngrDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecKeysMngrKlassId); 
    } 
    return(klass);   
}

/**
 * xmlSecSimpleKeysMngrAddKey:
 * @keysMngr: the pointer to the simple keys manager.
 * @key: the pointer to the #xmlSecValue structure.
 *
 * Adds new key to the key manager
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSimpleKeysMngrAddKey(xmlSecSimpleKeysMngrPtr keysMngr, xmlSecKeyPtr key) {
    int ret;
    
    xmlSecAssert2(keysMngr != NULL, -1);
    xmlSecAssert2(keysMngr->keys != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    
    ret = xmlSecListFind(keysMngr->keys, key);
    if(ret >= 0) {
	/* todo: change error code */
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecListFind - key already present");
	return(-1);		    
    }
    
    ret = xmlSecListAppend(keysMngr->keys, key);
    if(ret < 0) {
    	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecListAppend - %d", ret);
	return(-1);		    
    }
    return(0);
}

/**
 * xmlSecSimpleKeysMngrLoad:
 * @mngr: the pointer to the simple keys manager.
 * @uri: the keys file uri.
 * @strict: the flag which determines whether we stop after first error or not.
 *
 * Reads the XML keys files into simple keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSimpleKeysMngrLoad(xmlSecSimpleKeysMngrPtr keysMngr, const char *uri, int strict) {
    xmlSecKeysMngrCtxPtr keysMngrCtx;
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlSecKeyPtr key;
    int ret;

    xmlSecAssert2(keysMngr != NULL, -1);
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
    
    keysMngrCtx = xmlSecKeysMngrCtxCreate(xmlSecKeysMngrCast(keysMngr));
    if(keysMngrCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrCtxCreate");
	xmlFreeDoc(doc);
	return(-1);
    }    
    keysMngrCtx->allowedOrigins = xmlSecKeyOriginAll;

    cur = xmlSecGetNextElementNode(root->children);
    while(xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecDSigNs)) {  
	key = xmlSecKeyInfoNodeRead(cur, keysMngrCtx);
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyInfoNodeRead");
	    if(strict) {
		xmlSecKeysMngrCtxDestroy(keysMngrCtx);
		xmlFreeDoc(doc);
		return(-1);	
	    }
	} else {
	    ret = xmlSecSimpleKeysMngrAddKey(keysMngr, key);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecSimpleKeysMngrAddKey - %d", ret);
		xmlSecKeysMngrCtxDestroy(keysMngrCtx);
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
	xmlSecKeysMngrCtxDestroy(keysMngrCtx);
	xmlFreeDoc(doc);
	return(-1);	    
    }
    
    xmlSecKeysMngrCtxDestroy(keysMngrCtx);
    xmlFreeDoc(doc);
    return(0);
}

/**
 * xmlSecSimpleKeysMngrSave:
 * @keysMngr: the pointer to the simple keys manager.
 * @filename: the destination filename.
 * @type: the keys type (private/public).
 *
 * Writes all the keys from the simple keys manager to 
 * an XML file @filename.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSimpleKeysMngrSave(xmlSecSimpleKeysMngrPtr keysMngr, const char *filename) {
    xmlSecKeysMngrCtxPtr keysMngrCtx = NULL;
    xmlDocPtr doc = NULL;
    xmlSecKeyPtr key;
    xmlNodePtr root;
    xmlNodePtr cur;
    int res = -1;
    int ret;
    size_t i;

    xmlSecAssert2(keysMngr != NULL, -1);
    xmlSecAssert2(keysMngr->keys != NULL, -1);
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

        keysMngrCtx = xmlSecKeysMngrCtxCreate(xmlSecKeysMngrCast(keysMngr));
    if(keysMngrCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrCtxCreate");
	goto done;
    }    
    keysMngrCtx->allowedOrigins = xmlSecKeyOriginAll;

    for(i = 0; i < xmlSecListGetSize(keysMngr->keys); ++i) {
	key = xmlSecListGetData(keysMngr->keys, i);
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecListGetData(%d)", i);
	    goto done;
	}

	cur = xmlSecAddChild(root, BAD_CAST "KeyInfo", xmlSecDSigNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyInfo\")");
	    goto done;
	}
	
	if(xmlSecAddChild(cur, BAD_CAST "KeyName", xmlSecDSigNs) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyName\")");
	    goto done;
	}

	if(xmlSecAddChild(cur, BAD_CAST "KeyValue", xmlSecDSigNs) == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecAddChild(\"KeyValue\")");
	    goto done;
	}

#ifndef XMLSEC_NO_X509
	if((key->x509Data != NULL)){
	    if(xmlSecAddChild(cur, BAD_CAST "X509Data", xmlSecDSigNs) == NULL) {
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
	    xmlSecKeysMngrCtxDestroy(keysMngrCtx);
    xmlFreeDoc(doc);
    return(res);
}

static void
xmlSecSimpleKeysMngrKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecKeysMngrKlassPtr keysMngrKlass = (xmlSecKeysMngrKlassPtr)klass;

    xmlSecAssert(keysMngrKlass != NULL);

    klass->debugDump 		= xmlSecSimpleKeysMngrDebugDump;
    klass->debugXmlDump 	= xmlSecSimpleKeysMngrDebugXmlDump;
    keysMngrKlass->findKey	= xmlSecSimpleKeysMngrFindKey;
}

static int
xmlSecSimpleKeysMngrConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecSimpleKeysMngrPtr keysMngr = xmlSecSimpleKeysMngrCast(obj);

    xmlSecAssert2(keysMngr != NULL, -1);
    xmlSecAssert2(keysMngr->keys == NULL, -1);
    
    keysMngr->keys = xmlSecListNew();
    if(keysMngr		->keys == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecListNew()");
	return(-1);		    
    }

    return(0);
}

static int
xmlSecSimpleKeysMngrDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecSimpleKeysMngrPtr keysMngrDst = xmlSecSimpleKeysMngrCast(dst);
    xmlSecSimpleKeysMngrPtr keysMngrSrc = xmlSecSimpleKeysMngrCast(src);
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
xmlSecSimpleKeysMngrDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecSimpleKeysMngrPtr keysMngr = xmlSecSimpleKeysMngrCast(obj);

    xmlSecAssert(keysMngr != NULL);
    
    if(keysMngr->keys != NULL) {
	xmlSecPtr tmp;
	size_t i;
	
	while((i = xmlSecListGetSize(keysMngr->keys)) > 0) {
	    tmp = xmlSecListGetData(keysMngr->keys, i - 1);
	    xmlSecListRemove(keysMngr->keys, i - 1);
	    xmlSecAssert(tmp != NULL);
		
	    xmlSecKeyDestroy((xmlSecKeyPtr)tmp);
	}
        xmlSecObjDelete(xmlSecObjCast(keysMngr->keys));
    }
}
    
static void
xmlSecSimpleKeysMngrDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecSimpleKeysMngrPtr keysMngr = xmlSecSimpleKeysMngrCast(obj);

    xmlSecAssert(output != NULL);
    xmlSecAssert(keysMngr != NULL);
    xmlSecAssert(keysMngr->keys != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "simple keys manager:\n");
    xmlSecObjDebugDump(xmlSecObjCast(keysMngr->keys), output, level + 1);
}

static void
xmlSecSimpleKeysMngrDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecSimpleKeysMngrPtr keysMngr = xmlSecSimpleKeysMngrCast(obj);
	    
    xmlSecAssert(output != NULL);
    xmlSecAssert(keysMngr != NULL);
    xmlSecAssert(keysMngr->keys != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<SimpleKeysMngr>\n");
    xmlSecObjDebugXmlDump(xmlSecObjCast(keysMngr->keys), output, level + 1);
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "</SimpleKeysMngr>\n");
}

static xmlSecKeyPtr 		
xmlSecSimpleKeysMngrFindKey(xmlSecKeysMngrPtr km, xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecSimpleKeysMngrPtr keysMngr = xmlSecSimpleKeysMngrCast(km);
    xmlSecKeyPtr tmp;
    xmlSecKeyPtr key = NULL;
    size_t i;

    xmlSecAssert2(km != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);
    xmlSecAssert2(keysMngr != NULL, NULL);
    xmlSecAssert2(keysMngr->keys != NULL, NULL);

    for(i = 0; i < xmlSecListGetSize(keysMngr->keys); ++i) {
	tmp = xmlSecListGetData(keysMngr->keys, i);
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
