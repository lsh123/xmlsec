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
#include <xmlsec/strings.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/errors.h>



/*********************************************************************
 *
 * Keys Manager
 *
 *********************************************************************/
static void		xmlSecKeysMngrKlassInit		(xmlSecObjKlassPtr klass);
static int		xmlSecKeysMngrConstructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr obj);
static int		xmlSecKeysMngrDuplicator	(xmlSecObjKlassPtr klass, 
						         xmlSecObjPtr dst, 
							 xmlSecObjPtr src);
static void		xmlSecKeysMngrDestructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst);
static void		xmlSecKeysMngrDebugDump		(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static void		xmlSecKeysMngrDebugXmlDump	(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static xmlSecKeyPtr 	xmlSecKeysMngrGetKeyImp		(xmlSecKeysMngrPtr keysMngr, 
							 xmlSecKeysMngrCtxPtr keysMngrCtx, 
		    					 xmlNodePtr keyInfoNode);

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
	    xmlSecKeysMngrConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecKeysMngrDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecKeysMngrDestructor,	/* xmlSecObjKlassDestructorMethod */
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
    xmlSecAssert2(keysMngrKlass != NULL, NULL);
    
    if(keysMngrKlass->getKey != NULL) {
	return(keysMngrKlass->getKey(keysMngr, keysMngrCtx, keyInfoNode)); 
    }
    return(NULL);
}

static void
xmlSecKeysMngrKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecKeysMngrKlassPtr keysMngrKlass = (xmlSecKeysMngrKlassPtr)klass;

    xmlSecAssert(keysMngrKlass != NULL);
    
    klass->debugDump 	= xmlSecKeysMngrDebugDump;
    klass->debugXmlDump = xmlSecKeysMngrDebugXmlDump;
    keysMngrKlass->getKey = xmlSecKeysMngrGetKeyImp;
}

static int
xmlSecKeysMngrConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecKeysMngrPtr keysMngr = xmlSecKeysMngrCast(obj);

    xmlSecAssert2(keysMngr != NULL, -1);

    return(0);
}

static int
xmlSecKeysMngrDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecKeysMngrPtr keysMngrDst = xmlSecKeysMngrCast(dst);
    xmlSecKeysMngrPtr keysMngrSrc = xmlSecKeysMngrCast(src);
    
    xmlSecAssert2(keysMngrDst != NULL, -1);
    xmlSecAssert2(keysMngrSrc != NULL, -1);

    if(keysMngrSrc->keysStore != NULL) {
	xmlSecAssert2(keysMngrDst->keysStore == NULL, -1);
	
	keysMngrDst->keysStore = (xmlSecKeysStorePtr)
			xmlSecObjDuplicate(xmlSecObjCast(keysMngrSrc->keysStore));
	if(keysMngrDst->keysStore == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlSecObjDuplicate(keysStore)");
	    return(-1);
	}
    }    

    if(keysMngrSrc->x509Store != NULL) {
	xmlSecAssert2(keysMngrDst->x509Store == NULL, -1);
	
	keysMngrDst->x509Store = (xmlSecX509StorePtr)
			xmlSecObjDuplicate(xmlSecObjCast(keysMngrSrc->x509Store));
	if(keysMngrDst->x509Store == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlSecObjDuplicate(x509Store)");
	    return(-1);
	}
    }    

    if(keysMngrSrc->pgpStore != NULL) {
	xmlSecAssert2(keysMngrDst->pgpStore == NULL, -1);
	
	keysMngrDst->pgpStore = (xmlSecPgpStorePtr)
			xmlSecObjDuplicate(xmlSecObjCast(keysMngrSrc->pgpStore));
	if(keysMngrDst->pgpStore == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlSecObjDuplicate(pgpStore)");
	    return(-1);
	}
    }    

    return(0);
}

static void
xmlSecKeysMngrDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecKeysMngrPtr keysMngr = xmlSecKeysMngrCast(obj);

    xmlSecAssert(keysMngr != NULL);

    if(keysMngr->keysStore != NULL) {
	xmlSecObjDelete(xmlSecObjCast(keysMngr->keysStore));
	keysMngr->keysStore = NULL;
    }
    if(keysMngr->x509Store != NULL) {
	xmlSecObjDelete(xmlSecObjCast(keysMngr->x509Store));
	keysMngr->x509Store = NULL;
    }
    if(keysMngr->pgpStore != NULL) {
	xmlSecObjDelete(xmlSecObjCast(keysMngr->pgpStore));
	keysMngr->pgpStore = NULL;
    }
}
    
static void
xmlSecKeysMngrDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecKeysMngrPtr keysMngr = xmlSecKeysMngrCast(obj);

    xmlSecAssert(output != NULL);
    xmlSecAssert(keysMngr != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "keys manager:\n");
    if(keysMngr->keysStore != NULL) {
	xmlSecObjDebugDump(xmlSecObjCast(keysMngr->keysStore), output, level + 1);
    }
    if(keysMngr->x509Store != NULL) {
	xmlSecObjDebugDump(xmlSecObjCast(keysMngr->x509Store), output, level + 1);
    }
    if(keysMngr->pgpStore != NULL) {
	xmlSecObjDebugDump(xmlSecObjCast(keysMngr->pgpStore), output, level + 1);
    }
}

static void
xmlSecKeysMngrDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecKeysMngrPtr keysMngr = xmlSecKeysMngrCast(obj);
	    
    xmlSecAssert(output != NULL);
    xmlSecAssert(keysMngr != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<KeysMngr>\n");
    
    /* todo 
    xmlSecObjDebugXmlDump(xmlSecObjCast(keysMngr->), output, level + 1);
    */
    
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "</KeysMngr>\n");
}


static xmlSecKeyPtr 	
xmlSecKeysMngrGetKeyImp(xmlSecKeysMngrPtr keysMngr, xmlSecKeysMngrCtxPtr keysMngrCtx, 
		    	xmlNodePtr keyInfoNode) {
    xmlSecKeyPtr key = NULL;

    xmlSecAssert2(keysMngr != NULL, NULL);
    xmlSecAssert2(keysMngrCtx != NULL, NULL);

    if((key == NULL) && (keyInfoNode != NULL)) {
	key = xmlSecKeyInfoNodeRead(keyInfoNode, keysMngrCtx);
    }
    
    if((key == NULL) && (keysMngrCtx->allowedOrigins & xmlSecKeyOriginKeyManager)) {
	if(keysMngrCtx->keyName != NULL) {
	    xmlFree(keysMngrCtx->keyName);
	    keysMngrCtx->keyName = NULL;
	}
	if(keysMngr->keysStore != NULL) {
	    key = xmlSecKeysStoreFind(keysMngr->keysStore, keysMngrCtx);
	}
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
 * Keys Manager Context
 *
 *********************************************************************/
static void		xmlSecKeysMngrCtxKlassInit	(xmlSecObjKlassPtr klass);
static int		xmlSecKeysMngrCtxConstructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr obj);
static int		xmlSecKeysMngrCtxDuplicator	(xmlSecObjKlassPtr klass, 
						         xmlSecObjPtr dst, 
							 xmlSecObjPtr src);
static void		xmlSecKeysMngrCtxDestructor	(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst);
static void		xmlSecKeysMngrCtxDebugDump	(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static void		xmlSecKeysMngrCtxDebugXmlDump(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);

xmlSecObjKlassPtr
xmlSecKeysMngrCtxKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecKeysMngrCtxKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecKeysMngrCtxKlass),
	    "xmlSecKeysMngrCtx",
	    xmlSecKeysMngrCtxKlassInit, 	/* xmlSecObjKlassInitMethod */
	    NULL,				/* xmlSecObjKlassFinalizeMethod */
	    
    	    /* obj info */
	    sizeof(xmlSecKeysMngrCtx),
	    xmlSecKeysMngrCtxConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecKeysMngrCtxDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecKeysMngrCtxDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecObjKlassId); 
    } 
    return(klass);   
}

xmlSecKeysMngrCtxPtr 
xmlSecKeysMngrCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecKeysMngrCtxPtr keysMngrCtx;
    xmlSecObjPtr tmp;

    xmlSecAssert2(keysMngr != NULL, NULL);
        
    tmp = xmlSecObjNew(xmlSecKeysMngrCtxKlassId);
    if(tmp == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecObjNew(xmlSecKeysMngrCtxId)");
	return(NULL);    
    }
    
    keysMngrCtx = xmlSecKeysMngrCtxCast(tmp);
    if(keysMngrCtx == NULL) {
	xmlSecObjDelete(tmp);
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeysMngrCtxCast");
	return(NULL);    
    }
    keysMngrCtx->keysMngr = keysMngr;
    
    return(keysMngrCtx);
}

int
xmlSecKeysMngrCtxCheckOrigin(xmlSecKeysMngrCtxPtr keysMngrCtx, xmlSecKeyOrigin origin) {
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    
    return((keysMngrCtx->allowedOrigins & origin) ? 1 : 0);
}

int
xmlSecKeysMngrCtxCheckRetrievalsLevel(xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecAssert2(keysMngrCtx != NULL, -1);
    
    return(keysMngrCtx->maxRetrievalsLevel > keysMngrCtx->curRetrievalsLevel);
}

int
xmlSecKeysMngrCtxCheckEncKeysLevel(xmlSecKeysMngrCtxPtr keysMngrCtx) {
    xmlSecAssert2(keysMngrCtx != NULL, -1);

    return(keysMngrCtx->maxEncKeysLevel > keysMngrCtx->curEncKeysLevel);
}

void
xmlSecKeysMngrCtxSetCurKey(xmlSecKeysMngrCtxPtr keysMngrCtx, xmlSecKeyPtr key) {
    xmlSecAssert(keysMngrCtx != NULL);

    if(keysMngrCtx->curKey != NULL) {
	xmlSecKeyDestroy(keysMngrCtx->curKey);
/* todo
	xmlSecObjDelete(xmlSecObjCast(keysMngrCtx->curKey));
*/
    }
    keysMngrCtx->curKey = key;
}


static void
xmlSecKeysMngrCtxKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecKeysMngrCtxKlassPtr keysMngrCtxKlass = (xmlSecKeysMngrCtxKlassPtr)klass;

    xmlSecAssert(keysMngrCtxKlass != NULL);

    klass->debugDump 		= xmlSecKeysMngrCtxDebugDump;
    klass->debugXmlDump 	= xmlSecKeysMngrCtxDebugXmlDump;
}


static int
xmlSecKeysMngrCtxConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecKeysMngrCtxPtr keysMngrCtx = xmlSecKeysMngrCtxCast(obj);

    xmlSecAssert2(keysMngrCtx != NULL, -1);

    /* set "smart" defaults */
    keysMngrCtx->allowedOrigins = xmlSecKeyOriginAll;
    keysMngrCtx->maxRetrievalsLevel = 1;
    keysMngrCtx->maxEncKeysLevel = 1;

    return(0);
}

static int
xmlSecKeysMngrCtxDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecKeysMngrCtxPtr keysMngrCtxDst = xmlSecKeysMngrCtxCast(dst);
    xmlSecKeysMngrCtxPtr keysMngrCtxSrc = xmlSecKeysMngrCtxCast(src);
    
    xmlSecAssert2(keysMngrCtxDst != NULL, -1);
    xmlSecAssert2(keysMngrCtxSrc != NULL, -1);
    
    keysMngrCtxDst->keysMngr 		 = keysMngrCtxSrc->keysMngr;

    /* restrictions */
    keysMngrCtxDst->allowedOrigins 	 = keysMngrCtxSrc->allowedOrigins;
    keysMngrCtxDst->maxRetrievalsLevel 	 = keysMngrCtxSrc->maxRetrievalsLevel;
    keysMngrCtxDst->maxEncKeysLevel 	 = keysMngrCtxSrc->maxEncKeysLevel;
    keysMngrCtxDst->certsVerificationTime= keysMngrCtxSrc->certsVerificationTime;

    /* desired key */
    keysMngrCtxDst->keyId 		= keysMngrCtxSrc->keyId;
    keysMngrCtxDst->keyType		= keysMngrCtxSrc->keyType;
    keysMngrCtxDst->keyUsage 		= keysMngrCtxSrc->keyUsage;
    if(keysMngrCtxSrc->keyName != NULL) {
	xmlSecAssert2(keysMngrCtxDst->keyName == NULL, -1);
	
	keysMngrCtxDst->keyName 	= xmlStrdup(keysMngrCtxSrc->keyName);
    }

    /* don't duplicate current state! */
    return(0);
}

static void
xmlSecKeysMngrCtxDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecKeysMngrCtxPtr keysMngrCtx = xmlSecKeysMngrCtxCast(obj);

    xmlSecAssert(keysMngrCtx != NULL);

    if(keysMngrCtx->keyName != NULL) {
	xmlFree(keysMngrCtx->keyName);
	keysMngrCtx->keyName = NULL;
    }
    xmlSecKeysMngrCtxSetCurKey(keysMngrCtx, NULL);
}
    
static void
xmlSecKeysMngrCtxDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecKeysMngrCtxPtr keysMngrCtx = xmlSecKeysMngrCtxCast(obj);

    xmlSecAssert(output != NULL);
    xmlSecAssert(keysMngrCtx != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "simple keys manager:\n");
    /* todo 
    xmlSecObjDebugDump(xmlSecObjCast(keysMngrCtx->), output, level + 1);
    */
}

static void
xmlSecKeysMngrCtxDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecKeysMngrCtxPtr keysMngrCtx = xmlSecKeysMngrCtxCast(obj);
	    
    xmlSecAssert(output != NULL);
    xmlSecAssert(keysMngrCtx != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<KeysMngrCtx>\n");
    
    /* todo 
    xmlSecObjDebugXmlDump(xmlSecObjCast(keysMngrCtx->), output, level + 1);
    */
    
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "</KeysMngrCtx>\n");
}

