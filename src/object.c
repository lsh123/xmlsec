/**		
 * XMLSec library
 *
 * Objects/classes system. It is similar to one found in GLib/GTK/GDK.
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/object.h>
#include <xmlsec/errors.h>

static	void 		xmlSecObjKlassRegisterRecursive		(xmlSecPtr buf, 
								 size_t size, 
								 xmlSecObjKlassPtr klass);
static int		xmlSecObjNewRecursive			(xmlSecObjPtr newObj, 
								 xmlSecObjKlassPtr klass);
static int		xmlSecObjDuplicateRecursive		(xmlSecObjPtr newObj,
								 xmlSecObjPtr obj, 
								 xmlSecObjKlassPtr klass);
static void		xmlSecObjDeleteRecursive		(xmlSecObjPtr obj, 
								 xmlSecObjKlassPtr klass);


static void		xmlSecObjKlassInitImp			(xmlSecObjKlassPtr klass);
static void		xmlSecObjDebugDumpImp			(xmlSecObjPtr obj, 
								 FILE* output, 
								 size_t level);
static void		xmlSecObjDebugXmlDumpImp		(xmlSecObjPtr obj, 
								 FILE* output, 
								 size_t level);

/*********************************************************************
 *
 * Private klasses structure functions and macros. Don't use them 
 * in your code directly.
 *
 ********************************************************************/	
#define xmlSecObjKlassInfoIsValid(ki) \
	(((ki) != NULL) && ((ki)->klassName != NULL))

#define xmlSecObjKlassIsValid(kl) \
	(xmlSecObjKlassInfoIsValid(xmlSecObjKlassGetKlassInfo((kl))))

#define xmlSecObjIsValid(obj) \
	(xmlSecObjKlassIsValid(xmlSecObjGetKlass((obj))))

/*********************************************************************
 *
 * klasses registration and creation helpers
 *
 ********************************************************************/
xmlSecObjKlassPtr 	
xmlSecObjKlassRegister(xmlSecPtr buf, size_t size, xmlSecObjKlassInfoPtr klassInfo, 
			xmlSecObjKlassPtr parent) {
    xmlSecObjKlassPtr klass = (xmlSecObjKlassPtr)buf;
    
    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(xmlSecObjKlassInfoIsValid(klassInfo), NULL);
    xmlSecAssert2(klassInfo->klassSize == size, NULL);
    
    /* init all parents */
    if(parent != NULL) {
	xmlSecAssert2(xmlSecObjKlassIsValid(parent), NULL);
	xmlSecObjKlassRegisterRecursive(buf, size, parent);
    }
    
    /* now init our klass */
    klass->klassInfo 	= klassInfo;
    klass->klassParent	= parent;
    if(klassInfo->klassInit != NULL) {
	klassInfo->klassInit(klass);
    }
    return(klass);
}

const char*		
xmlSecObjKlassGetKlassName(xmlSecObjKlassPtr klass) {
    xmlSecObjKlassInfoPtr klassInfo = xmlSecObjKlassGetKlassInfo(klass);

    return(((klassInfo != NULL) && 
	    (klassInfo->klassName != NULL)) ? 
	    klassInfo->klassName : "invalid");
}

xmlSecObjKlassPtr	
xmlSecObjKlassCheckCastFunc(xmlSecObjKlassPtr klass, xmlSecObjKlassPtr dst) {
    xmlSecAssert2(xmlSecObjKlassIsValid(klass), NULL);
    xmlSecAssert2(xmlSecObjKlassIsValid(dst), NULL);
    
    if(klass == dst) {
	return(klass);
    }
    if(klass->klassParent != NULL) {
	return(xmlSecObjKlassCheckCastFunc(klass->klassParent, dst));
    }
    return(NULL);
}

static void
xmlSecObjKlassRegisterRecursive(xmlSecPtr buf,  size_t size, xmlSecObjKlassPtr klass) {
    xmlSecAssert(buf);
    xmlSecAssert(xmlSecObjKlassIsValid(klass));
    xmlSecAssert(xmlSecObjKlassGetKlassInfo(klass)->klassSize <= size);
    
    if(klass->klassParent != NULL) {
	xmlSecObjKlassRegisterRecursive(buf, size, klass->klassParent);
    }
    if(xmlSecObjKlassGetKlassInfo(klass)->klassSize > 0) {
	memcpy(buf, klass, xmlSecObjKlassGetKlassInfo(klass)->klassSize);
    }
}


/*********************************************************************
 *
 * new/delete methods
 *
 ********************************************************************/
xmlSecObjPtr
xmlSecObjNew(xmlSecObjKlassPtr klass) {
    xmlSecObjKlassInfoPtr klassInfo = xmlSecObjKlassGetKlassInfo(klass);
    xmlSecObjPtr newObj;
    int ret;
    
    xmlSecAssert2(xmlSecObjKlassIsValid(klass), NULL);
    xmlSecAssert2(klassInfo != NULL, NULL);
    
    newObj = (xmlSecObjPtr)xmlMalloc(klassInfo->objSize);
    if(newObj == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_MALLOC_FAILED,	
		    "klass \"%s\" (%d bytess)", 
		    xmlSecObjKlassGetKlassName(klass),
		    klassInfo->objSize);
	return(NULL);
    }
    memset(newObj, 0, klassInfo->objSize);
    newObj->klass = klass;
    
    ret = xmlSecObjNewRecursive(newObj, klass);
    if(ret < 0) {
	xmlSecObjDelete(newObj);
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecObjNewRecursive(\"%s\")", 
		    xmlSecObjKlassGetKlassName(klass));
	return(NULL);
    }
    
    return(newObj);
}

xmlSecObjPtr
xmlSecObjDuplicate(xmlSecObjPtr obj) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(obj);
    xmlSecObjKlassInfoPtr klassInfo = xmlSecObjGetKlassInfo(obj);
    xmlSecObjPtr newObj;
    int ret;
    
    xmlSecAssert2(xmlSecObjIsValid(obj), NULL);
    xmlSecAssert2(klass != NULL, NULL);
    xmlSecAssert2(klassInfo != NULL, NULL);
    
    newObj = (xmlSecObjPtr)xmlMalloc(klassInfo->objSize);
    if(newObj == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_MALLOC_FAILED,	
		    "klass \"%s\" (%d bytess)", 
		    xmlSecObjKlassGetKlassName(klass),
		    klassInfo->objSize);
	return(NULL);
    }
    memset(newObj, 0, klassInfo->objSize);
    newObj->klass = klass;
    
    ret = xmlSecObjDuplicateRecursive(newObj, obj, klass);
    if(ret < 0) {
	xmlSecObjDelete(newObj);
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecObjDuplicateRecursive(\"%s\")", 
		    xmlSecObjKlassGetKlassName(klass));
	return(NULL);
    }
    
    return(newObj);
}

void
xmlSecObjDelete(xmlSecObjPtr obj) {
    xmlSecObjKlassPtr klass = xmlSecObjGetKlass(obj);
    xmlSecObjKlassInfoPtr klassInfo = xmlSecObjGetKlassInfo(obj);

    xmlSecAssert(xmlSecObjIsValid(obj));
    xmlSecAssert(klass != NULL);
    xmlSecAssert(klassInfo != NULL);

    xmlSecObjDeleteRecursive(obj, klass);
    memset(obj, 0, klassInfo->objSize);
    xmlFree(obj);    
}

static int
xmlSecObjNewRecursive(xmlSecObjPtr newObj, xmlSecObjKlassPtr klass) {
    xmlSecObjKlassInfoPtr klassInfo = xmlSecObjKlassGetKlassInfo(klass);
    int ret;
    
    xmlSecAssert2(newObj != NULL, -1);
    xmlSecAssert2(xmlSecObjKlassIsValid(klass), -1);
    xmlSecAssert2(klassInfo != NULL, -1);
    
    if(klass->klassParent != NULL) {
	ret = xmlSecObjNewRecursive(newObj, klass->klassParent);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
    			XMLSEC_ERRORS_R_XMLSEC_FAILED,	
			"xmlSecObjNewRecursive(\"%s\")", 
			xmlSecObjKlassGetKlassName(klass));
	    return(-1);
	}
    }
    
    if(klassInfo->objConstructor != NULL) {
	ret = klassInfo->objConstructor(klass, newObj);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
    			XMLSEC_ERRORS_R_XMLSEC_FAILED,	
			"objConstructor(\"%s\")", 
			xmlSecObjKlassGetKlassName(klass));
	    return(-1);
	}
    }
    return(0);
}

static int		
xmlSecObjDuplicateRecursive(xmlSecObjPtr newObj, xmlSecObjPtr obj, xmlSecObjKlassPtr klass) {
    xmlSecObjKlassInfoPtr klassInfo = xmlSecObjKlassGetKlassInfo(klass);
    int ret;
    
    xmlSecAssert2(newObj != NULL, -1);
    xmlSecAssert2(obj != NULL, -1);
    xmlSecAssert2(xmlSecObjKlassIsValid(klass), -1);
    xmlSecAssert2(klassInfo != NULL, -1);
    
    if(klass->klassParent != NULL) {
	ret = xmlSecObjDuplicateRecursive(newObj, obj, klass->klassParent);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
    			XMLSEC_ERRORS_R_XMLSEC_FAILED,	
			"xmlSecObjDuplicateRecursive(\"%s\")", 
			xmlSecObjKlassGetKlassName(klass));
	    return(-1);
	}
    }
    
    if(klassInfo->objDuplicator != NULL) {
	ret = klassInfo->objDuplicator(klass, newObj, obj);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
    			XMLSEC_ERRORS_R_XMLSEC_FAILED,	
			"objDuplicator(\"%s\")", 
			xmlSecObjKlassGetKlassName(klass));
	    return(-1);
	}
    }
    return(0);
}

static void		
xmlSecObjDeleteRecursive(xmlSecObjPtr obj, xmlSecObjKlassPtr klass) {
    xmlSecObjKlassInfoPtr klassInfo = xmlSecObjKlassGetKlassInfo(klass);

    xmlSecAssert(xmlSecObjIsValid(obj));
    xmlSecAssert(xmlSecObjKlassIsValid(klass));
    xmlSecAssert(klassInfo != NULL);

    if(klassInfo->objDestructor != NULL) {
	klassInfo->objDestructor(klass, obj);
    }
    
    if(klass->klassParent != NULL) {
	xmlSecObjDeleteRecursive(obj, klass->klassParent);
    }    
}


/*********************************************************************
 *
 * Base Klass 
 *
 *********************************************************************/
xmlSecObjKlassPtr	
xmlSecObjKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    
    if(klass == NULL) {
	static xmlSecObjKlass kklass;
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecObjKlass),
	    "xmlSecObj",
	    xmlSecObjKlassInitImp, 	/* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecObj),
	    NULL,			/* xmlSecObjKlassConstructorMethod */
	    NULL,			/* xmlSecObjKlassDuplicatorMethod */
	    NULL			/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, NULL); 
    } 
    return(klass);   
}

void
xmlSecObjDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecObjKlassPtr klass = xmlSecObjKlassCast(xmlSecObjGetKlass(obj));

    xmlSecAssert(obj != NULL);
    xmlSecAssert(output != NULL);
    xmlSecAssert(klass != NULL);
    xmlSecAssert(klass->debugDump != NULL);
    
    klass->debugDump(obj, output, level);
}

void
xmlSecObjDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecObjKlassPtr klass = xmlSecObjKlassCast(xmlSecObjGetKlass(obj));

    xmlSecAssert(obj != NULL);
    xmlSecAssert(output != NULL);
    xmlSecAssert(klass != NULL);
    xmlSecAssert(klass->debugXmlDump != NULL);
    
    klass->debugXmlDump(obj, output, level);
}

void
xmlSecObjDebugIndent(FILE* output, size_t level) {
    size_t i;
    xmlSecAssert(output != NULL);
    
    for(i = 0; i < level; ++i) {
	fprintf(output, "  ");
    }
}

static void
xmlSecObjKlassInitImp(xmlSecObjKlassPtr klass) {
    xmlSecObjKlassPtr objKlass = xmlSecObjKlassCast(klass);
    
    xmlSecAssert(objKlass);
    objKlass->debugDump 	= xmlSecObjDebugDumpImp;
    objKlass->debugXmlDump 	= xmlSecObjDebugXmlDumpImp;
}

static void
xmlSecObjDebugDumpImp(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecAssert(output != NULL);
    xmlSecAssert(obj != NULL);
    
    xmlSecObjDebugIndent(output, level);
    fprintf(output, "klass name=%s\n", 
	    xmlSecObjKlassGetKlassName(xmlSecObjGetKlass(obj)));
}

static void
xmlSecObjDebugXmlDumpImp(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecAssert(output != NULL);
    xmlSecAssert(obj != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<KlassName>%s</KlassName>\n", 
	    xmlSecObjKlassGetKlassName(xmlSecObjGetKlass(obj)));
}
