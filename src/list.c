/**		
 * XMLSec library
 *
 * Serializable Objects
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/errors.h>

static void		xmlSecListKlassInit		(xmlSecObjKlassPtr klass);
static int		xmlSecListConstructor		(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr obj);
static int		xmlSecListDuplicator		(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst, 
							 xmlSecObjPtr src);
static void		xmlSecListDestructor		(xmlSecObjKlassPtr klass, 
							 xmlSecObjPtr dst);
static void		xmlSecListDebugDump		(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static void		xmlSecListDebugXmlDump		(xmlSecObjPtr obj,
							 FILE* output,
							 size_t level);
static int		xmlSecListReallocate		(xmlSecListPtr list,
							size_t delta);
/*********************************************************************
 *
 * Binary List
 *
 *********************************************************************/
xmlSecObjKlassPtr
xmlSecListKlassGet(void) {
    static xmlSecObjKlassPtr klass = NULL;
    static xmlSecListKlass kklass;
    
    if(klass == NULL) {
	static xmlSecObjKlassInfo kklassInfo = {
	    /* klass data */
	    sizeof(xmlSecListKlass),
	    "xmlSecList",
	    xmlSecListKlassInit, 	/* xmlSecObjKlassInitMethod */
	    NULL,			/* xmlSecObjKlassFinalizeMethod */
	    
	    /* obj info */
	    sizeof(xmlSecList),
	    xmlSecListConstructor,	/* xmlSecObjKlassConstructorMethod */
	    xmlSecListDuplicator,	/* xmlSecObjKlassDuplicatorMethod */
	    xmlSecListDestructor,	/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecObjKlassId); 
    } 
    return(klass);   
}

xmlSecPtr
xmlSecListGetData(xmlSecListPtr list, size_t pos) {
    xmlSecAssert2(list != NULL, NULL);
    
    return((pos < list->size) ? list->data[pos] : NULL);
}

size_t
xmlSecListGetSize(xmlSecListPtr list) {
    xmlSecAssert2(list != NULL, 0);
    
    return(list->size);
}

int
xmlSecListFind(xmlSecListPtr list, xmlSecPtr data) {
    size_t i;
    
    xmlSecAssert2(list != NULL, -1);

    for(i = 0; i < list->size; ++i) {
	xmlSecAssert2(list->data != NULL, -1);
	if(list->data[i] == data) {
	    return(i);
	}
    }
    return(-1);
}

int
xmlSecListAppend(xmlSecListPtr list, xmlSecPtr data) {
    xmlSecAssert2(list != NULL, -1);
    
    return (xmlSecListInsert(list, list->size, data));
}

int
xmlSecListPrepend(xmlSecListPtr list, xmlSecPtr data) {
    xmlSecAssert2(list != NULL, -1);
    
    return (xmlSecListInsert(list, 0, data));
}

int
xmlSecListInsert(xmlSecListPtr list, size_t pos, xmlSecPtr data	) {
    size_t i;
    int ret;
    
    xmlSecAssert2(list != NULL, -1);
    xmlSecAssert2(pos <= list->size, -1);
    xmlSecAssert2(data != NULL, -1);
    
    
    ret = xmlSecListReallocate(list, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecListReallocate(delta=%d)", 1);
	return(-1);			
    }
    xmlSecAssert2(list->data != NULL, -1);
    xmlSecAssert2(list->maxSize >= list->size + 1, -1);
    
    if(list->size > 0) {
	for(i = list->size - 1; i >= pos; --i) {
	    list->data[i + 1] = list->data[i];
	}
    }
    list->data[pos] = data;
    ++list->size;
    return(0);    
}

void
xmlSecListRemove(xmlSecListPtr list, size_t pos) {
    size_t i;
    
    xmlSecAssert(list != NULL);
    xmlSecAssert2(pos < list->size, -1);
    
    if(list->size > 0) {
	for(i = list->size - 1; i > pos ; --i) {
    	    xmlSecAssert(list->data != NULL);
    	    list->data[i - 1] = list->data[i];
	}
    }
    --list->size;
}

void
xmlSecListEmpty(xmlSecListPtr list) {
    xmlSecAssert(list != NULL);

    if(list->maxSize > 0) {
	xmlSecAssert(list->data != NULL);
	memset(list->data, 0, list->maxSize * sizeof(xmlSecPtr));
    }
    list->size = 0;
}

static void
xmlSecListKlassInit(xmlSecObjKlassPtr klass) {
    klass->debugDump 		= xmlSecListDebugDump;
    klass->debugXmlDump 	= xmlSecListDebugXmlDump;
}

static int
xmlSecListConstructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr obj) {
    xmlSecListPtr list = xmlSecListCast(obj);

    xmlSecAssert2(list != NULL, -1);

    list->data 	= NULL;
    list->size	= 0;
    list->maxSize= 0;
    
    return(0);
}

static int
xmlSecListDuplicator(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
			xmlSecObjPtr dst, xmlSecObjPtr src) {
    xmlSecListPtr listDst = xmlSecListCast(dst);
    xmlSecListPtr listSrc = xmlSecListCast(src);
    size_t i;
    int ret;
        
    xmlSecAssert2(listDst != NULL, -1);
    xmlSecAssert2(listSrc != NULL, -1);

    xmlSecListEmpty(listDst);
    for(i = 0; i < xmlSecListGetSize(listSrc); ++i) {
	ret = xmlSecListAppend(listDst, xmlSecListGetData(listSrc, i));
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecListAppend");
	    return(-1);			
	}
    }    
    return(0);
}

static void
xmlSecListDestructor(xmlSecObjKlassPtr klass ATTRIBUTE_UNUSED, 
				    xmlSecObjPtr obj) {
    xmlSecListPtr list = xmlSecListCast(obj);

    xmlSecAssert(list != NULL);

    xmlSecListEmpty(list);
    if(list->data != NULL) {
	xmlFree(list->data);
    }
    list->data   = NULL;
    list->size	 = 0;
    list->maxSize= 0;
}

static void
xmlSecListDebugDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecListPtr list = xmlSecListCast(obj);

    xmlSecAssert(list != NULL);
    xmlSecAssert(output != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "list size: %d\n", list->size);
}

static void
xmlSecListDebugXmlDump(xmlSecObjPtr obj, FILE* output, size_t level) {
    xmlSecListPtr list = xmlSecListCast(obj);
	    
    xmlSecAssert(list != NULL);
    xmlSecAssert(output != NULL);

    xmlSecObjDebugIndent(output, level);
    fprintf(output, "<List size=\"%d\"/>\n", list->size);
}

static int
xmlSecListReallocate(xmlSecListPtr list, size_t delta) {
    xmlSecPtr* p;
    size_t size;
    
    xmlSecAssert2(list != NULL, -1);
    
    if(list->size + delta < list->maxSize) {
	return(0);
    }
    
    size = 4 * (list->size + delta) / 3 + 1;
    p = (xmlSecPtr*)xmlRealloc(list->data, size * sizeof(xmlSecPtr));
    if(p == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_MALLOC_FAILED,	
		    "%d", size);
	return(-1);			
    }
    
    list->data = p;
    list->maxSize = size;
    return(0);	
}

