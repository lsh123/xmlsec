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

/*********************************************************************
 *
 * Binary List
 *
 *********************************************************************/
static void		xmlSecListKlassInit		(xmlSecObjKlassPtr klass);

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
	    NULL,			/* xmlSecObjKlassConstructorMethod */
	    NULL,			/* xmlSecObjKlassDuplicatorMethod */
	    NULL,			/* xmlSecObjKlassDestructorMethod */
	};
	klass = xmlSecObjKlassRegister(&kklass, sizeof(kklass), 
				       &kklassInfo, xmlSecBaseBufferKlassId); 
    } 
    return(klass);   
}

xmlSecPtr
xmlSecListGetData(xmlSecListPtr list, size_t pos) {
    xmlSecBaseBufferPtr baseBuf = xmlSecBaseBufferCast(list);
    xmlSecPtr* data;
    
    xmlSecAssert2(baseBuf != NULL, NULL);
    
    data = (xmlSecPtr*)xmlSecBaseBufferGetData(baseBuf, pos);
    return((data != NULL) ? (*data) : NULL);
}

size_t
xmlSecListGetSize(xmlSecListPtr list) {
    xmlSecBaseBufferPtr baseBuf = xmlSecBaseBufferCast(list);
    
    xmlSecAssert2(baseBuf != NULL, 0);
    
    return(xmlSecBaseBufferGetSize(baseBuf));
}

int
xmlSecListFind(xmlSecListPtr list, xmlSecPtr data) {
    xmlSecBaseBufferPtr baseBuf = xmlSecBaseBufferCast(list);
    xmlSecPtr item;
    size_t size;
    size_t i;

    xmlSecAssert2(baseBuf != NULL, -1);

    size = xmlSecBaseBufferGetSize(baseBuf);
    for(i = 0; i < size; ++i) {
	item = xmlSecListGetData(list, i);
	if(item == data) {
	    return(i);
	}
    }
    return(-1);
}

int
xmlSecListAppend(xmlSecListPtr list, xmlSecPtr data) {
    xmlSecAssert2(list != NULL, -1);
    
    return (xmlSecListInsert(list, xmlSecListGetSize(list), data));
}

int
xmlSecListPrepend(xmlSecListPtr list, xmlSecPtr data) {
    xmlSecAssert2(list != NULL, -1);
    
    return (xmlSecListInsert(list, 0, data));
}

int
xmlSecListInsert(xmlSecListPtr list, size_t pos, xmlSecPtr data) {
    xmlSecBaseBufferPtr baseBuf = xmlSecBaseBufferCast(list);
    xmlSecPtr* item;
    int ret;

    xmlSecAssert2(baseBuf != NULL, -1);
    xmlSecAssert2(pos <= baseBuf->size, -1);
    xmlSecAssert2(data != NULL, -1);
    
    ret = xmlSecBaseBufferInsert(baseBuf, pos, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
    		    XMLSEC_ERRORS_R_XMLSEC_FAILED,	
		    "xmlSecBaseBufferInsert(pos=%d, size=%d)", pos, 1);
	return(-1);			
    }

    item = (xmlSecPtr*)xmlSecBaseBufferGetData(baseBuf, pos);
    xmlSecAssert2(item != NULL, -1);
    
    (*item) = data;
    return(0);    
}

void
xmlSecListRemove(xmlSecListPtr list, size_t pos) {
    xmlSecBaseBufferPtr baseBuf = xmlSecBaseBufferCast(list);

    xmlSecAssert(baseBuf != NULL);
    
    xmlSecBaseBufferRemove(baseBuf, pos, 1);
}

void
xmlSecListEmpty(xmlSecListPtr list) {
    xmlSecBaseBufferPtr baseBuf = xmlSecBaseBufferCast(list);

    xmlSecAssert(baseBuf != NULL);
    
    xmlSecBaseBufferEmpty(baseBuf);
}

static void
xmlSecListKlassInit(xmlSecObjKlassPtr klass) {
    xmlSecBaseBufferKlassPtr baseBufferKlass = (xmlSecBaseBufferKlassPtr)klass;

    baseBufferKlass->itemSize	= sizeof(xmlSecPtr);    
}

