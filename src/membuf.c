/** 
 * XMLSec library
 *
 * Memory buffer transform
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
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/keys.h>
#include <xmlsec/membuf.h>
#include <xmlsec/errors.h>

static xmlSecTransformPtr xmlSecMemBufTransformCreate	(xmlSecTransformId id);
static void		xmlSecMemBufTransformDestroy	(xmlSecTransformPtr transform);
static int  		xmlSecMemBufTransformRead	(xmlSecTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
static int  		xmlSecMemBufTransformWrite	(xmlSecTransformPtr transform, 
							 const unsigned char *buf, 
							 size_t size);
static int  		xmlSecMemBufTransformFlush	(xmlSecTransformPtr transform);

static const struct _xmlSecTransformKlass xmlSecMemBufTransformId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "membuf",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    0,					/* xmlSecAlgorithmUsage usage; */
    NULL,				/* const xmlChar href; */

    xmlSecMemBufTransformCreate, 	/* xmlSecTransformCreateMethod create; */
    xmlSecMemBufTransformDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    
    /* binary methods */
    NULL,
    xmlSecMemBufTransformRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecMemBufTransformWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecMemBufTransformFlush,		/* xmlSecTransformFlushMethod flushBin; */
    
    NULL,
    NULL,
};
xmlSecTransformId xmlSecMemBuf = (xmlSecTransformId)&xmlSecMemBufTransformId; 

/**
 * xmlSecMemBufTransformGetBuffer:
 * @transform: the pointer to memory buffer transform.
 * @removeBuffer: the flag that indicates whether the buffer
 * 	will be removed from the transform.
 * 
 * Gets the memory transform buffer. 
 *
 * Returns the xmlBufferPtr. If @removeBuffer is set to 1 then the buffer 
 * is removed from transform and the caller is responsible for freeing it
 */
xmlBufferPtr
xmlSecMemBufTransformGetBuffer(xmlSecTransformPtr transform, int removeBuffer) {
    xmlBufferPtr ptr;

    xmlSecAssert2(transform != NULL, NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMemBuf");
	return(NULL);
    }
    
    ptr = (xmlBufferPtr)(transform->reserved0);
    if(removeBuffer) {
	transform->reserved0 = NULL;
    }
    return(ptr);
}

/**
 * xmlSecMemBufTransformCreate:
 */
static xmlSecTransformPtr 
xmlSecMemBufTransformCreate(xmlSecTransformId id) {
    xmlSecTransformPtr ptr;

    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecMemBuf){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMemBuf");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecTransform and fill the fields.
     */
    ptr = (xmlSecTransformPtr) xmlMalloc(sizeof(xmlSecTransform));
    if(ptr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecTransform)=%d", 
		    sizeof(xmlSecTransform));
	return(NULL);
    }
    memset(ptr, 0, sizeof(xmlSecTransform));
    
    ptr->id = (xmlSecTransformId)id;
    return((xmlSecTransformPtr)ptr);    
}

/**
 * xmlSecMemBufTransformDestroy:
 */
static void
xmlSecMemBufTransformDestroy(xmlSecTransformPtr transform) {
    xmlSecAssert(transform != NULL);
                
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMemBuf");
	return;
    }
    
    if(transform->reserved0 != NULL) {
	xmlBufferEmpty((xmlBufferPtr)(transform->reserved0));
	xmlBufferFree((xmlBufferPtr)(transform->reserved0)); 
    }    
    memset(transform, 0, sizeof(xmlSecTransform));
    xmlFree(transform);    
}

/**
 * xmlSecMemBufTransformRead
 */
static int
xmlSecMemBufTransformRead(xmlSecTransformPtr transform, 
			unsigned char *buf, size_t size) {
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);

    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMemBuf");
	return(-1);
    }

    if(transform->prev == NULL) {
	/* nothing to read */
	return(0);
    }
    
    ret = xmlSecTransformReadBin((xmlSecTransformPtr)(transform->prev), buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformRead - %d", ret);
	return(-1);
    }
    
    if(ret == 0) {
	/* we are done */
	return(0);
    }
    
    if(transform->reserved0 == NULL) {
	transform->reserved0 = xmlBufferCreate();
	if(transform->reserved0 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlBufferCreate");
	    return(-1);
	}
    }
    
    xmlBufferAdd((xmlBufferPtr)(transform->reserved0), buf, ret);
    return(ret);
}

/**
 * xmlSecMemBufTransformWrite
 */
static int
xmlSecMemBufTransformWrite(xmlSecTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    xmlBufferPtr ptr;
    int ret;
            
    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);    
    
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMemBuf");
	return(-1);
    }

    if((buf == NULL) || (size == 0)) {
	/* nothing to write */
	return(0);
    }
    
    if(transform->reserved0 == NULL) {
	transform->reserved0 = ptr = xmlBufferCreate();
	if(transform->reserved0 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_XML_FAILED,
			"xmlBufferCreate");
	    return(-1);
	}
    } else {
	ptr = (xmlBufferPtr)(transform->reserved0);
    }
    
    if(transform->next == NULL) {
	/* nothing to write to */
	xmlBufferAdd(ptr, buf, size);	
	return(size);
    }
    
    ret = xmlSecTransformWriteBin((xmlSecTransformPtr)(transform->next), buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformWrite - %d", ret);
	return(-1);
    }

    xmlBufferAdd(ptr, buf, ret);
    return(ret);
}

/**
 * xmlSecMemBufTransformFlush:
 */
static int
xmlSecMemBufTransformFlush(xmlSecTransformPtr transform) {
    int ret;

    xmlSecAssert2(transform != NULL, -1);
        
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMemBuf");
	return(-1);
    }
    
    if(transform->next == NULL) { 
	/* nothing to flush */
	return(0);
    }

    ret = xmlSecTransformFlushBin((xmlSecTransformPtr)(transform->next));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformFlush");
	return(-1);
    }

    return(ret);
}


