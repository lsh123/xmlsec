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
static int  		xmlSecMemBufTransformRead	(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
static int  		xmlSecMemBufTransformWrite	(xmlSecBinTransformPtr transform, 
							 const unsigned char *buf, 
							 size_t size);
static int  		xmlSecMemBufTransformFlush	(xmlSecBinTransformPtr transform);

static const struct _xmlSecBinTransformIdStruct xmlSecMemBufTransformId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    0,					/* xmlSecAlgorithmUsage usage; */
    NULL,				/* const xmlChar href; */

    xmlSecMemBufTransformCreate, 	/* xmlSecTransformCreateMethod create; */
    xmlSecMemBufTransformDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    NULL,				/* xmlSecTransformReadMethod read; */
    
    /* binary methods */
    xmlSecKeyIdUnknown,
    xmlSecKeyTypeAny,			/* xmlSecKeyType encryption; */
    xmlSecKeyTypeAny,			/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeNone,
    NULL,				/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecMemBufTransformRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecMemBufTransformWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecMemBufTransformFlush,		/* xmlSecBinTransformFlushMethod flushBin; */
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
    
    ptr = (xmlBufferPtr)(transform->data);
    if(removeBuffer) {
	transform->data = NULL;
    }
    return(ptr);
}

/**
 * xmlSecMemBufTransformCreate:
 */
static xmlSecTransformPtr 
xmlSecMemBufTransformCreate(xmlSecTransformId id) {
    xmlSecBinTransformPtr ptr;

    xmlSecAssert2(id != NULL, NULL);
        
    if(id != xmlSecMemBuf){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMemBuf");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBinTransform and fill the fields.
     */
    ptr = (xmlSecBinTransformPtr) xmlMalloc(sizeof(xmlSecBinTransform));
    if(ptr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBinTransform)=%d", 
		    sizeof(xmlSecBinTransform));
	return(NULL);
    }
    memset(ptr, 0, sizeof(xmlSecBinTransform));
    
    ptr->id = (xmlSecBinTransformId)id;
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
    
    if(transform->data != NULL) {
	xmlBufferEmpty((xmlBufferPtr)(transform->data));
	xmlBufferFree((xmlBufferPtr)(transform->data)); 
    }    
    memset(transform, 0, sizeof(xmlSecBinTransform));
    xmlFree(transform);    
}

/**
 * xmlSecMemBufTransformRead
 */
static int
xmlSecMemBufTransformRead(xmlSecBinTransformPtr transform, 
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
    
    ret = xmlSecBinTransformRead((xmlSecTransformPtr)(transform->prev), buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBinTransformRead - %d", ret);
	return(-1);
    }
    
    if(ret == 0) {
	/* we are done */
	return(0);
    }
    
    if(transform->data == NULL) {
	transform->data = xmlBufferCreate();
	if(transform->data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlBufferCreate");
	    return(-1);
	}
    }
    
    xmlBufferAdd((xmlBufferPtr)(transform->data), buf, ret);
    return(ret);
}

/**
 * xmlSecMemBufTransformWrite
 */
static int
xmlSecMemBufTransformWrite(xmlSecBinTransformPtr transform, 
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
    
    if(transform->data == NULL) {
	transform->data = ptr = xmlBufferCreate();
	if(transform->data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_XML_FAILED,
			"xmlBufferCreate");
	    return(-1);
	}
    } else {
	ptr = (xmlBufferPtr)(transform->data);
    }
    
    if(transform->next == NULL) {
	/* nothing to write to */
	xmlBufferAdd(ptr, buf, size);	
	return(size);
    }
    
    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)(transform->next), buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBinTransformWrite - %d", ret);
	return(-1);
    }

    xmlBufferAdd(ptr, buf, ret);
    return(ret);
}

/**
 * xmlSecMemBufTransformFlush:
 */
static int
xmlSecMemBufTransformFlush(xmlSecBinTransformPtr transform) {
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

    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)(transform->next));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBinTransformFlush");
	return(-1);
    }

    return(ret);
}


