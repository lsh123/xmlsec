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
#include <xmlsec/base64.h>
#include <xmlsec/membuf.h>
#include <xmlsec/errors.h>

/*****************************************************************************
 *
 * xmlSecBuffer
 *
 ****************************************************************************/
xmlSecBufferPtr 
xmlSecBufferCreate(size_t size) {
    xmlSecBufferPtr buf;
    int ret;
    
    buf = (xmlSecBufferPtr)xmlMalloc(sizeof(xmlSecBuffer));
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBuffer)=%d", sizeof(xmlSecBuffer));
	return(NULL);
    }

    ret = xmlSecBufferInitialize(buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferInitialize(size=%d)", size);
	xmlSecBufferDestroy(buf);
	return(NULL);
    }
    
    return(buf);
}

void 
xmlSecBufferDestroy(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);
    
    xmlSecBufferFinalize(buf);
    xmlFree(buf);
}

int 
xmlSecBufferInitialize(xmlSecBufferPtr buf, size_t size) {
    xmlSecAssert2(buf != NULL, -1);

    buf->data = NULL;
    buf->size = buf->maxSize = 0;
    buf->allocMode = xmlSecAllocExact;
        
    return(xmlSecBufferSetMaxSize(buf, size));
}

void 
xmlSecBufferFinalize(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);

    xmlSecBufferEmpty(buf);    
    if(buf->data != 0) {
	xmlFree(buf->data);
    }
    buf->data = NULL;
    buf->size = buf->maxSize = 0;
}

void
xmlSecBufferEmpty(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);
    
    if(buf->data != 0) {
	xmlSecAssert(buf->maxSize > 0);

	memset(buf->data, 0, buf->maxSize);
    }
    buf->size = 0;
}

unsigned char* 
xmlSecBufferGetData(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, NULL);
    
    return(buf->data);
}

int 
xmlSecBufferSetData(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);

    xmlSecBufferEmpty(buf);
    if(size > 0) {
	xmlSecAssert2(data != NULL, -1);
    
	ret = xmlSecBufferSetMaxSize(buf, size);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferSetMaxSize(size=%d)", size);
	    return(-1);
        }
	
	memcpy(buf->data, data, size);
    }
    
    buf->size = size;    
    return(0);
}

size_t 
xmlSecBufferGetSize(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, 0);

    return(buf->size);
}

int 
xmlSecBufferSetSize(xmlSecBufferPtr buf, size_t size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);

    ret = xmlSecBufferSetMaxSize(buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetMaxSize(size=%d)", size);
	return(-1);
    }
    
    
    buf->size = size;
    return(0);
}

size_t 
xmlSecBufferGetMaxSize(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, 0);

    return(buf->maxSize);
}

int 
xmlSecBufferSetMaxSize(xmlSecBufferPtr buf, size_t size) {
    unsigned char* newData;
    size_t newSize;
    
    xmlSecAssert2(buf != NULL, -1);
    if(size <= buf->maxSize) {
	return(0);
    }
    
    switch(buf->allocMode) {
	case xmlSecAllocExact:
	    newSize = size + 8;
	    break;
	case xmlSecAllocDouble:
	    newSize = 2 * size + 8;
	    break;
	default:
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"unknown allocation mode %d", buf->allocMode);
	    return(-1);
    }
    
    newData = (unsigned char*)xmlRealloc(buf->data, newSize);
    if(newData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", newSize);
	return(-1);
    }
    
    buf->data = newData;
    buf->maxSize = newSize;

    if(buf->size < buf->maxSize) {
	xmlSecAssert2(buf->data != NULL, -1);
	memset(buf->data + buf->size, 0, buf->maxSize - buf->size);
    }
    
    return(0);
}


int 
xmlSecBufferAppend(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);

    if(size > 0) {
	xmlSecAssert2(data != NULL, -1);
    
        ret = xmlSecBufferSetMaxSize(buf, buf->size + size);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferSetMaxSize(size=%d)", buf->size + size);
	    return(-1);
	}
	
	memcpy(buf->data + buf->size, data, size);
	buf->size += size;    
    }
    
    return(0);
}

int
xmlSecBufferPrepend(xmlSecBufferPtr buf, const unsigned char* data, size_t size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);

    if(size > 0) {
	xmlSecAssert2(data != NULL, -1);
    
	ret = xmlSecBufferSetMaxSize(buf, buf->size + size);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferSetMaxSize(size=%d)", buf->size + size);
	    return(-1);
	}

	memmove(buf->data + size, buf->data, buf->size);	
	memcpy(buf->data, data, size);
	buf->size += size;    
    }
    
    return(0);
}

int 
xmlSecBufferRemoveHead(xmlSecBufferPtr buf, size_t size) {
    xmlSecAssert2(buf != NULL, -1);
    
    if(size < buf->size) {
	xmlSecAssert2(buf->data != NULL, -1);
	
	buf->size -= size;
	memmove(buf->data, buf->data + size, buf->size);
    } else {
	buf->size = 0;
    }
    if(buf->size < buf->maxSize) {
	xmlSecAssert2(buf->data != NULL, -1);
	memset(buf->data + buf->size, 0, buf->maxSize - buf->size);
    }
    return(0);
}

int 
xmlSecBufferRemoveTail(xmlSecBufferPtr buf, size_t size) {
    xmlSecAssert2(buf != NULL, -1);

    if(size < buf->size) {
	buf->size -= size;
    } else {
	buf->size = 0;
    }
    if(buf->size < buf->maxSize) {
	xmlSecAssert2(buf->data != NULL, -1);
	memset(buf->data + buf->size, 0, buf->maxSize - buf->size);
    }
    return(0);
}

int 
xmlSecBufferBase64NodeContentRead(xmlSecBufferPtr buf, xmlNodePtr node) {
    xmlChar* content;
    size_t size;
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    content = xmlNodeGetContent(node);
    if(content == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "%s", (node->name != NULL) ? node->name : BAD_CAST "NULL");
	return(-1);		
    }
    
    /* base64 decode size is less than input size */
    ret = xmlSecBufferSetMaxSize(buf, xmlStrlen(content));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetMaxSize");
	xmlFree(content);
	return(-1);
    }
    
    ret = xmlSecBase64Decode(content, xmlSecBufferGetData(buf), xmlSecBufferGetMaxSize(buf));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode");
	xmlFree(content);
	return(-1);
    }
    size = ret;

    ret = xmlSecBufferSetSize(buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetSize(%d)", size);
	xmlFree(content);
	return(-1);
    }
    xmlFree(content);
    
    return(0);
}


int 
xmlSecBufferBase64NodeContentWrite(xmlSecBufferPtr buf, xmlNodePtr node, int columns) {
    xmlChar* content;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    content = xmlSecBase64Encode(xmlSecBufferGetData(buf), xmlSecBufferGetSize(buf), columns);
    if(content == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Encode");
	return(-1);
    }
    xmlNodeAddContent(node, content);
    xmlFree(content);
    
    return(0);
}
















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
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
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
 * Returns the xmlSecBufferPtr. If @removeBuffer is set to 1 then the buffer 
 * is removed from transform and the caller is responsible for freeing it
 */
xmlSecBufferPtr
xmlSecMemBufTransformGetBuffer(xmlSecTransformPtr transform, int removeBuffer) {
    xmlSecBufferPtr ptr;

    xmlSecAssert2(transform != NULL, NULL);
    
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecMemBuf");
	return(NULL);
    }
    
    ptr = (xmlSecBufferPtr)(transform->reserved0);
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
	xmlSecBufferDestroy((xmlSecBufferPtr)(transform->reserved0)); 
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
	transform->reserved0 = xmlSecBufferCreate(0);
	if(transform->reserved0 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlSecBufferCreate");
	    return(-1);
	}
    }
    
    xmlSecBufferAppend((xmlSecBufferPtr)(transform->reserved0), buf, ret);
    return(ret);
}

/**
 * xmlSecMemBufTransformWrite
 */
static int
xmlSecMemBufTransformWrite(xmlSecTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    xmlSecBufferPtr ptr;
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
	transform->reserved0 = ptr = xmlSecBufferCreate(0);
	if(transform->reserved0 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        XMLSEC_ERRORS_R_XML_FAILED,
			"xmlSecBufferCreate");
	    return(-1);
	}
    } else {
	ptr = (xmlSecBufferPtr)(transform->reserved0);
    }
    
    if(transform->next == NULL) {
	/* nothing to write to */
	xmlSecBufferAppend(ptr, buf, size);	
	return(size);
    }
    
    ret = xmlSecTransformWriteBin((xmlSecTransformPtr)(transform->next), buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformWrite - %d", ret);
	return(-1);
    }

    xmlSecBufferAppend(ptr, buf, ret);
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


