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


/*****************************************************************************
 *
 * Memory Buffer Transform
 * 
 * reserved0 --> the result buffer (xmlSecBufferPtr)
 * 
 ****************************************************************************/
#define xmlSecTransformMemBufGetBuf(transform) \
    ((xmlSecBufferPtr)((transform)->reserved0))

static int		xmlSecTransformMemBufInitialize		(xmlSecTransformPtr transform);
static void		xmlSecTransformMemBufFinalize		(xmlSecTransformPtr transform);
static int  		xmlSecTransformMemBufExecute		(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecTransformMemBufKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    xmlSecNameMemBuf,			/* const xmlChar* name; */
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    0,					/* xmlSecAlgorithmUsage usage; */
    NULL,				/* const xmlChar href; */

    xmlSecTransformMemBufInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformMemBufFinalize,	/* xmlSecTransformFianlizeMethod finalize; */
    NULL,				/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformMemBufExecute,	/* xmlSecTransformExecuteMethod execute; */
    
    /* binary methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */
    
    NULL,
    NULL,
};

xmlSecTransformId 
xmlSecTransformMemBufGetKlass(void) {
    return(&xmlSecTransformMemBufKlass);
}

/**
 * xmlSecTransformMemBufGetBuffer:
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
xmlSecTransformMemBufGetBuffer(xmlSecTransformPtr transform, int removeBuffer) {
    xmlSecBufferPtr ptr;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformMemBufId), NULL);
    xmlSecAssert2(xmlSecTransformMemBufGetBuf(transform) != NULL, NULL);
    
    ptr = xmlSecTransformMemBufGetBuf(transform);
    if(removeBuffer) {
	transform->reserved0 = NULL;
    }
    return(ptr);
}

static int
xmlSecTransformMemBufInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformMemBufId), -1);

    transform->reserved0 = xmlSecBufferCreate(0);
    if(transform->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferCreate");
	return(-1);
    }
    return(0);    
}

static void
xmlSecTransformMemBufFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecTransformMemBufId));
    
    if(xmlSecTransformMemBufGetBuf(transform) != NULL) {
	xmlSecBufferDestroy(xmlSecTransformMemBufGetBuf(transform)); 
    }    
    transform->reserved0 = NULL;
}

static int 
xmlSecTransformMemBufExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr buffer;
    xmlSecBufferPtr in, out;
    size_t inSize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformMemBufId), -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    buffer = xmlSecTransformMemBufGetBuf(transform);
    xmlSecAssert2(buffer != NULL, -1);
    
    in = &(transform->inBuf);
    out = &(transform->outBuf);
    
    inSize = xmlSecBufferGetSize(in);

    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    }
    
    if(transform->status == xmlSecTransformStatusWorking) {	
	/* just copy everything from in to our buffer and out */
	ret = xmlSecBufferAppend(buffer, xmlSecBufferGetData(in), inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferAppend(buffer, %d)", inSize);
	    return(-1);
	}
	
	ret = xmlSecBufferAppend(out, xmlSecBufferGetData(in), inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferAppend(out, %d)", inSize);
	    return(-1);
	}
	
	ret = xmlSecBufferRemoveHead(in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferRemoveHead(%d)", inSize);
	    return(-1);
	}
	    
	if(last != 0) {
	    transform->status = xmlSecTransformStatusFinished;
	}
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(inSize == 0, -1);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "invalid transform status %d", transform->status);
	return(-1);
    }
    return(0);
}
