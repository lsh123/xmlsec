/** 
 * XMLSec library
 *
 * Memory buffer transform
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>

/*****************************************************************************
 *
 * xmlSecBuffer
 *
 ****************************************************************************/
static xmlSecAllocMode gAllocMode = xmlSecAllocModeDouble;
static size_t gInitialSize = 1024;

void 
xmlSecBufferSetDefaultAllocMode(xmlSecAllocMode defAllocMode, size_t defInitialSize) {
    xmlSecAssert(defInitialSize > 0);
    
    gAllocMode = defAllocMode;
    gInitialSize = defInitialSize;
}

xmlSecBufferPtr 
xmlSecBufferCreate(size_t size) {
    xmlSecBufferPtr buf;
    int ret;
    
    buf = (xmlSecBufferPtr)xmlMalloc(sizeof(xmlSecBuffer));
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBuffer",
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBuffer)=%d", sizeof(xmlSecBuffer));
	return(NULL);
    }
    
    ret = xmlSecBufferInitialize(buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBuffer",
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
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
    buf->allocMode = gAllocMode;
        
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
			"xmlSecBuffer",
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", size);
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
		    "xmlSecBuffer",
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
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
    size_t newSize = 0;
    
    xmlSecAssert2(buf != NULL, -1);
    if(size <= buf->maxSize) {
	return(0);
    }
    
    switch(buf->allocMode) {
	case xmlSecAllocModeExact:
	    newSize = size + 8;
	    break;
	case xmlSecAllocModeDouble:
	    newSize = 2 * size + 32;
	    break;
    }

    if(newSize < gInitialSize) {
	newSize = gInitialSize;
    }
    
    newData = (unsigned char*)xmlRealloc(buf->data, newSize);
    if(newData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBuffer",
		    "xmlRealloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d", newSize);
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
			"xmlSecBuffer",
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", buf->size + size);
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
			"xmlSecBuffer",
			"xmlSecBufferSetMaxSize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", buf->size + size);
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
		    "xmlSecBuffer",
		    "xmlNodeGetContent",
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "node=%s", (node->name != NULL) ? node->name : BAD_CAST "NULL");
	return(-1);		
    }
    
    /* base64 decode size is less than input size */
    ret = xmlSecBufferSetMaxSize(buf, xmlStrlen(content));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBuffer",
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(content);
	return(-1);
    }
    
    ret = xmlSecBase64Decode(content, xmlSecBufferGetData(buf), xmlSecBufferGetMaxSize(buf));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBuffer",
		    "xmlSecBase64Decode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(content);
	return(-1);
    }
    size = ret;

    ret = xmlSecBufferSetSize(buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBuffer",
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
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
		    "xmlSecBuffer",
		    "xmlSecBase64Encode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    xmlNodeAddContent(node, content);
    xmlFree(content);
    
    return(0);
}


/************************************************************************
 *
 * IO buffer
 *
 ************************************************************************/ 
static int	xmlSecBufferIOWrite				(xmlSecBufferPtr buf,
								 const unsigned char *data,
								 size_t size);		
static int	xmlSecBufferIOClose				(xmlSecBufferPtr buf);

/**
 * xmlSecBufferCreateOutputBuffer:
 *
 * Caller is responsible for destroying @buf (if necessary)
 * when processing is done. 
 */
xmlOutputBufferPtr 
xmlSecBufferCreateOutputBuffer(xmlSecBufferPtr buf) {
    return(xmlOutputBufferCreateIO((xmlOutputWriteCallback)xmlSecBufferIOWrite,
				     (xmlOutputCloseCallback)xmlSecBufferIOClose,
				     buf,
				     NULL)); 
}

static int 
xmlSecBufferIOWrite(xmlSecBufferPtr buf, const unsigned char *data, size_t size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    
    ret = xmlSecBufferAppend(buf, data, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecBuffer",
		    "xmlSecBufferAppend",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
	return(-1);
    }
    
    return(size);    
}

static int 
xmlSecBufferIOClose(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, -1);
    
    /* just do nothing */
    return(0);
}

