/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Memory buffer.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>

/*****************************************************************************
 *
 * xmlSecBuffer
 *
 ****************************************************************************/
static xmlSecAllocMode gAllocMode = xmlSecAllocModeDouble;
static xmlSecSize gInitialSize = 1024;

/**
 * xmlSecBufferSetDefaultAllocMode:
 * @defAllocMode:	the new default buffer allocation mode.
 * @defInitialSize:	the new default buffer minimal intial size.
 * 
 * Sets new global default allocation mode and minimal intial size.
 */
void 
xmlSecBufferSetDefaultAllocMode(xmlSecAllocMode defAllocMode, xmlSecSize defInitialSize) {
    xmlSecAssert(defInitialSize > 0);
    
    gAllocMode = defAllocMode;
    gInitialSize = defInitialSize;
}

/**
 * xmlSecBufferCreate:
 * @size: 		the intial size.
 *
 * Allocates and initalizes new memory buffer with given size.
 * Caller is responsible for calling #xmlSecBufferDestroy function
 * to free the buffer.
 *
 * Returns pointer to newly allocated buffer or NULL if an error occurs.
 */
xmlSecBufferPtr 
xmlSecBufferCreate(xmlSecSize size) {
    xmlSecBufferPtr buf;
    int ret;
    
    buf = (xmlSecBufferPtr)xmlMalloc(sizeof(xmlSecBuffer));
    if(buf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBuffer)=%d", sizeof(xmlSecBuffer));
	return(NULL);
    }
    
    ret = xmlSecBufferInitialize(buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
	xmlSecBufferDestroy(buf);
	return(NULL);
    }
    return(buf);
}

/**
 * xmlSecBufferDestroy:
 * @buf:		the pointer to buffer object.
 *
 * Desrtoys buffer object created with #xmlSecBufferCreate function.
 */
void 
xmlSecBufferDestroy(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);
    
    xmlSecBufferFinalize(buf);
    xmlFree(buf);
}

/**
 * xmlSecBufferInitialize:
 * @buf:		the pointer to buffer object.
 * @size:		the initial buffer size.
 *
 * Initializes buffer object @buf. Caller is responsible for calling
 * #xmlSecBufferFinalize function to free allocated resources.
 * 
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferInitialize(xmlSecBufferPtr buf, xmlSecSize size) {
    xmlSecAssert2(buf != NULL, -1);

    buf->data = NULL;
    buf->size = buf->maxSize = 0;
    buf->allocMode = gAllocMode;
        
    return(xmlSecBufferSetMaxSize(buf, size));
}

/**
 * xmlSecBufferFinalize:
 * @buf:		the pointer to buffer object.
 *
 * Frees allocated resource for a buffer intialized with #xmlSecBufferInitialize
 * function.
 */
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

/**
 * xmlSecBufferEmpty:
 * @buf:		the pointer to buffer object.
 *
 * Empties the buffer.
 */
void
xmlSecBufferEmpty(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);
    
    if(buf->data != 0) {
	xmlSecAssert(buf->maxSize > 0);

	memset(buf->data, 0, buf->maxSize);
    }
    buf->size = 0;
}

/**
 * xmlSecBufferGetData:
 * @buf:		the pointer to buffer object.
 *
 * Gets pointer to buffer's data.
 *
 * Returns pointer to buffer's data.
 */
xmlSecByte* 
xmlSecBufferGetData(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, NULL);
    
    return(buf->data);
}

/**
 * xmlSecBufferSetData:
 * @buf:		the pointer to buffer object.
 * @data:		the data.
 * @size:		the data size.
 *
 * Sets the value of the buffer to @data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferSetData(xmlSecBufferPtr buf, const xmlSecByte* data, xmlSecSize size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);

    xmlSecBufferEmpty(buf);
    if(size > 0) {
	xmlSecAssert2(data != NULL, -1);
    
	ret = xmlSecBufferSetMaxSize(buf, size);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
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

/**
 * xmlSecBufferGetSize:
 * @buf:		the pointer to buffer object.
 *
 * Gets the current buffer data size.
 *
 * Returns the current data size.
 */
xmlSecSize 
xmlSecBufferGetSize(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, 0);

    return(buf->size);
}

/**
 * xmlSecBufferSetSize:
 * @buf:		the pointer to buffer object.
 * @size:		the new data size.
 *
 * Sets new buffer data size. If necessary, buffer grows to 
 * have at least @size bytes. 
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferSetSize(xmlSecBufferPtr buf, xmlSecSize size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);

    ret = xmlSecBufferSetMaxSize(buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
	return(-1);
    }
    
    
    buf->size = size;
    return(0);
}

/**
 * xmlSecBufferGetMaxSize:
 * @buf:		the pointer to buffer object.
 *
 * Gets the maximum (allocated) buffer size.
 *
 * Returns the maximum (allocated) buffer size.
 */
xmlSecSize 
xmlSecBufferGetMaxSize(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, 0);

    return(buf->maxSize);
}

/**
 * xmlSecBufferSetMaxSize:
 * @buf:		the pointer to buffer object.
 * @size:		the new maximum size.
 *
 * Sets new buffer maximum size. If necessary, buffer grows to 
 * have at least @size bytes. 
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferSetMaxSize(xmlSecBufferPtr buf, xmlSecSize size) {
    xmlSecByte* newData;
    xmlSecSize newSize = 0;
    
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
    
    newData = (xmlSecByte*)xmlRealloc(buf->data, newSize);
    if(newData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
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

/**
 * xmlSecBufferAppend:
 * @buf:		the pointer to buffer object.
 * @data:		the data.
 * @size:		the data size.
 *
 * Appends the @data after the current data stored in the buffer.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferAppend(xmlSecBufferPtr buf, const xmlSecByte* data, xmlSecSize size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);

    if(size > 0) {
	xmlSecAssert2(data != NULL, -1);
    
        ret = xmlSecBufferSetMaxSize(buf, buf->size + size);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
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

/**
 * xmlSecBufferPrepend:
 * @buf:		the pointer to buffer object.
 * @data:		the data.
 * @size:		the data size.
 *
 * Prepends the @data before the current data stored in the buffer.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferPrepend(xmlSecBufferPtr buf, const xmlSecByte* data, xmlSecSize size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);

    if(size > 0) {
	xmlSecAssert2(data != NULL, -1);
    
	ret = xmlSecBufferSetMaxSize(buf, buf->size + size);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
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

/**
 * xmlSecBufferRemoveHead:
 * @buf:		the pointer to buffer object.
 * @size:		the number of bytes to be removed.
 *
 * Removes @size bytes from the beginning of the current buffer.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferRemoveHead(xmlSecBufferPtr buf, xmlSecSize size) {
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

/**
 * xmlSecBufferRemoveTail:
 * @buf:		the pointer to buffer object.
 * @size:		the number of bytes to be removed.
 *
 * Removes @size bytes from the end of current buffer.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferRemoveTail(xmlSecBufferPtr buf, xmlSecSize size) {
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

/**
 * xmlSecBufferReadFile:
 * @buf:		the pointer to buffer object.
 * @filename:		the filename.
 *
 * Reads the content of the file @filename in the buffer.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferReadFile(xmlSecBufferPtr buf, const char* filename) {
    xmlSecByte buffer[1024];
    FILE* f;
    int ret, len;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    f = fopen(filename, "rb");
    if(f == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "fopen",
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "filename=%s;errno=%d", 
		    xmlSecErrorsSafeString(filename),
		    errno);
	return(-1);
    }

    while(1) {
        len = fread(buffer, 1, sizeof(buffer), f);
	if(len == 0) {
            break;
        }else if(len < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "fread",
                        XMLSEC_ERRORS_R_IO_FAILED,
                        "filename=%s;errno=%d", 
                        xmlSecErrorsSafeString(filename),
			errno);
            fclose(f);
            return(-1);
        }

	ret = xmlSecBufferAppend(buf, buffer, len);
	if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecBufferAppend",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "size=%d", 
                        len);
            fclose(f);
            return(-1);
        }     
    }

    fclose(f);
    return(0);
}

/**
 * xmlSecBufferBase64NodeContentRead:
 * @buf:		the pointer to buffer object.
 * @node:		the pointer to node.
 *
 * Reads the content of the @node, base64 decodes it and stores the
 * result in the buffer.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferBase64NodeContentRead(xmlSecBufferPtr buf, xmlNodePtr node) {
    xmlChar* content;
    xmlSecSize size;
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    content = xmlNodeGetContent(node);
    if(content == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);		
    }
    
    /* base64 decode size is less than input size */
    ret = xmlSecBufferSetMaxSize(buf, xmlStrlen(content));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFree(content);
	return(-1);
    }
    
    ret = xmlSecBase64Decode(content, xmlSecBufferGetData(buf), xmlSecBufferGetMaxSize(buf));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
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
		    NULL,
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
	xmlFree(content);
	return(-1);
    }
    xmlFree(content);
    
    return(0);
}

/**
 * xmlSecBufferBase64NodeContentWrite:
 * @buf:		the pointer to buffer object.
 * @node:		the pointer to a node.
 * @columns:		the max line size fro base64 encoded data.
 *
 * Sets the content of the @node to the base64 encoded buffer data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferBase64NodeContentWrite(xmlSecBufferPtr buf, xmlNodePtr node, int columns) {
    xmlChar* content;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    content = xmlSecBase64Encode(xmlSecBufferGetData(buf), xmlSecBufferGetSize(buf), columns);
    if(content == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
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
								 const xmlSecByte *data,
								 xmlSecSize size);		
static int	xmlSecBufferIOClose				(xmlSecBufferPtr buf);

/**
 * xmlSecBufferCreateOutputBuffer:
 * @buf:		the pointer to buffer.
 *
 * Creates new LibXML output buffer to store data in the @buf. Caller is 
 * responsible for destroying @buf when processing is done. 
 *
 * Returns pointer to newly allocated output buffer or NULL if an error
 * occurs.
 */
xmlOutputBufferPtr 
xmlSecBufferCreateOutputBuffer(xmlSecBufferPtr buf) {
    return(xmlOutputBufferCreateIO((xmlOutputWriteCallback)xmlSecBufferIOWrite,
				     (xmlOutputCloseCallback)xmlSecBufferIOClose,
				     buf,
				     NULL)); 
}

static int 
xmlSecBufferIOWrite(xmlSecBufferPtr buf, const xmlSecByte *data, xmlSecSize size) {
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    
    ret = xmlSecBufferAppend(buf, data, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
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

/************************************************************************
 *
 * Binary <-> Hex formatting/unformatting functions. 
 *
 ************************************************************************/ 
/* table for converting bytes to hex digits */
static const unsigned char xmlSecBinaryHexChars[] = "0123456789ABCDEF";

/* table for converting hex digits back to bytes */
static const int xmlSecBinaryHexLookupTable[] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

/* few macros to simplify the code */
#define xmlSecBinaryHexChar1(b)        	\
	xmlSecBinaryHexChars[((((int) (b)) & 0xF0) >> 4)]
#define xmlSecBinaryHexChar2(b)         \
	xmlSecBinaryHexChars[(((int) (b)) & 0x0F)]
#define xmlSecBinaryMakeByte(c1, c2)    \
	(((xmlSecBinaryHexLookupTable[(c1)] & 0x0F) << 4) | \
	  (xmlSecBinaryHexLookupTable[(c2)] & 0x0F))
#define xmlSecIsHexChar(ch)            \
	(xmlSecBinaryHexLookupTable[(ch)] != -1)

/**
 * xmlSecBufferToHexString:
 * @buf:          	the input buffer.
 * @columns:		the max columns, if 0 then we don't insert line breaks.
 *
 * Converts a binary data in the buffer into a hex-encoded string.
 *
 * Returns the pointer to newly allocated string (caller muste free
 * it with xmlFree function) on success or NULL if an error occurs.
 */
xmlChar* 
xmlSecBufferToHexString(xmlSecBufferPtr buf, int columns) {
    xmlChar* str;
        
    xmlSecAssert2(buf != NULL, NULL);

    str = xmlSecBinaryToHexString(xmlSecBufferGetData(buf), xmlSecBufferGetSize(buf), columns);
    if(str == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBinaryToHexString",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    
    return (str);
}

/**
 * xmlSecBufferFromHexString:
 * @buf:          	the buffer to append results to.
 * @str:    		the hex string.
 *
 * Converts a hex-encoded string into binary data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecBufferFromHexString(xmlSecBufferPtr buf, const xmlChar* str) {
    xmlSecSize size;
    xmlSecByte* buffer;
    xmlSecSize i, j;
    int ch1, ch2;
    int ret;
    
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(str != NULL, -1);
    
    /* the result could not be longer than Length(str) / 2, allocate space */
    size = xmlSecBufferGetMaxSize(buf) + xmlStrlen(str) / 2;

    /* allocate necessary size */
    ret = xmlSecBufferSetMaxSize(buf, size + 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferSetMaxSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "new size=%d", size + 1);
	return(-1);
    }

    buffer = xmlSecBufferGetData(buf);
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferGetData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    
    for(i = 0, j = xmlSecBufferGetSize(buf); (j < size); ++i) {
	ch1 = str[i]; 
	while((ch1 != 0) && isspace(ch1)) {
	    ch1 = str[++i];
	}
	if(ch1 == 0) {
	    /* we are done */
	    buffer[j] = 0;
	    break;
	} else if(!xmlSecIsHexChar(ch1)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBufferSetSize",
			XMLSEC_ERRORS_R_INVALID_DATA,
			"ch=x%02x;pos=%d", ch1, i);
	    return(-1);
	}

	ch2 = str[i]; 
	while((ch2 != 0) && isspace(ch2)) {
	    ch2 = str[++i];
	}
	if(!xmlSecIsHexChar(ch2)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecBufferSetSize",
			XMLSEC_ERRORS_R_INVALID_DATA,
			"ch=x%02x;pos=%d", ch2, i);
	    return(-1);
	}

	buffer[j++] = xmlSecBinaryMakeByte(ch1, ch2);
    }
    
    if(j >= size) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "size=%d", size);
	return(-1);
    }
    
    ret = xmlSecBufferSetSize(buf, j);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "new size=%d", j);
	return(-1);
    }

    return(0);
}
 
/**
 * xmlSecBinaryToHexString:
 * @buf:		the pointer to binary buffer.
 * @bufSize:		the buffer size.
 * @columns:		the max columns, if 0 then we don't insert line breaks.
 *
 * Converts a block of binary data into a hex-encoded string.
 *
 * Returns the pointer to newly allocated string (caller muste free
 * it with xmlFree function) on success or NULL if an error occurs.
 */
xmlChar*
xmlSecBinaryToHexString(const xmlSecByte *buf, xmlSecSize bufSize, int columns) {
    xmlSecSize size, i, j;
    xmlChar *res;
    int iCol;
    int ch;

    xmlSecAssert2(((buf != NULL) || (bufSize == 0)), NULL);
    /* TODO: get rid of constant
       make sure that the byte count doubled will still fit inside
       an xmlChar string without overflowing 'int' values */
    xmlSecAssert2(bufSize <= 0x3FFFFFFF, NULL);
    
    /* calculate the new size */
    size = 2 * bufSize;
    if(columns > 0) {
	size += size / columns + 1;
    }
    
    /* allocate buffer */
    res = (xmlChar*)xmlMalloc(size + 1);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d", size + 1);
	return(NULL);
    }
    memset(res, 0, size + 1);

    for(i = j = 0, iCol = 0; ((i < bufSize) && (j < size)); ++i, iCol += 2) {
	ch = buf[i];

	if((columns > 0) && (iCol >= columns)) {
	    res[j++] = '\n';
	    iCol = 0;
	}
	if(j >= size) {
	    break;
	}

        res[j++] = xmlSecBinaryHexChar1(ch);
	if(j >= size) {
	    break;
	}

        res[j++] = xmlSecBinaryHexChar2(ch);
	if(j >= size) {
	    break;
	}
    }
	
    if(j >= size) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_SIZE,
		    "size=%d", size);
	xmlFree(res);
	return(NULL);
    }

    return(res);
}
