/** 
 * XMLSec library
 *
 * Buffered
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/buffered.h>

/****************************************************************************
 *
 *   BinTransform methods to be used in the Id structure
 *
 ****************************************************************************/
/**
 * xmlSecBufferedTransformRead
 * @transform: the buffered transform
 * @buf: the buffer
 * @size: the buffer size
 *
 * Reads the all data from previous transform and returns 
 * to the caller.
 *
 * Returns the number of bytes in the buffer or negative value.
 */
int  	
xmlSecBufferedTransformRead(xmlSecBinTransformPtr transform, 
			  unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBufferedTransformRead";
    xmlSecBufferedTransformPtr buffered;
    size_t res = 0;
    int ret;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeBuffered)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    buffered = (xmlSecBufferedTransformPtr)transform;
    
    if((buf == NULL) || (size == 0)) {
	return(0);
    }

    if((buffered->status != xmlSecTransformStatusNone) || (buffered->prev == NULL)) {
	/* nothing to read (already called final or there are no previous transform */ 
	return(0);
    }

    if(buffered->buffer == NULL) {
	/*
	 * create the buffer, read everything from previous transform
	 * and call process method
	 */
	buffered->buffer = xmlBufferCreate();
	if(buffered->buffer == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create buffer\n",
		func);	
#endif
	    return(-1);
	}
	do {
	    ret = xmlSecBinTransformRead((xmlSecTransformPtr)buffered->prev, buf, size);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: read from previous transform failed\n",
		    func);	
#endif
		return(-1);
	    } else if(ret > 0) {
		xmlBufferAdd(buffered->buffer, buf, ret);
	    }
	} while(ret > 0);
	
	ret = xmlSecBufferedProcess(transform, buffered->buffer);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: process failed\n",
	        func);	
#endif
	    return(-1);
	}
    }
    
    res = xmlBufferLength(buffered->buffer);
    if(res <= size) {
	memcpy(buf, xmlBufferContent(buffered->buffer), res);
        buffered->status = xmlSecTransformStatusOk;  /* we are done */
	xmlBufferEmpty(buffered->buffer);
	xmlBufferFree(buffered->buffer);
	buffered->buffer = NULL;
    } else {
	res = size;
	memcpy(buf, xmlBufferContent(buffered->buffer), res);
	memset((void*)xmlBufferContent(buffered->buffer), 0, res);
	xmlBufferShrink(buffered->buffer, res);
    }
    
    return(res);
}

/**
 * xmlSecBufferedTransformWrite:
 * @transform: the buffered transform 
 * @buf: the data buffer
 * @size: the data size
 *
 * Adds the data to the internal buffer.
 * 
 * Returns 0 if success or a negative value otherwise.
 */
int  	
xmlSecBufferedTransformWrite(xmlSecBinTransformPtr transform, 
                          const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBufferedTransformWrite";
    xmlSecBufferedTransformPtr buffered;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeBuffered)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    buffered = (xmlSecBufferedTransformPtr)transform;
    
    if((buf == NULL) || (size == 0)) {
	return(0);
    }

    if((buffered->status != xmlSecTransformStatusNone) || (buffered->next == NULL)) {
	/* nothing to read (already called final or there are no next transform */ 
	return(0);
    }

    if(buffered->buffer == NULL) {
	buffered->buffer = xmlBufferCreate();
	if(buffered->buffer == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create buffer\n",
		func);	
#endif
	    return(-1);
	}
    }
    xmlBufferAdd(buffered->buffer, buf, size);
    return(0);
}

/**
 * xmlSecBufferedTransformFlush:
 * @transform: the buffered transform
 * 
 * Writes internal data to previos transform.
 * 
 * Returns 0 if success or negative value otherwise.
 */
int
xmlSecBufferedTransformFlush(xmlSecBinTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBufferedTransformFlush";
    xmlSecBufferedTransformPtr buffered;
    int ret;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeBuffered)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    buffered = (xmlSecBufferedTransformPtr)transform;
    
    if((buffered->status != xmlSecTransformStatusNone) || 
       (buffered->next == NULL) || (buffered->buffer == NULL)) {
	/* nothing to read (already called final or there are no next transform */ 
	return(0);
    }

    ret = xmlSecBufferedProcess(transform, buffered->buffer);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: process failed\n",
	    func);	
#endif
	return(-1);
    }
    
    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)buffered->next, 
				  xmlBufferContent(buffered->buffer), 
				  xmlBufferLength(buffered->buffer));
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: next transform write failed\n",
	    func);	
#endif
	return(-1);
    }	  

    buffered->status = xmlSecTransformStatusOk;  /* we are done */
    xmlBufferEmpty(buffered->buffer);
    xmlBufferFree(buffered->buffer);
    buffered->buffer = NULL;

    /* do not forget to flush next transform */
    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)buffered->next);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: next transform flush failed\n",
	    func);	
#endif
	return(-1);
    }	  
    return(0);
}

/** 
 * xmlSecBufferedDestroy
 * @transform: the buffered transform
 *
 * Destroys the buffered transform.
 */
void 	
xmlSecBufferedDestroy(xmlSecBufferedTransformPtr buffered) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBufferedDestroy";
    
    if(buffered == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return;
    }
    if(buffered->buffer != NULL) {
	xmlBufferEmpty(buffered->buffer);
	xmlBufferFree(buffered->buffer);
    }
}

/** 
 * xmlSecBufferedProcess:
 * @transform: the buffered transform
 * @buffer: the buffered transform result
 *
 * Executes buffered transform.
 *
 * Returns number of bytes processed or a negative value
 * if an error occurs.
 */
int 	
xmlSecBufferedProcess(xmlSecBinTransformPtr transform, xmlBufferPtr buffer) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBufferedProcess";
    xmlSecBufferedTransformPtr buffered;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeBuffered) ||
       (buffer == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or buffer is NULL\n",
	    func);	
#endif
	return(-1);
    }
    buffered = (xmlSecBufferedTransformPtr)transform;
    if(buffered->id->bufferedProcess != NULL) {
	return(buffered->id->bufferedProcess(buffered, buffer));
    }
    return(0);
}

