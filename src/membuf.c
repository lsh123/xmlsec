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

static xmlSecTransformPtr xmlSecMemBufTransformCreate	(xmlSecTransformId id);
static void		xmlSecMemBufTransformDestroy	(xmlSecTransformPtr transform);
static int  		xmlSecMemBufTransformRead	(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
static int  		xmlSecMemBufTransformWrite	(xmlSecBinTransformPtr transform, 
							 const unsigned char *buf, 
							 size_t size);
static int  		xmlSecMemBufTransformFlush	(xmlSecBinTransformPtr transform);

static const struct _xmlSecBinTransformId xmlSecMemBufTransformId = {
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
 * @transform:
 * @removeBuffer:
 * 
 * Returns the xmlBufferPtr. If @removeBuffer is set to 1 then the buffer 
 * is removed from transform and the caller is responsible for freeing it
 */
xmlBufferPtr
xmlSecMemBufTransformGetBuffer(xmlSecTransformPtr transform, int removeBuffer) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMemBufTransformGetBuffer";
    xmlBufferPtr ptr;
       
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
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
 * @id:
 *
 * Creates new memory buffer object
 */
static xmlSecTransformPtr 
xmlSecMemBufTransformCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMemBufTransformCreate";
    xmlSecBinTransformPtr ptr;
    
    if(id != xmlSecMemBuf){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is not recognized\n",
	    func);
#endif 	    
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBinTransform and fill the fields.
     */
    ptr = (xmlSecBinTransformPtr) xmlMalloc(sizeof(xmlSecBinTransform));
    if(ptr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecBinTransform malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(ptr, 0, sizeof(xmlSecBinTransform));
    
    ptr->id = (xmlSecBinTransformId)id;
    return((xmlSecTransformPtr)ptr);    
}

/**
 * xmlSecMemBufTransformDestroy:
 * @transform
 *
 * Destroys the current object
 */
static void
xmlSecMemBufTransformDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMemBufTransformDestroy";
            
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
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
 * @transform:
 * @buf:
 * @size:
 *
 * Reads data from previous transform and stores them in the buffer
 */
static int
xmlSecMemBufTransformRead(xmlSecBinTransformPtr transform, 
			unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMemBufTransformRead";
    int ret;
       
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }

    if(transform->prev == NULL) {
	/* nothing to read */
	return(0);
    }
    
    ret = xmlSecBinTransformRead((xmlSecTransformPtr)(transform->prev), buf, size);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: previous transform read failed\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    if(ret == 0) {
	/* we are done */
	return(0);
    }
    
    if(transform->data == NULL) {
	transform->data = xmlBufferCreate();
	if(transform->data == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create xml buffer\n",
		func);	
#endif 	    
	    return(-1);
	}
    }
    
    xmlBufferAdd((xmlBufferPtr)(transform->data), buf, ret);
    return(ret);
}

/**
 * xmlSecMemBufTransformWrite
 * @transform:
 * @buf:
 * @size:
 *
 * Writes data to the next buffer and stores them in the memory
 */
static int
xmlSecMemBufTransformWrite(xmlSecBinTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMemBufTransformWrite";
    xmlBufferPtr ptr;
    int ret;
            
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }

    if((buf == NULL) || (size == 0)) {
	/* nothing to write */
	return(0);
    }
    
    if(transform->data == NULL) {
	transform->data = ptr = xmlBufferCreate();
	if(transform->data == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create xml buffer\n",
		func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: next transform write failed\n",
	    func);	
#endif 	    
	return(-1);
    }

    xmlBufferAdd(ptr, buf, ret);
    return(ret);
}

/**
 * xmlSecMemBufTransformFlush
 * @transform:
 *
 * Flushes the next transform
 *
 */
static int
xmlSecMemBufTransformFlush(xmlSecBinTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecMemBufTransformFlush";
    int ret;
        
    if(!xmlSecTransformCheckId(transform, xmlSecMemBuf)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    if(transform->next == NULL) { 
	/* nothing to flush */
	return(0);
    }

    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)(transform->next));
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: next transform flush failed\n",
	    func);	
#endif 	    
	return(-1);
    }

    return(ret);
}


