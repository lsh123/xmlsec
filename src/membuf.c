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
#include <xmlsec/buffer.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/keys.h>
#include <xmlsec/base64.h>
#include <xmlsec/membuf.h>
#include <xmlsec/errors.h>


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
    NULL,				/* xmlSecTransformNodeReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,	/* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,	/* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,	/* xmlSecTransformPopBinMethod popBin; */
    NULL,				/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,				/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecTransformMemBufExecute,	/* xmlSecTransformExecuteMethod execute; */

    NULL,					/* xmlSecTransformExecuteXmlMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
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
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
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
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", inSize);
	    return(-1);
	}
	
	ret = xmlSecBufferAppend(out, xmlSecBufferGetData(in), inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferAppend",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", inSize);
	    return(-1);
	}
	
	ret = xmlSecBufferRemoveHead(in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", inSize);
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
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "status=%d", transform->status);
	return(-1);
    }
    return(0);
}

