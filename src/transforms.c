/** 
 * XML Security Library
 *
 * The Transforms Element (http://www.w3.org/TR/xmldsig-core/#sec-Transforms)
 * 
 * The optional Transforms element contains an ordered list of Transform 
 * elements; these describe how the signer obtained the data object that 
 * was digested.
 *
 * Schema Definition:
 * 
 *  <element name="Transforms" type="ds:TransformsType"/>
 *  <complexType name="TransformsType">
 *    <sequence>
 *      <element ref="ds:Transform" maxOccurs="unbounded"/> 
 *    </sequence>
 *   </complexType>
 *
 *  <element name="Transform" type="ds:TransformType"/>
 *  <complexType name="TransformType" mixed="true">
 *    <choice minOccurs="0" maxOccurs="unbounded"> 
 *      <any namespace="##other" processContents="lax"/>
 *      <!-- (1,1) elements from (0,unbounded) namespaces -->
 *      <element name="XPath" type="string"/> 
 *    </choice>
 *    <attribute name="Algorithm" type="anyURI" use="required"/> 
 *  </complexType>
 *    
 * DTD:
 *    
 *  <!ELEMENT Transforms (Transform+)>
 *  <!ELEMENT Transform (#PCDATA|XPath %Transform.ANY;)* >
 *  <!ATTLIST Transform Algorithm    CDATA    #REQUIRED >
 *  <!ELEMENT XPath (#PCDATA) >
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */

#include "globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpointer.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/io.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

/*
#define XMLSEC_BUFFER_DEBUG 1
*/

/**************************************************************************
 *
 * xmlSecTransform
 *
 *************************************************************************/
/**
 * xmlSecTransformCreate:
 * @id: the transform id to create.
 * @dontDestroy: the flag that controls wherther the transforms
 *		can destroy the transforms automatically
 *
 * Creates new transform from the transform id object.
 *
 * Returns the pointer to newly created #xmlSecTransform structure
 * or NULL if an error occurs.
 */ 
xmlSecTransformPtr	
xmlSecTransformCreate(xmlSecTransformId id, int dontDestroy) {
    xmlSecTransformPtr transform;
    int ret;
    
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->klassSize >= sizeof(xmlSecTransformKlass), NULL);
    xmlSecAssert2(id->objSize >= sizeof(xmlSecTransform), NULL);
    xmlSecAssert2(id->name != NULL, NULL);
        
    /* Allocate a new xmlSecTransform and fill the fields. */
    transform = (xmlSecTransformPtr)xmlMalloc(id->objSize);
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d", id->objSize); 
	return(NULL);
    }
    memset(transform, 0, id->objSize);    
    transform->id = id;
    transform->dontDestroy = dontDestroy;
    
    if(id->initialize != NULL) {
	ret = (id->initialize)(transform);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"id->initialize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecTransformDestroy(transform, 1);
	    return(NULL);
	}
    }

    ret = xmlSecBufferInitialize(&(transform->inBuf), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", 0);
	xmlSecTransformDestroy(transform, 1);
	return(NULL);	
    }

    ret = xmlSecBufferInitialize(&(transform->outBuf), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecBufferInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", 0);
	xmlSecTransformDestroy(transform, 1);
	return(NULL);	
    }
    
    return(transform);
}

/**
 * xmlSecTransformDestroy:
 * @transform: the pointer to #xmlSecTransform structure.
 * @forceDestroy: the flag whether the transform destruction will be
 *   forced.
 *
 * Destroys transform by calling appropriate transform specific function.
 */
void
xmlSecTransformDestroy(xmlSecTransformPtr transform, int forceDestroy) {
    xmlSecAssert(xmlSecTransformIsValid(transform));
    xmlSecAssert(transform->id->objSize > 0);
    
    /* first need to remove ourselves from chain */
    if(transform->id->type == xmlSecTransformTypeBinary) {
	xmlSecTransformRemove(transform);
    }

    if((transform->dontDestroy) && (!forceDestroy)){
	/* requested do not destroy transform */
	return;
    }    
    
#ifdef XMLSEC_BUFFER_DEBUG
    fprintf(stderr, "-- buffer debug: %s, in: %d\n", 
	    transform->id->name, 
	    xmlSecBufferGetMaxSize(&(transform->inBuf)));
    fprintf(stderr, "-- buffer debug: %s, out: %d\n", 
	    transform->id->name, 
	    xmlSecBufferGetMaxSize(&(transform->outBuf)));
#endif /* XMLSEC_BUFFER_DEBUG */
    xmlSecBufferFinalize(&(transform->inBuf));
    xmlSecBufferFinalize(&(transform->outBuf));

    /* we never destroy input nodes, output nodes
     * are destroyed if and only if they are different
     * from input nodes 
     */
    if((transform->outNodes != NULL) && (transform->outNodes != transform->inNodes)) {
	xmlSecNodeSetDestroy(transform->outNodes);
    }
    if(transform->id->finalize != NULL) { 
	(transform->id->finalize)(transform);
    }
    memset(transform, 0, transform->id->objSize);
    xmlFree(transform);
}

/** 
 * xmlSecTransformRead:
 * @transform: the pointer to #xmlSecTransform structure.
 * @node: the pointer to the <dsig:Transform> node.
 *
 * Reads transform information from the @transformNode using 
 * transform specific function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformRead(xmlSecTransformPtr transform, xmlNodePtr node) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(node != NULL, -1);

    if(transform->id->readNode != NULL) {
	return(transform->id->readNode(transform, node));
    }
    return(0);
}

/**
 * xmlSecTransformSetKey:
 * @transform: the pointer to #xmlSecTransform structure.
 * @key: the pointer to #xmlSecKey structure. 
 *
 * Sets the key for binary transform (wrapper for transform specific 
 * setKey() method).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformSetKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(key != NULL, -1);
        
    if(transform->id->setKey != NULL) {
	return((transform->id->setKey)(transform, key));
    }
    return(0);
}

/**
 * xmlSecTransformSetKeyReq:
 * @transform: the pointer to #xmlSecTransform structure.
 * @keyInfoCtx: the pointer to #xmlSecKeyInfoCtx structure. 
 *
 * Sets the key for binary transform (wrapper for transform specific 
 * setKeyReq() method).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyReqPtr keyReq) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(keyReq != NULL, -1);
        
    keyReq->keyId 	= xmlSecKeyDataIdUnknown;
    keyReq->keyType = xmlSecKeyDataTypeUnknown;
    keyReq->keyUsage= xmlSecKeyUsageAny;
    
    if(transform->id->setKeyReq != NULL) {
	return((transform->id->setKeyReq)(transform, keyReq));
    }
    return(0);
}

int 
xmlSecTransformVerify(xmlSecTransformPtr transform, const unsigned char* data,
		    size_t dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->verify != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->verify)(transform, data, dataSize, transformCtx));
}

xmlSecTransformDataType	
xmlSecTransformGetDataType(xmlSecTransformPtr transform, xmlSecTransformMode mode, 
		    xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), xmlSecTransformDataTypeUnknown);
    xmlSecAssert2(transform->id->getDataType != NULL, xmlSecTransformDataTypeUnknown);
    
    return((transform->id->getDataType)(transform, mode, transformCtx));    
}

int 
xmlSecTransformPushBin(xmlSecTransformPtr transform, const unsigned char* data,
		    size_t dataSize, int final, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->pushBin != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    
    return((transform->id->pushBin)(transform, data, dataSize, final, transformCtx));    
}

int 
xmlSecTransformPopBin(xmlSecTransformPtr transform, unsigned char* data,
		    size_t* dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->popBin != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->popBin)(transform, data, dataSize, transformCtx));    
}

int 
xmlSecTransformPushXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr nodes,
		    xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->pushXml != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->pushXml)(transform, nodes, transformCtx));    
}

int 
xmlSecTransformPopXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr* nodes,
		    xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->popXml != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->popXml)(transform, nodes, transformCtx));    
}

int 
xmlSecTransformExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->execute != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->execute)(transform, last, transformCtx));
}

/**
 * xmlSecTransformExecuteXml:
 * @transform: the pointer to XML transform.
 * @ctxDoc: the pointer to the document containing the transform's 
 *		<dsig:Transform> node.
 * @doc: the pointer to the pointer to current document.
 * @nodes: the pointer to the pointer to current and result nodes set.
 *
 * Executes the XML @transform and returns result nodes set in @nodes
 * (wrapper for transform specific executeXml() method).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformExecuteXml(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			  xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);

    if(transform->id->executeXml != NULL) {
	return((transform->id->executeXml)(transform, ctxDoc, doc, nodes));
    }
    return(0);
}

/**
 * xmlSecTransformExecuteC14N:
 * @transform: the pointer to C14N transform.
 * @doc: the pointer to current document.
 * @nodes: the pointer to current nodes set.
 * @buffer: the result buffer.
 *
 * Executes the C14N @transform and returns result in the @buffer
 * (wrapper for transform specific executeC14n() method). If the 
 * @trnaform is NULL then the default #xmlSecC14NInclusive 
 * transform is executed.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int	
xmlSecTransformExecuteC14N(xmlSecTransformPtr transform,
			   xmlDocPtr doc, xmlSecNodeSetPtr nodes,
			   xmlOutputBufferPtr buffer) {
    xmlSecTransformId id;  

    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    
    /* todo */
    if(transform != NULL) {
	xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
	id = transform->id;
    } else {
	id = xmlSecC14NInclusive; /* the default c14n transform */
    }
    
    if(id->executeC14N != NULL) {
	return((id->executeC14N)(transform, doc, nodes, buffer));
    }
    return(0);
}

/**
 * xmlSecTransformAddAfter:
 * @curTransform: the pointer to current transform (may be NULL).
 * @newTransform: the pointer to new transform.
 * 
 * Adds @newTransform after the @curTransform.
 *
 * Returns pointer to the new transforms chain or NULL if an error occurs.
 */
xmlSecTransformPtr	
xmlSecTransformAddAfter(xmlSecTransformPtr curTransform, 
			xmlSecTransformPtr newTransform) {
    xmlSecAssert2(xmlSecTransformIsValid(newTransform), NULL);

    if(curTransform != NULL) {
	xmlSecAssert2(xmlSecTransformIsValid(curTransform), NULL);

	newTransform->prev = curTransform;
	newTransform->next = curTransform->next;
	curTransform->next = newTransform;
	if(newTransform->next != NULL) {
	    newTransform->next->prev = newTransform;
	}
    } else {
 	newTransform->next = newTransform->prev = NULL;
    }
    return(newTransform);
}

/**
 * xmlSecTransformAddBefore
 * @curTransform: the pointer to current transform (may be NULL).
 * @newTransform: the pointer to new transform.
 * 
 * Adds @newTransform before the @curTransform.
 *
 * Returns pointer to the new transforms chain or NULL if an error occurs.
 */
xmlSecTransformPtr	
xmlSecTransformAddBefore(xmlSecTransformPtr curTransform, 
			    xmlSecTransformPtr newTransform) {
    xmlSecAssert2(xmlSecTransformIsValid(newTransform), NULL);

    if(curTransform != NULL) {
	xmlSecAssert2(xmlSecTransformIsValid(curTransform), NULL);

	newTransform->next = curTransform;
	newTransform->prev = curTransform->prev;
	curTransform->prev = newTransform;
	if(newTransform->prev != NULL) {
	    newTransform->prev->next = newTransform;
	}
    } else {
	newTransform->next = newTransform->prev = NULL;
    }
    return(newTransform);
    
}

/**
 * xmlSecTransformRemove:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Removes @transform from the chain. This method MUST be called by any 
 * bin transform id destructor.
 */
void
xmlSecTransformRemove(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformIsValid(transform));

    if(transform->next != NULL) {
	transform->next->prev = transform->prev;
    }
    if(transform->prev != NULL) {
	transform->prev->next = transform->next;
    }
    transform->next = transform->prev = NULL;
}

/**
 * xmlSecTransformDestroyAll:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Destroys all transforms in the chain.
 */
void
xmlSecTransformDestroyAll(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformIsValid(transform));

    while(transform->next != NULL) {
	xmlSecTransformDestroy(transform->next, 0);
    }
    while(transform->prev != NULL) {
	xmlSecTransformDestroy(transform->prev, 0);
    }	
    xmlSecTransformDestroy(transform, 0);
}

/**
 * xmlSecTransformReadBin:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the output buffer.
 * @size: the output buffer size.
 *
 * Reads chunk of data from the transform (wrapper transform specific
 * readBin() function).
 *
 * Returns the number of bytes in the buffer or negative value
 * if an error occurs.
 */
int
xmlSecTransformReadBin(xmlSecTransformPtr transform, 
		       unsigned char *buf, size_t size) {
    xmlSecTransformCtx ctx; /* todo */
    int ret;
        
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(buf != NULL, -1);
    
    ret = xmlSecTransformPopBin(transform, buf, &size, &ctx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecTransformPopBin",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(size);
}

/**
 * xmlSecTransformWriteBin:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the input data buffer.
 * @size: the input data size.
 *
 * Writes data to the transform (wrapper to the transform specific
 * writeBin() function).
 * 
 * Returns the number of bytes consumed or a negative value otherwise.
 */
int
xmlSecTransformWriteBin(xmlSecTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    xmlSecTransformCtx ctx; /* todo */
    int ret;
        
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(buf != NULL, -1);
    
    ret = xmlSecTransformPushBin(transform, buf, size, 0, &ctx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecTransformPushBin",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(size);
}

/**
 * xmlSecTransformFlushBin:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Finalizes writing (wrapper for transform specific flushBin() method). 
 *
 * Returns 0 if success or negative value otherwise.
 */
int
xmlSecTransformFlushBin(xmlSecTransformPtr transform) {
    xmlSecTransformCtx ctx; /* todo */
    int ret;
        
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    
    ret = xmlSecTransformPushBin(transform, NULL, 0, 1, &ctx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecTransformPushBin",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

xmlSecTransformDataType 
xmlSecTransformDefaultGetDataType(xmlSecTransformPtr transform, xmlSecTransformMode mode,
				  xmlSecTransformCtxPtr transformCtx) {
    xmlSecTransformDataType type = xmlSecTransformDataTypeUnknown;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), xmlSecTransformDataTypeUnknown);
    xmlSecAssert2(transformCtx != NULL, xmlSecTransformDataTypeUnknown);

    /* we'll try to guess the data type based on the handlers we have */
    switch(mode) {
	case xmlSecTransformModePush:
	    if(transform->id->pushBin != NULL) {
		type |= xmlSecTransformDataTypeBin;
	    } 
	    if(transform->id->pushXml != NULL) {
		type |= xmlSecTransformDataTypeXml;
	    } 
	    break;
	case xmlSecTransformModePop:
	    if(transform->id->popBin != NULL) {
		type |= xmlSecTransformDataTypeBin;
	    } 
	    if(transform->id->popXml != NULL) {
		type |= xmlSecTransformDataTypeXml;
	    } 
	    break;
	default:
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			NULL,
		        XMLSEC_ERRORS_R_INVALID_DATA,
			"mode=%d", mode);
	    return(xmlSecTransformDataTypeUnknown);
    }
    
    return(type);
}

int 
xmlSecTransformDefaultPushBin(xmlSecTransformPtr transform, const unsigned char* data,
			size_t dataSize, int final, xmlSecTransformCtxPtr transformCtx) {
    size_t inSize = 0;
    size_t outSize = 0;
    int finalData = 0;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    
    do {
        /* append data to input buffer */    
	if(dataSize > 0) {
	    size_t chunkSize;
	    
	    xmlSecAssert2(data != NULL, -1);

	    chunkSize = dataSize;
	    if(chunkSize > XMLSEC_TRANSFORM_BINARY_CHUNK) {
		chunkSize = XMLSEC_TRANSFORM_BINARY_CHUNK;
	    }
	    
	    ret = xmlSecBufferAppend(&(transform->inBuf), data, chunkSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecBufferAppend",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "size=%d", chunkSize);
		return(-1);
	    }	

	    dataSize -= chunkSize;
	    data += chunkSize;
	}

	/* process data */
	inSize = xmlSecBufferGetSize(&(transform->inBuf));
	outSize = xmlSecBufferGetSize(&(transform->outBuf));
	finalData = (((dataSize == 0) && (final != 0)) ? 1 : 0);
	ret = xmlSecTransformExecute(transform, finalData, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecTransformExecute",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"final=%d", final);
	    return(-1);
	}

	/* push data to the next transform */
	inSize = xmlSecBufferGetSize(&(transform->inBuf));
	outSize = xmlSecBufferGetSize(&(transform->outBuf));
	if(inSize > 0) {
	    finalData = 0;
	}

	/* we don't want to puch too much */
	if(outSize > XMLSEC_TRANSFORM_BINARY_CHUNK) {
	    outSize = XMLSEC_TRANSFORM_BINARY_CHUNK;
	    finalData = 0;
	}
	if((transform->next != NULL) && ((outSize > 0) || (finalData != 0))) {
	    ret = xmlSecTransformPushBin(transform->next, 
			    xmlSecBufferGetData(&(transform->outBuf)),
			    outSize,
			    finalData,
			    transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform->next)),
			    "xmlSecTransformPushBin",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "final=%d;outSize=%d", final,outSize);
		return(-1);
	    }
	}
	
	/* remove data anyway */
	if(outSize > 0) {
	    ret = xmlSecBufferRemoveHead(&(transform->outBuf), outSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecBufferAppend",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "size=%d", outSize);
		return(-1);
	    }
	}
    } while((dataSize > 0) || (outSize > 0));
    
    return(0);
}

int 
xmlSecTransformDefaultPopBin(xmlSecTransformPtr transform, unsigned char* data,
			    size_t* dataSize, xmlSecTransformCtxPtr transformCtx) {
    size_t outSize;
    int final = 0;
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    while((xmlSecBufferGetSize(&(transform->outBuf)) == 0) && (final == 0)) {
	/* read data from previous transform if exist */
	if(transform->prev != NULL) {    
    	    size_t inSize, chunkSize;

	    inSize = xmlSecBufferGetSize(&(transform->inBuf));
	    chunkSize = XMLSEC_TRANSFORM_BINARY_CHUNK;

	    /* ensure that we have space for at least one data chunk */
    	    ret = xmlSecBufferSetMaxSize(&(transform->inBuf), inSize + chunkSize);
    	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			    "xmlSecBufferSetMaxSize",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "size=%d", inSize + chunkSize);
		return(-1);
	    }	

	    /* get data from previous transform */
	    ret = xmlSecTransformPopBin(transform->prev, 
			    xmlSecBufferGetData(&(transform->inBuf)) + inSize,
			    &chunkSize, transformCtx);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecTransformGetName(transform->prev)),
			    "xmlSecTransformPopBin",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	    }
	
	    /* adjust our size if needed */
	    if(chunkSize > 0) {
		ret = xmlSecBufferSetSize(&(transform->inBuf), inSize + chunkSize);
		if(ret < 0) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
				"xmlSecBufferSetSize",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				"size=%d", inSize + chunkSize);
		    return(-1);
	        }
		final = 0; /* the previous transform returned some data..*/
	    } else {
		final = 1; /* no data returned from previous transform, we are done */
	    }
	} else {
	    final = 1; /* no previous transform, we are "permanently final" */
	}	

	/* execute our transform */
    	ret = xmlSecTransformExecute(transform, final, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecTransformExecute",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }
    
    /* copy result (if any) */
    outSize = xmlSecBufferGetSize(&(transform->outBuf)); 
    if(outSize > (*dataSize)) {
	outSize = (*dataSize);
    }
    
    /* we don't want to put too much */
    if(outSize > XMLSEC_TRANSFORM_BINARY_CHUNK) {
	outSize = XMLSEC_TRANSFORM_BINARY_CHUNK;
    }
    if(outSize > 0) {
	xmlSecAssert2(xmlSecBufferGetData(&(transform->outBuf)), -1);
	
	memcpy(data, xmlSecBufferGetData(&(transform->outBuf)), outSize);
    	    
	ret = xmlSecBufferRemoveHead(&(transform->outBuf), outSize);
    	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"size=%d", outSize);
	    return(-1);
	}	
    }
    
    /* set the result */
    (*dataSize) = outSize;
    return(0);
}

int 
xmlSecTransformDefaultPushXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr nodes, 
			    xmlSecTransformCtxPtr transformCtx) {
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->inNodes == NULL, -1);
    xmlSecAssert2(transform->outNodes == NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    /* execute our transform */
    transform->inNodes = nodes;
    ret = xmlSecTransformExecute(transform, 1, transformCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecTransformExecute",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* push result to the next transform (if exist) */
    if(transform->next != NULL) {
	ret = xmlSecTransformPushXml(transform->next, transform->outNodes, transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecTransformPushXml",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }        
    return(0);
}

int xmlSecTransformDefaultPopXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr* nodes, 
			    xmlSecTransformCtxPtr transformCtx) {
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->inNodes == NULL, -1);
    xmlSecAssert2(transform->outNodes == NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    
    /* pop result from the prev transform (if exist) */
    if(transform->prev != NULL) {
	ret = xmlSecTransformPopXml(transform->prev, &(transform->inNodes), transformCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecTransformPopXml",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
    }        

    /* execute our transform */
    ret = xmlSecTransformExecute(transform, 1, transformCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecTransformExecute",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* return result if requested */
    if(nodes != NULL) {
	(*nodes) = transform->outNodes;
    }
    
    return(0);
}

int  
xmlSecTransformOldExecuteXml(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			    xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecTransformCtx ctx;
    int ret;
    			    
    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(ctxDoc != NULL, -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);
    xmlSecAssert2(nodes != NULL, -1);
    
    memset(&ctx, 0, sizeof(ctx));

    ctx.ctxDoc = ctxDoc;

    /* execute our transform */
    transform->inNodes = (*nodes);
    ret = xmlSecTransformExecute(transform, 1, &ctx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecTransformExecute",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    if(transform->outNodes != NULL) {
	(*nodes)= transform->outNodes;
	(*doc) 	= transform->outNodes->doc;
	/* we don;t want to destroy the nodes set in transform */
	transform->outNodes = NULL;
    } else {
	(*nodes)= NULL;
	(*doc) 	= NULL;
    }

    return(0);    
}



#include "transforms-old.c"
