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
#include <xmlsec/xmltree.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/io.h>
#include <xmlsec/membuf.h>
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
    xmlSecAssert2(id->create != NULL, NULL);

    transform = id->create(id);
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->create");
	return(NULL);	
    }
    transform->dontDestroy = dontDestroy;
    
    ret = xmlSecBufferInitialize(&(transform->inBuf), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferInitialize");
	xmlSecTransformDestroy(transform, 1);
	return(NULL);	
    }

    ret = xmlSecBufferInitialize(&(transform->outBuf), 0);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferInitialize");
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
    xmlSecAssert(transform->id->destroy != NULL);
    
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
    transform->id->destroy(transform);
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
xmlSecTransformSetKeyReq(xmlSecTransformPtr transform, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
        
    keyInfoCtx->keyId 	= xmlSecKeyDataIdUnknown;
    keyInfoCtx->keyType = xmlSecKeyDataTypeUnknown;
    keyInfoCtx->keyUsage= xmlSecKeyUsageAny;
    
    if(transform->id->setKeyReq != NULL) {
	return((transform->id->setKeyReq)(transform, keyInfoCtx));
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

int 
xmlSecTransformExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(transform->id->execute != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    return((transform->id->execute)(transform, last, transformCtx));
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
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(buf != NULL, -1);
    
    if(transform->id->readBin != NULL) {
	return((transform->id->readBin)(transform, buf, size));
    }
    return(0);
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
 * Returns 0 if success or a negative value otherwise.
 */
int
xmlSecTransformWriteBin(xmlSecTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);
    xmlSecAssert2(buf != NULL, -1);
    
    if(transform->id->writeBin != NULL) {
	return((transform->id->writeBin)(transform, buf, size));
    }
    return(0);
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
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);

    if(transform->id->flushBin != NULL) {
	return((transform->id->flushBin)(transform));
    }
    return(0);
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
 * xmlSecTransformDefault2ReadBin:
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
xmlSecTransformDefault2ReadBin(xmlSecTransformPtr transform, 
		       unsigned char *buf, size_t size) {
    xmlSecTransformCtx ctx; /* todo */
    unsigned char chunk[XMLSEC_TRANSFORM_BINARY_CHUNK];
    size_t chunkSize;
    size_t res = 0;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);

    while((xmlSecBufferGetSize(&(transform->outBuf)) == 0) &&
	  (!xmlSecTransformStatusIsDone(transform->status))) {

	/* read chunk from previous transform (if exist) */
	if(transform->prev != NULL) {
	    ret = xmlSecTransformReadBin(transform->prev, chunk, sizeof(chunk));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecTransformReadBin");
		return(-1);
	    }
	    chunkSize = ret;
	    
	    ret = xmlSecBufferAppend(&(transform->inBuf), chunk, chunkSize);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecBufferAppend(%d)", chunkSize);
		return(-1);
	    }
	} else {
	    chunkSize = 0;
	}
	
	/* process the current data */
	ret = xmlSecTransformExecute(transform, (chunkSize == 0) ? 1 : 0, &ctx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformExecute");
	    return(-1);
	}
	
	if(chunkSize == 0) {
	    /* we have no more data from previous transform
	     */ 
	     break;
	}
    }
    
    /* copy result to output buffer */
    res = xmlSecBufferGetSize(&(transform->outBuf));
    if(res > size) {
	res = size;
    }
    if(res > 0) {
	xmlSecAssert2(buf != NULL, -1);

	memcpy(buf, xmlSecBufferGetData(&(transform->outBuf)), res);
	xmlSecBufferRemoveHead(&(transform->outBuf), res);
    }
    
    /* cleanup the buffer, it might be sensitive */
    memset(chunk, 0, sizeof(chunk));
    return(res);
}

/**
 * xmlSecTransformDefault2WriteBin:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the input data buffer.
 * @size: the input data size.
 *
 * Writes data to the transform (wrapper to the transform specific
 * writeBin() function).
 * 
 * Returns 0 if success or a negative value otherwise.
 */
int
xmlSecTransformDefault2WriteBin(xmlSecTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    xmlSecTransformCtx ctx; /* todo */
    size_t res = size;
    size_t chunkSize;
    int ret;
    
    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);

    for(;size > 0; size -= chunkSize, buf += chunkSize) {
	xmlSecAssert2(buf != NULL, -1);
	
	/* add next chunk */
	chunkSize = XMLSEC_TRANSFORM_BINARY_CHUNK;
	if(chunkSize > size) {
	    chunkSize = size;
	}
	ret = xmlSecBufferAppend(&(transform->inBuf), buf, chunkSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBufferAppend(%d)", chunkSize);
	    return(-1);
	}
	
	/* process the current data */
	ret = xmlSecTransformExecute(transform, 0, &ctx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformExecute");
	    return(-1);
	}
    
	/* write results to next transform */
	if((xmlSecBufferGetSize(&(transform->outBuf)) > 0) && (transform->next != NULL)) {
	    ret = xmlSecTransformWriteBin(transform->next,
					  xmlSecBufferGetData(&(transform->outBuf)),
					  xmlSecBufferGetSize(&(transform->outBuf)));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecTransformWriteBin");
		return(-1);
	    }
	}	
	xmlSecBufferSetSize(&(transform->outBuf), 0);
    }    
    return(res);
}

/**
 * xmlSecTransformDefault2FlushBin:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Finalizes writing (wrapper for transform specific flushBin() method). 
 *
 * Returns 0 if success or negative value otherwise.
 */
int
xmlSecTransformDefault2FlushBin(xmlSecTransformPtr transform) {
    xmlSecTransformCtx ctx; /* todo */
    int ret;

    xmlSecAssert2(xmlSecTransformIsValid(transform), -1);

    while(1) {
	/* process data */
	ret = xmlSecTransformExecute(transform, 1, &ctx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformExecute");
	    return(-1);
	}
    
	/* quit or write results to next transform */
	if(xmlSecBufferGetSize(&(transform->outBuf)) == 0) {
	    break;
	} else if(transform->next != NULL) {
	    ret = xmlSecTransformWriteBin(transform->next,
					  xmlSecBufferGetData(&(transform->outBuf)),
					  xmlSecBufferGetSize(&(transform->outBuf)));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecTransformWriteBin");
		return(-1);
	    }
	}	
	xmlSecBufferSetSize(&(transform->outBuf), 0);
    }    

    if(transform->next != NULL) {
	ret = xmlSecTransformFlushBin(transform->next);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformFlushBin");
	    return(-1);
	}
    }

    return(0);
}



#include "transforms-old.c"
