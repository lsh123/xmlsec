/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/base64.h>
#include <xmlsec/digests.h>
#include <xmlsec/errors.h>

/***********************************************************************
 *
 * Digest specific hi-level methods
 *
 **********************************************************************/
  
/**
 * xmlSecDigestSignNode:
 * @transform: the pointer to a digest transform.
 * @valueNode: the pointer to <dsig:DigestValue> node.
 * @removeOldContent: the flag that indicates whether the previous
 *             node content will be removed or not.
 *
 * Finalizes the digest result, signs it (if necessary), base64 encodes and
 * puts in the given node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 	
xmlSecDigestSignNode(xmlSecTransformPtr transform, xmlNodePtr valueNode, 
		 int removeOldContent) {
    unsigned char *buffer = NULL;
    size_t size = 0;
    xmlChar* resultString = NULL;
    int ret;
    
    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(valueNode != NULL, -1);
        
    ret = xmlSecDigestSign(transform, &buffer, &size);
    if(ret < 0) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDigestSign - %d", ret);
	return(-1);	
    }
    
    if((buffer != NULL) && (size > 0)) {
	resultString = xmlSecBase64Encode(buffer, size, -1);
	if(resultString == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBase64Encode");
	    return(-1);	
	}
    }
    
    if(removeOldContent) {
	xmlNodeSetContent(valueNode, resultString);
    } else if(resultString != NULL) {
	xmlNodeAddContent(valueNode, resultString);
    }
    
    if(resultString != NULL) {
	xmlFree(resultString);    
    }
    return(0);    
}

/**
 * xmlSecDigestVerifyNode:
 * @transform: the pointer to a digest transform.
 * @valueNode: the pointer to a <dsig:DigestValue> node.
 *
 * Reads the node content, base64 decodes it, finalizes the digest result and
 * verifies that it does match with the content of the node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecDigestVerifyNode(xmlSecTransformPtr transform, const xmlNodePtr valueNode) {
    xmlChar *nodeContent;
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(valueNode != NULL, -1);
    
    
    nodeContent = xmlNodeGetContent(valueNode);
    if(nodeContent == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    " ");
	return(-1);
    }
    
    /* 
     * small trick: decode in the same buffer becasue base64 decode result 
     * buffer size is always less than input buffer size
     */
    ret = xmlSecBase64Decode(nodeContent, (unsigned char *)nodeContent, 
			     xmlStrlen(nodeContent) + 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBase64Decode - %d", ret);
	xmlFree(nodeContent);
	return(-1);
    }		     

    ret = xmlSecDigestVerify(transform, (unsigned char *)nodeContent, ret);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDigestVerify - %d", ret);
	xmlFree(nodeContent);
	return(-1);
    }
    xmlFree(nodeContent);    
    return(0);    
}

/**
 * xmlSecDigestSetPushMode:
 * @transform: the pointer to a digests transform.
 * @enabled: the new "push mode" flag.
 *
 * Sets the push more flag. If push mode is enabled then the digest is
 * finalized and send to next transform when 
 *	1) read from previous transform returned 0
 *	2) flush called
 */
void
xmlSecDigestSetPushMode(xmlSecTransformPtr transform, int enabled) {
    xmlSecDigestTransformPtr digest;    

    xmlSecAssert(transform != NULL);    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeDigest");
	return;
    }
    digest = (xmlSecDigestTransformPtr)transform;

    digest->pushModeEnabled = enabled;    
}

/************************************************************************
 *
 * Digest specific low-level methods
 *
 ***********************************************************************/ 
/**
 * xmlSecDigestUpdate:
 * @transform: the pointer to a digests transform.
 * @buffer: the input data.
 * @size: the input data size.
 *
 * Updates data with the new chunk of data (wrapper for 
 * xmlSecDigestTransformId::digestUpdate method).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecDigestUpdate(xmlSecTransformPtr transform,
		   const unsigned char *buffer, size_t size) {
    xmlSecDigestTransformPtr digest;    

    xmlSecAssert2(transform != NULL, -1);
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeDigest");
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;

    if((digest->id->digestUpdate) != NULL) {
	return((digest->id->digestUpdate)(digest, buffer, size));    
    }
    return(0);
}

/**
 * xmlSecDigestSign:
 * @transform: the pointer to a digests transform.
 * @buffer: the pointer to the pointer to the output buffer.
 * @size: the pointer to the output buffer size.
 *
 * Finalizes digest and writes the result into the allocated 
 * buffer (wrapper for xmlSecDigestTransformId::digestSign function).
 * Caller is responsble for freeing allocated buffer with xmlFree() function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecDigestSign(xmlSecTransformPtr transform, 
		 unsigned char **buffer, size_t *size) {
    xmlSecDigestTransformPtr digest;    

    xmlSecAssert2(transform != NULL, -1);
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeDigest");
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;
    
    if((digest->id->digestSign) != NULL) {
	return((digest->id->digestSign)(digest, buffer, size)); 
    }
    return(0);    
}

/**
 * xmlSecDigestVerify:
 * @transform: the pointer to a digests transform.
 * @buffer: the input buffer.
 * @size: the input buffer size.
 *
 * Checks the computed digest and the data in the input buffer
 * (wrapper for xmlSecDigestTransformId::digestVerify function).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecDigestVerify(xmlSecTransformPtr transform,
		const unsigned char *buffer, size_t size) {
    xmlSecDigestTransformPtr digest;    

    xmlSecAssert2(transform != NULL, -1);

    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeDigest");
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;

    if((digest->id->digestVerify) != NULL) {
        return((digest->id->digestVerify)(digest, buffer, size));
    }
    return(0);
}


/*******************************************************************
 *
 * BinTransform methods to be used in the Id structure
 *
 ******************************************************************/
/**
 * xmlSecDigestTransformRead:
 * @transform: the pointer to a digest transform.
 * @buf: the output buffer.
 * @size: the output buffer size.
 *
 * Reads all data from previos transform and digests it. If the 
 * push mode enabled then the result is finalized and returned to the caller,
 * otherwise we return 0
 *
 * Returns the number of bytes in the buffer or negative value
 * if an error occurs.
 */
int
xmlSecDigestTransformRead(xmlSecBinTransformPtr transform, 
			unsigned char *buf, size_t size) {
    xmlSecDigestTransformPtr digest;    
    int s;
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(size > 0, -1);
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeDigest");
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;

    if((digest->status != xmlSecTransformStatusNone) || (digest->prev == NULL)) {
	/* nothing to read (already called final or there are no previous transform */ 
	return(0);
    }
    
    do {
	s = ret = xmlSecBinTransformRead((xmlSecTransformPtr)digest->prev, buf, size);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBinTransformRead - %d", ret);
	    return(-1);
	}
	
	ret = xmlSecDigestUpdate((xmlSecTransformPtr)transform, buf, s);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDigestUpdate - %d", ret);
	    return(-1);
	}	
    } while(s > 0);
    
    if(digest->pushModeEnabled) {
	unsigned char *res = NULL;
	size_t resSize = 0;
	
	ret = xmlSecDigestSign((xmlSecTransformPtr)transform, &res, &resSize);
	if((ret < 0) || (res == NULL) || (resSize == 0)){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDigestSign - %d", ret);
	    return(-1);
	}	
	if(resSize > size) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_SIZE,
			"%d bytes required (%d found)", resSize, size);
	    return(-1);	    
	}
	memcpy(buf, res, resSize);
	return(resSize);
    }
    return(0);    
}

/**
 * xmlSecDigestTransformWrite:
 * @transform: the poiter to a digests transform.
 * @buf: the input data buffer.
 * @size: the input data size.
 *
 * Adds new chunk of data to the digest.
 * 
 * Returns 0 if success or a negative value otherwise.
 */
int
xmlSecDigestTransformWrite(xmlSecBinTransformPtr transform, 
                        const unsigned char *buf, size_t size) {
    xmlSecDigestTransformPtr digest;    
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeDigest");
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;

    if((digest->status != xmlSecTransformStatusNone) || (buf == NULL) || (size == 0)){
	/* nothing to write: already */ 
	return(0);
    }

    ret = xmlSecDigestUpdate((xmlSecTransformPtr)transform, buf, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecDigestUpdate - %d", ret);
	return(-1);
    }	
    return(size);
}

/**
 * xmlSecDigestTransformFlush
 * @transform: the pointer to a digests transform.
 *
 * If the push mode enabled then the function finalizes the result,
 * writes it to the next transform and calls flush for it. Otherwise,
 * it just calls flush for next transform
 * 
 * Returns 0 if success or negative value otherwise.
 */
int
xmlSecDigestTransformFlush(xmlSecBinTransformPtr transform) {
    xmlSecDigestTransformPtr digest;    
    int ret;

    xmlSecAssert2(transform != NULL, -1);
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecBinTransformSubTypeDigest");
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;

    if(digest->pushModeEnabled) {
	unsigned char *res = NULL;
	size_t resSize = 0;
	
	ret = xmlSecDigestSign((xmlSecTransformPtr)transform, &res, &resSize);
	if((ret < 0) || (res == NULL) || (resSize == 0)){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecDigestSign - %d", ret);
	    return(-1);
	}	
	if(digest->next != NULL) {
	    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)digest->next, res, resSize);
	    if(ret < 0){
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecBinTransformWrite - %d", ret);
		return(-1);
	    }	    	    
	}	
    }

    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)digest->next);
    if(ret < 0){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBinTransformFlush - %d", ret);
	return(-1);
    }	    	    
    return(0);    
}

