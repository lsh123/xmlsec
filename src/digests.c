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

/** 
 * Digest specific hi-level methods
 */ 
/**
 * xmlSecDigestSignNode:
 * @transform: 
 * @valueNode:
 * @removeOldContent:
 *
 * Finalizes the digest result, signs it (if necessary), base64 encodes and
 * puts in the node content
 */
int 	
xmlSecDigestSignNode(xmlSecTransformPtr transform, xmlNodePtr valueNode, 
		 int removeOldContent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestSignNode";
    unsigned char *buffer = NULL;
    size_t size = 0;
    xmlChar* resultString = NULL;
    int ret;
    
    if(valueNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: valueNode is null\n",
	    func);	
#endif
	return(-1);
    }    
        
    ret = xmlSecDigestSign(transform, &buffer, &size);
    if(ret < 0) { 
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: digest sign failed\n",
	    func);	
#endif
	return(-1);	
    }
    
    if((buffer != NULL) && (size > 0)) {
	resultString = xmlSecBase64Encode(buffer, size, -1);
	if(resultString == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: base64 failed\n",
		func);	
#endif
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
 * @transform:
 * @valueNode:
 *
 * Reads the node content, base64 decodes it, finalizes the digest result and
 * verifies that it does match with the content of the node.
 * This functions returns only operation status (ok, fail). Verification
 * status is stored in xmlSecTransform::state variable 
 */
int
xmlSecDigestVerifyNode(xmlSecTransformPtr transform, const xmlNodePtr valueNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestVerifyNode";
    xmlChar *nodeContent;
    int ret;
    
    if(valueNode == NULL) {   
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: valueNode is null\n",
	    func);	
#endif
	return(-1);
    }
    
    nodeContent = xmlNodeGetContent(valueNode);
    if(nodeContent == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to get node content\n",
	    func);	
#endif
	return(-1);
    }
    
    /* 
     * small trick: decode in the same buffer becasue base64 decode result 
     * buffer size is always less than input buffer size
     */
    ret = xmlSecBase64Decode(nodeContent, (unsigned char *)nodeContent, 
			     xmlStrlen(nodeContent) + 1);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: base64 decode failed\n",
	    func);	
#endif
	xmlFree(nodeContent);
	return(-1);
    }		     

    ret = xmlSecDigestVerify(transform, (unsigned char *)nodeContent, ret);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: digest verification failed\n",
	    func);	
#endif
	xmlFree(nodeContent);
	return(-1);
    }
    xmlFree(nodeContent);    
    return(0);    
}

/**
 * xmlSecDigestSetPushMode
 * @transform:
 * @enabled:
 *
 * Sets the push more flag. If push mode is enabled then the digest is
 * finalized and send to next transform when 
 *	1) read from previous transform returned 0
 *	2) flush called
 */
void
xmlSecDigestSetPushMode(xmlSecTransformPtr transform, int enabled) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestSetPushMode";
    xmlSecDigestTransformPtr digest;    

    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return;
    }
    digest = (xmlSecDigestTransformPtr)transform;

    digest->pushModeEnabled = enabled;    
}

/** 
 * Digest specific low-level methods
 */ 
/**
 * xmlSecDigestUpdate
 * @transform:
 * @buffer:
 * @size:
 *
 * Envelope for xmlSecDigestTransformId::digestUpdate
 */
int
xmlSecDigestUpdate(xmlSecTransformPtr transform,
		   const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestUpdate";
    xmlSecDigestTransformPtr digest;    

    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;

    if((digest->id->digestUpdate) != NULL) {
	return((digest->id->digestUpdate)(digest, buffer, size));    
    }
    return(0);
}

/**
 * xmlSecDigestSign
 * @transform:
 * @buffer:
 * @size:
 *
 * Envelope for xmlSecDigestTransformId::digestSign
 */
int
xmlSecDigestSign(xmlSecTransformPtr transform, 
		 unsigned char **buffer, size_t *size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestSign";
    xmlSecDigestTransformPtr digest;    

    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;
    if((digest->id->digestSign) != NULL) {
	return((digest->id->digestSign)(digest, buffer, size)); 
    }
    return(0);    
}

/**
 * xmlSecDigestVerify
 * @transform:
 * @buffer:
 * @size:
 *
 * Envelope for xmlSecDigestTransformId::digestVerify
 * This functions returns only operation status (ok, fail). Verification
 * status is stored in xmlSecTransform::state variable 
 */
int
xmlSecDigestVerify(xmlSecTransformPtr transform,
		const unsigned char *buffer, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestVerify";
    xmlSecDigestTransformPtr digest;    

    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;
    if((digest->id->digestVerify) != NULL) {
        return((digest->id->digestVerify)(digest, buffer, size));
    }
    return(0);
}


/**
 * BinTransform methods to be used in the Id structure
 */
/**
 * xmlSecDigestTransformRead
 * @transform:
 * @buf:
 * @size:
 *
 * Reads all data from previos transform and digests it. If the 
 * push mode enabled then the result is finalized and returned to the caller,
 * otherwise we return 0
 */
int
xmlSecDigestTransformRead(xmlSecBinTransformPtr transform, 
			unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestTransformRead";
    xmlSecDigestTransformPtr digest;    
    int s;
    int ret;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest) ||
	(buf == NULL) || (size == 0)) { 
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or buf is null\n",
	    func);	
#endif
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
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: read from previous transform failed\n",
		func);	
#endif
	    return(-1);
	}
	
	ret = xmlSecDigestUpdate((xmlSecTransformPtr)transform, buf, s);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: digest update failed\n",
		func);	
#endif
	    return(-1);
	}	
    } while(s > 0);
    
    if(digest->pushModeEnabled) {
	unsigned char *res = NULL;
	size_t resSize = 0;
	
	ret = xmlSecDigestSign((xmlSecTransformPtr)transform, &res, &resSize);
	if((ret < 0) || (res == NULL) || (resSize == 0)){
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: digest sign failed\n",
		func);	
#endif
	    return(-1);
	}	
	if(resSize > size) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: buffer size is too small (%d bytes required)\n",
		func, resSize);	
#endif
	    return(-1);	    
	}
	memcpy(buf, res, resSize);
	return(resSize);
    }
    return(0);    
}

/**
 * xmlSecDigestTransformWrite
 * @transform:
 * @buf:
 * @size:
 * 
 * Just Updates the digest with the data in the  buffer
 */
int
xmlSecDigestTransformWrite(xmlSecBinTransformPtr transform, 
                        const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestTransformWrite";
    xmlSecDigestTransformPtr digest;    
    int ret;
    
    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;

    if((digest->status != xmlSecTransformStatusNone) || (buf == NULL) || (size == 0)){
	/* nothing to write: already */ 
	return(0);
    }

    ret = xmlSecDigestUpdate((xmlSecTransformPtr)transform, buf, size);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: digest update failed\n",
	    func);	
#endif
	return(-1);
    }	
    return(size);
}

/**
 * xmlSecDigestTransformFlush
 * @transform:
 *
 * If the push mode enabled then the function finalizes the result,
 * writes it to the next trasnform and calls flush for it. Otherwise,
 * it just calls flush for next trasnform
 */
int
xmlSecDigestTransformFlush(xmlSecBinTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecDigestTransformFlush";
    xmlSecDigestTransformPtr digest;    
    int ret;

    if(!xmlSecBinTransformCheckSubType(transform, xmlSecBinTransformSubTypeDigest)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    digest = (xmlSecDigestTransformPtr)transform;

    if(digest->pushModeEnabled) {
	unsigned char *res = NULL;
	size_t resSize = 0;
	
	ret = xmlSecDigestSign((xmlSecTransformPtr)transform, &res, &resSize);
	if((ret < 0) || (res == NULL) || (resSize == 0)){
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: digest sign failed\n",
		func);	
#endif
	    return(-1);
	}	
	if(digest->next != NULL) {
	    ret = xmlSecBinTransformWrite((xmlSecTransformPtr)digest->next, res, resSize);
	    if(ret < 0){
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: write to next transform failed\n",
		    func);	
#endif
		return(-1);
	    }	    	    
	}	
    }

    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)digest->next);
    if(ret < 0){
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: flush to next transform failed\n",
	    func);	
#endif
	return(-1);
    }	    	    
    return(0);    
}




