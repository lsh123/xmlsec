/** 
 * XMLSec library
 *
 * XSLT Transform (http://www.w3.org/TR/xmldsig-core/#sec-XSLT)
 *
 * The normative specification for XSL Transformations is [XSLT]. 
 * Specification of a namespace-qualified stylesheet element, which MUST be 
 * the sole child of the Transform element, indicates that the specified style 
 * sheet should be used. Whether this instantiates in-line processing of local 
 * XSLT declarations within the resource is determined by the XSLT processing 
 * model; the ordered application of multiple stylesheet may require multiple 
 * Transforms. No special provision is made for the identification of a remote 
 * stylesheet at a given URI because it can be communicated via an  xsl:include 
 * or  xsl:import within the stylesheet child of the Transform.
 *
 * This transform requires an octet stream as input. If the actual input is an 
 * XPath node-set, then the signature application should attempt to convert it 
 * to octets (apply Canonical XML]) as described in the Reference Processing 
 * Model (section 4.3.3.2).]
 *
 * The output of this transform is an octet stream. The processing rules for 
 * the XSL style sheet or transform element are stated in the XSLT specification
 * [XSLT]. We RECOMMEND that XSLT transform authors use an output method of xml 
 * for XML and HTML. As XSLT implementations do not produce consistent 
 * serializations of their output, we further RECOMMEND inserting a transform 
 * after the XSLT transform to canonicalize the output. These steps will help 
 * to ensure interoperability of the resulting signatures among applications 
 * that support the XSLT transform. Note that if the output is actually HTML, 
 * then the result of these steps is logically equivalent [XHTML].
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#ifndef XMLSEC_NO_XSLT

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>

static int		xmlSecTransformXsltInitialize	(xmlSecTransformPtr transform);
static void		xmlSecTransformXsltFinalize	(xmlSecTransformPtr transform);
static int 		xmlSecTransformXsltReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int  		xmlSecTransformXsltRead		(xmlSecTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
static int  		xmlSecTransformXsltWrite	(xmlSecTransformPtr transform, 
							 const unsigned char *buf, 
							 size_t size);
static int  		xmlSecTransformXsltFlush	(xmlSecTransformPtr transform);
static int		xmlSecTransformXsltExecute	(xmlSecBufferPtr buffer,
							 xmlBufferPtr xslt);

static const struct _xmlSecTransformKlass xmlSecTransformXsltId = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    /* same as xmlSecTransformId */    
    BAD_CAST "xslt",
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/TR/1999/REC-xslt-19991116", /* const xmlChar href; */

    xmlSecTransformXsltInitialize,	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXsltFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXsltReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
    /* binary methods */
    NULL,
    xmlSecTransformXsltRead,		/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformXsltWrite,		/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformXsltFlush,		/* xmlSecTransformFlushMethod flushBin; */
    
    NULL,
    NULL,
};

xmlSecTransformId xmlSecTransformXslt = (xmlSecTransformId)&xmlSecTransformXsltId; 

#define xmlSecTransformXsltGetXsl(transform) \
    ((xmlBufferPtr)((transform)->reserved1))
    
/**
 * xmlSecTransformXsltInitialize:
 */
static int 
xmlSecTransformXsltInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXslt), -1);
    
    transform->reserved0 = transform->reserved1 = NULL;
    return(0);
}

/**
 * xmlSecTransformXsltFinalize:
 */
static void
xmlSecTransformXsltFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecTransformXslt));

    if(transform->reserved0 != NULL) {
	xmlSecBufferDestroy((xmlSecBufferPtr)(transform->reserved0)); 
    }    
    if(xmlSecTransformXsltGetXsl(transform) != NULL) {
	xmlBufferEmpty(xmlSecTransformXsltGetXsl(transform)); 
	xmlBufferFree(xmlSecTransformXsltGetXsl(transform)); 
    }
    transform->reserved0 = transform->reserved1 = NULL;
}

/**
 * xmlSecTransformXsltRead:
 */
static int
xmlSecTransformXsltRead(xmlSecTransformPtr transform, 
			unsigned char *buf, size_t size) {
    xmlSecTransformPtr xsltTransform;
    xmlSecBufferPtr buffer;
    int ret;

    xmlSecAssert2(transform != NULL, -1);    
           
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(-1);
    }
    xsltTransform = (xmlSecTransformPtr)transform;

    xmlSecAssert2(xmlSecTransformXsltGetXsl(xsltTransform) != NULL, -1);

    /* it's the first call, read data! */
    buffer = (xmlSecBufferPtr)(xsltTransform->reserved0);
    if(buffer == NULL) {
	if(xsltTransform->prev == NULL) {
	    /* nothing to read */
	    return(0);
	}
	
	xsltTransform->reserved0 = buffer = xmlSecBufferCreate(0);
	if(xsltTransform->reserved0 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlSecBufferCreate");
	    return(-1);
	}
	
	do{
	    ret = xmlSecTransformReadBin(xsltTransform->prev, buf, size);
	    if(ret < 0) {
	        xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecTransformRead - %d", ret);
	        return(-1);
	    } else if(ret > 0) {
		xmlSecBufferAppend(buffer, buf, ret);
	    }
	}while(ret > 0);
	
	/* execute xslt transform */
	ret = xmlSecTransformXsltExecute(buffer, xmlSecTransformXsltGetXsl(xsltTransform));
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformXsltExecute - %d", ret);
	    return(-1);
	}
    }
    
    if(size > (size_t)xmlSecBufferGetSize(buffer)) {
	size = (size_t)xmlSecBufferGetSize(buffer);
    }
    if((size > 0) && (buf != NULL)) {
	/* copy data to the caller */
	memcpy(buf, xmlSecBufferGetData(buffer), size);
	/* remove them from our buffer */
	xmlSecBufferRemoveHead(buffer, size);
	return(size);
    }    
    return(size);
}

/**
 * xmlSecTransformXsltWrite:
 */
static int
xmlSecTransformXsltWrite(xmlSecTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    xmlSecTransformPtr xsltTransform;
    xmlSecBufferPtr ptr;

    xmlSecAssert2(transform != NULL, -1);    
            
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(-1);
    }
    xsltTransform = (xmlSecTransformPtr)transform;

    if((buf == NULL) || (size == 0)) {
	/* nothing to write */
	return(0);
    }
    
    if(xsltTransform->reserved0 == NULL) {
	xsltTransform->reserved0 = ptr = xmlSecBufferCreate(0);
	if(xsltTransform->reserved0 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlSecBufferCreate");
	    return(-1);
	}
    } else {
	ptr = (xmlSecBufferPtr)(xsltTransform->reserved0);
    }

    xmlSecBufferAppend(ptr, buf, size);
    return(size);
}

/**
 * xmlSecTransformXsltFlush:
 */
static int
xmlSecTransformXsltFlush(xmlSecTransformPtr transform) {
    int ret;
    xmlSecTransformPtr xsltTransform;

    xmlSecAssert2(transform != NULL, -1);    
        
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(-1);
    }
    xsltTransform = (xmlSecTransformPtr)transform;

    xmlSecAssert2(xmlSecTransformXsltGetXsl(xsltTransform) != NULL, -1);
    
    if(xsltTransform->next == NULL) {
    	/* nothing to flush */
	return(0);
    }

    
    if(xsltTransform->reserved0 != NULL) { 
	xmlSecBufferPtr buffer;
		
	buffer = (xmlSecBufferPtr)(xsltTransform->reserved0); 
	
	/* execute xslt transform */
	ret = xmlSecTransformXsltExecute(buffer, xmlSecTransformXsltGetXsl(xsltTransform));
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformXsltExecute - %d", ret);
	    return(-1);
	}

	ret = xmlSecTransformWriteBin((xmlSecTransformPtr)(xsltTransform->next), 
		    xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer));
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformWrite - %d", ret);
	    return(-1);
	}
	/* remove them from our buffer */
	xmlSecBufferEmpty(buffer);
    }

    ret = xmlSecTransformFlushBin((xmlSecTransformPtr)(xsltTransform->next));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformFlush - %d", ret);
	return(-1);
    }

    return(ret);
}

/**
 * xmlSecTransformXsltReadNode:
 */
static int
xmlSecTransformXsltReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecTransformPtr xsltTransform;
    xmlBufferPtr buffer;
    xmlNodePtr cur;

    xmlSecAssert2(transform != NULL, -1);    
    xmlSecAssert2(xmlSecTransformXsltGetXsl(transform) == NULL, -1);
    xmlSecAssert2(transformNode != NULL, -1);    
        
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(-1);
    }    
    xsltTransform = (xmlSecTransformPtr)transform;

    buffer = xmlBufferCreate();
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlSecBufferCreate");
	return(-1);
    }
    
    cur = transformNode->children;
    while(cur != NULL) {
	xmlNodeDump(buffer, cur->doc, cur, 0, 0);
	cur = cur->next;
    }
        
    xsltTransform->reserved1 = buffer;
    return(0);
}

/**
 * xmlSecTransformXsltAdd:
 * @transformNode: the pointer to <dsig:Transform> node.
 * @xslt: the XSLT transform exspression.
 * 
 * Writes the XSLT transform expression to the @transformNode.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformXsltAdd(xmlNodePtr transformNode, const xmlChar *xslt) {
    xmlDocPtr xslt_doc;
    int ret;
        
    xmlSecAssert2(transformNode != NULL, -1);    
    xmlSecAssert2(xslt != NULL, -1);    
    
    xslt_doc = xmlParseMemory(xslt, xmlStrlen(xslt));
    if(xslt_doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlParseMemory");
	return(-1);
    }
    
    ret = xmlSecReplaceContent(transformNode, xmlDocGetRootElement(xslt_doc));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecReplaceContent");
	xmlFreeDoc(xslt_doc);
	return(-1);
    }
    
    xmlFreeDoc(xslt_doc);
    return(0);
}


/**
 * xmlSecTransformXsltExecute:
 */
static int
xmlSecTransformXsltExecute(xmlSecBufferPtr buffer, xmlBufferPtr xslt) {
    xmlDocPtr doc = NULL;
    xmlDocPtr docXslt = NULL;
    xsltStylesheetPtr cur = NULL;
    xmlDocPtr docRes = NULL;
    xmlOutputBufferPtr output = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(buffer != NULL, -1);    
    xmlSecAssert2(xslt != NULL, -1);    

    doc = xmlSecParseMemory(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer), 1);
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecParseMemory");
	goto done;	
    }

    docXslt = xmlSecParseMemory(xmlBufferContent(xslt), xmlBufferLength(xslt), 1);
    if(docXslt == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecParseMemory");
	goto done;	
    }

    cur = xsltParseStylesheetDoc(docXslt);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XSLT_FAILED,
		    "xsltParseStylesheetDoc");
	/* 
	 * after parsing stylesheet doc is assigned
	 * to it and will be freed by xsltFreeStylesheet()
	 */    
	xmlFreeDoc(docXslt);
	goto done;	
    }

    docRes = xsltApplyStylesheet(cur, doc, NULL);
    if(docRes == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XSLT_FAILED,
		    "xsltApplyStylesheet");
	goto done;	
    }
    
    output = xmlAllocOutputBuffer(NULL);
    if(output == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlAllocOutputBuffer");
	goto done;	
    }

    ret = xsltSaveResultTo(output, docRes, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XSLT_FAILED,
		    "xsltSaveResultTo - %d", ret);
	goto done;	
    }

    ret = xmlSecBufferSetData(buffer, xmlBufferContent(output->buffer), 
			    xmlBufferLength(output->buffer));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBufferSetData");
	goto done;	
    }

    res = 0;

    
done:   
    if(output != NULL) xmlOutputBufferClose(output);
    if(docRes != NULL) xmlFreeDoc(docRes);
    if(cur != NULL) xsltFreeStylesheet(cur);
    if(doc != NULL) xmlFreeDoc(doc);
    return(res);    
}


#endif /* XMLSEC_NO_XSLT */

