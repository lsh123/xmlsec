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

static xmlSecTransformPtr xmlSecTransformXsltCreate	(xmlSecTransformId id);
static void		xmlSecTransformXsltDestroy	(xmlSecTransformPtr transform);
static int 		xmlSecTransformXsltReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int  		xmlSecTransformXsltRead		(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
static int  		xmlSecTransformXsltWrite	(xmlSecBinTransformPtr transform, 
							 const unsigned char *buf, 
							 size_t size);
static int  		xmlSecTransformXsltFlush	(xmlSecBinTransformPtr transform);
static int		xmlSecTransformXsltExecute	(xmlBufferPtr buffer,
							 xmlBufferPtr xslt);

static const struct _xmlSecBinTransformIdStruct xmlSecTransformXsltId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    xmlSecTransformXsltHref, 		/* const xmlChar href; */

    xmlSecTransformXsltCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecTransformXsltDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecTransformXsltReadNode,	/* xmlSecTransformReadMethod read; */
    
    /* binary methods */
    xmlSecKeyIdUnknown,
    xmlSecKeyTypeAny,			/* xmlSecKeyType encryption; */
    xmlSecKeyTypeAny,			/* xmlSecKeyType decryption; */
    xmlSecBinTransformSubTypeNone,
    NULL,				/* xmlSecBinTransformAddKeyMethod addBinKey; */
    xmlSecTransformXsltRead,		/* xmlSecBinTransformReadMethod readBin; */
    xmlSecTransformXsltWrite,		/* xmlSecBinTransformWriteMethod writeBin; */
    xmlSecTransformXsltFlush,		/* xmlSecBinTransformFlushMethod flushBin; */
};

xmlSecTransformId xmlSecTransformXslt = (xmlSecTransformId)&xmlSecTransformXsltId; 

/**
 * xmlSecTransformXsltCreate:
 */
static xmlSecTransformPtr 
xmlSecTransformXsltCreate(xmlSecTransformId id) {
    xmlSecBinTransformPtr ptr;
    
    xmlSecAssert2(id != NULL, NULL);    
    if(id != xmlSecTransformXslt){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(NULL);
    }

    /*
     * Allocate a new xmlSecBinTransform and fill the fields.
     */
    ptr = (xmlSecBinTransformPtr) xmlMalloc(sizeof(xmlSecBinTransform));
    if(ptr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecBinTransform)=%d",
		    sizeof(xmlSecBinTransform));
	return(NULL);
    }
    memset(ptr, 0, sizeof(xmlSecBinTransform));
    
    ptr->id = (xmlSecBinTransformId)id;
    return((xmlSecTransformPtr)ptr);    
}

/**
 * xmlSecTransformXsltDestroy:
 */
static void
xmlSecTransformXsltDestroy(xmlSecTransformPtr transform) {
    xmlSecBinTransformPtr xsltTransform;

    xmlSecAssert(transform != NULL);    
            
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return;
    }    
    xsltTransform = (xmlSecBinTransformPtr)transform;
    
    if(xsltTransform->data != NULL) {
	xmlBufferEmpty((xmlBufferPtr)(xsltTransform->data));
	xmlBufferFree((xmlBufferPtr)(xsltTransform->data)); 
    }    
    if(xsltTransform->binData != NULL) {
	xmlBufferEmpty((xmlBufferPtr)(xsltTransform->binData));
	xmlBufferFree((xmlBufferPtr)(xsltTransform->binData)); 
    }

    memset(transform, 0, sizeof(xmlSecBinTransform));
    xmlFree(transform);    
}

/**
 * xmlSecTransformXsltRead:
 */
static int
xmlSecTransformXsltRead(xmlSecBinTransformPtr transform, 
			unsigned char *buf, size_t size) {
    xmlSecBinTransformPtr xsltTransform;
    xmlBufferPtr buffer;
    int ret;

    xmlSecAssert2(transform != NULL, -1);    
           
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(-1);
    }
    xsltTransform = (xmlSecBinTransformPtr)transform;

    xmlSecAssert2(xsltTransform->binData != NULL, -1);

    /* it's the first call, read data! */
    buffer = (xmlBufferPtr)(xsltTransform->data);
    if(buffer == NULL) {
	if(xsltTransform->prev == NULL) {
	    /* nothing to read */
	    return(0);
	}
	
	xsltTransform->data = buffer = xmlBufferCreate();
	if(xsltTransform->data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlBufferCreate");
	    return(-1);
	}
	
	do{
	    ret = xmlSecBinTransformRead((xmlSecTransformPtr)(xsltTransform->prev), buf, size);
	    if(ret < 0) {
	        xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecBinTransformRead - %d", ret);
	        return(-1);
	    } else if(ret > 0) {
		xmlBufferAdd(buffer, buf, ret);
	    }
	}while(ret > 0);
	
	/* execute xslt transform */
	ret = xmlSecTransformXsltExecute(buffer, 
				        (xmlBufferPtr)xsltTransform->binData);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformXsltExecute - %d", ret);
	    return(-1);
	}
    }
    
    if(size > (size_t)xmlBufferLength(buffer)) {
	size = (size_t)xmlBufferLength(buffer);
    }
    if((size > 0) && (buf != NULL)) {
	/* copy data to the caller */
	memcpy(buf, xmlBufferContent(buffer), size);
	/* remove them from our buffer */
	xmlBufferShrink(buffer, size);
	return(size);
    }    
    return(size);
}

/**
 * xmlSecTransformXsltWrite:
 */
static int
xmlSecTransformXsltWrite(xmlSecBinTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    xmlSecBinTransformPtr xsltTransform;
    xmlBufferPtr ptr;

    xmlSecAssert2(transform != NULL, -1);    
            
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(-1);
    }
    xsltTransform = (xmlSecBinTransformPtr)transform;

    if((buf == NULL) || (size == 0)) {
	/* nothing to write */
	return(0);
    }
    
    if(xsltTransform->data == NULL) {
	xsltTransform->data = ptr = xmlBufferCreate();
	if(xsltTransform->data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XML_FAILED,
			"xmlBufferCreate");
	    return(-1);
	}
    } else {
	ptr = (xmlBufferPtr)(xsltTransform->data);
    }

    xmlBufferAdd(ptr, buf, size);
    return(size);
}

/**
 * xmlSecTransformXsltFlush:
 */
static int
xmlSecTransformXsltFlush(xmlSecBinTransformPtr transform) {
    int ret;
    xmlSecBinTransformPtr xsltTransform;

    xmlSecAssert2(transform != NULL, -1);    
        
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(-1);
    }
    xsltTransform = (xmlSecBinTransformPtr)transform;

    xmlSecAssert2(xsltTransform->binData != NULL, -1);
    
    if(xsltTransform->next == NULL) {
    	/* nothing to flush */
	return(0);
    }

    
    if(xsltTransform->data != NULL) { 
	xmlBufferPtr buffer;
		
	buffer = (xmlBufferPtr)(xsltTransform->data); 
	
	/* execute xslt transform */
	ret = xmlSecTransformXsltExecute(buffer, 
				        (xmlBufferPtr)xsltTransform->binData);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformXsltExecute - %d", ret);
	    return(-1);
	}

	ret = xmlSecBinTransformWrite((xmlSecTransformPtr)(xsltTransform->next), 
		    xmlBufferContent(buffer), xmlBufferLength(buffer));
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBinTransformWrite - %d", ret);
	    return(-1);
	}
	/* remove them from our buffer */
	xmlBufferEmpty(buffer);
    }

    ret = xmlSecBinTransformFlush((xmlSecTransformPtr)(xsltTransform->next));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBinTransformFlush - %d", ret);
	return(-1);
    }

    return(ret);
}

/**
 * xmlSecTransformXsltReadNode:
 */
static int
xmlSecTransformXsltReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecBinTransformPtr xsltTransform;
    xmlBufferPtr buffer;
    xmlNodePtr cur;

    xmlSecAssert2(transform != NULL, -1);    
    xmlSecAssert2(transformNode != NULL, -1);    
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXslt)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformXslt");
	return(-1);
    }    
    xsltTransform = (xmlSecBinTransformPtr)transform;

    buffer = xmlBufferCreate();
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlBufferCreate");
	return(-1);
    }
    
    cur = transformNode->children;
    while(cur != NULL) {
	xmlNodeDump(buffer, cur->doc, cur, 0, 0);
	cur = cur->next;
    }
        
    if(xsltTransform->binData != NULL) {
	xmlBufferEmpty((xmlBufferPtr)xsltTransform->binData);
	xmlBufferFree((xmlBufferPtr)(xsltTransform->data)); 
    }
    xsltTransform->binData = buffer;
    return(0);
}

/**
 * xmlSecTransformXsltExecute:
 */
static int
xmlSecTransformXsltExecute(xmlBufferPtr buffer, xmlBufferPtr xslt) {
    xmlDocPtr doc = NULL;
    xmlDocPtr docXslt = NULL;
    xsltStylesheetPtr cur = NULL;
    xmlDocPtr docRes = NULL;
    xmlOutputBufferPtr output = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(buffer != NULL, -1);    
    xmlSecAssert2(xslt != NULL, -1);    

    doc = xmlSecParseMemory(xmlBufferContent(buffer), xmlBufferLength(buffer), 1);
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

    xmlBufferEmpty(buffer);
    xmlBufferAdd(buffer, xmlBufferContent(output->buffer), 
		xmlBufferLength(output->buffer));
    res = 0;

    
done:   
    if(output != NULL) xmlOutputBufferClose(output);
    if(docRes != NULL) xmlFreeDoc(docRes);
    if(cur != NULL) xsltFreeStylesheet(cur);
    if(doc != NULL) xmlFreeDoc(doc);
    return(res);    
}


#endif /* XMLSEC_NO_XSLT */

