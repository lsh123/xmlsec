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

/****************************************************************************
 *
 * XSLT transform
 *
 * resereved0 --> parsed stylesheet (xsltStylesheetPtr)
 * 
 ***************************************************************************/
#define xmlSecXsltGetStylesheet(transform) \
    ((xsltStylesheetPtr)((transform)->reserved0))
static int		xmlSecXsltInitialize			(xmlSecTransformPtr transform);
static void		xmlSecXsltFinalize			(xmlSecTransformPtr transform);
static int 		xmlSecXsltReadNode			(xmlSecTransformPtr transform,
								 xmlNodePtr transformNode);
static int  		xmlSecXsltExecute			(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);
static int		xmlSecXslProcess			(xmlSecBufferPtr in,
								 xmlSecBufferPtr out,
								 xsltStylesheetPtr stylesheet);
static xmlSecTransformKlass xmlSecXsltKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    xmlSecNameXslt,			/* const xmlChar* name; */
    xmlSecTransformTypeBinary,		/* xmlSecTransformType type; */
    xmlSecTransformUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefXslt, 			/* const xmlChar href; */

    xmlSecXsltInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecXsltFinalize,			/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecXsltReadNode,			/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    xmlSecXsltExecute,			/* xmlSecTransformExecuteMethod execute; */
    
    /* binary methods */
    NULL,
    xmlSecTransformDefault2ReadBin,	/* xmlSecTransformReadMethod readBin; */
    xmlSecTransformDefault2WriteBin,	/* xmlSecTransformWriteMethod writeBin; */
    xmlSecTransformDefault2FlushBin,	/* xmlSecTransformFlushMethod flushBin; */
    
    NULL,
    NULL,
};

xmlSecTransformId 
xmlSecTransformXsltGetKlass(void) {
    return(&xmlSecXsltKlass);
}
    
static int 
xmlSecXsltInitialize(xmlSecTransformPtr transform) {    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXsltId), -1);

    transform->reserved0 = NULL;    
    return(0);
}

static void
xmlSecXsltFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecTransformXsltId));
    
    if(xmlSecXsltGetStylesheet(transform) != NULL) {
	xsltFreeStylesheet(xmlSecXsltGetStylesheet(transform));
    }
    transform->reserved0 = NULL;    
}

/**
 * xmlSecXsltReadNode:
 */
static int
xmlSecXsltReadNode(xmlSecTransformPtr transform, xmlNodePtr node) {
    xmlBufferPtr buffer;
    xmlDocPtr doc;
    xmlNodePtr cur;
    
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXsltId), -1);
    xmlSecAssert2(xmlSecXsltGetStylesheet(transform) == NULL, -1);
    xmlSecAssert2(node != NULL, -1);    

    /* read content in the buffer */    
    buffer = xmlBufferCreate();
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlBufferCreate",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    cur = node->children;
    while(cur != NULL) {
	xmlNodeDump(buffer, cur->doc, cur, 0, 0);
	cur = cur->next;
    }
    
    /* parse the buffer */
    doc = xmlSecParseMemory(xmlBufferContent(buffer), 
			     xmlBufferLength(buffer), 1);
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecParseMemory",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlBufferFree(buffer);
	return(-1);
    }

    /* pre-process stylesheet */    
    transform->reserved0 = xsltParseStylesheetDoc(doc);
    if(transform->reserved0 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xsltParseStylesheetDoc",
		    XMLSEC_ERRORS_R_XSLT_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	/* after parsing stylesheet doc is assigned
	 * to it and will be freed by xsltFreeStylesheet() */    
	xmlFreeDoc(doc);
	xmlBufferFree(buffer);
	return(-1);
    }
    
    xmlBufferFree(buffer);
    return(0);
}

static int 
xmlSecXsltExecute(xmlSecTransformPtr transform, int last, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr in, out;
    size_t inSize, outSize;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXsltId), -1);
    xmlSecAssert2(xmlSecXsltGetStylesheet(transform) != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    in = &(transform->inBuf);
    out = &(transform->outBuf);
    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);    
    xmlSecAssert2(outSize == 0, -1);
    
    if(transform->status == xmlSecTransformStatusNone) {
	transform->status = xmlSecTransformStatusWorking;
    } else if((transform->status == xmlSecTransformStatusWorking) && (last == 0)) {
	/* just do nothing */
    } else  if((transform->status == xmlSecTransformStatusWorking) && (last != 0)) {
	ret = xmlSecXslProcess(in, out, xmlSecXsltGetStylesheet(transform));
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecXslProcess",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	
	ret = xmlSecBufferRemoveHead(in, inSize);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE, 
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecBufferRemoveHead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"%d", inSize);
	    return(-1);
	}
	
	transform->status = xmlSecTransformStatusFinished;
    } else if(transform->status == xmlSecTransformStatusFinished) {
	/* the only way we can get here is if there is no input */
	xmlSecAssert2(xmlSecBufferGetSize(&(transform->inBuf)) == 0, -1);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_STATUS,
		    "%d", transform->status);
	return(-1);
    }
    return(0);
}

static int 
xmlSecXslProcess(xmlSecBufferPtr in, xmlSecBufferPtr out,  xsltStylesheetPtr stylesheet) {
    xmlDocPtr docIn = NULL;
    xmlDocPtr docOut = NULL;
    xmlOutputBufferPtr output = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(stylesheet != NULL, -1);

    docIn = xmlSecParseMemory(xmlSecBufferGetData(in), xmlSecBufferGetSize(in), 1);
    if(docIn == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecParseMemory",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;	
    }

    docOut = xsltApplyStylesheet(stylesheet, docIn, NULL);
    if(docOut == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xsltApplyStylesheet",
		    XMLSEC_ERRORS_R_XSLT_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;	
    }
    
    output = xmlAllocOutputBuffer(NULL);
    if(output == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlAllocOutputBuffer",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;	
    }

    ret = xsltSaveResultTo(output, docOut, stylesheet);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xsltSaveResultTo",
		    XMLSEC_ERRORS_R_XSLT_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;	
    }

    ret = xmlSecBufferSetData(out, xmlBufferContent(output->buffer), 
			    xmlBufferLength(output->buffer));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecBufferSetData",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;	
    }
    
    res = 0;

done:   
    if(output != NULL) xmlOutputBufferClose(output);
    if(docIn != NULL) xmlFreeDoc(docIn);
    if(docOut != NULL) xmlFreeDoc(docOut);
    return(res);    
}

#endif /* XMLSEC_NO_XSLT */

