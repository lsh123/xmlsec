/** 
 * XMLSec library
 *
 * Enveloped transform
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
#include <libxml/xpathInternals.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/errors.h>

/* Enveloped transform */
static int 	xmlSecTransformEnvelopedReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 	xmlSecTransformEnvelopedExecute		(xmlSecTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);


struct _xmlSecTransformKlass xmlSecTransformEnvelopedId = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    xmlSecNameEnveloped,
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecTransformUsageDSigTransform,	/* xmlSecTransformUsage	usage; */
    xmlSecHrefEnveloped,		/* const xmlChar *href; */
    
    NULL,				/* xmlSecTransformInitializeMethod initialize; */
    NULL,				/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformEnvelopedReadNode,	/* xmlSecTransformReadNodeMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmSecTransformPushBinMethod pushBin; */
    NULL,				/* xmSecTransformPopBinMethod popBin; */
    NULL,				/* xmSecTransformPushXmlMethod pushXml; */
    NULL,				/* xmSecTransformPopXmlMethod popXml; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */

    /* bin transforms */
    NULL,
    NULL,
    NULL,
    NULL,
    
    /* xmlTransform info */
    xmlSecTransformEnvelopedExecute,	/* xmlSecTransformExecuteMethod executeXml; */

    /* c14n */
    NULL
};

xmlSecTransformId xmlSecTransformEnveloped = (xmlSecTransformId)(&xmlSecTransformEnvelopedId);

/****************************************************************************
 *
 * Enveloped transform 
 *
 ****************************************************************************/
/**
 * xmlSecTransformEnvelopedReadNode:
 */
static int 
xmlSecTransformEnvelopedReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformEnveloped), -1);
    xmlSecAssert2(transformNode!= NULL, -1);

    transform->hereNode = transformNode;
    return(0);
}

/**
 * xmlSecTransformEnvelopedExecute:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-EnvelopedSignature
 *
 * An enveloped signature transform T removes the whole Signature element 
 * containing T from the digest calculation of the Reference element 
 * containing T. The entire string of characters used by an XML processor 
 * to match the Signature with the XML production element is removed. 
 * The output of the transform is equivalent to the output that would 
 * result from replacing T with an XPath transform containing the following 
 * XPath parameter element:
 *
 * <XPath xmlns:dsig="&dsig;">
 *   count(ancestor-or-self::dsig:Signature |
 *   here()/ancestor::dsig:Signature[1]) >
 *   count(ancestor-or-self::dsig:Signature)</XPath>
 *    
 * The input and output requirements of this transform are identical to 
 * those of the XPath transform, but may only be applied to a node-set from 
 * its parent XML document. Note that it is not necessary to use an XPath 
 * expression evaluator to create this transform. However, this transform 
 * MUST produce output in exactly the same manner as the XPath transform 
 * parameterized by the XPath expression above.
 */
static int
xmlSecTransformEnvelopedExecute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecTransformPtr xmlTransform;
    xmlNodePtr signature;
    xmlSecNodeSetPtr res;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformEnveloped), -1);
    xmlSecAssert2(ctxDoc != NULL, -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);
    xmlSecAssert2(nodes != NULL, -1);
    
    xmlTransform = (xmlSecTransformPtr)transform;

    if(((*doc) != ctxDoc) || (xmlTransform->hereNode == NULL) || (xmlTransform->hereNode->doc != (*doc))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_SAME_DOCUMENT_REQUIRED,
		    "enveloped transform works only on the same document");
	return(-1);
    }

    signature = xmlSecFindParent(xmlTransform->hereNode, BAD_CAST "Signature", xmlSecDSigNs);
    if(signature == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecFindParent",
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    "<dsig:Signature>");
	return(-1);
    }
    
    res = xmlSecNodeSetGetChildren((*doc), signature, 1, 1);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecNodeSetGetChildren",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    (*nodes) = xmlSecNodeSetAdd((*nodes), res, xmlSecNodeSetIntersection);
    if((*nodes) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecNodeSetAdd",		    
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecNodeSetDestroy(res);
	return(-1);
    }
    return(0);
}

