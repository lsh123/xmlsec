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
#include <xmlsec/xpath.h>

/* Enveloped transform */
static xmlSecTransformPtr xmlSecTransformEnvelopedCreate(xmlSecTransformId id);
static void		xmlSecTransformEnvelopedDestroy	(xmlSecTransformPtr transform);
static int 		xmlSecTransformEnvelopedReadNode(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformEnvelopedExecute	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);


struct _xmlSecXmlTransformIdStruct xmlSecTransformEnvelopedId = {
    /* same as xmlSecTransformId */ 
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    BAD_CAST "http://www.w3.org/2000/09/xmldsig#enveloped-signature", 
					/* const xmlChar *href; */

    xmlSecTransformEnvelopedCreate,	/* xmlSecTransformCreateMethod create; */
    xmlSecTransformEnvelopedDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    xmlSecTransformEnvelopedReadNode,	/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlTransform info */
    xmlSecTransformEnvelopedExecute	/* xmlSecXmlTransformExecuteMethod executeXml; */
};

xmlSecTransformId xmlSecTransformEnveloped = (xmlSecTransformId)(&xmlSecTransformEnvelopedId);

/****************************************************************************
 *
 * Enveloped transform 
 *
 ****************************************************************************/
/**
 * xmlSecTransformEnvelopedCreate
 * @id: the enveloped transform id
 * 
 * Creates new enveloped transform.
 *
 * Returns enveloped transform or NULL if an error occurs.
 */
static xmlSecTransformPtr 
xmlSecTransformEnvelopedCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformEnvelopedCreate";
    xmlSecXmlTransformPtr xmlTransform; 
    
    if(id != xmlSecTransformEnveloped){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is not recognized\n",
	    func);
#endif 	    
	return(NULL);
    }
    
    xmlTransform = (xmlSecXmlTransformPtr)xmlMalloc(sizeof(struct _xmlSecXmlTransform));
    if(xmlTransform == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate struct _xmlSecXmlTransform \n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(xmlTransform, 0,  sizeof(struct _xmlSecXmlTransform));
    xmlTransform->id = (xmlSecXmlTransformId)xmlSecTransformEnveloped;    
    return((xmlSecTransformPtr)xmlTransform);
}

/**
 * xmlSecTransformEnvelopedDestroy
 * @transform: the enveloped transform.  
 *
 * Destroys the enveloped trasnform.
 */
static void
xmlSecTransformEnvelopedDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformEnvelopedDestroy";
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformEnveloped)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return;
    }    
    memset(transform, 0,  sizeof(struct _xmlSecXmlTransform));  
    xmlFree(transform);
}

/**
 * xmlSecTransformEnvelopedReadNode
 * @transform:
 * @transformNode:
 *
 */
static int 
xmlSecTransformEnvelopedReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformEnvelopedReadNode";
    xmlSecXmlTransformPtr xmlTransform;
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformEnveloped) || 
       (transformNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    xmlTransform->here = transformNode;
    return(0);
}


/**
 * xmlSecTransformEnvelopedExecute
 * @transform:
 * @ctxDoc:
 * @doc:
 * @nodes:
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
xmlSecTransformEnvelopedExecute(xmlSecXmlTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformEnvelopedExecute";
    xmlSecXmlTransformPtr xmlTransform;
    xmlNodePtr signature;
    xmlSecNodeSetPtr res;
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformEnveloped) || 
       (nodes == NULL) || (doc == NULL) || ((*doc) == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or something else is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;

    if(((*doc) != ctxDoc) || (xmlTransform->here == NULL) || 
	(xmlTransform->here->doc != (*doc))) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: enveloped transform works only on the same document\n",
	    func);	
#endif
	return(-1);
    }

    signature = xmlSecFindParent(xmlTransform->here, BAD_CAST "Signature", xmlSecDSigNs);
    if(signature == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: \"Signature\" node is not found\n",
	    func);	
#endif
	return(-1);
    }
    
    res = xmlSecNodeSetGetChildren((*doc), signature, 1, 1);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create nodes set\n",
	    func);	
#endif
	return(-1);
    }

    (*nodes) = xmlSecNodeSetAdd((*nodes), res, xmlSecNodeSetIntersection);
    if((*nodes) == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add subset\n",
	        func);	
#endif
	xmlSecNodeSetDestroy(res);
	return(-1);
    }
    return(0);
}



