/** 
 * XMLSec library
 *
 * XPath transform
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
#include <libxml/xpointer.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/debug.h>
#include <xmlsec/errors.h>


typedef enum {
    xmlSecXPathTypeXPath,
    xmlSecXPathTypeXPath2,
    xmlSecXPathTypeXPointer
#ifdef XMLSEC_XPATH2_ALLOW_XPOINTER
    , xmlSecXPathTypeXPointer2
#endif /* XMLSEC_XPATH2_ALLOW_XPOINTER */    
} xmlSecXPathType;

/* XPath transform */
typedef struct _xmlSecXPathData xmlSecXPathData, *xmlSecXPathDataPtr;
struct _xmlSecXPathData {
    xmlChar			*expr;
    xmlChar			**nsList;
    size_t			nsListSize;
    xmlSecXPathType		xpathType;
    xmlSecXPath2TransformType	xpath2Type;
    xmlSecXPathDataPtr		next;
};


static xmlSecXPathDataPtr xmlSecXPathDataCreate		(const xmlNodePtr node,
							 xmlSecXPathDataPtr prev,
							 xmlSecXPathType xpathType);
static void		  xmlSecXPathDataDestroy	(xmlSecXPathDataPtr data);
static int		  xmlSecXPathDataReadNode	(xmlSecXPathDataPtr data,
							 const xmlNodePtr node);
static int		  xmlSecXPathDataReadNsList	(xmlSecXPathDataPtr data,
							 const xmlNodePtr node);
static xmlSecNodeSetPtr	  xmlSecXPathDataExecute	(xmlSecXPathDataPtr data,
							 xmlDocPtr doc,
							 xmlNodePtr hereNode);

static int 		xmlSecTransformXPathInitialize	(xmlSecTransformPtr transform);
static void		xmlSecTransformXPathFinalize	(xmlSecTransformPtr transform);

static int 		xmlSecTransformXPathReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPathExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);

static int 		xmlSecTransformXPath2ReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPath2Execute	(xmlSecTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);

static int 		xmlSecTransformXPointerReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPointerExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);

struct _xmlSecTransformKlass xmlSecTransformXPathId = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    /* same as xmlSecTransformId */ 
    BAD_CAST "xpath",
    xmlSecTransformTypeXml,			/* xmlSecTransformType type; */
    xmlSecTransformUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    xmlSecXPathNs, 				/* const xmlChar *href; */

    xmlSecTransformXPathInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPathReadNode,		/* xmlSecTransformReadNodeMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,					/* xmlSecTransformPushBinMethod pushBin; */
    NULL,					/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    NULL,					/* xmlSecTransformExecuteMethod execute; */
    
    xmlSecTransformXPathExecute,		/* xmlSecTransformExecuteMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};
xmlSecTransformId xmlSecTransformXPath = (xmlSecTransformId)(&xmlSecTransformXPathId);

struct _xmlSecTransformKlass xmlSecTransformXPath2Id = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    sizeof(xmlSecTransform),			/* size_t objSize */

    BAD_CAST "xpath2",
    xmlSecTransformTypeXml,			/* xmlSecTransformType type; */
    xmlSecTransformUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    xmlSecXPath2Ns, 				/* const xmlChar *href; */

    xmlSecTransformXPathInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPath2ReadNode,		/* xmlSecTransformReadNodeMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,					/* xmlSecTransformPushBinMethod pushBin; */
    NULL,					/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    NULL,					/* xmlSecTransformExecuteMethod execute; */

    xmlSecTransformXPath2Execute,		/* xmlSecTransformExecuteMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};
xmlSecTransformId xmlSecTransformXPath2 = (xmlSecTransformId)(&xmlSecTransformXPath2Id);

struct _xmlSecTransformKlass xmlSecTransformXPointerId = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    sizeof(xmlSecTransform),			/* size_t objSize */

    BAD_CAST "xpointer",
    xmlSecTransformTypeXml,			/* xmlSecTransformType type; */
    xmlSecTransformUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    xmlSecXPointerNs, 				/* const xmlChar *href; */

    xmlSecTransformXPathInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPointerReadNode,		/* xmlSecTransformReadNodeMethod read; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,					/* xmlSecTransformPushBinMethod pushBin; */
    NULL,					/* xmlSecTransformPopBinMethod popBin; */
    NULL,					/* xmlSecTransformPushXmlMethod pushXml; */
    NULL,					/* xmlSecTransformPopXmlMethod popXml; */
    NULL,					/* xmlSecTransformExecuteMethod execute; */

    xmlSecTransformXPointerExecute,		/* xmlSecTransformExecuteMethod executeXml; */
    NULL,					/* xmlSecTransformExecuteC14NMethod executeC14N; */
};
xmlSecTransformId xmlSecTransformXPointer = (xmlSecTransformId)(&xmlSecTransformXPointerId);


static const xmlChar xpathPattern[] = "(//. | //@* | //namespace::*)[%s]";

/** 
 * xmlSecXPathHereFunction:
 *
 * The implementation of XPath "here()" function.
 * See xmlXPtrHereFunction() in xpointer.c. the only change is that 
 * we return NodeSet instead of NodeInterval.
 */
static void 
xmlSecXPathHereFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);

    if((ctxt == NULL) || (ctxt->context == NULL) || (ctxt->context->here == NULL)) {
	XP_ERROR(XPTR_SYNTAX_ERROR);
    }
    valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->here));
}



/***************************************************************************
 *
 *         Common XPath/XPointer transforms functions
 *
 **************************************************************************/
#define xmlSecTransformXPathCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecTransformXPath) || \
     xmlSecTransformCheckId((transform), xmlSecTransformXPath2) || \
     xmlSecTransformCheckId((transform), xmlSecTransformXPointer))

#define xmlSecTransformXPathGetData(transform) \
    ((xmlSecXPathDataPtr)((transform)->reserved2))
     
/**
 * xmlSecTransformXPathInitialize
 */
static int
xmlSecTransformXPathInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformXPathCheckId(transform), -1);

    transform->reserved2 = NULL;
    return(0);
}

/**
 * xmlSecTransformXPathFinalize:
 */
static void
xmlSecTransformXPathFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecTransformXPathCheckId(transform));
    
    if(xmlSecTransformXPathGetData(transform) != NULL) {
	xmlSecXPathDataDestroy(xmlSecTransformXPathGetData(transform));
    }
    transform->reserved2 = NULL;
}

/***************************************************************************
 *
 *         XPath transform 
 *
 **************************************************************************/
/**
 * xmlSecTransformXPathAdd:
 * @transformNode: the pointer to the <dsig:Transform> node.
 * @expression: the XPath expression.
 * @namespaces: NULL terminated list of namespace prefix/href pairs.
 *
 * Writes XPath transform infromation to the <dsig:Transform> node 
 * @transformNode.
 *
 * Returns 0 for success or a negative value otherwise.
 */
int 	
xmlSecTransformXPathAdd(xmlNodePtr transformNode, const xmlChar *expression,
			 const xmlChar **namespaces) {
    xmlNodePtr xpathNode;
    
    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(expression != NULL, -1);
    

    xpathNode = xmlSecFindChild(transformNode, xmlSecNodeXPath, xmlSecDSigNs);
    if(xpathNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeXPath),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    xpathNode = xmlSecAddChild(transformNode, xmlSecNodeXPath, xmlSecDSigNs);
    if(xpathNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPath));
	return(-1);    
    }
    
    
    xmlNodeSetContent(xpathNode, expression);
    if(namespaces != NULL) {	
	xmlNsPtr ns;
	const xmlChar *prefix;
    	const xmlChar *href;
	const xmlChar **ptr;
	
	ptr = namespaces;
	while((*ptr) != NULL) {
	    if(xmlStrEqual(BAD_CAST "#default", (*ptr))) {
		prefix = NULL;
	    } else {
		prefix = (*ptr);
	    }
	    if((++ptr) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "unexpected end of namespaces list");
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpathNode, href, prefix);
	    if(ns == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlNewNs",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "href=%s;prefix=%s", 
			    xmlSecErrorsSafeString(href),
			    xmlSecErrorsSafeString(prefix));
		return(-1);
	    }
	}
    }
    return(0);
}


/**
 * xmlSecTransformXPathReadNode
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-XPath
 */
static int 
xmlSecTransformXPathReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath), -1);
    xmlSecAssert2(transformNode != NULL, -1);

    xmlTransform = (xmlSecTransformPtr)transform;
    
    /* There is only one required node XPath*/
    cur = xmlSecGetNextElementNode(transformNode->children);  
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeXPath, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPath));
	return(-1);
    }

    data = xmlSecXPathDataCreate(cur, NULL, xmlSecXPathTypeXPath);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecGetNextElementNode(cur->next);        
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }

    if(xmlTransform->reserved2 != NULL) {
	xmlSecXPathDataDestroy((xmlSecXPathDataPtr)xmlTransform->reserved2);
    }
    xmlTransform->reserved2 = data;
    xmlTransform->hereNode  = transformNode;
    return(0);
}

/**
 * xmlSecTransformXPathExecute:
 */
static int
xmlSecTransformXPathExecute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr hereNode;
    xmlSecNodeSetPtr res;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath), -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);
    xmlSecAssert2(nodes != NULL, -1);

    xmlTransform = (xmlSecTransformPtr)transform;
    data = (xmlSecXPathDataPtr)xmlTransform->reserved2;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(data->expr != NULL, -1);
    xmlSecAssert2(data->next == NULL, -1);
    
    /* function here() works only in he same document */  
    hereNode = ((*doc) == ctxDoc) ? xmlTransform->hereNode : NULL;
    res = xmlSecXPathDataExecute(data, (*doc), hereNode);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataExecute",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    (*nodes) = xmlSecNodeSetAdd((*nodes), res, xmlSecNodeSetIntersection);
    if((*nodes) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNodeSetAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecNodeSetIntersection");
	xmlSecNodeSetDestroy(res);
	return(-1);
    }

    return(0);
}



/***************************************************************************
 *
 *         XPath2 transform 
 *
 **************************************************************************/
/**
 * xmlSecTransformXPath2Add:
 * @transformNode: the pointer to the <dsig:Transform> node.
 * @type: XPath2 transform type ("union", "intersect" or "subtract").
 * @expression: the XPath expression.
 * @namespaces: NULL terminated list of namespace prefix/href pairs.
 *
 * Writes XPath2 transform infromation to the <dsig:Transform> node 
 * @transformNode.
 *
 * Returns 0 for success or a negative value otherwise.
 */
int
xmlSecTransformXPath2Add(xmlNodePtr transformNode, xmlSecXPath2TransformType type,
			const xmlChar *expression, const xmlChar **namespaces) {
    xmlNodePtr xpathNode;

    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(expression != NULL, -1);

    xpathNode = xmlSecAddChild(transformNode, xmlSecNodeXPath, xmlSecXPath2Ns);
    if(xpathNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPath));
	return(-1);    
    }
    
    switch(type) {
    case xmlSecXPathTransformIntersect:
	xmlSetProp(xpathNode, BAD_CAST "Filter", BAD_CAST "intersect");
	break;
    case xmlSecXPathTransformSubtract:
	xmlSetProp(xpathNode, BAD_CAST "Filter", BAD_CAST "subtract");
	break;
    case xmlSecXPathTransformUnion:
	xmlSetProp(xpathNode, BAD_CAST "Filter", BAD_CAST "union");
	break;
    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "type=%d", type);
	return(-1);    	
    }
    
    xmlNodeSetContent(xpathNode, expression);
    if(namespaces != NULL) {	
	xmlNsPtr ns;
	const xmlChar *prefix;
    	const xmlChar *href;
	const xmlChar **ptr;
	
	ptr = namespaces;
	while((*ptr) != NULL) {
	    if(xmlStrEqual(BAD_CAST "#default", (*ptr))) {
		prefix = NULL;
	    } else {
		prefix = (*ptr);
	    }
	    if((++ptr) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "unexpected end of namespaces list");
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpathNode, href, prefix);
	    if(ns == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlNewNs",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "href=%s;prefix=%s", 
			    xmlSecErrorsSafeString(href),
			    xmlSecErrorsSafeString(prefix));
		return(-1);
	    }
	}
    }
    return(0);
}

/**
 * xmlSecTransformXPath2ReadNode:
 */
static int 
xmlSecTransformXPath2ReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecTransformPtr xmlTransform;
    xmlSecXPathDataPtr data = NULL;
    xmlSecXPathType xpathType = xmlSecXPathTypeXPath2;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath2), -1);
    xmlSecAssert2(transformNode != NULL, -1);
    
    xmlTransform = (xmlSecTransformPtr)transform;
    if(xmlTransform->reserved2 != NULL) {
	xmlSecXPathDataDestroy((xmlSecXPathDataPtr)xmlTransform->reserved2);
	xmlTransform->reserved2 = NULL;
    }

    /* There are only XPath nodes */
    cur = xmlSecGetNextElementNode(transformNode->children);  
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, xmlSecNodeXPath, xmlSecXPath2Ns)) {
	    xpathType = xmlSecXPathTypeXPath2;
#ifdef XMLSEC_XPATH2_ALLOW_XPOINTER
	} else if(xmlSecCheckNodeName(cur, xmlSecNodeXPointer, xmlSecXPath2Ns)) {
	    xpathType = xmlSecXPathTypeXPointer2;
#endif /* XMLSEC_XPATH2_ALLOW_XPOINTER */
	} else {
	    break;
	}
	
        data = xmlSecXPathDataCreate(cur, data, xpathType);
	if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	if(xmlTransform->reserved2 == NULL) {
	    xmlTransform->reserved2 = data;
	}
        cur = xmlSecGetNextElementNode(cur->next);  
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }
    xmlTransform->hereNode 	  = transformNode;
    return(0);
}

/**
 * xmlSecTransformXPath2Execute:
 */
static int
xmlSecTransformXPath2Execute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr hereNode;
    xmlSecNodeSetPtr res = NULL;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath2), -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);
    xmlSecAssert2(nodes != NULL, -1);
    
    xmlTransform = (xmlSecTransformPtr)transform;
    data = (xmlSecXPathDataPtr)xmlTransform->reserved2;
    hereNode = ((*doc) == ctxDoc) ? xmlTransform->hereNode : NULL;

    xmlSecAssert2(data != NULL, -1);

    res = xmlSecXPathDataExecute(data, (*doc), hereNode);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataExecute",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    (*nodes) = xmlSecNodeSetAddList((*nodes), res, xmlSecNodeSetIntersection);
    if((*nodes) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNodeSetAddList",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecNodeSetIntersection");
	xmlSecNodeSetDestroy(res);
	return(-1);
    }
    
    return(0);
}



/***************************************************************************
 *
 *         XPointer transform 
 *
 **************************************************************************/
/**
 * xmlSecTransformXPointerAdd:
 * @transformNode: the pointer to the <dsig:Transform> node.
 * @expression: the XPath expression.
 * @namespaces: NULL terminated list of namespace prefix/href pairs.
 *
 * Writes XPoniter transform infromation to the <dsig:Transform> node 
 * @transformNode.
 *
 * Returns 0 for success or a negative value otherwise.
 */
int 	
xmlSecTransformXPointerAdd(xmlNodePtr transformNode, const xmlChar *expression,
			 const xmlChar **namespaces) {
    xmlNodePtr xpointerNode;

    xmlSecAssert2(expression != NULL, -1);
    xmlSecAssert2(transformNode != NULL, -1);

    xpointerNode = xmlSecFindChild(transformNode, xmlSecNodeXPointer, xmlSecXPointerNs);
    if(xpointerNode != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeXPointer),
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);    
    }

    xpointerNode = xmlSecAddChild(transformNode, xmlSecNodeXPointer, xmlSecXPointerNs);
    if(xpointerNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPointer));
	return(-1);    
    }
    
    
    xmlNodeSetContent(xpointerNode, expression);
    if(namespaces != NULL) {	
	xmlNsPtr ns;
	const xmlChar *prefix;
    	const xmlChar *href;
	const xmlChar **ptr;
	
	ptr = namespaces;
	while((*ptr) != NULL) {
	    if(xmlStrEqual(BAD_CAST "#default", (*ptr))) {
		prefix = NULL;
	    } else {
		prefix = (*ptr);
	    }
	    if((++ptr) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    NULL,
			    XMLSEC_ERRORS_R_INVALID_DATA,
			    "unexpected end of namespaces list");
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpointerNode, href, prefix);
	    if(ns == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlNewNs",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "href=%s;prefix=%s", 
			    xmlSecErrorsSafeString(href),
			    xmlSecErrorsSafeString(prefix));
		return(-1);
	    }
	}
    }
    return(0);
}


/**
 * xmlSecTransformXPointerReadNode:
 *
 * http://www.ietf.org/internet-drafts/draft-eastlake-xmldsig-uri-02.txt
 */
static int 
xmlSecTransformXPointerReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPointer), -1);
    xmlSecAssert2(transformNode != NULL, -1);
    
    xmlTransform = (xmlSecTransformPtr)transform;
    
    /* There is only one required node XPointer*/
    cur = xmlSecGetNextElementNode(transformNode->children);  
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "XPointer", xmlSecXPointerNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPointer));
	return(-1);
    }

    data = xmlSecXPathDataCreate(cur, NULL, xmlSecXPathTypeXPointer);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    cur = xmlSecGetNextElementNode(cur->next);        
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }

    if(xmlTransform->reserved2 != NULL) {
	xmlSecXPathDataDestroy((xmlSecXPathDataPtr)xmlTransform->reserved2);
    }
    xmlTransform->reserved2 = data;
    xmlTransform->hereNode 	  = transformNode;
    return(0);
}

/**
 * xmlSecTransformXPointerExecute:
 */
static int
xmlSecTransformXPointerExecute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr hereNode;
    xmlSecNodeSetPtr res;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPointer), -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);
    xmlSecAssert2(nodes != NULL, -1);

    xmlTransform = (xmlSecTransformPtr)transform;
    data = (xmlSecXPathDataPtr)xmlTransform->reserved2;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(data->expr != NULL, -1);
    xmlSecAssert2(data->next == NULL, -1);
    
    /* function here() works only in he same document */  
    hereNode = ((*doc) == ctxDoc) ? xmlTransform->hereNode : NULL;
    res = xmlSecXPathDataExecute(data, (*doc), hereNode);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataExecute",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    (*nodes) = xmlSecNodeSetAdd((*nodes), res, xmlSecNodeSetIntersection);
    if((*nodes) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNodeSetAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecNodeSetIntersection");
	xmlSecNodeSetDestroy(res);
	return(-1);
    }

    return(0);
}



/***************************************************************************
 *
 *   XPath Transform Data
 *
 ***************************************************************************/ 
/**
 * xmlSecXPathDataCreate:
 */
static xmlSecXPathDataPtr	
xmlSecXPathDataCreate(const xmlNodePtr node, xmlSecXPathDataPtr prev, xmlSecXPathType xpathType) {
    xmlSecXPathDataPtr data;
    
    data = (xmlSecXPathDataPtr) xmlMalloc(sizeof(xmlSecXPathData));
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecXPathData)=%d",
		    sizeof(xmlSecXPathData));
	return(NULL);
    }
    memset(data, 0, sizeof(xmlSecXPathData)); 
    
    data->xpathType = xpathType;        
    if((node != NULL) && (xmlSecXPathDataReadNode(data, node) < 0)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataReadNode",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)));
	xmlSecXPathDataDestroy(data);    
	return(NULL);	
    }
    
    if(prev != NULL) {
	prev->next = data;
    }
    return(data);    
}

/**
 * xmlSecXPathDataDestroy:
 */
static void				
xmlSecXPathDataDestroy(xmlSecXPathDataPtr data) {
    xmlSecXPathDataPtr 	tmp;
    
    while((tmp = data) != NULL) {
	data = data->next;
        if(tmp->expr != NULL) {
	    xmlFree(tmp->expr);
        }
	if(tmp->nsList != NULL) {
	    size_t i;
		
	    for(i = 0; i < tmp->nsListSize; ++i) {
		if((tmp->nsList)[i] != NULL) {
	    	    xmlFree((tmp->nsList)[i]);
		}
	    }
	    memset(tmp->nsList, 0, sizeof(xmlChar*) * (tmp->nsListSize));
	    xmlFree(tmp->nsList);
	}
	memset(tmp, 0, sizeof(xmlSecXPathData));  
        xmlFree(tmp);
    }
}

static int		  
xmlSecXPathDataReadNode	(xmlSecXPathDataPtr data, const xmlNodePtr node) {
    xmlChar *xpath2Type;
    xmlChar* expr;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(data->expr == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    expr = xmlNodeGetContent(node);
    if(expr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
	
    /**
     * Create full XPath expression
     */
    switch(data->xpathType) {
    case xmlSecXPathTypeXPath:
	/* Create full XPath expression */
        data->expr = (xmlChar*) xmlMalloc(sizeof(xmlChar) * 
	        (xmlStrlen(expr) + xmlStrlen(xpathPattern) + 1));
	if(data->expr == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlMalloc",
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			"size=%d",
			xmlStrlen(expr) + xmlStrlen(xpathPattern) + 1);
    	    return(-1);
        }
        sprintf((char*)data->expr, (char*)xpathPattern, (char*)expr);	
        xmlFree(expr);
	break;
    case xmlSecXPathTypeXPath2:
	data->expr = expr;
	break;
    case xmlSecXPathTypeXPointer:
	data->expr = expr;
	break;
#ifdef XMLSEC_XPATH2_ALLOW_XPOINTER
    case xmlSecXPathTypeXPointer2:
	data->expr = expr;
	break;
#endif /* XMLSEC_XPATH2_ALLOW_XPOINTER */
    }

    if(xmlSecXPathDataReadNsList(data, node) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataReadNsList",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    switch(data->xpathType) {
    case xmlSecXPathTypeXPath:
    case xmlSecXPathTypeXPointer: 
	/* do nothing */
	break;
    case xmlSecXPathTypeXPath2:
#ifdef XMLSEC_XPATH2_ALLOW_XPOINTER
    case xmlSecXPathTypeXPointer2: 
#endif /* XMLSEC_XPATH2_ALLOW_XPOINTER */
        xpath2Type = xmlGetProp(node, xmlSecAttrFilter);
        if(xpath2Type == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlGetProp",
			XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
			"attr=%s",
			xmlSecErrorsSafeString(xmlSecAttrFilter));
	    return(-1);
        }

        if(xmlStrEqual(xpath2Type, BAD_CAST "intersect")) {
    	    data->xpath2Type = xmlSecXPathTransformIntersect;
	} else if(xmlStrEqual(xpath2Type, BAD_CAST "subtract")) {
	    data->xpath2Type = xmlSecXPathTransformSubtract;
	} else if(xmlStrEqual(xpath2Type, BAD_CAST "union")) {
	    data->xpath2Type = xmlSecXPathTransformUnion;
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			NULL,
			XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
			"filter=%s", 
			xmlSecErrorsSafeString(xpath2Type));
	    xmlFree(xpath2Type);
	    return(-1);
	}
    	xmlFree(xpath2Type);
	break;
    }    
    return(0);
}

static int		  
xmlSecXPathDataReadNsList(xmlSecXPathDataPtr data, const xmlNodePtr node) {
    xmlNodePtr tmp;
    xmlNsPtr ns;
    size_t count;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(data->nsList == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* how many namespaces we have? */
    count = 0;
    for(tmp = node; tmp != NULL; tmp = tmp->parent) {  
	ns = tmp->nsDef; 
        while(ns != NULL) {	
    	    ++count;
	    ns = ns->next;
	}
    }
    
    data->nsList = (xmlChar**)xmlMalloc(sizeof(xmlChar*) * (2 * count));
    if(data->nsList == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d", 2 * count);
	return(-1);
    }    
    data->nsListSize = 2 * count;
    memset(data->nsList, 0, sizeof(xmlChar*) * (data->nsListSize));
    
    count = 0;
    for(tmp = node; tmp != NULL; tmp = tmp->parent) {
	ns = tmp->nsDef;
        while((ns != NULL) && (count < data->nsListSize)){	
	    if(ns->prefix != NULL) {
		data->nsList[count++] = xmlStrdup(ns->prefix);
	    } else {
		data->nsList[count++] = NULL;
	    }	
	    if(ns->href != NULL) {
		data->nsList[count++] = xmlStrdup(ns->href);
	    } else {
		data->nsList[count++] = NULL;
	    }
	    ns = ns->next;
	}
    }
    return(0);
}

static xmlSecNodeSetPtr		  
xmlSecXPathDataExecute(xmlSecXPathDataPtr data, xmlDocPtr doc, xmlNodePtr hereNode) {
    xmlSecNodeSetPtr res = NULL;
    xmlSecNodeSetPtr tmp1, tmp2;
    xmlSecNodeSetOp op;
    xmlSecNodeSetType nodeSetType = xmlSecNodeSetNormal;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(data->expr != NULL, NULL);
    xmlSecAssert2(doc != NULL, NULL);
    
    while(data != NULL) {
	xmlXPathObjectPtr xpath = NULL; 
	xmlXPathContextPtr ctx = NULL; 


	switch(data->xpath2Type) {
	case xmlSecXPathTransformIntersect:
	    op = xmlSecNodeSetIntersection;
    	    break;
	case xmlSecXPathTransformSubtract:
	    op = xmlSecNodeSetSubtraction;
	    break;
	case xmlSecXPathTransformUnion:
	    op = xmlSecNodeSetUnion;
	    break;
	default:
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			NULL,
			XMLSEC_ERRORS_R_INVALID_TYPE,
			"xpathType=%d", data->xpath2Type);
	    if(res != NULL) {
		xmlSecNodeSetDestroy(res);
	    }
	    return(NULL);
	}

        /**
	 * Create XPath context
	 */
	switch(data->xpathType) {
	case xmlSecXPathTypeXPath:
	case xmlSecXPathTypeXPath2:
	    ctx = xmlXPathNewContext(doc);
	    break;
	case xmlSecXPathTypeXPointer:
#ifdef XMLSEC_XPATH2_ALLOW_XPOINTER
	case xmlSecXPathTypeXPointer2:
#endif /* XMLSEC_XPATH2_ALLOW_XPOINTER */
	    ctx = xmlXPtrNewContext(doc, xmlDocGetRootElement(doc), NULL);
	    break;
	}
        if(ctx == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlXPathNewContext or xmlXPtrNewContext",			
			XMLSEC_ERRORS_R_XML_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    if(res != NULL) xmlSecNodeSetDestroy(res);
	    return(NULL);
	}
    
	if(hereNode != NULL) {
	    xmlXPathRegisterFunc(ctx, (xmlChar *)"here", xmlSecXPathHereFunction);
	    ctx->here = hereNode;
	    ctx->xptr = 1;
	}
    
	/*
	 * Register namespaces
         */
	if(data->nsList != NULL) {
	    xmlChar *prefix;
	    xmlChar *href;
	    int i;
		
	    for(i = data->nsListSize - 1; i > 0; ) {
		href = (data->nsList)[i--];
		prefix = (data->nsList)[i--];
	        if((prefix != NULL) && (xmlXPathRegisterNs(ctx, prefix, href) != 0)) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlXPathRegisterNs",
				XMLSEC_ERRORS_R_XML_FAILED,
				"href=%s;prefix=%s",
				xmlSecErrorsSafeString(href),
				xmlSecErrorsSafeString(prefix)); 
		    xmlXPathFreeContext(ctx); 	     
		    if(res != NULL) xmlSecNodeSetDestroy(res);
		    return(NULL);
		}
	    }
	}

	/*  
         * Evaluate xpath
	 */
	switch(data->xpathType) {
	case xmlSecXPathTypeXPath:
	case xmlSecXPathTypeXPath2:
	    xpath = xmlXPathEvalExpression(data->expr, ctx);
	    break;
	case xmlSecXPathTypeXPointer:
#ifdef XMLSEC_XPATH2_ALLOW_XPOINTER
	case xmlSecXPathTypeXPointer2:
#endif /* XMLSEC_XPATH2_ALLOW_XPOINTER */
	    xpath = xmlXPtrEval(data->expr, ctx);
	    break;
	}
	if(xpath == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlXPathEvalExpression or xmlXPtrEval",
			XMLSEC_ERRORS_R_XML_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlXPathFreeContext(ctx); 
	    if(res != NULL) xmlSecNodeSetDestroy(res);
    	    return(NULL);
	}

	/* store nodes set */
	switch(data->xpathType) {
	case xmlSecXPathTypeXPath:
	    nodeSetType = xmlSecNodeSetNormal;
	    break;
	case xmlSecXPathTypeXPath2:
	    nodeSetType = xmlSecNodeSetTree;
	    break;
	case xmlSecXPathTypeXPointer:
	    nodeSetType = xmlSecNodeSetTree;
	    break;
#ifdef XMLSEC_XPATH2_ALLOW_XPOINTER
	case xmlSecXPathTypeXPointer2:
	    nodeSetType = xmlSecNodeSetTree;
	    break;
#endif /* XMLSEC_XPATH2_ALLOW_XPOINTER */
	}
	tmp1 = xmlSecNodeSetCreate(doc, xpath->nodesetval, nodeSetType);
	if(tmp1 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecNodeSetCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"type=%d", nodeSetType);
	    xmlXPathFreeObject(xpath);     
	    xmlXPathFreeContext(ctx); 
	    if(res != NULL) xmlSecNodeSetDestroy(res);
    	    return(NULL);
	}
        xpath->nodesetval = NULL;

	tmp2 = xmlSecNodeSetAdd(res, tmp1, op);
	if(tmp2 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecNodeSetAdd",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecNodeSetDestroy(tmp1);
	    xmlXPathFreeObject(xpath);     
	    xmlXPathFreeContext(ctx); 
	    if(res != NULL) xmlSecNodeSetDestroy(res);
    	    return(NULL);
	}
	res = tmp2;
	
	/* free everything we do not need */
	xmlXPathFreeObject(xpath);     
	xmlXPathFreeContext(ctx);      

	data = data->next;
    }
    return(res);    
}


