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
#include <xmlsec/xpath.h>
#include <xmlsec/debug.h>


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

static xmlSecTransformPtr xmlSecTransformXPathCreate	(xmlSecTransformId id);
static void		xmlSecTransformXPathDestroy	(xmlSecTransformPtr transform);

static int 		xmlSecTransformXPathReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPathExecute	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);

static int 		xmlSecTransformXPath2ReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPath2Execute	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);

static int 		xmlSecTransformXPointerReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPointerExecute	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);

struct _xmlSecXmlTransformIdStruct xmlSecTransformXPathId = {
    /* same as xmlSecTransformId */ 
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    xmlSecXPathNs, /* const xmlChar *href; */

    xmlSecTransformXPathCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecTransformXPathDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    xmlSecTransformXPathReadNode,	/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlTransform info */
    xmlSecTransformXPathExecute		/* xmlSecXmlTransformExecuteMethod executeXml; */
};
xmlSecTransformId xmlSecTransformXPath = (xmlSecTransformId)(&xmlSecTransformXPathId);

struct _xmlSecXmlTransformIdStruct xmlSecTransformXPath2Id = {
    /* same as xmlSecTransformId */ 
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    xmlSecXPath2Ns, /* const xmlChar *href; */

    xmlSecTransformXPathCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecTransformXPathDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    xmlSecTransformXPath2ReadNode,	/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlTransform info */
    xmlSecTransformXPath2Execute	/* xmlSecXmlTransformExecuteMethod executeXml; */
};
xmlSecTransformId xmlSecTransformXPath2 = (xmlSecTransformId)(&xmlSecTransformXPath2Id);

struct _xmlSecXmlTransformIdStruct xmlSecTransformXPointerId = {
    /* same as xmlSecTransformId */ 
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    xmlSecXPointerNs, /* const xmlChar *href; */

    xmlSecTransformXPathCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecTransformXPathDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    xmlSecTransformXPointerReadNode,	/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlTransform info */
    xmlSecTransformXPointerExecute		/* xmlSecXmlTransformExecuteMethod executeXml; */
};
xmlSecTransformId xmlSecTransformXPointer = (xmlSecTransformId)(&xmlSecTransformXPointerId);


static const xmlChar xpathPattern[] = "(//. | //@* | //namespace::*)[%s]";

/** 
 * xmlSecXPathHereFunction:
 * @ctxt:
 * @nargs:
 *
 * see xmlXPtrHereFunction() in xpointer.c. the only change is that 
 * we return NodeSet instead of NodeInterval
 */
void 
xmlSecXPathHereFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);

    if (ctxt->context->here == NULL)
	XP_ERROR(XPTR_SYNTAX_ERROR);
    
    valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->here));
}



/***************************************************************************
 *
 *         Common XPath/XPointer transforms functions
 *
 **************************************************************************/
/**
 * xmlSecTransformXPathCreate
 * @id:
 *
 *
 */
static xmlSecTransformPtr 
xmlSecTransformXPathCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPathCreate";
    xmlSecXmlTransformPtr xmlTransform; 
    
    if((id != xmlSecTransformXPath) && 
       (id != xmlSecTransformXPath2) && 
       (id != xmlSecTransformXPointer)) {
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
    xmlTransform->id = (xmlSecXmlTransformId)id;    
    return((xmlSecTransformPtr)xmlTransform);
}

/**
 * xmlSecTransformXPathDestroy
 * @transform:
 *
 *
 */
static void
xmlSecTransformXPathDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPathDestroy";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXPath) && 
       !xmlSecTransformCheckId(transform, xmlSecTransformXPath2) &&
       !xmlSecTransformCheckId(transform, xmlSecTransformXPointer)) {

#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return;
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    data = (xmlSecXPathDataPtr)xmlTransform->xmlData;
    
    if(data != NULL) {
	xmlSecXPathDataDestroy(data);
    }
    memset(xmlTransform, 0,  sizeof(struct _xmlSecXmlTransform));  
    xmlFree(xmlTransform);
}

/***************************************************************************
 *
 *         XPath transform 
 *
 **************************************************************************/
/**
 * xmlSecTransformXPathAdd:
 * @transformNode: the transform node
 * @expression: the XPath expression
 * @namespaces: NULL terminated list of namespace prefix/href pairs
 *
 */
int 	
xmlSecTransformXPathAdd(xmlNodePtr transformNode, const xmlChar *expression,
			 const xmlChar **namespaces) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPathAdd";
    xmlNodePtr xpathNode;
    
    if((transformNode == NULL) || (expression == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transformNode or expression is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    xpathNode = xmlSecFindChild(transformNode, BAD_CAST "XPath", xmlSecDSigNs);
    if(xpathNode != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XPath node is already present\n",
	    func);	
#endif 	    
	return(-1);    
    }

    xpathNode = xmlSecAddChild(transformNode, BAD_CAST "XPath", xmlSecDSigNs);
    if(xpathNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create XPath node\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: unexpected end of namespaces list\n",
		    func);	
#endif 	    
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpathNode, href, prefix);
	    if(ns == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to add namespace (%s=%s)\n",
		    func, 
		    ((prefix != NULL) ? (char*)prefix : "null"), href);
#endif 	    
		return(-1);
	    }
	}
    }
    return(0);
}


/**
 * xmlSecTransformXPathReadNode
 * @transform:
 * @transformNode:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-XPath
 */
static int 
xmlSecTransformXPathReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPathReadNode";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr cur;
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXPath) ||
       (transformNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    
    /* There is only one required node XPath*/
    cur = xmlSecGetNextElementNode(transformNode->children);  
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "XPath", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"XPath\" missed\n",
	    func);
#endif	    
	return(-1);
    }

    data = xmlSecXPathDataCreate(cur, NULL, xmlSecXPathTypeXPath);
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read XPath node\n",
	    func);	
#endif 	    
	return(-1);
    }

    cur = xmlSecGetNextElementNode(cur->next);        
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: unexpected node found\n",
		func);
#endif		
	xmlSecXPathDataDestroy(data);
	return(-1);
    }

    if(xmlTransform->xmlData != NULL) {
	xmlSecXPathDataDestroy((xmlSecXPathDataPtr)xmlTransform->xmlData);
    }
    xmlTransform->xmlData = data;
    xmlTransform->here 	  = transformNode;
    return(0);
}

/**
 * xmlSecTransformXPathExecute
 * @transform:
 * @ctxDoc:
 * @doc:
 * @nodes:
 *
 */
static int
xmlSecTransformXPathExecute(xmlSecXmlTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPathExecute";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr hereNode;
    xmlSecNodeSetPtr res;

    if(!xmlSecTransformCheckId(transform, xmlSecTransformXPath) || 
       (nodes == NULL) || (doc == NULL) || ((*doc) == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or something else is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    data = (xmlSecXPathDataPtr)xmlTransform->xmlData;
    
    if((data == NULL) || (data->expr == NULL) || (data->next != NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath data is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }

    /* function here() works only in he same document */  
    hereNode = ((*doc) == ctxDoc) ? xmlTransform->here : NULL;
    res = xmlSecXPathDataExecute(data, (*doc), hereNode);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath expression failed\n",
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



/***************************************************************************
 *
 *         XPath2 transform 
 *
 **************************************************************************/
int
xmlSecTransformXPath2Add(xmlNodePtr transformNode, xmlSecXPath2TransformType type,
			const xmlChar *expression, const xmlChar **namespaces) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPath2Add";
    xmlNodePtr xpathNode;
    
    if((transformNode == NULL) || (expression == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transformNode or expression is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    xpathNode = xmlSecAddChild(transformNode, BAD_CAST "XPath", xmlSecXPath2Ns);
    if(xpathNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create XPath node\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unknown type %d\n",
	    func, type);	
#endif 	    	
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
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: unexpected end of namespaces list\n",
		    func);	
#endif 	    
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpathNode, href, prefix);
	    if(ns == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to add namespace (%s=%s)\n",
		    func, 
		    ((prefix != NULL) ? (char*)prefix : "null"), href);
#endif 	    
		return(-1);
	    }
	}
    }
    return(0);
}

/**
 * xmlSecTransformXPath2ReadNode
 * @transform:
 * @transformNode:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-XPath
 */
static int 
xmlSecTransformXPath2ReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPath2ReadNode";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathDataPtr data = NULL;
    xmlSecXPathType xpathType = xmlSecXPathTypeXPath2;
    xmlNodePtr cur;
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXPath2) || 
       (transformNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    if(xmlTransform->xmlData != NULL) {
	xmlSecXPathDataDestroy((xmlSecXPathDataPtr)xmlTransform->xmlData);
	xmlTransform->xmlData = NULL;
    }

    /* There are only XPath nodes */
    cur = xmlSecGetNextElementNode(transformNode->children);  
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur, BAD_CAST "XPath", xmlSecXPath2Ns)) {
	    xpathType = xmlSecXPathTypeXPath2;
#ifdef XMLSEC_XPATH2_ALLOW_XPOINTER
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "XPointer", xmlSecXPath2Ns)) {
	    xpathType = xmlSecXPathTypeXPointer2;
#endif /* XMLSEC_XPATH2_ALLOW_XPOINTER */
	} else {
	    break;
	}
	
        data = xmlSecXPathDataCreate(cur, data, xpathType);
	if(data == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read XPath node\n",
	        func);	
#endif 	    
	    return(-1);
	}
	if(xmlTransform->xmlData == NULL) {
	    xmlTransform->xmlData = data;
	}
        cur = xmlSecGetNextElementNode(cur->next);  
    }

    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: unexpected node found\n",
		func);
#endif		
	xmlSecXPathDataDestroy(data);
	return(-1);
    }
    xmlTransform->here 	  = transformNode;
    return(0);
}

/**
 * xmlSecTransformXPath2Execute
 * @transform:
 * @ctxDoc:
 * @doc:
 * @nodes:
 *
 */
static int
xmlSecTransformXPath2Execute(xmlSecXmlTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPath2Execute";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr hereNode;
    xmlSecNodeSetPtr res = NULL;
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXPath2) || 
       (nodes == NULL) || (doc == NULL) || ((*doc) == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or something else is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    data = (xmlSecXPathDataPtr)xmlTransform->xmlData;
    hereNode = ((*doc) == ctxDoc) ? xmlTransform->here : NULL;

    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath data is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    res = xmlSecXPathDataExecute(data, (*doc), hereNode);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
		"%s: xpath expression failed\n",
	        func);	
#endif
	return(-1);
    }

    (*nodes) = xmlSecNodeSetAddList((*nodes), res, xmlSecNodeSetIntersection);
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



/***************************************************************************
 *
 *         XPointer transform 
 *
 **************************************************************************/
/**
 * xmlSecTransformXPointerAdd:
 * @transformNode: the transform node
 * @expression: the XPointer expression
 * @namespaces: NULL terminated list of namespace prefix/href pairs
 *
 */
int 	
xmlSecTransformXPointerAdd(xmlNodePtr transformNode, const xmlChar *expression,
			 const xmlChar **namespaces) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPointerAdd";
    xmlNodePtr xpointerNode;
    
    if((transformNode == NULL) || (expression == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transformNode or expression is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    xpointerNode = xmlSecFindChild(transformNode, BAD_CAST "XPointer", xmlSecXPointerNs);
    if(xpointerNode != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: XPointer node is already present\n",
	    func);	
#endif 	    
	return(-1);    
    }

    xpointerNode = xmlSecAddChild(transformNode, BAD_CAST "XPointer", xmlSecXPointerNs);
    if(xpointerNode == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create XPointer node\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: unexpected end of namespaces list\n",
		    func);	
#endif 	    
		return(-1);
	    }
	    href = *(ptr++);

	    ns = xmlNewNs(xpointerNode, href, prefix);
	    if(ns == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to add namespace (%s=%s)\n",
		    func, 
		    ((prefix != NULL) ? (char*)prefix : "null"), href);
#endif 	    
		return(-1);
	    }
	}
    }
    return(0);
}


/**
 * xmlSecTransformXPointerReadNode
 * @transform:
 * @transformNode:
 *
 * http://www.ietf.org/internet-drafts/draft-eastlake-xmldsig-uri-02.txt
 */
static int 
xmlSecTransformXPointerReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPointerReadNode";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr cur;
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXPointer) ||
       (transformNode == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    
    /* There is only one required node XPointer*/
    cur = xmlSecGetNextElementNode(transformNode->children);  
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "XPointer", xmlSecXPointerNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"XPointer\" missed\n",
	    func);
#endif	    
	return(-1);
    }

    data = xmlSecXPathDataCreate(cur, NULL, xmlSecXPathTypeXPointer);
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read XPointer node\n",
	    func);	
#endif 	    
	return(-1);
    }

    cur = xmlSecGetNextElementNode(cur->next);        
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: unexpected node found\n",
		func);
#endif		
	xmlSecXPathDataDestroy(data);
	return(-1);
    }

    if(xmlTransform->xmlData != NULL) {
	xmlSecXPathDataDestroy((xmlSecXPathDataPtr)xmlTransform->xmlData);
    }
    xmlTransform->xmlData = data;
    xmlTransform->here 	  = transformNode;
    return(0);
}

/**
 * xmlSecTransformXPointerExecute
 * @transform:
 * @ctxDoc:
 * @doc:
 * @nodes:
 *
 */
static int
xmlSecTransformXPointerExecute(xmlSecXmlTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPointerExecute";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr hereNode;
    xmlSecNodeSetPtr res;

    if(!xmlSecTransformCheckId(transform, xmlSecTransformXPointer) || 
       (nodes == NULL) || (doc == NULL) || ((*doc) == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or something else is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    data = (xmlSecXPathDataPtr)xmlTransform->xmlData;
    
    if((data == NULL) || (data->expr == NULL) || (data->next != NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath data is invalid\n",
	    func);	
#endif 	    
	return(-1);
    }

    /* function here() works only in he same document */  
    hereNode = ((*doc) == ctxDoc) ? xmlTransform->here : NULL;
    res = xmlSecXPathDataExecute(data, (*doc), hereNode);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath expression failed\n",
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



/***************************************************************************
 *
 *   XPath Transform Data
 *
 ***************************************************************************/ 
/**
 * xmlSecXPathDataCreate:
 *
 */
xmlSecXPathDataPtr	
xmlSecXPathDataCreate(const xmlNodePtr node, xmlSecXPathDataPtr prev, xmlSecXPathType xpathType) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataCreate";    
    xmlSecXPathDataPtr data;
    
    data = (xmlSecXPathDataPtr) xmlMalloc(sizeof(xmlSecXPathData));
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate xmlSecXPathData \n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(data, 0, sizeof(xmlSecXPathData)); 
    
    data->xpathType = xpathType;        
    if((node != NULL) && (xmlSecXPathDataReadNode(data, node) < 0)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read node \n",
	    func);	
#endif 	
	xmlSecXPathDataDestroy(data);    
	return(NULL);	
    }
    
    if(prev != NULL) {
	prev->next = data;
    }
    return(data);    
}

/**
 * xmlSecXPathDataDestroy
 * @data:
 *
 */
void				
xmlSecXPathDataDestroy(xmlSecXPathDataPtr data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataDestroy";
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataReadNode";
    xmlChar *xpath2Type;
    xmlChar* expr;

    if((data == NULL) || (data->expr != NULL) || (node == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: node or data is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    expr = xmlNodeGetContent(node);
    if(expr == NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to get xpath expression from ndoe\n",
	    func);
#endif		
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
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to allocate xpath expr buffer\n",
	        func);	
#endif
    	    return(-1);
        }
        sprintf((char*)data->expr, (char*) xpathPattern, expr);	
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
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to get xpath expression from ndoe\n",
	    func);
#endif		
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
        xpath2Type = xmlGetProp(node, BAD_CAST "Filter");
        if(xpath2Type == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: \"Filter\" is not specified for XPath2 transform\n",
	        func);
#endif		
	    return(-1);
        }

        if(xmlStrEqual(xpath2Type, BAD_CAST "intersect")) {
    	    data->xpath2Type = xmlSecXPathTransformIntersect;
	} else if(xmlStrEqual(xpath2Type, BAD_CAST "subtract")) {
	    data->xpath2Type = xmlSecXPathTransformSubtract;
	} else if(xmlStrEqual(xpath2Type, BAD_CAST "union")) {
	    data->xpath2Type = xmlSecXPathTransformUnion;
	} else {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: \"Filter\" xpath2Type \"%s\" is unkown\n",
	        func, xpath2Type);
#endif		
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataReadNsList";
    xmlNodePtr tmp;
    xmlNsPtr ns;
    size_t count;

    if((data == NULL) || (data->nsList != NULL) || (node == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: node or data is null\n",
	    func);	
#endif 	    
	return(-1);
    }

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
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create namespace list\n",
		func);
#endif		
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
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataExecute";
    xmlSecNodeSetPtr res = NULL;
    xmlSecNodeSetPtr tmp1, tmp2;
    xmlSecNodeSetOp op;
    xmlSecNodeSetType nodeSetType = xmlSecNodeSetNormal;
    
    if((data == NULL) || (data->expr == NULL) || (doc == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: doc, nodes or data is null\n",
	    func);	
#endif 	    
	return(NULL);
    }
    
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
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: unknown node xpath2 type %d\n",
		func, data->xpath2Type);	
#endif 	    
	    if(res != NULL) xmlSecNodeSetDestroy(res);
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
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: xpath context is null\n",
		func);	
#endif
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
#ifdef XMLSEC_DEBUG
		    xmlGenericError(xmlGenericErrorContext, 
			"%s: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", 
			func, 
			((prefix != NULL) ? (char*)prefix : "null"),
		        ((href != NULL) ? (char*)href : "null"));
#endif
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
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext, 
		"xmlSecXPathTransformRead: xpath eval failed\n",
		func);
#endif
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
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext, 
		"xmlSecXPathTransformRead: failed to create nodes set\n",
		func);
#endif
	    xmlXPathFreeObject(xpath);     
	    xmlXPathFreeContext(ctx); 
	    if(res != NULL) xmlSecNodeSetDestroy(res);
    	    return(NULL);
	}
        xpath->nodesetval = NULL;

	tmp2 = xmlSecNodeSetAdd(res, tmp1, op);
	if(tmp2 == NULL) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext, 
		"xmlSecXPathTransformRead: failed to add nodes set\n",
		func);
#endif
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


