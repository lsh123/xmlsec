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

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/xpath.h>
#include <xmlsec/debug.h>



/* XPath transform */
typedef struct _xmlSecXPathData xmlSecXPathData, *xmlSecXPathDataPtr;
struct _xmlSecXPathData {
    xmlChar			*expr;
    xmlChar			**nsList;
    size_t			nsListSize;
    xmlNodeSetPtr		nodes;
    xmlSecXPath2TransformType	type;
    xmlSecXPathDataPtr		next;
};


static xmlSecXPathDataPtr xmlSecXPathDataCreate		(const xmlNodePtr node,
							 xmlSecXPathDataPtr prev,
							 int xpath2);
static void		  xmlSecXPathDataDestroy	(xmlSecXPathDataPtr data);
static int		  xmlSecXPathDataReadNode	(xmlSecXPathDataPtr data,
							 const xmlNodePtr node,
							 int xpath2);
static int		  xmlSecXPathDataReadNsList	(xmlSecXPathDataPtr data,
							 const xmlNodePtr node);
static int		  xmlSecXPathDataExecute	(xmlSecXPathDataPtr data,
							 xmlDocPtr doc,
							 xmlNodePtr hereNode);
static int		  xmlSecXPathDataCheckNode	(xmlSecXPathDataPtr data,
							 xmlNodePtr node,
							 int status,
							 xmlNodePtr parent);
static int		  xmlSecXPathDataFinal		(xmlSecXPathDataPtr data,
							 xmlSecNodeSetPtr nset,
							 xmlNodeSetPtr res,
							 xmlNodePtr node,
							 xmlNodePtr parent);

static int		  xmlSecXPathIsNodeInSubtree	(xmlNodeSetPtr nodes,
							 xmlNodePtr node,
							 xmlNodePtr parent);

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

struct _xmlSecXmlTransformIdStruct xmlSecTransformXPathId = {
    /* same as xmlSecTransformId */ 
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    BAD_CAST "http://www.w3.org/TR/1999/REC-xpath-19991116", /* const xmlChar *href; */

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
    BAD_CAST "http://www.w3.org/2002/06/xmldsig-filter2", /* const xmlChar *href; */

    xmlSecTransformXPathCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecTransformXPathDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    xmlSecTransformXPath2ReadNode,	/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlTransform info */
    xmlSecTransformXPath2Execute	/* xmlSecXmlTransformExecuteMethod executeXml; */
};
xmlSecTransformId xmlSecTransformXPath2 = (xmlSecTransformId)(&xmlSecTransformXPath2Id);


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
 *         XPath transform 
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
    
    if((id != xmlSecTransformXPath) && (id != xmlSecTransformXPath2)) {
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
        !xmlSecTransformCheckId(transform, xmlSecTransformXPath2)) {
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

    data = xmlSecXPathDataCreate(cur, NULL, 0);
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
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "XPath", xmlSecXPath2Ns)) {
        data = xmlSecXPathDataCreate(cur, data, 1);
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
    if(xmlSecXPathDataExecute(data, (*doc), hereNode) < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath expression failed\n",
	    func);	
#endif
	return(-1);
    }
    
    if((*nodes) != NULL) {
	(*nodes) = xmlSecNodeSetIntersect((*nodes), data->nodes);
    } else {
	(*nodes) = xmlSecNodeSetCreate((*doc), data->nodes, xmlSecNodeSetNormal);
	data->nodes = NULL;
    }
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
    xmlNodeSetPtr res = NULL;
    xmlNodePtr cur;	
    int ret;
    
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

    if(xmlSecXPathDataExecute(data, (*doc), hereNode) < 0) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
		"%s: xpath expression failed\n",
	        func);	
#endif
	return(-1);
    }

    res = xmlXPathNodeSetCreate(NULL);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create nodes set\n",
	    func);	
#endif 	    
	return(-1);
    }

    for(cur = (*doc)->children; cur != NULL; cur = cur->next) {
        ret = xmlSecXPathDataFinal(data, (*nodes), res, cur, NULL);
        if(ret < 0) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: node subtree check failed\n",
		func);	
#endif 	    
	    xmlXPathFreeNodeSet(res);
	    return(-1);
	}
    }
    (*nodes) = xmlSecNodeSetCreate((*doc), res, xmlSecNodeSetNormal);
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
 *
 *
 */
xmlSecXPathDataPtr	
xmlSecXPathDataCreate(const xmlNodePtr node, xmlSecXPathDataPtr prev, int xpath2) {
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
    
    if((node != NULL) && (xmlSecXPathDataReadNode(data, node, xpath2) < 0)){
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
    
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: data is null\n",
	    func);	
#endif 	    
	return;    	
    }
    if(data->expr != NULL) {
	xmlFree(data->expr);
    }
    if(data->nsList != NULL) {
	size_t i;
		
	for(i = 0; i < data->nsListSize; ++i) {
	    if((data->nsList)[i] != NULL) {
	        xmlFree((data->nsList)[i]);
	    }
	}
	memset(data->nsList, 0, sizeof(xmlChar*) * (data->nsListSize));
	xmlFree(data->nsList);
    }
    if(data->nodes != NULL) {
	xmlXPathFreeNodeSet(data->nodes);
    }
    
    if(data->next != NULL) {
	xmlSecXPathDataDestroy(data->next);
    }
    memset(data, 0, sizeof(xmlSecXPathData));  
    xmlFree(data);
}

static int		  
xmlSecXPathDataReadNode	(xmlSecXPathDataPtr data, const xmlNodePtr node, int xpath2) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataReadNode";
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
    if(xpath2) {
	data->expr = expr;
    } else {	
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
    }

    if(xmlSecXPathDataReadNsList(data, node) < 0) {
#ifdef XMLSEC_DEBUG    
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to get xpath expression from ndoe\n",
	    func);
#endif		
        return(-1);
    }
    
    if(xpath2) {
        xmlChar *type;

        type = xmlGetProp(node, BAD_CAST "Filter");
        if(type == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: \"Filter\" is not specified for XPath2 transform\n",
	        func);
#endif		
	    return(-1);
        }

        if(xmlStrEqual(type, BAD_CAST "intersect")) {
    	    data->type = xmlSecXPathTransformIntersect;
	} else if(xmlStrEqual(type, BAD_CAST "subtract")) {
	    data->type = xmlSecXPathTransformSubtract;
	} else if(xmlStrEqual(type, BAD_CAST "union")) {
	    data->type = xmlSecXPathTransformUnion;
	} else {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: \"Filter\" type \"%s\" is unkown\n",
	        func, type);
#endif		
	    xmlFree(type);
	    return(-1);
	}
    	xmlFree(type);
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

static int		  
xmlSecXPathDataExecute(xmlSecXPathDataPtr data, xmlDocPtr doc, xmlNodePtr hereNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataExecute";
    xmlXPathObjectPtr xpath; 
    xmlXPathContextPtr ctx; 

    if((data == NULL) || (data->expr == NULL) || (doc == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: doc, nodes or data is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    /**
     * Create XPath context
     */
    ctx = xmlXPathNewContext(doc);
    if(ctx == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath context is null\n",
	    func);	
#endif
	return(-1);
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
		return(-1);
	    }
	}
    }

    /*  
     * Evaluate xpath
     */
    xpath = xmlXPathEvalExpression(data->expr, ctx);
    if(xpath == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext, 
	    "xmlSecXPathTransformRead: xpath eval failed\n",
	    func);
#endif
	xmlXPathFreeContext(ctx); 
        return(-1);
    }

    /* store nodes set */
    if(data->nodes != NULL) {
	xmlXPathFreeNodeSet(data->nodes);
    }
    data->nodes = xpath->nodesetval;
    xpath->nodesetval = NULL;

    /* free everything we do not need */
    xmlXPathFreeContext(ctx);      
    xmlXPathFreeObject(xpath);     
    
    return((data->next != NULL) ? 
	    xmlSecXPathDataExecute (data->next, doc, hereNode) : 0);		    
}

static int
xmlSecXPathDataCheckNode(xmlSecXPathDataPtr data, xmlNodePtr node, int status, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataCheckNode";
    xmlSecXPathDataPtr p;
    
    if((data == NULL) || (node == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: data or node is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    for(p = data; p != NULL; p = p->next) {
	
	switch(p->type) {
	case xmlSecXPathTransformIntersect:
	    if(status && !xmlSecXPathIsNodeInSubtree(p->nodes, node, parent)) {
		status = 0;
	    }
    	    break;
	case xmlSecXPathTransformSubtract:
	    if(status && xmlSecXPathIsNodeInSubtree(p->nodes, node, parent)) {
		status = 0;
	    }
	    break;
	case xmlSecXPathTransformUnion:
	    if(!status && xmlSecXPathIsNodeInSubtree(p->nodes, node, parent)) {
		status = 1;
	    }	
	    break;
	default:
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: unknown node type %d\n",
		func, p->type);	
#endif 	    
	    return(-1);
	}
    }
    return(status);
}

static int		  
xmlSecXPathDataFinal(xmlSecXPathDataPtr data, xmlSecNodeSetPtr nset, xmlNodeSetPtr res, xmlNodePtr node, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataFinal";
    int ret;
    
    if((node == NULL) || (res == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: node is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    /* check node itself */
    if((nset == NULL) || xmlSecNodeSetContain(nset, node, parent)) {	
        ret = xmlSecXPathDataCheckNode(data, node, 1, parent);
	if(ret > 0) {
    	    if(node->type != XML_NAMESPACE_DECL) {
    		xmlXPathNodeSetAdd(res, node); 
	    } else {
		xmlXPathNodeSetAddNs(res, parent, (xmlNsPtr)node);
	    }
	} else if(ret < 0) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
		"%s: node check failed\n",
    		func);	
#endif 	    
	    return(-1);
	}
    }
    
    /* check children */
    if(node->type == XML_ELEMENT_NODE) {
	xmlNodePtr cur;
	
	for(cur = node->children; cur != NULL; cur = cur->next) {
	    if(xmlSecXPathDataFinal(data, nset, res, cur, node) < 0) {
#ifdef XMLSEC_DEBUG
		xmlGenericError(xmlGenericErrorContext,
		    "%s: children check failed\n",
    		    func);	
#endif 	    
		return(-1);
	    }
	}
    }    


    /* check attribute nodes */
    if(node->type == XML_ELEMENT_NODE) {
	xmlAttrPtr cur;
	
	for(cur = node->properties; cur != NULL; cur = cur->next) {
	    if(xmlSecXPathDataFinal(data, nset, res, (xmlNodePtr)cur, node) < 0) {
#ifdef XMLSEC_DEBUG
		xmlGenericError(xmlGenericErrorContext,
		    "%s: attribute check failed\n",
    		    func);	
#endif 	    
		return(-1);
	    }
	}
    }    

    /* check namespace */
    if(node->type == XML_ELEMENT_NODE) {
	xmlNodePtr cur;
	xmlNsPtr ns, tmp;
	
	for(cur = node; cur != NULL; cur = cur->parent) {
	    for(ns = cur->nsDef; ns != NULL; ns = ns->next) {
		/* include only the last namespace */
		tmp = xmlSearchNs(node->doc, node, ns->prefix);
		if((tmp == ns) && (xmlSecXPathDataFinal(data, nset, res, (xmlNodePtr)ns, node) < 0)) {
#ifdef XMLSEC_DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"%s: children check failed\n",
    			func);	
#endif 	    
		    return(-1);
		}
	    }
	}
    }    
    
    return(0);
}

static int		 
xmlSecXPathIsNodeInSubtree(xmlNodeSetPtr nodes, xmlNodePtr node, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathIsNodeInSubtree";
    
    if(node == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: node is null or bad parent\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    if((nodes == NULL) || xmlXPathNodeSetContains(nodes, node)) {
	return(1);
    }
    
    if((parent != NULL) && (parent->type == XML_ELEMENT_NODE) && 
       (parent->parent != NULL) && (parent->parent->type == XML_ELEMENT_NODE)) {
	return(xmlSecXPathIsNodeInSubtree(nodes, parent, parent->parent));
    }
    return(0);
}




