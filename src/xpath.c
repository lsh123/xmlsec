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


/* XPath transform */
typedef struct _xmlSecXPathData xmlSecXPathData, *xmlSecXPathDataPtr;
struct _xmlSecXPathData {
    xmlChar			*expr;
    xmlChar			**nsList;
    size_t			nsListSize;
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
							 xmlNodePtr hereNode,
							 int addSubtrees,
							 xmlNodeSetPtr* nodes);

static xmlSecTransformPtr xmlSecTransformXPathCreate	(xmlSecTransformId id);
static void		xmlSecTransformXPathDestroy	(xmlSecTransformPtr transform);
static int 		xmlSecTransformXPathReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPathExecute	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlNodeSetPtr *nodes);
static int 		xmlSecTransformXPath2ReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPath2Execute	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlNodeSetPtr *nodes);

static xmlNodeSetPtr	xmlSecXPathGetNodes		(xmlDocPtr doc,
							 xmlNodeSetPtr src,
							 xmlNodeSetPtr xpathRes);
static xmlNodeSetPtr	xmlSecXPath2IntersectGetNodes	(xmlDocPtr doc,
							 xmlNodeSetPtr src,
							 xmlNodeSetPtr xpathRes);
static xmlNodeSetPtr	xmlSecXPath2SubtractGetNodes	(xmlDocPtr doc,
							 xmlNodeSetPtr src,
							 xmlNodeSetPtr xpathRes);
static xmlNodeSetPtr	xmlSecXPath2UnionGetNodes	(xmlDocPtr doc,
							 xmlNodeSetPtr src,
							 xmlNodeSetPtr xpathRes);
static xmlNodeSetPtr	xmlSecXPath2SubtractFromDoc	(xmlNodePtr cur, 
							 xmlNodeSetPtr nodes, 
							 xmlNodeSetPtr exclude);
static xmlNodeSetPtr	xmlSecXPath2AddSubtrees		(xmlNodeSetPtr nodes);
static void		xmlSecNodeSetDebugDump		(xmlNodeSetPtr nodes,
							 FILE *output);

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
    data->type = xmlSecXPathTransformIntersect; /* Original XPath Filter */

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
			     xmlDocPtr *doc, xmlNodeSetPtr *nodes) {
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
    
    if((data == NULL) || (data->expr == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath data or xpath expression is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    /* function here() works only in he same document */  
    hereNode = ((*doc) == ctxDoc) ? xmlTransform->here : NULL;
    if(xmlSecXPathDataExecute(data, (*doc), hereNode, 0, nodes) < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath expression failed\n",
	    func);	
#endif
	return(-1);
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
			     xmlDocPtr *doc, xmlNodeSetPtr *nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformXPath2Execute";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathDataPtr data;
    xmlNodePtr hereNode;
    xmlNodeSetPtr res = NULL;
    xmlNodeSetPtr old;
    
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

    while(data != NULL) {
	if(data->expr == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: xpath expression is null\n",
		func);	
#endif 		
	    goto error;
	}

	old = res;
        if(xmlSecXPathDataExecute(data, (*doc), hereNode, 1, &res) < 0) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
		"%s: xpath expression failed\n",
	        func);	
#endif
    	    goto error;
	}
	xmlXPathFreeNodeSet(old);    
	
	data = data->next;
    }
    if(nodes == NULL) {
	(*nodes) = NULL;
    } else {
	(*nodes) = xmlXPathIntersection((*nodes), res);
	xmlXPathFreeNodeSet(res);
    }
    return(0);

error:
    if(res != NULL) {
	xmlXPathFreeNodeSet(res);
    }
    return(-1);    
}

static xmlNodeSetPtr
xmlSecXPath2AddSubtrees(xmlNodeSetPtr nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPath2AddSubtrees";    
    int i, l;

    if(nodes == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nodes is null\n",
	    func);	
#endif 	    
	return(NULL);
    }
	
    l = xmlXPathNodeSetGetLength(nodes);
    for(i = 0; i < l; ++i) {
	if(xmlSecGetChildNodeSet(xmlXPathNodeSetItem(nodes, i), nodes, 1) == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to add nodes\n",
	        func);	
#endif 	    
	    return(NULL);
	}
    } 
    return(nodes);
}

static xmlNodeSetPtr
xmlSecXPathGetNodes(xmlDocPtr doc, xmlNodeSetPtr src, xmlNodeSetPtr xpathRes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathGetNodes";    

    if((doc == NULL) || (xpathRes == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: doc or xpathRes is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    return( (src != NULL) ? xmlXPathIntersection(src, xpathRes) : 
			    xmlXPathNodeSetMerge(NULL, xpathRes));
}

static xmlNodeSetPtr	
xmlSecXPath2IntersectGetNodes(xmlDocPtr doc, xmlNodeSetPtr src, xmlNodeSetPtr xpathRes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPath2IntersectGetNodes";    

    if((doc == NULL) || (xpathRes == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: doc or xpathRes is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    return( (src != NULL) ? xmlXPathIntersection(src, xpathRes) : 
			    xmlXPathNodeSetMerge(NULL, xpathRes));
}


static xmlNodeSetPtr	
xmlSecXPath2SubtractGetNodes(xmlDocPtr doc, xmlNodeSetPtr src, xmlNodeSetPtr xpathRes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPath2SubtractGetNodes";    

    if((doc == NULL) || (xpathRes == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: doc or xpathRes is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    return((src != NULL) ? xmlXPathDifference(src, xpathRes) :
	    xmlSecXPath2SubtractFromDoc(xmlDocGetRootElement(doc), NULL, xpathRes));
}

static xmlNodeSetPtr	
xmlSecXPath2UnionGetNodes(xmlDocPtr doc, xmlNodeSetPtr src, xmlNodeSetPtr xpathRes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPath2UnionGetNodes";    
    xmlNodeSetPtr ret;

    if((doc == NULL) || (xpathRes == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: doc or xpathRes is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    ret = xmlXPathNodeSetMerge(NULL, xpathRes);
    if(ret == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to duplicate nodes set\n",
	    func);	
#endif 	    
	return(NULL);
    }

    return(xmlXPathNodeSetMerge(ret, src));
}

static xmlNodeSetPtr
xmlSecXPath2SubtractFromDoc(xmlNodePtr cur, xmlNodeSetPtr nodes, xmlNodeSetPtr exclude) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPath2SubtractFromDoc";    
    int allocated = 0;

    if((cur == NULL) || (exclude == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: cur or exclude is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    if(nodes == NULL) {
	nodes = xmlXPathNodeSetCreate(NULL);
	if(nodes == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create nodes set\n",
	        func);	
#endif 	    
	    return(NULL);
	}
	allocated = 1;
    }

    /* we are operating on the subtrees! */
    if(!xmlXPathNodeSetContains(exclude, cur)) {
	xmlXPathNodeSetAdd(nodes, cur);

	if(cur->type == XML_ELEMENT_NODE) { 
	    xmlNodePtr n;
	    xmlNsPtr ns;
	    xmlAttrPtr attr;
	    
	    /* add attrs */
	    attr = cur->properties; 
	    while (attr != NULL) {
	        if(!xmlXPathNodeSetContains(exclude, (xmlNodePtr)attr)) {
    		    xmlXPathNodeSetAdd(nodes, (xmlNodePtr)attr); 
		}
    		attr = attr->next; 
	    }	
    
	    /* add namespaces */
	    for(n = cur; n != NULL; n = n->parent) {
	        for (ns = n->nsDef; ns != NULL; ns = ns->next) {
        	    if(!xmlXPathNodeSetContains(exclude, (xmlNodePtr)ns)) {			
		        xmlNsPtr tmp;
		
		        /* include only the last namespace */
		        tmp = xmlSearchNs(cur->doc, cur, ns->prefix);
		        if(tmp == ns) {
			    xmlXPathNodeSetAddNs(nodes, cur, ns);
			}
		    }
		}
	    }

	    /* check children */
	    cur = cur->children;
	    while(cur != NULL) {
		if(xmlSecXPath2SubtractFromDoc(cur, nodes, exclude) == NULL) {
#ifdef XMLSEC_DEBUG
    		    xmlGenericError(xmlGenericErrorContext,
			"%s: failed to get childs\n",
	    	        func);	
#endif 	    
		    if(allocated) {
			xmlXPathFreeNodeSet(nodes);
		    }
		    return(NULL);
		}

		cur = cur->next;
	    }	    
	}	
    }
    return(nodes);
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
xmlSecXPathDataExecute(xmlSecXPathDataPtr data, xmlDocPtr doc, xmlNodePtr hereNode, 
			int addSubtrees, xmlNodeSetPtr* nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathDataExecute";
    xmlXPathObjectPtr xpath; 
    xmlXPathContextPtr ctx; 

    if((data == NULL) || (data->expr == NULL) || (nodes == NULL) || (doc == NULL)) {
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

    /* free everything we do not need */
    xmlXPathFreeContext(ctx);      


    /* add the subtrees */
    if(addSubtrees) {    
        if(xmlSecXPath2AddSubtrees(xpath->nodesetval) == NULL) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
    	        "%s: failed to add subtrees\n",
		func);	
#endif
	    xmlXPathFreeObject(xpath); 
	    return(-1);
        }
    }

    switch(data->type) {
    case xmlSecXPathTransformIntersect:
        (*nodes) = xmlSecXPath2IntersectGetNodes(doc, (*nodes), xpath->nodesetval);
        break;
    case xmlSecXPathTransformSubtract:
        (*nodes) = xmlSecXPath2SubtractGetNodes(doc, (*nodes), xpath->nodesetval);
        break;
    case xmlSecXPathTransformUnion:
        (*nodes) = xmlSecXPath2UnionGetNodes(doc, (*nodes), xpath->nodesetval);
        break;
    default:
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: unknown xpath2 type\n",
	    func);	
#endif
	xmlXPathFreeObject(xpath); 
	return(-1);
    }

    if((*nodes) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: result node set is null\n",
	    func);	
#endif
	xmlXPathFreeObject(xpath); 
	return(-1);
    }   
    
    xmlXPathFreeObject(xpath);     
    return(0);	
}

static void
xmlSecNodeSetDebugDump(xmlNodeSetPtr nodes, FILE *output) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetDebugDump";    
    int i, l;
    xmlNodePtr cur;

    if((nodes == NULL) || (output == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nodes or output is null\n",
	    func);	
#endif 	    
	return;
    }

    fprintf(output, "== Nodes set\n");    
    l = xmlXPathNodeSetGetLength(nodes);
    for(i = 0; i < l; ++i) {
	cur = xmlXPathNodeSetItem(nodes, i);
	fprintf(output, "%d: %s\n", cur->type, 
	    (cur->name) ? cur->name : BAD_CAST "null");
    }
}


