/** 
 * XMLSec library
 *
 * XPath transform
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
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
typedef struct _xmlSecXPathTransformData {
    xmlChar			*xpathExpr;
    xmlChar			**xpathNamespaces;
    size_t			size;
} xmlSecXPathTransformData, *xmlSecXPathTransformDataPtr;


static xmlSecXPathTransformDataPtr	xmlSecXPathTransformDataCreate	(void);
static void		xmlSecXPathTransformDataDestroy	(xmlSecXPathTransformDataPtr data);
static xmlSecXPathTransformDataPtr	xmlSecXPathTransformDataRead	(const xmlNodePtr node);

static xmlSecTransformPtr xmlSecTransformXPathCreate	(xmlSecTransformId id);
static void		xmlSecTransformXPathDestroy	(xmlSecTransformPtr transform);
static int 		xmlSecTransformXPathReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPathExecute	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlNodeSetPtr *nodes);


struct _xmlSecXmlTransformId xmlSecTransformXPathId = {
    /* same as xmlSecTransformId */ 
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    BAD_CAST "http://www.w3.org/TR/1999/REC-xpath-19991116", 
					/* const xmlChar *href; */

    xmlSecTransformXPathCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecTransformXPathDestroy,	/* xmlSecTransformDestroyMethod destroy; */
    xmlSecTransformXPathReadNode,	/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlTransform info */
    xmlSecTransformXPathExecute		/* xmlSecXmlTransformExecuteMethod executeXml; */
};

xmlSecTransformId xmlSecTransformXPath = (xmlSecTransformId)(&xmlSecTransformXPathId);

static const xmlChar xpathPattern[] = "(//. | //@* | //namespace::*)[%s]";

/** 
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



/**
 * XPath transform 
 */
/**
 * xmlSecTransformXPathCreate
 * @id
 *
 *
 */
static xmlSecTransformPtr 
xmlSecTransformXPathCreate(xmlSecTransformId id) {
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecTransformXPathCreate";
    xmlSecXmlTransformPtr xmlTransform; 
    
    if(id != xmlSecTransformXPath){
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
    xmlTransform->id = (xmlSecXmlTransformId)xmlSecTransformXPath;    
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecTransformXPathDestroy";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathTransformDataPtr data;
    
    if(!xmlSecTransformCheckId(transform, xmlSecTransformXPath)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return;
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;
    data = (xmlSecXPathTransformDataPtr)xmlTransform->xmlData;
    
    if(data != NULL) {
	xmlSecXPathTransformDataDestroy(data);
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecTransformXPathReadNode";
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathTransformDataPtr data;
    
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
    
    data = xmlSecXPathTransformDataRead(transformNode);
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to read transform data\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    if(xmlTransform->xmlData != NULL) {
	xmlSecXPathTransformDataDestroy((xmlSecXPathTransformDataPtr)xmlTransform->xmlData);
    }
    xmlTransform->xmlData = data;
    xmlTransform->here = transformNode;
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecTransformXPathAddExpression";
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
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecTransformXPathExecute";
    xmlChar *expr;    
    xmlSecXmlTransformPtr xmlTransform;
    xmlSecXPathTransformDataPtr data;
    xmlXPathObjectPtr xpath; 
    xmlXPathContextPtr ctx; 

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
    data = (xmlSecXPathTransformDataPtr)xmlTransform->xmlData;
    
    if((data == NULL) || (data->xpathExpr == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath data or xpath expression is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    /**
     * Create full XPath expression
     */
    expr = (xmlChar*) xmlMalloc(sizeof(xmlChar) * 
		(xmlStrlen(data->xpathExpr) + xmlStrlen(xpathPattern) + 1));
    if(expr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate xpath expr buffer\n",
	    func);	
#endif
	return(-1);
    }
    sprintf((char*) expr, (char*) xpathPattern, data->xpathExpr);

    /**
     * Create XPath context
     */
    ctx = xmlXPathNewContext(*doc);
    if(ctx == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xpath context is null\n",
	    func);	
#endif
	xmlFree(expr); 
	return(-1);
    }
    
    /* function here() works only in he same document */  
    if((*doc) == ctxDoc) {
	xmlXPathRegisterFunc(ctx, (xmlChar *)"here", xmlSecXPathHereFunction);
	ctx->here = xmlTransform->here;
	ctx->xptr = 1;
    }
    
    /*
     * Register namespaces
     */
    if(data->xpathNamespaces != NULL) {
	xmlChar *prefix;
	xmlChar *href;
	size_t i;
		
	for(i = 0; i + 1 < data->size;) {
	    prefix = (data->xpathNamespaces)[i++];
	    href = (data->xpathNamespaces)[i++];
	    if(xmlXPathRegisterNs(ctx, prefix, href) != 0) {
#ifdef XMLSEC_DEBUG
		xmlGenericError(xmlGenericErrorContext, 
		    "%s: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", 
		    func, 
		    ((prefix != NULL) ? (char*)prefix : "null"),
		    ((href != NULL) ? (char*)href : "null"));
#endif
    		xmlFree(expr); 
		xmlXPathFreeContext(ctx); 	     
		return(-1);
	    }
	}
    }

    /*  
     * Evaluate xpath
     */
    xpath = xmlXPathEvalExpression(expr, ctx);
    if(xpath == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext, 
	    "xmlSecXPathTransformRead: xpath eval failed\n",
	    func);
#endif
    	xmlFree(expr); 
	xmlXPathFreeContext(ctx); 
        return(-1);
    }

    /* free everything we do not need */
    xmlFree(expr); 
    xmlXPathFreeContext(ctx);      
    
    if((*nodes) != NULL) {
	(*nodes) = xmlXPathIntersection((*nodes), xpath->nodesetval);
    } else {
	(*nodes) = xmlXPathNodeSetMerge(NULL, xpath->nodesetval);
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


/**
 * XPath Transform Data
 */ 
/**
 * xmlSecXPathTransformDataCreate:
 *
 *
 *
 */
xmlSecXPathTransformDataPtr	
xmlSecXPathTransformDataCreate(void) {
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecXPathTransformDataCreate";    
    xmlSecXPathTransformDataPtr data;
    
    data = (xmlSecXPathTransformDataPtr) xmlMalloc(sizeof(xmlSecXPathTransformData));
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate xmlSecXPathTransformData \n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(data, 0, sizeof(xmlSecXPathTransformData)); 

    return(data);    
}

/**
 * @xmlSecXPathTransformDataDestroy:
 * @data
 *
 *
 */
void				
xmlSecXPathTransformDataDestroy(xmlSecXPathTransformDataPtr data) {
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecXPathTransformDataDestroy";
    
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: data is null\n",
	    func);	
#endif 	    
	return;    	
    }
    if(data->xpathExpr != NULL) {
	xmlFree(data->xpathExpr);
    }
    if(data->xpathNamespaces != NULL) {
	size_t i;
		
	for(i = 0; i < data->size; ++i) {
	    if((data->xpathNamespaces)[i] != NULL) {
	        xmlFree((data->xpathNamespaces)[i]);
	    }
	}
	memset(data->xpathNamespaces, 0, sizeof(xmlChar*) * (data->size));
	xmlFree(data->xpathNamespaces);
    }
    memset(data, 0, sizeof(xmlSecXPathTransformData));  
    xmlFree(data);
}

/**
 * xmlSecXPathTransformDataRead
 * @node
 *
 *
 */
xmlSecXPathTransformDataPtr	
xmlSecXPathTransformDataRead(const xmlNodePtr node) {
    static const char func[] _UNUSED_VARIABLE_ = "xmlSecXPathTransformDataRead";
    xmlSecXPathTransformDataPtr data;
    xmlNodePtr cur;
    xmlNsPtr ns;
    size_t count;
        
    if(node == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: node is null \n",
	    func);	
#endif 	    
	return(NULL);
    }
        
    data = xmlSecXPathTransformDataCreate();
    if(data == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create xmlSecXPathTransformData \n",
	    func);	
#endif 	    
	return(NULL);
    }
    
    cur = xmlSecGetNextElementNode(node->children);  
    /* There is only one required node XPath*/
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, BAD_CAST "XPath", xmlSecDSigNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"XPath\" missed\n",
	    func);
#endif	    
	xmlSecXPathTransformDataDestroy(data);
	return(NULL);
    }

    data->xpathExpr = xmlNodeGetContent(cur);
    if(data->xpathExpr == NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: failed to get xpath expression from ndoe\n",
		func);
#endif		
	xmlSecXPathTransformDataDestroy(data);
	return(NULL);
    }
    
    /* how many namespaces we have? */
    ns = cur->nsDef;
    count = 0;
    while(ns != NULL) {	
	++count;
	ns = ns->next;
    }
    
    data->xpathNamespaces = (xmlChar**)xmlMalloc(sizeof(xmlChar*) * (2 * count));
    if(data->xpathNamespaces == NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create namespace list\n",
		func);
#endif		
	xmlSecXPathTransformDataDestroy(data);
	return(NULL);
    }    
    data->size = 2 * count;
    memset(data->xpathNamespaces, 0, sizeof(xmlChar*) * (data->size));
    
    ns = cur->nsDef;
    count = 0;
    while((ns != NULL) && (count < data->size)){	
	if(ns->prefix != NULL) {
	    data->xpathNamespaces[count++] = xmlStrdup(ns->prefix);
	} else {
	    data->xpathNamespaces[count++] = NULL;
	}	
	if(ns->href != NULL) {
	    data->xpathNamespaces[count++] = xmlStrdup(ns->href);
	} else {
	    data->xpathNamespaces[count++] = NULL;
	}
	ns = ns->next;
    }
    cur = xmlSecGetNextElementNode(cur->next);
        
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: unexpected node found\n",
		func);
#endif		
	xmlSecXPathTransformDataDestroy(data);
	return(NULL);
    }
    
    return(data);
}

