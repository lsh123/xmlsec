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

#ifndef XMLSEC_NO_XPATHALT

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

static void		xmlSecNodeSetDebugDump		(xmlNodeSetPtr nodes,
							 FILE *output);


static xmlSecTransformPtr xmlSecXPathAltCreate		(xmlSecTransformId id);
static void		xmlSecXPathAltDestroy		(xmlSecTransformPtr transform);
static int 		xmlSecXPathAltReadNode		(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecXPathAltExecute		(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlNodeSetPtr *nodes);

struct _xmlSecXmlTransformId xmlSecXPathAltId = {
    /* same as xmlSecTransformId */ 
    xmlSecTransformTypeXml,		/* xmlSecTransformType type; */
    xmlSecUsageDSigTransform,		/* xmlSecTransformUsage	usage; */
    BAD_CAST "http://www.nue.et-inf.uni-siegen.de/~geuer-pollmann/#xpathFilter", /* const xmlChar *href; */

    xmlSecXPathAltCreate,		/* xmlSecTransformCreateMethod create; */
    xmlSecXPathAltDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecXPathAltReadNode,		/* xmlSecTransformReadNodeMethod read; */
    
    /* xmlTransform info */
    xmlSecXPathAltExecute		/* xmlSecXmlTransformExecuteMethod executeXml; */
};
xmlSecTransformId xmlSecXPathAlt = (xmlSecTransformId)(&xmlSecXPathAltId);


static xmlNodeSetPtr 	xmlSecXPathAltAddNodes		(xmlNodeSetPtr nodes,
							 xmlNodePtr cur,
							 xmlNodePtr here,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr doc);
static int		xmlSecXPathAltWalkTheTree	(xmlNodeSetPtr nodes, 
							 xmlNodePtr cur,
							 xmlNodeSetPtr includeSet, 
							 xmlNodeSetPtr excludeSet, 
							 xmlNodeSetPtr includeSearchSet, 
							 xmlNodeSetPtr excludeSearchSet,
							 int mode);
static int		xmlSecXPathAltAddNode		(xmlNodeSetPtr nodes, 
							 xmlNodePtr cur,
							 xmlNodeSetPtr includeSet, 
							 xmlNodeSetPtr excludeSet, 
							 xmlNodeSetPtr includeSearchSet, 
							 xmlNodeSetPtr excludeSearchSet,
							 int mode);
							 
static const xmlChar xmlSecXPathAltNs[] = "http://www.nue.et-inf.uni-siegen.de/~geuer-pollmann/#xpathFilter";

/**
 * XPathAlt transform 
 */
/**
 * xmlSecXPathAltCreate
 * @id
 *
 *
 */
static xmlSecTransformPtr 
xmlSecXPathAltCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathAltCreate";
    xmlSecXmlTransformPtr xmlTransform; 
    
    if((id != xmlSecXPathAlt)) {
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
 * xmlSecXPathAltDestroy
 * @transform:
 *
 *
 */
static void
xmlSecXPathAltDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathAltDestroy";
    xmlSecXmlTransformPtr xmlTransform;
    
    if(!xmlSecTransformCheckId(transform, xmlSecXPathAlt)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or transformNode is null\n",
	    func);	
#endif 	    
	return;
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;

    memset(xmlTransform, 0,  sizeof(struct _xmlSecXmlTransform));  
    xmlFree(xmlTransform);
}

/**
 * xmlSecXPathAltReadNode
 * @transform:
 * @transformNode:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-XPath
 */
static int 
xmlSecXPathAltReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathAltReadNode";
    xmlSecXmlTransformPtr xmlTransform;
    xmlNodePtr cur;
    
    if((!xmlSecTransformCheckId(transform, xmlSecXPathAlt)) || 
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

    cur = xmlSecGetNextElementNode(transformNode->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  BAD_CAST "XPathAlternative", xmlSecXPathAltNs))) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: required element \"XPathAlternative\" missed\n",
	    func);
#endif	    
	return(-1);
    }
    xmlTransform->xmlData = cur;
        
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	 xmlGenericError(xmlGenericErrorContext,
		"%s: unexpected node found \"%s\"\n",
		func, cur->name);
#endif		
	return(-1);
    }
    
    return(0);
}

/**
 * xmlSecXPathAltExecute
 * @transform:
 * @ctxDoc:
 * @doc:
 * @nodes:
 *
 */
static int
xmlSecXPathAltExecute(xmlSecXmlTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlNodeSetPtr *nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathAltExecute";
    xmlSecXmlTransformPtr xmlTransform;
    xmlNodeSetPtr includeSet = NULL;
    xmlNodeSetPtr excludeSet = NULL;
    xmlNodeSetPtr includeSearchSet = NULL;
    xmlNodeSetPtr excludeSearchSet = NULL;
    xmlNodeSetPtr tmp;
    xmlNodePtr cur;
    xmlChar *prop;
    int res = -1;
    int mode = 1;
        
    if((!xmlSecTransformCheckId(transform, xmlSecXPathAlt)) || 
       (nodes == NULL) || (doc == NULL) || ((*doc) == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or something else is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    xmlTransform = (xmlSecXmlTransformPtr)transform;

    if(xmlTransform->here == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform node is null\n",
	    func);	
#endif 	    
	goto done;
    }
    
    /* create nodes */
    cur = xmlSecGetNextElementNode(((xmlNodePtr)xmlTransform->xmlData)->children);
    while(cur != NULL) {
	if(xmlSecCheckNodeName(cur,  BAD_CAST "Include", xmlSecXPathAltNs)) {
	    tmp = xmlSecXPathAltAddNodes(includeSet, cur, xmlTransform->here, ctxDoc, *doc);
	    if(tmp == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to get Include nodes\n",
		    func);	
#endif 	    
		goto done;		
	    }
	    includeSet = tmp;
	} else if(xmlSecCheckNodeName(cur, BAD_CAST "Exclude", xmlSecXPathAltNs)) {
	    tmp = xmlSecXPathAltAddNodes(excludeSet, cur, xmlTransform->here, ctxDoc, *doc);
	    if(tmp == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to get Exclude nodes\n",
		    func);	
#endif 	    
		goto done;		
	    }
	    excludeSet = tmp;
	} else if(xmlSecCheckNodeName(cur,  BAD_CAST "IncludeButSearch", xmlSecXPathAltNs)) {
	    tmp = xmlSecXPathAltAddNodes(includeSearchSet, cur, xmlTransform->here, ctxDoc, *doc);
	    if(tmp == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to get IncludeButSearch nodes\n",
		    func);	
#endif 	    
		goto done;		
	    }
	    includeSearchSet = tmp;
	} else if(xmlSecCheckNodeName(cur,  BAD_CAST "ExcludeButSearch", xmlSecXPathAltNs)) {
	    tmp = xmlSecXPathAltAddNodes(excludeSearchSet, cur, xmlTransform->here, ctxDoc, *doc);
	    if(tmp == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to get ExcludeButSearch nodes\n",
		    func);	
#endif 	    
		goto done;		
	    }
	    excludeSearchSet = tmp;
	} else {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: unknown node \"%s\"\n",
		func, cur->name);	
#endif 	    
	    goto done;
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }    

/*
    fprintf(stderr, "=Include set\n");
    xmlSecNodeSetDebugDump(includeSet, stderr);
    fprintf(stderr, "=Exclude set\n");
    xmlSecNodeSetDebugDump(excludeSet, stderr);
    fprintf(stderr, "=Include Search set\n");
    xmlSecNodeSetDebugDump(includeSearchSet, stderr);
    fprintf(stderr, "=Exclude Search set\n");
    xmlSecNodeSetDebugDump(excludeSearchSet, stderr);
*/
    
    /* read IncludeSlashPolicy */
    cur = xmlDocGetRootElement(*doc);
    prop = xmlGetProp(cur, BAD_CAST "IncludeSlashPolicy");
    if((prop != NULL) && (xmlStrEqual(prop, BAD_CAST "true"))) {
        tmp = xmlXPathNodeSetCreate(cur);
	mode = 1;
	xmlFree(prop);
    } else if((prop != NULL)) {
        tmp = xmlXPathNodeSetCreate(NULL);
	mode = 0;
	xmlFree(prop);
    } else {
	/* todo: error>? */
        tmp = xmlXPathNodeSetCreate(NULL);
	mode = 0;
    }
    if(tmp == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create nodes set\n",
	    func);	
#endif 	    
	goto done;
    }

    res = xmlSecXPathAltWalkTheTree(tmp, cur, includeSet, excludeSet, includeSearchSet, 
				    excludeSearchSet, mode);
    if(res < 0) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: tree walk failed\n",
	    func);	
#endif 	  
	xmlXPathFreeNodeSet(tmp);  
	goto done;
    }

/*
    fprintf(stderr, "=Result set\n");
    xmlSecNodeSetDebugDump(tmp, stderr);
*/
        
    (*nodes) = xmlXPathIntersection((*nodes), tmp);
    xmlXPathFreeNodeSet(tmp);  
    
    res = 0;    
    
done:
    if(includeSet != NULL) {
	xmlXPathFreeNodeSet(includeSet);
    }
    if(excludeSet != NULL) {
	xmlXPathFreeNodeSet(excludeSet);
    }
    if(includeSearchSet != NULL) {
	xmlXPathFreeNodeSet(includeSearchSet);
    }
    if(excludeSearchSet != NULL) {
	xmlXPathFreeNodeSet(excludeSearchSet);
    }
    return(res);
}    
    
static xmlNodeSetPtr 	
xmlSecXPathAltAddNodes(xmlNodeSetPtr nodes, xmlNodePtr cur,
		      xmlNodePtr here, xmlDocPtr ctxDoc, xmlDocPtr doc) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXPathAltAddNodes";
    xmlChar *expr;
    xmlXPathObjectPtr xpath; 
    xmlXPathContextPtr ctx; 
    xmlNodeSetPtr res;
    xmlNodePtr tmp;
    xmlNsPtr ns;
    
    if(doc == NULL)  {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: doc is null\n",
	    func);	
#endif 	    
	return(NULL);
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
	return(NULL);
    }
    
    /* function here() works only in he same document */  
    if(doc == ctxDoc) {
	xmlXPathRegisterFunc(ctx, (xmlChar *)"here", xmlSecXPathHereFunction);
	ctx->here = here;
	ctx->xptr = 1;
    }

    /* register namespaces */
    for(tmp = cur; tmp != NULL; tmp = tmp->parent) {
	for(ns = tmp->nsDef; ns != NULL; ns = ns->next){	
	    if((ns->prefix != NULL) && (xmlXPathRegisterNs(ctx, ns->prefix, ns->href) != 0)) {
#ifdef XMLSEC_DEBUG
		xmlGenericError(xmlGenericErrorContext, 
		    "%s: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", 
		    func, 
		    ((ns->prefix != NULL) ? (char*)ns->prefix : "null"),
		    ((ns->href != NULL) ? (char*)ns->href : "null"));
#endif
		xmlXPathFreeContext(ctx); 	     
		return(NULL);
	    }
	}
    }

    expr = xmlNodeGetContent(cur);
    if(expr == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext, 
	    "%s: failed to get node content\n",
	    func);
#endif
	xmlXPathFreeContext(ctx); 
        return(NULL);
    }
    
    /*  
     * Evaluate xpath
     */
    xpath = xmlXPathEvalExpression(expr, ctx);
    if(xpath == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext, 
	    "%s: xpath eval failed\n",
	    func);
#endif
	xmlFree(expr);
	xmlXPathFreeContext(ctx); 
        return(NULL);
    }

    if(xpath->nodesetval != NULL) {
	res = xmlXPathNodeSetMerge(nodes, xpath->nodesetval);
	if(res == NULL) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext, 
		"%s nodes set merge failed\n",
		func);
#endif
	    xmlFree(expr);
	    xmlXPathFreeObject(xpath);
	    xmlXPathFreeContext(ctx); 
    	    return(NULL);
	}
    } else {
	res = nodes;
    }
    
    /* free everything */
    xmlFree(expr);
    xmlXPathFreeContext(ctx);      
    xmlXPathFreeObject(xpath);
    return(res);
}

    
static int		
xmlSecXPathAltWalkTheTree(xmlNodeSetPtr nodes, xmlNodePtr cur, 
			  xmlNodeSetPtr includeSet, xmlNodeSetPtr excludeSet, 
			  xmlNodeSetPtr includeSearchSet, xmlNodeSetPtr excludeSearchSet,
			  int mode) {
    static const char func[] = "xmlSecXPathAltWalkTheTree";
    int ret;
    
    if((nodes == NULL) || (cur == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nodes or cur is null\n",
	    func);	
#endif 	    
	return(-1);
    }    
    
    ret = 0;
    for(cur = cur->children; cur != NULL; cur = cur->next) {
	if((includeSet != NULL) && xmlXPathNodeSetContains(includeSet, cur)) {
	    /* add all nodes from subtree */
	    xmlSecGetChildNodeSet(cur, nodes, 1);	    
	} else if((excludeSet != NULL) && xmlXPathNodeSetContains(excludeSet, cur)) {
	    /* do nothing */
	} else if((includeSearchSet != NULL) && xmlXPathNodeSetContains(includeSearchSet, cur)) {
	    ret = xmlSecXPathAltAddNode(nodes, cur, includeSet, excludeSet, 
				  includeSearchSet, excludeSearchSet, 1);
            if(ret >= 0) {
    		ret = xmlSecXPathAltWalkTheTree(nodes, cur, includeSet, excludeSet, 
						includeSearchSet, excludeSearchSet, 
						1);
	    }
	} else if((excludeSearchSet != NULL) && xmlXPathNodeSetContains(excludeSearchSet, cur)) {
	    ret = xmlSecXPathAltAddNode(nodes, cur, includeSet, excludeSet, 
				  includeSearchSet, excludeSearchSet, 0);
            if(ret >= 0) {
    		ret = xmlSecXPathAltWalkTheTree(nodes, cur, includeSet, excludeSet, 
						includeSearchSet, excludeSearchSet, 
						0);
	    }
	} else {
	    ret = xmlSecXPathAltAddNode(nodes, cur, includeSet, excludeSet, 
				  includeSearchSet, excludeSearchSet, mode);
            if(ret >= 0) {
    		ret = xmlSecXPathAltWalkTheTree(nodes, cur, includeSet, excludeSet, 
						includeSearchSet, excludeSearchSet, 
						mode);
	    }
	}

	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed\n",
		func);	
#endif 	    
	    return(-1);
	}
    }
    
    return(0);
}
    
static int
xmlSecXPathAltAddNode(xmlNodeSetPtr nodes, xmlNodePtr cur,
			  xmlNodeSetPtr includeSet, xmlNodeSetPtr excludeSet, 
			  xmlNodeSetPtr includeSearchSet, xmlNodeSetPtr excludeSearchSet,
			  int mode) {

    static const char func[] = "xmlSecXPathAltWalkTheTree";
    int include;
    int exclude;
    xmlNsPtr ns;
    xmlAttrPtr attr;
    
    if((nodes == NULL) || (cur == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nodes or cur is null\n",
	    func);	
#endif 	    
	return(-1);
    }    

    if(mode) {
	xmlXPathNodeSetAdd(nodes, cur);
    }
    
    /* add all attrs */
    attr = cur->properties; 
    while (attr != NULL) {
	include = ((includeSet != NULL) && 
		   xmlXPathNodeSetContains(includeSet, (xmlNodePtr)attr)) || 
		  ((includeSearchSet != NULL) && 
		   xmlXPathNodeSetContains(includeSearchSet, (xmlNodePtr)attr));		  
	exclude = ((excludeSet != NULL) && 
		   xmlXPathNodeSetContains(excludeSet, (xmlNodePtr)attr)) || 
		  ((excludeSearchSet != NULL) && 
		   xmlXPathNodeSetContains(excludeSearchSet, (xmlNodePtr)attr));
		   
	if((mode && !exclude) || include) {
    	    xmlXPathNodeSetAdd(nodes, (xmlNodePtr)attr); 
	} 
    	attr = attr->next; 
    }	
    
    /* add namespaces */
    for (ns = cur->nsDef; ns != NULL; ns = ns->next) {
	include = ((includeSet != NULL) && 
		   xmlXPathNodeSetContains(includeSet, (xmlNodePtr)ns)) || 
		  ((includeSearchSet != NULL) && 
		   xmlXPathNodeSetContains(includeSearchSet, (xmlNodePtr)ns));		  
	exclude = ((excludeSet != NULL) && 
		   xmlXPathNodeSetContains(excludeSet, (xmlNodePtr)ns)) || 
		  ((excludeSearchSet != NULL) && 
		   xmlXPathNodeSetContains(excludeSearchSet, (xmlNodePtr)ns));
	if((mode && !exclude) || include) {
	    xmlXPathNodeSetAddNs(nodes, cur,  ns);
	}
    }
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

#endif /* XMLSEC_NO_XPATHALT */

