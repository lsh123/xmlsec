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
} xmlSecXPathType;

/* XPath transform */
typedef struct _xmlSecXPathData xmlSecXPathData, *xmlSecXPathDataPtr;
struct _xmlSecXPathData {
    xmlChar			*expr;
    xmlChar			**nsList;
    size_t			nsListSize;
    xmlSecXPath2TransformType	xpath2Type;
    xmlSecXPathDataPtr		next;
};
static xmlSecXPathDataPtr xmlSecXPathDataCreate		(void);
static void		  xmlSecXPathDataDestroy	(xmlSecXPathDataPtr data);
static int		  xmlSecXPathDataReadNsList	(xmlSecXPathDataPtr data,
							 const xmlNodePtr node);
static xmlSecNodeSetPtr	  xmlSecXPathDataExecute	(xmlSecXPathDataPtr data,
							 xmlSecXPathType type,
							 xmlDocPtr doc,
							 xmlNodePtr hereNode);


/**************************************************************************
 *
 * Internal XPath/XPointer ctx
 *
 *****************************************************************************/
typedef struct _xmlSecXPathTransformCtx		xmlSecXPathTransformCtx,
						*xmlSecXPathTransformCtxPtr;
struct _xmlSecXPathTransformCtx {
    xmlSecXPathType		type;
    xmlSecXPathDataPtr		operations;    

    xmlXPathContextPtr		context;
    xmlChar*			expr;
};

/******************************************************************************
 *
 * XPath/XPointer transforms
 *
 * xmlSecXPathTransformCtx block is located after xmlSecTransform structure
 * 
 *****************************************************************************/
#define xmlSecXPathTransformSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecXPathTransformCtx))
#define xmlSecXPathTransformGetCtx(transform) \
    ((xmlSecXPathTransformCtxPtr)(((unsigned char*)(transform)) + sizeof(xmlSecTransform)))
#define xmlSecTransformXPathCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecTransformXPath) || \
     xmlSecTransformCheckId((transform), xmlSecTransformXPath2) || \
     xmlSecTransformCheckId((transform), xmlSecTransformXPointer))

static int 		xmlSecTransformXPathInitialize	(xmlSecTransformPtr transform);
static void		xmlSecTransformXPathFinalize	(xmlSecTransformPtr transform);
static void 		xmlSecXPathHereFunction		(xmlXPathParserContextPtr ctxt, 
							 int nargs);

static int
xmlSecTransformXPathInitialize(xmlSecTransformPtr transform) {	
    xmlSecXPathTransformCtxPtr ctx;
    
    xmlSecAssert2(xmlSecTransformXPathCheckId(transform), -1);

    ctx = xmlSecXPathTransformGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    
    memset(ctx, 0, sizeof(xmlSecXPathTransformCtx));
    if(transform->id == xmlSecTransformXPath) {
	ctx->type = xmlSecXPathTypeXPath;
    } else if(transform->id == xmlSecTransformXPath2) {
	ctx->type = xmlSecXPathTypeXPath2;
    } else if(transform->id == xmlSecTransformXPointer) {
	ctx->type = xmlSecXPathTypeXPointer;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

static void
xmlSecTransformXPathFinalize(xmlSecTransformPtr transform) {
    xmlSecXPathTransformCtxPtr ctx;

    xmlSecAssert(xmlSecTransformXPathCheckId(transform));

    ctx = xmlSecXPathTransformGetCtx(transform);
    xmlSecAssert(ctx != NULL);
    
    if(ctx->context != NULL) {
	xmlXPathFreeContext(ctx->context);
    }
    if(ctx->expr != NULL) {
	xmlFree(ctx->expr);
    }
    if(ctx->operations != NULL) {
	xmlSecXPathDataDestroy(ctx->operations);
    }
    memset(ctx, 0, sizeof(xmlSecXPathTransformCtx));
}

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

/******************************************************************************
 *
 * XPath transform
 * 
 *****************************************************************************/
static int 		xmlSecTransformXPathReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecTransformXPathExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);

static xmlSecTransformKlass xmlSecTransformXPathId = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    xmlSecXPathTransformSize,		/* size_t objSize */

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

static const char xpathPattern[] = "(//. | //@* | //namespace::*)[%s]";
/**
 * http://www.w3.org/TR/xmldsig-core/#sec-XPath
 */


static int 
xmlSecTransformXPathReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecXPathTransformCtxPtr ctx;
    xmlNsPtr ns;
    xmlNodePtr cur, tmp;
    xmlChar* expr;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath), -1);
    xmlSecAssert2(transformNode != NULL, -1);

    ctx = xmlSecXPathTransformGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->context == NULL, -1);

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
    
    /* create xpath context */
    ctx->context = xmlXPathNewContext(NULL); /* we'll set doc in the context later */
    if(ctx->context == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlXPathNewContext",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    /* register namespaces */
    for(tmp = cur; tmp != NULL; tmp = tmp->parent) {
	for(ns = tmp->nsDef; ns != NULL; ns = ns->next) {
	    ret = xmlXPathRegisterNs(ctx->context, ns->prefix, ns->href);
	    if(ret != 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlXPathRegisterNs",
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "href=%s;prefix=%s",
			    xmlSecErrorsSafeString(ns->href),
			    xmlSecErrorsSafeString(ns->prefix)); 
		return(-1);
	    }
	}
    }

    /* read node */
    expr = xmlNodeGetContent(cur);
    if(expr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* create full XPath expression */
    ctx->expr = (xmlChar*) xmlMalloc(sizeof(xmlChar) * 
			(xmlStrlen(expr) + strlen(xpathPattern) + 1));
    if(ctx->expr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d",
		    xmlStrlen(expr) + strlen(xpathPattern) + 1);
	xmlFree(expr);
    	return(-1);
    }
    sprintf((char*)ctx->expr, xpathPattern, (char*)expr);	
    xmlFree(expr);
    
    /* check that we have nothing else */
    cur = xmlSecGetNextElementNode(cur->next);        
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

/**
 * xmlSecTransformXPathExecute:
 */
static int
xmlSecTransformXPathExecute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecXPathTransformCtxPtr ctx;
    xmlXPathObjectPtr xpathObj;
    xmlSecNodeSetPtr res;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath), -1);
    xmlSecAssert2(transform->hereNode != NULL, -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);
    xmlSecAssert2(nodes != NULL, -1);

    ctx = xmlSecXPathTransformGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->context != NULL, -1);
    xmlSecAssert2(ctx->expr != NULL, -1);

    /* first set doc in the xpath context */
    ctx->context->doc = (*doc);

    /* function here() works only in he same document */  
    if((*doc) == transform->hereNode->doc) {
	xmlXPathRegisterFunc(ctx->context, (xmlChar *)"here", xmlSecXPathHereFunction);
	ctx->context->here = transform->hereNode;
	ctx->context->xptr = 1;
    }

    xpathObj = xmlXPathEvalExpression(ctx->expr, ctx->context);
    if(xpathObj == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlXPathEvalExpression",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
    	return(-1);
    }
    
    res = xmlSecNodeSetCreate((*doc), xpathObj->nodesetval, xmlSecNodeSetNormal);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNodeSetCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "type=%d", xmlSecNodeSetNormal);
	xmlXPathFreeObject(xpathObj);     
    	return(-1);
    }
    xpathObj->nodesetval = NULL;
    xmlXPathFreeObject(xpathObj);     
    
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

struct _xmlSecTransformKlass xmlSecTransformXPath2Id = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* size_t klassSize */
    xmlSecXPathTransformSize,			/* size_t objSize */

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
    xmlSecXPathTransformSize,			/* size_t objSize */

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








/***************************************************************************
 *
 *         XPath transform 
 *
 **************************************************************************/


/***************************************************************************
 *
 *         XPath2 transform 
 *
 **************************************************************************/

/**
 * xmlSecTransformXPath2ReadNode:
 */
static int 
xmlSecTransformXPath2ReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecXPathTransformCtxPtr ctx;
    xmlSecXPathDataPtr data = NULL;
    xmlSecXPathDataPtr prev = NULL;
    xmlChar* xpath2Type;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath2), -1);
    xmlSecAssert2(transformNode != NULL, -1);
    
    ctx = xmlSecXPathTransformGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->operations == NULL, -1);

    /* There are only XPath nodes */
    cur = xmlSecGetNextElementNode(transformNode->children);  
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeXPath, xmlSecXPath2Ns)) {
	/* create new data and append it to the existing chain */
        data = xmlSecXPathDataCreate();
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecXPathDataCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
        if(prev != NULL) {
	    prev->next = data;
	}
	if(ctx->operations == NULL) {
	    ctx->operations = data;
	}
	prev = data;
	
	/* read xpath expression */
	data->expr = xmlNodeGetContent(cur);
	if(data->expr == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
			XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}

        if(xmlSecXPathDataReadNsList(data, cur) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecXPathDataReadNsList",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
    	    return(-1);
	}
    
	/* determine operation type */
	xpath2Type = xmlGetProp(cur, xmlSecAttrFilter);
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

        cur = xmlSecGetNextElementNode(cur->next);  
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

/**
 * xmlSecTransformXPath2Execute:
 */
static int
xmlSecTransformXPath2Execute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecXPathTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    xmlSecNodeSetPtr res = NULL;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath2), -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);
    xmlSecAssert2(nodes != NULL, -1);

    ctx = xmlSecXPathTransformGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->operations != NULL, -1);

    
    hereNode = ((*doc) == ctxDoc) ? transform->hereNode : NULL;

    res = xmlSecXPathDataExecute(ctx->operations, ctx->type, (*doc), hereNode);
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
 * xmlSecTransformXPointerReadNode:
 *
 * http://www.ietf.org/internet-drafts/draft-eastlake-xmldsig-uri-02.txt
 */
static int 
xmlSecTransformXPointerReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecXPathTransformCtxPtr ctx;
    xmlNodePtr cur;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPointer), -1);
    xmlSecAssert2(transformNode != NULL, -1);

    ctx = xmlSecXPathTransformGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->operations == NULL, -1);
    
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

    ctx->operations = xmlSecXPathDataCreate();
    if(ctx->operations == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* read node */
    ctx->operations->expr = xmlNodeGetContent(cur);
    if(ctx->operations->expr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* read namespaces */
    if(xmlSecXPathDataReadNsList(ctx->operations, cur) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecXPathDataReadNsList",
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
	return(-1);
    }
    return(0);
}

/**
 * xmlSecTransformXPointerExecute:
 */
static int
xmlSecTransformXPointerExecute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			     xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecXPathTransformCtxPtr ctx;
    xmlNodePtr hereNode;
    xmlSecNodeSetPtr res;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPointer), -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);
    xmlSecAssert2(nodes != NULL, -1);

    ctx = xmlSecXPathTransformGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->operations != NULL, -1);
    xmlSecAssert2(ctx->operations->expr != NULL, -1);
    xmlSecAssert2(ctx->operations->next == NULL, -1);
    
    /* function here() works only in he same document */  
    hereNode = ((*doc) == ctxDoc) ? transform->hereNode : NULL;
    res = xmlSecXPathDataExecute(ctx->operations, ctx->type, (*doc), hereNode);
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
static xmlSecXPathDataPtr	
xmlSecXPathDataCreate(void) {
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
    
    data->xpath2Type = xmlSecXPathTransformIntersect; /* default */
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
xmlSecXPathDataExecute(xmlSecXPathDataPtr data, xmlSecXPathType type, xmlDocPtr doc, xmlNodePtr hereNode) {
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
	switch(type) {
	case xmlSecXPathTypeXPath:
	case xmlSecXPathTypeXPath2:
	    ctx = xmlXPathNewContext(doc);
	    break;
	case xmlSecXPathTypeXPointer:
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
	switch(type) {
	case xmlSecXPathTypeXPath:
	case xmlSecXPathTypeXPath2:
	    xpath = xmlXPathEvalExpression(data->expr, ctx);
	    break;
	case xmlSecXPathTypeXPointer:
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
	switch(type) {
	case xmlSecXPathTypeXPath:
	    nodeSetType = xmlSecNodeSetNormal;
	    break;
	case xmlSecXPathTypeXPath2:
	    nodeSetType = xmlSecNodeSetTree;
	    break;
	case xmlSecXPathTypeXPointer:
	    nodeSetType = xmlSecNodeSetTree;
	    break;
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


