/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * XPath transform
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
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
#include <xmlsec/list.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>


/**************************************************************************
 *
 * xmlSecXPathHereFunction:
 * @ctxt:		the ponter to XPath context.
 * @nargs:		the arguments nubmer.
 *
 * The implementation of XPath "here()" function.
 * See xmlXPtrHereFunction() in xpointer.c. the only change is that 
 * we return NodeSet instead of NodeInterval.
 *
 *****************************************************************************/
static void 
xmlSecXPathHereFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);

    if((ctxt == NULL) || (ctxt->context == NULL) || (ctxt->context->here == NULL)) {
	XP_ERROR(XPTR_SYNTAX_ERROR);
    }
    valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->here));
}

/**************************************************************************
 *
 * XPath/XPointer data
 *
 *****************************************************************************/
typedef struct _xmlSecXPathData			xmlSecXPathData,
						*xmlSecXPathDataPtr;
typedef enum {
    xmlSecXPathDataTypeXPath,
    xmlSecXPathDataTypeXPath2,
    xmlSecXPathDataTypeXPointer
} xmlSecXPathDataType;

struct _xmlSecXPathData {
    xmlSecXPathDataType			type;
    xmlXPathContextPtr			ctx;
    xmlChar*				expr;
    xmlSecNodeSetOp			nodeSetOp;
    xmlSecNodeSetType			nodeSetType;    
};

static xmlSecXPathDataPtr 	xmlSecXPathDataCreate		(xmlSecXPathDataType type);
static void		  	xmlSecXPathDataDestroy		(xmlSecXPathDataPtr data);
static int		  	xmlSecXPathDataSetExpr		(xmlSecXPathDataPtr data,
								 const xmlChar* expr);
static int		  	xmlSecXPathDataNodeRead		(xmlSecXPathDataPtr data,
								 xmlNodePtr node);
static xmlSecNodeSetPtr		xmlSecXPathDataExecute		(xmlSecXPathDataPtr data,
								 xmlDocPtr doc,
								 xmlNodePtr hereNode);

static xmlSecXPathDataPtr  
xmlSecXPathDataCreate(xmlSecXPathDataType type) {
    xmlSecXPathDataPtr data;

    data = (xmlSecXPathDataPtr) xmlMalloc(sizeof(xmlSecXPathData));
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecXPathData)=%d",
		    sizeof(xmlSecXPathData));
	return(NULL);
    }
    memset(data, 0, sizeof(xmlSecXPathData)); 

    data->type = type;
    data->nodeSetType = xmlSecNodeSetTree;

    /* create xpath or xpointer context */
    switch(data->type) {
    case xmlSecXPathDataTypeXPath:    
    case xmlSecXPathDataTypeXPath2:    
	data->ctx = xmlXPathNewContext(NULL); /* we'll set doc in the context later */
	if(data->ctx == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlXPathNewContext",
			XMLSEC_ERRORS_R_XML_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecXPathDataDestroy(data);
	    return(NULL);
	}
	break;
    case xmlSecXPathDataTypeXPointer:    
	data->ctx = xmlXPtrNewContext(NULL, NULL, NULL); /* we'll set doc in the context later */
	if(data->ctx == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlXPtrNewContext",
			XMLSEC_ERRORS_R_XML_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecXPathDataDestroy(data);
	    return(NULL);
	}
	break;
    }

    return(data);
}

static void				
xmlSecXPathDataDestroy(xmlSecXPathDataPtr data) {
    xmlSecAssert(data != NULL);    

    if(data->expr != NULL) {
	xmlFree(data->expr);
    }
    if(data->ctx != NULL) {
	xmlXPathFreeContext(data->ctx);
    }
    memset(data, 0, sizeof(xmlSecXPathData));  
    xmlFree(data);
}

static int 
xmlSecXPathDataSetExpr(xmlSecXPathDataPtr data, const xmlChar* expr) {
    xmlSecAssert2(data != NULL, -1);    
    xmlSecAssert2(data->expr == NULL, -1);
    xmlSecAssert2(data->ctx != NULL, -1);
    xmlSecAssert2(expr != NULL, -1);    
            
    data->expr = xmlStrdup(expr);
    if(data->expr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_STRDUP_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    return(0);
}


static int 
xmlSecXPathDataNodeRead(xmlSecXPathDataPtr data, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlNsPtr ns;
    int ret;
    
    xmlSecAssert2(data != NULL, -1);    
    xmlSecAssert2(data->expr == NULL, -1);
    xmlSecAssert2(data->ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* register namespaces */
    for(cur = node; cur != NULL; cur = cur->parent) {
	for(ns = cur->nsDef; ns != NULL; ns = ns->next) {
	    /* check that we have no other namespace with same prefix already */
	    if((ns->prefix != NULL) && (xmlXPathNsLookup(data->ctx, ns->prefix) == NULL)){
	        ret = xmlXPathRegisterNs(data->ctx, ns->prefix, ns->href);
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
    }

    /* read node content and set expr */
    data->expr = xmlNodeGetContent(node);
    if(data->expr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    
    return(0);
}

static xmlSecNodeSetPtr
xmlSecXPathDataExecute(xmlSecXPathDataPtr data, xmlDocPtr doc, xmlNodePtr hereNode) {
    xmlXPathObjectPtr xpathObj = NULL; 
    xmlSecNodeSetPtr nodes;

    xmlSecAssert2(data != NULL, NULL);    
    xmlSecAssert2(data->expr != NULL, NULL);
    xmlSecAssert2(data->ctx != NULL, NULL);
    xmlSecAssert2(doc != NULL, NULL);
    xmlSecAssert2(hereNode != NULL, NULL);

    /* do not forget to set the doc */
    data->ctx->doc = doc;
    
    /* here function works only on the same document */
    if(hereNode->doc == doc) {
	xmlXPathRegisterFunc(data->ctx, (xmlChar *)"here", xmlSecXPathHereFunction);
	data->ctx->here = hereNode;
	data->ctx->xptr = 1;
    }

    /* execute xpath or xpointer expression */
    switch(data->type) {
    case xmlSecXPathDataTypeXPath:    
    case xmlSecXPathDataTypeXPath2:    
	xpathObj = xmlXPathEvalExpression(data->expr, data->ctx);
	if(xpathObj == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlXPathEvalExpression",
			XMLSEC_ERRORS_R_XML_FAILED,
			"expr=%s", 
			xmlSecErrorsSafeString(data->expr));
	    return(NULL);
	}
	break;
    case xmlSecXPathDataTypeXPointer:    
	xpathObj = xmlXPtrEval(data->expr, data->ctx);
	if(xpathObj == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlXPtrEval",
			XMLSEC_ERRORS_R_XML_FAILED,
			"expr=%s", 
			xmlSecErrorsSafeString(data->expr));
	    return(NULL);
	}
	break;
    }
    
    nodes = xmlSecNodeSetCreate(doc, xpathObj->nodesetval, data->nodeSetType);
    if(nodes == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecNodeSetCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "type=%d", data->nodeSetType);
	xmlXPathFreeObject(xpathObj);     
	return(NULL);
    }
    xpathObj->nodesetval = NULL;
    xmlXPathFreeObject(xpathObj); 
    
    return(nodes);
}


/**************************************************************************
 *
 * XPath data list
 *
 *****************************************************************************/
#define xmlSecXPathDataListId	\
	xmlSecXPathDataListGetKlass()
static xmlSecPtrListId 	xmlSecXPathDataListGetKlass		(void);
static xmlSecNodeSetPtr	xmlSecXPathDataListExecute		(xmlSecPtrListPtr dataList,
								 xmlDocPtr doc,
								 xmlNodePtr hereNode,
								 xmlSecNodeSetPtr nodes);

static xmlSecPtrListKlass xmlSecXPathDataListKlass = {
    BAD_CAST "xpath-data-list",
    NULL,						/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecXPathDataDestroy,	/* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,						/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,						/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};

static xmlSecPtrListId 
xmlSecXPathDataListGetKlass(void) {
    return(&xmlSecXPathDataListKlass);
}

static xmlSecNodeSetPtr	
xmlSecXPathDataListExecute(xmlSecPtrListPtr dataList, xmlDocPtr doc, 
		    	   xmlNodePtr hereNode, xmlSecNodeSetPtr nodes) {
    xmlSecXPathDataPtr data;
    xmlSecNodeSetPtr res, tmp, tmp2;
    xmlSecSize pos;
    
    xmlSecAssert2(xmlSecPtrListCheckId(dataList, xmlSecXPathDataListId), NULL);
    xmlSecAssert2(xmlSecPtrListGetSize(dataList) > 0, NULL);
    xmlSecAssert2(doc != NULL, NULL);
    xmlSecAssert2(hereNode != NULL, NULL);

    res = nodes;
    for(pos = 0; pos < xmlSecPtrListGetSize(dataList); ++pos) {
        data = (xmlSecXPathDataPtr)xmlSecPtrListGetItem(dataList, pos);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
			"xmlSecPtrListGetItem",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"pos=%d", pos);
	    if((res != NULL) && (res != nodes)) {
		xmlSecNodeSetDestroy(res);
	    }
	    return(NULL);
	}

	tmp = xmlSecXPathDataExecute(data, doc, hereNode);
	if(tmp == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecXPathDataExecute",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    if((res != NULL) && (res != nodes)) {
		xmlSecNodeSetDestroy(res);
	    }
	    return(NULL);
	}    

	tmp2 = xmlSecNodeSetAdd(res, tmp, data->nodeSetOp);
	if(tmp2 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecNodeSetAdd",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecNodeSetIntersection");
	    if((res != NULL) && (res != nodes)) {
		xmlSecNodeSetDestroy(res);
	    }
	    xmlSecNodeSetDestroy(tmp);
	    return(NULL);
	}
	res = tmp2;
    }

    return(res);
}

/******************************************************************************
 *
 * XPath/XPointer transforms
 *
 * xmlSecXPathDataList is located after xmlSecTransform structure
 * 
 *****************************************************************************/
#define xmlSecXPathTransformSize	\
    (sizeof(xmlSecTransform) + sizeof(xmlSecPtrList))
#define xmlSecXPathTransformGetDataList(transform) \
    ((xmlSecTransformCheckSize((transform), xmlSecXPathTransformSize)) ? \
	(xmlSecPtrListPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)) : \
	(xmlSecPtrListPtr)NULL)
#define xmlSecTransformXPathCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecTransformXPathId) || \
     xmlSecTransformCheckId((transform), xmlSecTransformXPath2Id) || \
     xmlSecTransformCheckId((transform), xmlSecTransformXPointerId))

static int 		xmlSecTransformXPathInitialize	(xmlSecTransformPtr transform);
static void		xmlSecTransformXPathFinalize	(xmlSecTransformPtr transform);
static int 		xmlSecTransformXPathExecute	(xmlSecTransformPtr transform,
							 int last, 
							 xmlSecTransformCtxPtr transformCtx);

static int
xmlSecTransformXPathInitialize(xmlSecTransformPtr transform) {	
    xmlSecPtrListPtr dataList;
    int ret;
        
    xmlSecAssert2(xmlSecTransformXPathCheckId(transform), -1);

    dataList = xmlSecXPathTransformGetDataList(transform);
    xmlSecAssert2(dataList != NULL, -1);
    
    ret = xmlSecPtrListInitialize(dataList, xmlSecXPathDataListId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

static void
xmlSecTransformXPathFinalize(xmlSecTransformPtr transform) {
    xmlSecPtrListPtr dataList;

    xmlSecAssert(xmlSecTransformXPathCheckId(transform));

    dataList = xmlSecXPathTransformGetDataList(transform);
    xmlSecAssert(xmlSecPtrListCheckId(dataList, xmlSecXPathDataListId));
    
    xmlSecPtrListFinalize(dataList);
}

static int
xmlSecTransformXPathExecute(xmlSecTransformPtr transform, int last,
			    xmlSecTransformCtxPtr transformCtx) {
    xmlSecPtrListPtr dataList;
    xmlDocPtr doc;
    
    xmlSecAssert2(xmlSecTransformXPathCheckId(transform), -1);
    xmlSecAssert2(transform->hereNode != NULL, -1);
    xmlSecAssert2(transform->outNodes == NULL, -1);
    xmlSecAssert2(last != 0, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dataList = xmlSecXPathTransformGetDataList(transform);
    xmlSecAssert2(xmlSecPtrListCheckId(dataList, xmlSecXPathDataListId), -1);
    xmlSecAssert2(xmlSecPtrListGetSize(dataList) > 0, -1);

    doc = (transform->inNodes != NULL) ? transform->inNodes->doc : transform->hereNode->doc;
    xmlSecAssert2(doc != NULL, -1);

    transform->outNodes = xmlSecXPathDataListExecute(dataList, doc, 
				transform->hereNode, transform->inNodes);
    if(transform->outNodes == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecXPathDataExecute",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    return(0);
}

/******************************************************************************
 *
 * XPath transform
 * 
 *****************************************************************************/
static int 		xmlSecTransformXPathNodeRead	(xmlSecTransformPtr transform,
							 xmlNodePtr node,
							 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecTransformXPathKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecXPathTransformSize,			/* xmlSecSize objSize */

    xmlSecNameXPath,				/* const xmlChar* name; */
    xmlSecXPathNs, 				/* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,		/* xmlSecTransformUsage	usage; */

    xmlSecTransformXPathInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPathNodeRead,		/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,					/* xmlSecTransformPushBinMethod pushBin; */
    NULL,					/* xmlSecTransformPopBinMethod popBin; */
    xmlSecTransformDefaultPushXml,		/* xmlSecTransformPushXmlMethod pushXml; */
    xmlSecTransformDefaultPopXml,		/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecTransformXPathExecute,		/* xmlSecTransformExecuteMethod execute; */
    
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecTransformXPathGetKlass:
 *
 * The XPath transform evaluates given XPath expression and 
 * intersects the result with the previous nodes set. See 
 * http://www.w3.org/TR/xmldsig-core/#sec-XPath for more details.
 *
 * Returns XPath transform id.
 */
xmlSecTransformId 
xmlSecTransformXPathGetKlass(void) {
    return(&xmlSecTransformXPathKlass);
}

static const char xpathPattern[] = "(//. | //@* | //namespace::*)[%s]";
static int 
xmlSecTransformXPathNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecPtrListPtr dataList;
    xmlSecXPathDataPtr data;
    xmlNodePtr cur;
    xmlChar* tmp;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPathId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dataList = xmlSecXPathTransformGetDataList(transform);
    xmlSecAssert2(xmlSecPtrListCheckId(dataList, xmlSecXPathDataListId), -1);
    xmlSecAssert2(xmlSecPtrListGetSize(dataList) == 0, -1);

    /* there is only one required node */
    cur = xmlSecGetNextElementNode(node->children);  
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeXPath, xmlSecDSigNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected=%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPath));
	return(-1);
    }
    
    /* read information from the node */
    data = xmlSecXPathDataCreate(xmlSecXPathDataTypeXPath);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecXPathDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecXPathDataNodeRead(data, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecXPathDataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }
        
    /* append it to the list */
    ret = xmlSecPtrListAdd(dataList, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecPtrListAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }
    
    /* create full XPath expression */
    xmlSecAssert2(data->expr != NULL, -1);
    tmp = (xmlChar*) xmlMalloc(sizeof(xmlChar) * (xmlStrlen(data->expr) + 
						  strlen(xpathPattern) + 1));
    if(tmp == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d",
		    xmlStrlen(data->expr) + strlen(xpathPattern) + 1);
    	return(-1);
    }
    sprintf((char*)tmp, xpathPattern, (char*)data->expr);	
    xmlFree(data->expr);
    data->expr = tmp;

    /* set correct node set type and operation */
    data->nodeSetOp 	= xmlSecNodeSetIntersection;
    data->nodeSetType 	= xmlSecNodeSetNormal;
    
    /* check that we have nothing else */
    cur = xmlSecGetNextElementNode(cur->next);        
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

/******************************************************************************
 *
 * XPath2 transform
 * 
 *****************************************************************************/
static int 		xmlSecTransformXPath2NodeRead	(xmlSecTransformPtr transform,
							 xmlNodePtr node,
							 xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecTransformXPath2Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecXPathTransformSize,			/* xmlSecSize objSize */

    xmlSecNameXPath2,				/* const xmlChar* name; */
    xmlSecXPath2Ns, 				/* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,		/* xmlSecTransformUsage	usage; */

    xmlSecTransformXPathInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPath2NodeRead,		/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,					/* xmlSecTransformPushBinMethod pushBin; */
    NULL,					/* xmlSecTransformPopBinMethod popBin; */
    xmlSecTransformDefaultPushXml,		/* xmlSecTransformPushXmlMethod pushXml; */
    xmlSecTransformDefaultPopXml,		/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecTransformXPathExecute,		/* xmlSecTransformExecuteMethod execute; */

    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecTransformXPath2GetKlass:
 * 
 * The XPath2 transform (http://www.w3.org/TR/xmldsig-filter2/).
 *
 * Returns XPath2 transform klass.
 */
xmlSecTransformId 
xmlSecTransformXPath2GetKlass(void) {
    return(&xmlSecTransformXPath2Klass);
}

static int 
xmlSecTransformXPath2NodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecPtrListPtr dataList;
    xmlSecXPathDataPtr data;
    xmlNodePtr cur;
    xmlChar* op;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPath2Id), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dataList = xmlSecXPathTransformGetDataList(transform);
    xmlSecAssert2(xmlSecPtrListCheckId(dataList, xmlSecXPathDataListId), -1);
    xmlSecAssert2(xmlSecPtrListGetSize(dataList) == 0, -1);
    
    /* There are only xpath nodes */
    cur = xmlSecGetNextElementNode(node->children);  
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeXPath2, xmlSecXPath2Ns)) {
        /* read information from the node */
	data = xmlSecXPathDataCreate(xmlSecXPathDataTypeXPath2);
	if(data == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecXPathDataCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}

        ret = xmlSecXPathDataNodeRead(data, cur);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			"xmlSecXPathDataNodeRead",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecXPathDataDestroy(data);
	    return(-1);
	}
    
        /* append it to the list */
	ret = xmlSecPtrListAdd(dataList, data);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		        "xmlSecPtrListAdd",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecXPathDataDestroy(data);
	    return(-1);
	}

	/* set correct node set type and operation */
	data->nodeSetType = xmlSecNodeSetTree;
	op = xmlGetProp(cur, xmlSecAttrFilter);
	if(op == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			xmlSecErrorsSafeString(xmlSecAttrFilter),
			XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeGetName(cur)));
	    return(-1);
	}
        if(xmlStrEqual(op, xmlSecXPath2FilterIntersect)) {
    	    data->nodeSetOp = xmlSecNodeSetIntersection;
	} else if(xmlStrEqual(op, xmlSecXPath2FilterSubtract)) {
	    data->nodeSetOp = xmlSecNodeSetSubtraction;
	} else if(xmlStrEqual(op, xmlSecXPath2FilterUnion)) {
	    data->nodeSetOp = xmlSecNodeSetUnion;
	} else {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
			xmlSecErrorsSafeString(xmlSecAttrFilter),
			XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
			"filter=%s", 
			xmlSecErrorsSafeString(op));
	    xmlFree(op);
	    return(-1);
	}
	xmlFree(op);

        cur = xmlSecGetNextElementNode(cur->next);  
    }

    /* check that we have nothing else */
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

/******************************************************************************
 *
 * XPointer transform
 * 
 *****************************************************************************/
static int 		xmlSecTransformXPointerNodeRead	(xmlSecTransformPtr transform,
							 xmlNodePtr node,
							 xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecTransformXPointerKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),		/* xmlSecSize klassSize */
    xmlSecXPathTransformSize,			/* xmlSecSize objSize */

    xmlSecNameXPointer,				/* const xmlChar* name; */
    xmlSecXPointerNs, 				/* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,		/* xmlSecTransformUsage	usage; */

    xmlSecTransformXPathInitialize,		/* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,		/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPointerNodeRead,		/* xmlSecTransformNodeReadMethod readNode; */
    NULL,					/* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,					/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,					/* xmlSecTransformSetKeyMethod setKey; */
    NULL,					/* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,		/* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,					/* xmlSecTransformPushBinMethod pushBin; */
    NULL,					/* xmlSecTransformPopBinMethod popBin; */
    xmlSecTransformDefaultPushXml,		/* xmlSecTransformPushXmlMethod pushXml; */
    xmlSecTransformDefaultPopXml,		/* xmlSecTransformPopXmlMethod popXml; */
    xmlSecTransformXPathExecute,		/* xmlSecTransformExecuteMethod execute; */

    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecTransformXPointerGetKlass:
 * 
 * The XPointer transform klass 
 * (http://www.ietf.org/internet-drafts/draft-eastlake-xmldsig-uri-02.txt).
 *
 * Returns XPointer transform klass.
 */
xmlSecTransformId 
xmlSecTransformXPointerGetKlass(void) {
    return(&xmlSecTransformXPointerKlass);
}

/**
 * xmlSecTransformXPointerSetExpr: 
 * @transform:		the pointer to XPointer transform.
 * @expr:		the XPointer expression.
 * @nodeSetType:	the type of evaluated XPointer expression.
 * @hereNode:		the pointer to "here" node.
 *
 * Sets the XPointer expression for an XPointer @transform.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecTransformXPointerSetExpr(xmlSecTransformPtr transform, const xmlChar* expr, 
			    xmlSecNodeSetType  nodeSetType, xmlNodePtr hereNode) {
    xmlSecPtrListPtr dataList;
    xmlSecXPathDataPtr data;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPointerId), -1);
    xmlSecAssert2(transform->hereNode == NULL, -1);
    xmlSecAssert2(expr != NULL, -1);
    xmlSecAssert2(hereNode != NULL, -1);    

    transform->hereNode = hereNode;
    
    dataList = xmlSecXPathTransformGetDataList(transform);
    xmlSecAssert2(xmlSecPtrListCheckId(dataList, xmlSecXPathDataListId), -1);
    xmlSecAssert2(xmlSecPtrListGetSize(dataList) == 0, -1);

    data = xmlSecXPathDataCreate(xmlSecXPathDataTypeXPointer);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecXPathDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    ret = xmlSecXPathDataSetExpr(data, expr);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecXPathDataSetExpr",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }
    
    /* append it to the list */
    ret = xmlSecPtrListAdd(dataList, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecPtrListAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }

    /* set correct node set type and operation */
    data->nodeSetOp 	= xmlSecNodeSetIntersection;
    data->nodeSetType 	= nodeSetType;
    
    return(0);
}

static int 
xmlSecTransformXPointerNodeRead(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecPtrListPtr dataList;
    xmlSecXPathDataPtr data;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformXPointerId), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    dataList = xmlSecXPathTransformGetDataList(transform);
    xmlSecAssert2(xmlSecPtrListCheckId(dataList, xmlSecXPathDataListId), -1);
    xmlSecAssert2(xmlSecPtrListGetSize(dataList) == 0, -1);

    /* there is only one required node */
    cur = xmlSecGetNextElementNode(node->children);  
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeXPointer, xmlSecXPointerNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected=%s",
		    xmlSecErrorsSafeString(xmlSecNodeXPath));
	return(-1);
    }
    
    /* read information from the node */
    data = xmlSecXPathDataCreate(xmlSecXPathDataTypeXPointer);
    if(data == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecXPathDataCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    ret = xmlSecXPathDataNodeRead(data, cur);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecXPathDataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }
    
    /* append it to the list */
    ret = xmlSecPtrListAdd(dataList, data);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecPtrListAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecXPathDataDestroy(data);
	return(-1);
    }

    /* set correct node set type and operation */
    data->nodeSetOp 	= xmlSecNodeSetIntersection;
    data->nodeSetType 	= xmlSecNodeSetTree;
    
    /* check that we have nothing else */
    cur = xmlSecGetNextElementNode(cur->next);        
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_UNEXPECTED_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

