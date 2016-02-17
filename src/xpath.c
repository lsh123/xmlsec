/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * XPath transform
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xpointer.h>
#include <libxml/c14n.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/list.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>


/**************************************************************************
 *
 * xmlSecXPathHereFunction:
 * @ctxt:               the ponter to XPath context.
 * @nargs:              the arguments nubmer.
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
typedef struct _xmlSecXPathData                 xmlSecXPathData,
                                                *xmlSecXPathDataPtr;
typedef enum {
    xmlSecXPathDataTypeXPath,
    xmlSecXPathDataTypeXPath2,
    xmlSecXPathDataTypeXPointer
} xmlSecXPathDataType;

struct _xmlSecXPathData {
    xmlSecXPathDataType                 type;
    xmlXPathContextPtr                  ctx;
    xmlChar*                            expr;
    xmlSecNodeSetOp                     nodeSetOp;
    xmlSecNodeSetType                   nodeSetType;
};

static xmlSecXPathDataPtr       xmlSecXPathDataCreate           (xmlSecXPathDataType type);
static void                     xmlSecXPathDataDestroy          (xmlSecXPathDataPtr data);
static int                      xmlSecXPathDataSetExpr          (xmlSecXPathDataPtr data,
                                                                 const xmlChar* expr);
static int                      xmlSecXPathDataRegisterNamespaces(xmlSecXPathDataPtr data,
                                                                 xmlNodePtr node);
static int                      xmlSecXPathDataNodeRead         (xmlSecXPathDataPtr data,
                                                                 xmlNodePtr node);
static xmlSecNodeSetPtr         xmlSecXPathDataExecute          (xmlSecXPathDataPtr data,
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
                    (int)sizeof(xmlSecXPathData));
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
xmlSecXPathDataRegisterNamespaces(xmlSecXPathDataPtr data, xmlNodePtr node) {
    xmlNodePtr cur;
    xmlNsPtr ns;
    int ret;

    xmlSecAssert2(data != NULL, -1);
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

    return(0);
}

static int
xmlSecXPathDataNodeRead(xmlSecXPathDataPtr data, xmlNodePtr node) {
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(data->expr == NULL, -1);
    xmlSecAssert2(data->ctx != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    ret = xmlSecXPathDataRegisterNamespaces (data, node);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecXPathDataRegisterNamespaces",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
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

    /* sometime LibXML2 returns an empty nodeset or just NULL, we want
    to reserve NULL for our own purposes so we simply create an empty
    node set here */
    if(xpathObj->nodesetval == NULL) {
    	xpathObj->nodesetval = xmlXPathNodeSetCreate(NULL);
    	if(xpathObj->nodesetval == NULL) {
    		xmlXPathFreeObject(xpathObj);
    		xmlSecError(XMLSEC_ERRORS_HERE,
        				NULL,
                        "xmlXPathNodeSetCreate",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        "expr=%s",
                        xmlSecErrorsSafeString(data->expr));
    		return(NULL);
    	}
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
#define xmlSecXPathDataListId   \
        xmlSecXPathDataListGetKlass()
static xmlSecPtrListId  xmlSecXPathDataListGetKlass             (void);
static xmlSecNodeSetPtr xmlSecXPathDataListExecute              (xmlSecPtrListPtr dataList,
                                                                 xmlDocPtr doc,
                                                                 xmlNodePtr hereNode,
                                                                 xmlSecNodeSetPtr nodes);

static xmlSecPtrListKlass xmlSecXPathDataListKlass = {
    BAD_CAST "xpath-data-list",
    NULL,                                               /* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecXPathDataDestroy, /* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,                                               /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,                                               /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
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
#define xmlSecXPathTransformSize        \
    (sizeof(xmlSecTransform) + sizeof(xmlSecPtrList))
#define xmlSecXPathTransformGetDataList(transform) \
    ((xmlSecTransformCheckSize((transform), xmlSecXPathTransformSize)) ? \
        (xmlSecPtrListPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)) : \
        (xmlSecPtrListPtr)NULL)
#define xmlSecTransformXPathCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecTransformXPathId) || \
     xmlSecTransformCheckId((transform), xmlSecTransformXPath2Id) || \
     xmlSecTransformCheckId((transform), xmlSecTransformXPointerId))

static int              xmlSecTransformXPathInitialize  (xmlSecTransformPtr transform);
static void             xmlSecTransformXPathFinalize    (xmlSecTransformPtr transform);
static int              xmlSecTransformXPathExecute     (xmlSecTransformPtr transform,
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
static int              xmlSecTransformXPathNodeRead    (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecTransformXPathKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecXPathTransformSize,                   /* xmlSecSize objSize */

    xmlSecNameXPath,                            /* const xmlChar* name; */
    xmlSecXPathNs,                              /* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,          /* xmlSecTransformUsage usage; */

    xmlSecTransformXPathInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPathNodeRead,               /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,                                       /* xmlSecTransformPushBinMethod pushBin; */
    NULL,                                       /* xmlSecTransformPopBinMethod popBin; */
    xmlSecTransformDefaultPushXml,              /* xmlSecTransformPushXmlMethod pushXml; */
    xmlSecTransformDefaultPopXml,               /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecTransformXPathExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecTransformXPathGetKlass:
 *
 * The XPath transform evaluates given XPath expression and
 * intersects the result with the previous nodes set. See
 * http://www.w3.org/TR/xmldsig-core/#sec-XPath for more details.
 *
 * Returns: XPath transform id.
 */
xmlSecTransformId
xmlSecTransformXPathGetKlass(void) {
    return(&xmlSecTransformXPathKlass);
}

static const char xpathPattern[] = "(//. | //@* | //namespace::*)[boolean(%s)]";
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
                    (int)(xmlStrlen(data->expr) + strlen(xpathPattern) + 1));
        return(-1);
    }
    sprintf((char*)tmp, xpathPattern, (char*)data->expr);
    xmlFree(data->expr);
    data->expr = tmp;

    /* set correct node set type and operation */
    data->nodeSetOp     = xmlSecNodeSetIntersection;
    data->nodeSetType   = xmlSecNodeSetNormal;

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
static int              xmlSecTransformXPath2NodeRead   (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecTransformXPath2Klass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecXPathTransformSize,                   /* xmlSecSize objSize */

    xmlSecNameXPath2,                           /* const xmlChar* name; */
    xmlSecXPath2Ns,                             /* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,          /* xmlSecTransformUsage usage; */

    xmlSecTransformXPathInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPath2NodeRead,              /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,                                       /* xmlSecTransformPushBinMethod pushBin; */
    NULL,                                       /* xmlSecTransformPopBinMethod popBin; */
    xmlSecTransformDefaultPushXml,              /* xmlSecTransformPushXmlMethod pushXml; */
    xmlSecTransformDefaultPopXml,               /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecTransformXPathExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecTransformXPath2GetKlass:
 *
 * The XPath2 transform (http://www.w3.org/TR/xmldsig-filter2/).
 *
 * Returns: XPath2 transform klass.
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
static int              xmlSecTransformXPointerNodeRead (xmlSecTransformPtr transform,
                                                         xmlNodePtr node,
                                                         xmlSecTransformCtxPtr transformCtx);
static xmlSecTransformKlass xmlSecTransformXPointerKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecXPathTransformSize,                   /* xmlSecSize objSize */

    xmlSecNameXPointer,                         /* const xmlChar* name; */
    xmlSecXPointerNs,                           /* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,          /* xmlSecTransformUsage usage; */

    xmlSecTransformXPathInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformXPathFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecTransformXPointerNodeRead,            /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,                                       /* xmlSecTransformPushBinMethod pushBin; */
    NULL,                                       /* xmlSecTransformPopBinMethod popBin; */
    xmlSecTransformDefaultPushXml,              /* xmlSecTransformPushXmlMethod pushXml; */
    xmlSecTransformDefaultPopXml,               /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecTransformXPathExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecTransformXPointerGetKlass:
 *
 * The XPointer transform klass
 * (http://www.ietf.org/internet-drafts/draft-eastlake-xmldsig-uri-02.txt).
 *
 * Returns: XPointer transform klass.
 */
xmlSecTransformId
xmlSecTransformXPointerGetKlass(void) {
    return(&xmlSecTransformXPointerKlass);
}

/**
 * xmlSecTransformXPointerSetExpr:
 * @transform:          the pointer to XPointer transform.
 * @expr:               the XPointer expression.
 * @nodeSetType:        the type of evaluated XPointer expression.
 * @hereNode:           the pointer to "here" node.
 *
 * Sets the XPointer expression for an XPointer @transform.
 *
 * Returns: 0 on success or a negative value if an error occurs.
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

    ret = xmlSecXPathDataRegisterNamespaces(data, hereNode);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecXPathDataRegisterNamespaces",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecXPathDataDestroy(data);
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
    data->nodeSetOp     = xmlSecNodeSetIntersection;
    data->nodeSetType   = nodeSetType;

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
    data->nodeSetOp     = xmlSecNodeSetIntersection;
    data->nodeSetType   = xmlSecNodeSetTree;

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
 * Visa3DHack transform
 *
 *****************************************************************************/
#define xmlSecVisa3DHackTransformSize   \
    (sizeof(xmlSecTransform) + sizeof(xmlChar*))
#define xmlSecVisa3DHackTransformGetIDPtr(transform) \
    ((xmlSecTransformCheckSize((transform), xmlSecVisa3DHackTransformSize)) ? \
        (xmlChar**)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)) : \
        (xmlChar**)NULL)
#define xmlSecTransformVisa3DHackCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecTransformVisa3DHackId))

static int              xmlSecTransformVisa3DHackInitialize     (xmlSecTransformPtr transform);
static void             xmlSecTransformVisa3DHackFinalize       (xmlSecTransformPtr transform);
static int              xmlSecTransformVisa3DHackExecute        (xmlSecTransformPtr transform,
                                                                 int last,
                                                                 xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecTransformVisa3DHackKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecVisa3DHackTransformSize,              /* xmlSecSize objSize */

    BAD_CAST "Visa3DHackTransform",             /* const xmlChar* name; */
    NULL,                                       /* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,          /* xmlSecTransformUsage usage; */

    xmlSecTransformVisa3DHackInitialize,        /* xmlSecTransformInitializeMethod initialize; */
    xmlSecTransformVisa3DHackFinalize,          /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,                                       /* xmlSecTransformPushBinMethod pushBin; */
    NULL,                                       /* xmlSecTransformPopBinMethod popBin; */
    xmlSecTransformDefaultPushXml,              /* xmlSecTransformPushXmlMethod pushXml; */
    xmlSecTransformDefaultPopXml,               /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecTransformVisa3DHackExecute,           /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecTransformVisa3DHackGetKlass:
 *
 * The Visa3DHack transform klass. The only reason why we need this
 * is Visa3D protocol. It doesn't follow XML/XPointer/XMLDSig specs and allows
 * invalid XPointer expressions in the URI attribute. Since we couldn't evaluate
 * such expressions thru XPath/XPointer engine, we need to have this hack here.
 *
 * Returns: Visa3DHack transform klass.
 */
xmlSecTransformId
xmlSecTransformVisa3DHackGetKlass(void) {
    return(&xmlSecTransformVisa3DHackKlass);
}

/**
 * xmlSecTransformVisa3DHackSetID:
 * @transform:          the pointer to Visa3DHack transform.
 * @id:                 the ID value.
 *
 * Sets the ID value for an Visa3DHack @transform.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecTransformVisa3DHackSetID(xmlSecTransformPtr transform, const xmlChar* id) {
    xmlChar** idPtr;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformVisa3DHackId), -1);
    xmlSecAssert2(id != NULL, -1);

    idPtr = xmlSecVisa3DHackTransformGetIDPtr(transform);
    xmlSecAssert2(idPtr != NULL, -1);
    xmlSecAssert2((*idPtr) == NULL, -1);

    (*idPtr) = xmlStrdup(id);
    if((*idPtr) == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlStrdup",
                    XMLSEC_ERRORS_R_MALLOC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static int
xmlSecTransformVisa3DHackInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecTransformVisa3DHackCheckId(transform), -1);

    return(0);
}

static void
xmlSecTransformVisa3DHackFinalize(xmlSecTransformPtr transform) {
    xmlChar** idPtr;

    xmlSecAssert(xmlSecTransformVisa3DHackCheckId(transform));

    idPtr = xmlSecVisa3DHackTransformGetIDPtr(transform);
    xmlSecAssert(idPtr != NULL);

    if((*idPtr) != NULL) {
        xmlFree((*idPtr));
    }
    (*idPtr) = NULL;
}

static int
xmlSecTransformVisa3DHackExecute(xmlSecTransformPtr transform, int last,
                            xmlSecTransformCtxPtr transformCtx) {
    xmlChar** idPtr;
    xmlDocPtr doc;
    xmlAttrPtr attr;
    xmlNodeSetPtr nodeSet;

    xmlSecAssert2(xmlSecTransformVisa3DHackCheckId(transform), -1);
    xmlSecAssert2(transform->outNodes == NULL, -1);
    xmlSecAssert2(last != 0, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    idPtr = xmlSecVisa3DHackTransformGetIDPtr(transform);
    xmlSecAssert2(idPtr != NULL, -1);
    xmlSecAssert2((*idPtr) != NULL, -1);

    doc = (transform->inNodes != NULL) ? transform->inNodes->doc : transform->hereNode->doc;
    xmlSecAssert2(doc != NULL, -1);

    attr = xmlGetID(doc, (*idPtr));
    if((attr == NULL) || (attr->parent == NULL)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlGetID",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "id=\"%s\"",
                    xmlSecErrorsSafeString((*idPtr)));
        return(-1);
    }

    nodeSet = xmlXPathNodeSetCreate(attr->parent);
    if(nodeSet == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlXPathNodeSetCreate",
                    XMLSEC_ERRORS_R_XML_FAILED,
                    "id=\"%s\"",
                    xmlSecErrorsSafeString((*idPtr)));
        return(-1);
    }

    transform->outNodes = xmlSecNodeSetCreate(doc, nodeSet, xmlSecNodeSetTreeWithoutComments);
    if(transform->outNodes == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecNodeSetCreate",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlXPathFreeNodeSet(nodeSet);
        return(-1);
    }
    return(0);
}



/******************************************************************************
 *
 * Relationship transform
 *
 *****************************************************************************/
typedef struct _xmlSecRelationshipCtx           xmlSecRelationshipCtx,
                                                *xmlSecRelationshipCtxPtr;
struct _xmlSecRelationshipCtx {
    xmlSecPtrListPtr                    sourceIdList;
};
#define xmlSecRelationshipSize        \
    (sizeof(xmlSecTransform) + sizeof(xmlSecRelationshipCtx))
#define xmlSecRelationshipGetCtx(transform)        \
    ((xmlSecRelationshipCtxPtr)(((xmlSecByte*)(transform)) + sizeof(xmlSecTransform)))

static int              xmlSecRelationshipInitialize      (xmlSecTransformPtr transform);
static void             xmlSecRelationshipFinalize        (xmlSecTransformPtr transform);
static int              xmlSecTransformRelationshipPopBin (xmlSecTransformPtr transform,
                                                           xmlSecByte* data,
                                                           xmlSecSize maxDataSize,
                                                           xmlSecSize* dataSize,
                                                           xmlSecTransformCtxPtr transformCtx);
static int              xmlSecTransformRelationshipPushXml(xmlSecTransformPtr transform,
                                                           xmlSecNodeSetPtr nodes,
                                                           xmlSecTransformCtxPtr transformCtx);
static int              xmlSecRelationshipReadNode        (xmlSecTransformPtr transform,
                                                           xmlNodePtr node,
                                                           xmlSecTransformCtxPtr transformCtx);

static xmlSecTransformKlass xmlSecRelationshipKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecRelationshipSize,                     /* xmlSecSize objSize */

    xmlSecNameRelationship,                     /* const xmlChar* name; */
    xmlSecHrefRelationship,                     /* const xmlChar* href; */
    xmlSecTransformUsageDSigTransform,          /* xmlSecTransformUsage usage; */

    xmlSecRelationshipInitialize,               /* xmlSecTransformInitializeMethod initialize; */
    xmlSecRelationshipFinalize,                 /* xmlSecTransformFinalizeMethod finalize; */
    xmlSecRelationshipReadNode,                 /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    NULL,                                       /* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,                                       /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    NULL,                                       /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformRelationshipPopBin,          /* xmlSecTransformPopBinMethod popBin; */
    xmlSecTransformRelationshipPushXml,         /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    NULL,                                       /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

xmlSecTransformId
xmlSecTransformRelationshipGetKlass(void) {
    return(&xmlSecRelationshipKlass);
}

static int
xmlSecRelationshipInitialize(xmlSecTransformPtr transform) {
    xmlSecRelationshipCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformRelationshipId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecRelationshipSize), -1);

    ctx = xmlSecRelationshipGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* initialize context */
    memset(ctx, 0, sizeof(xmlSecRelationshipCtx));

    ctx->sourceIdList = xmlSecPtrListCreate(xmlSecStringListId);
    if(ctx->sourceIdList == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecPtrListCreate",
                     XMLSEC_ERRORS_R_XMLSEC_FAILED,
                     XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    return(0);
}

static void
xmlSecRelationshipFinalize(xmlSecTransformPtr transform) {
    xmlSecRelationshipCtxPtr ctx;

    xmlSecAssert(xmlSecTransformCheckId(transform, xmlSecTransformRelationshipId));
    xmlSecAssert(xmlSecTransformCheckSize(transform, xmlSecRelationshipSize));

    ctx = xmlSecRelationshipGetCtx(transform);
    xmlSecAssert(ctx != NULL);

    if(ctx->sourceIdList != NULL) {
       xmlSecPtrListDestroy(ctx->sourceIdList);
    }

    memset(ctx, 0, sizeof(xmlSecRelationshipCtx));
}

static int
xmlSecRelationshipReadNode(xmlSecTransformPtr transform, xmlNodePtr node, xmlSecTransformCtxPtr transformCtx) {
    xmlSecRelationshipCtxPtr ctx;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(xmlSecTransformCheckId(transform, xmlSecTransformRelationshipId), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecRelationshipSize), -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    ctx = xmlSecRelationshipGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    cur = node->children;
    while(cur != NULL) {
        if(xmlSecCheckNodeName(cur, xmlSecNodeRelationshipReference, xmlSecRelationshipReferenceNs)) {
            xmlChar* sourceId;
            xmlChar* tmp;

            sourceId = xmlGetProp(cur, "SourceId");
            if(sourceId == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            "xmlGetProp",
                            xmlSecErrorsSafeString("SourceId"),
                            XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
                            "node=%s",
                            xmlSecErrorsSafeString(xmlSecNodeGetName(node)));
                return(-1);
            }

            tmp = xmlStrdup(sourceId);
            if(tmp == NULL) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlStrdup",
                            XMLSEC_ERRORS_R_STRDUP_FAILED,
                            "len=%d", xmlStrlen(sourceId));
                return(-1);
            }

            ret = xmlSecPtrListAdd(ctx->sourceIdList, tmp);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecPtrListAdd",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                xmlFree(tmp);
                return(-1);
            }
        }

        cur = cur->next;
    }

    return(0);
}

/* Sorts Relationship elements by Id value in lexicographical order. */
static int
xmlSecTransformRelationshipCompare(xmlNodePtr node1, xmlNodePtr node2) {
    xmlChar* id1;
    xmlChar* id2;

    if(node1 == node2) {
        return(0);
    }
    if(node1 == NULL) {
        return(-1);
    }
    if(node2 == NULL) {
        return(1);
    }

    id1 = xmlGetProp(node1, "Id");
    id2 = xmlGetProp(node2, "Id");

    if(id1 == NULL) {
        return(-1);
    }

    if(id2 == NULL) {
        return(1);
    }

    return(xmlStrcmp(id1, id2));
}

static int
xmlSecTransformRelationshipProcessElementNode(xmlSecTransformPtr transform, xmlOutputBufferPtr buf, xmlNodePtr cur);

static int
xmlSecTransformRelationshipProcessNode(xmlSecTransformPtr transform, xmlOutputBufferPtr buf, xmlNodePtr cur) {
    int ret;

    if(xmlSecCheckNodeName(cur, xmlSecNodeRelationship, xmlSecRelationshipsNs)) {
        xmlChar* id = xmlGetProp(cur, "Id");
        if(id == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlGetProp",
                        XMLSEC_ERRORS_R_XML_FAILED,
                        "name=Id");
            return(-1);
        }

        int i;
        int found = -1;
        xmlSecRelationshipCtxPtr ctx;

        ctx = xmlSecRelationshipGetCtx(transform);
        for(i = 0; i < xmlSecPtrListGetSize(ctx->sourceIdList); ++i) {
            if(xmlStrcmp(xmlSecPtrListGetItem(ctx->sourceIdList, i), id) == 0) {
                found = 1;
                break;
            }
        }

        if(found < 0) {
            return(0);
        }
    }

    ret = xmlSecTransformRelationshipProcessElementNode(transform, buf, cur);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlSecTransformRelationshipProcessElementNode",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static int
xmlSecTransformRelationshipProcessNodeList(xmlSecTransformPtr transform, xmlOutputBufferPtr buf, xmlNodePtr cur) {
    xmlListPtr list;
    int ret;

    list = xmlListCreate(NULL, (xmlListDataCompare)xmlSecTransformRelationshipCompare);
    if(list == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlListCreate",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    for(; cur; cur = cur->next) {
        if(xmlStrcmp(cur->name, xmlSecNodeRelationship) == 0) {
            if(xmlListInsert(list, cur) != 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlListInsert",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        } else {
            ret = xmlSecTransformRelationshipProcessNode(transform, buf, cur);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecTransformRelationshipProcessNode",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                xmlListDelete(list);
                return(-1);
            }
        }
    }

    if(!xmlListEmpty(list)) {
        int size;
        int i;

        xmlListSort(list);
        size = xmlListSize(list);
        for(i = 0; i < size; ++i) {
            xmlLinkPtr link = xmlListFront(list);
            xmlNodePtr node = (xmlNodePtr)xmlLinkGetData(link);

            ret = xmlSecTransformRelationshipProcessNode(transform, buf, node);
            if(ret < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecTransformRelationshipProcessNode",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                xmlListDelete(list);
                return(-1);
            }

            xmlListPopFront(list);
        }
    }

    xmlListDelete(list);
    return(0);
}

static int
xmlSecTransformRelationshipProcessElementNode(xmlSecTransformPtr transform, xmlOutputBufferPtr buf, xmlNodePtr cur) {
    xmlAttrPtr attr;
    int foundTargetMode = 0;

    if(xmlOutputBufferWriteString(buf, "<") < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlOutputBufferWriteString",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    if(xmlOutputBufferWriteString(buf, (const char *)cur->name) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlOutputBufferWriteString",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    if(cur->nsDef != NULL) {
        if(xmlOutputBufferWriteString(buf, " xmlns=\"") < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlOutputBufferWriteString",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        if(cur->nsDef->href != NULL) {
            if(xmlOutputBufferWriteString(buf, cur->nsDef->href) < 0) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlOutputBufferWriteString",
                            XMLSEC_ERRORS_R_XMLSEC_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        }
        if(xmlOutputBufferWriteString(buf, "\"") < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlOutputBufferWriteString",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    for(attr = cur->properties; attr; attr = attr->next) {
        if(xmlOutputBufferWriteString(buf, " ") < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlOutputBufferWriteString",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        if(xmlOutputBufferWriteString(buf, (const char *)attr->name) < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlOutputBufferWriteString",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        if(xmlStrcmp(attr->name, "TargetMode") == 0) {
            foundTargetMode = 1;
        }
        if(xmlOutputBufferWriteString(buf, "=\"") < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlOutputBufferWriteString",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        if(xmlOutputBufferWriteString(buf, (const char *)xmlGetProp(cur, attr->name)) < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlOutputBufferWriteString",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        if(xmlOutputBufferWriteString(buf, "\"") < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlOutputBufferWriteString",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    if(xmlStrcmp(cur->name, xmlSecNodeRelationship) == 0 && !foundTargetMode) {
        if(xmlOutputBufferWriteString(buf, " TargetMode=\"Internal\"") < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlOutputBufferWriteString",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    if(xmlOutputBufferWriteString(buf, ">") < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlOutputBufferWriteString",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    if(cur->children != NULL) {
        int ret = xmlSecTransformRelationshipProcessNodeList(transform, buf, cur->children);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecTransformRelationshipProcessNodeList",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    if(xmlOutputBufferWriteString(buf, "</") < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlOutputBufferWriteString",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    if(xmlOutputBufferWriteString(buf, (const char *)cur->name) < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlOutputBufferWriteString",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    if(xmlOutputBufferWriteString(buf, ">") < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    "xmlOutputBufferWriteString",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

static int
xmlSecTransformRelationshipExecute(xmlSecTransformPtr transform, xmlOutputBufferPtr buf, xmlDocPtr doc) {
    if(doc->children != NULL) {
        int ret = xmlSecTransformRelationshipProcessNodeList(transform, buf, doc->children);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        "xmlSecTransformRelationshipProcessNodeList",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    return(0);
}

static int
xmlSecTransformRelationshipPushXml(xmlSecTransformPtr transform, xmlSecNodeSetPtr nodes, xmlSecTransformCtxPtr transformCtx)
{
    xmlOutputBufferPtr buf;
    xmlSecRelationshipCtxPtr ctx;
    int ret;

    xmlSecAssert2(nodes != NULL, -1);
    xmlSecAssert2(nodes->doc != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ctx = xmlSecRelationshipGetCtx(transform);
    xmlSecAssert2(ctx != NULL, -1);

    /* check/update current transform status */
    switch(transform->status) {
    case xmlSecTransformStatusNone:
       transform->status = xmlSecTransformStatusWorking;
       break;
    case xmlSecTransformStatusWorking:
    case xmlSecTransformStatusFinished:
       return(0);
    default:
       xmlSecError(XMLSEC_ERRORS_HERE,
                   xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                   NULL,
                   XMLSEC_ERRORS_R_INVALID_STATUS,
                   "status=%d", transform->status);
       return(-1);
    }
    xmlSecAssert2(transform->status == xmlSecTransformStatusWorking, -1);

    /* prepare output buffer: next transform or ourselves */
    if(transform->next != NULL) {
       buf = xmlSecTransformCreateOutputBuffer(transform->next, transformCtx);
       if(buf == NULL) {
           xmlSecError(XMLSEC_ERRORS_HERE,
                       xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                       "xmlSecTransformCreateOutputBuffer",
                       XMLSEC_ERRORS_R_XMLSEC_FAILED,
                       XMLSEC_ERRORS_NO_MESSAGE);
           return(-1);
       }
    } else {
       buf = xmlSecBufferCreateOutputBuffer(&(transform->outBuf));
       if(buf == NULL) {
           xmlSecError(XMLSEC_ERRORS_HERE,
                       xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                       "xmlSecBufferCreateOutputBuffer",
                       XMLSEC_ERRORS_R_XMLSEC_FAILED,
                       XMLSEC_ERRORS_NO_MESSAGE);
           return(-1);
       }
    }

    ret = xmlSecTransformRelationshipExecute(transform, buf, nodes->doc);
    if(ret < 0) {
       xmlSecError(XMLSEC_ERRORS_HERE,
                   xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                   "xmlC14NExecute",
                   XMLSEC_ERRORS_R_XMLSEC_FAILED,
                   XMLSEC_ERRORS_NO_MESSAGE);
       xmlOutputBufferClose(buf);
       return(-1);
    }

    ret = xmlOutputBufferClose(buf);
    if(ret < 0) {
       xmlSecError(XMLSEC_ERRORS_HERE,
                   xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                   "xmlOutputBufferClose",
                   XMLSEC_ERRORS_R_XML_FAILED,
                   XMLSEC_ERRORS_NO_MESSAGE);
       return(-1);
    }
    transform->status = xmlSecTransformStatusFinished;
    return(0);
}

static int
xmlSecTransformRelationshipPopBin(xmlSecTransformPtr transform, xmlSecByte* data, xmlSecSize maxDataSize, xmlSecSize* dataSize, xmlSecTransformCtxPtr transformCtx) {
    xmlSecBufferPtr out;
    int ret;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    out = &(transform->outBuf);
    if(transform->status == xmlSecTransformStatusNone) {
       xmlOutputBufferPtr buf;

       xmlSecAssert2(transform->inNodes == NULL, -1);

       if(transform->prev == NULL) {
           (*dataSize) = 0;
           transform->status = xmlSecTransformStatusFinished;
           return(0);
       }

       /* get xml data from previous transform */
       ret = xmlSecTransformPopXml(transform->prev, &(transform->inNodes), transformCtx);
       if(ret < 0) {
           xmlSecError(XMLSEC_ERRORS_HERE,
                       xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                       "xmlSecTransformPopXml",
                       XMLSEC_ERRORS_R_XMLSEC_FAILED,
                       XMLSEC_ERRORS_NO_MESSAGE);
           return(-1);
       }

       /* dump everything to internal buffer */
       buf = xmlSecBufferCreateOutputBuffer(out);
       if(buf == NULL) {
           xmlSecError(XMLSEC_ERRORS_HERE,
                       xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                       "xmlSecBufferCreateOutputBuffer",
                       XMLSEC_ERRORS_R_XMLSEC_FAILED,
                       XMLSEC_ERRORS_NO_MESSAGE);
           return(-1);
       }

       ret = xmlC14NExecute(transform->inNodes->doc, (xmlC14NIsVisibleCallback)xmlSecNodeSetContains, transform->inNodes, XML_C14N_1_0, NULL, 0, buf);
       if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                       xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                       "xmlSecTransformC14NExecute",
                       XMLSEC_ERRORS_R_XMLSEC_FAILED,
                       XMLSEC_ERRORS_NO_MESSAGE);
           xmlOutputBufferClose(buf);
           return(-1);
       }

       ret = xmlOutputBufferClose(buf);
       if(ret < 0) {
           xmlSecError(XMLSEC_ERRORS_HERE,
                       xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                       "xmlOutputBufferClose",
                       XMLSEC_ERRORS_R_XML_FAILED,
                       XMLSEC_ERRORS_NO_MESSAGE);
           return(-1);
       }
       transform->status = xmlSecTransformStatusWorking;
    }

    if(transform->status == xmlSecTransformStatusWorking) {
       xmlSecSize outSize;

       /* return chunk after chunk */
       outSize = xmlSecBufferGetSize(out);
       if(outSize > maxDataSize) {
           outSize = maxDataSize;
       }
       if(outSize > XMLSEC_TRANSFORM_BINARY_CHUNK) {
           outSize = XMLSEC_TRANSFORM_BINARY_CHUNK;
       }
       if(outSize > 0) {
           xmlSecAssert2(xmlSecBufferGetData(&(transform->outBuf)), -1);

           memcpy(data, xmlSecBufferGetData(&(transform->outBuf)), outSize);
           ret = xmlSecBufferRemoveHead(&(transform->outBuf), outSize);
           if(ret < 0) {
               xmlSecError(XMLSEC_ERRORS_HERE,
                           xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                           "xmlSecBufferRemoveHead",
                           XMLSEC_ERRORS_R_XMLSEC_FAILED,
                           "size=%d", outSize);
               return(-1);
           }
       } else if(xmlSecBufferGetSize(out) == 0) {
           transform->status = xmlSecTransformStatusFinished;
       }
       (*dataSize) = outSize;
    } else if(transform->status == xmlSecTransformStatusFinished) {
       /* the only way we can get here is if there is no output */
       xmlSecAssert2(xmlSecBufferGetSize(out) == 0, -1);
       (*dataSize) = 0;
    } else {
       xmlSecError(XMLSEC_ERRORS_HERE,
                   xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                   NULL,
                   XMLSEC_ERRORS_R_INVALID_STATUS,
                   "status=%d", transform->status);
       return(-1);
    }

    return(0);
}
