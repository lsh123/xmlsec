/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Relationship transform
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
#include <libxml/xpointer.h>
#include <libxml/c14n.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/list.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>


/******************************************************************************
 *
 * Relationship transform
 *
 * http://standards.iso.org/ittf/PubliclyAvailableStandards/c061796_ISO_IEC_29500-2_2012.zip
 *
 * 13.2.4.24 Relationships Transform Algorithm
 *
 * The relationships transform takes the XML document from the Relationships part and converts
 * it to another XML document.
 *
 * The package implementer might create relationships XML that contains content from several namespaces,
 * along with versioning instructions as defined in Part 3, “Markup Compatibility and Extensibility”. [O6.11]
 *
 * The relationships transform algorithm is as follows:
 *
 * Step 1: Process versioning instructions
 *   1. The package implementer shall process the versioning instructions, considering that the only
 *   known namespace is the Relationships namespace.
 *   2. The package implementer shall remove all ignorable content, ignoring preservation attributes.
 *   3. The package implementer shall remove all versioning instructions.
 *
 * Step 2: Sort and filter relationships
 *   1. The package implementer shall remove all namespace declarations except the Relationships
 *   namespace declaration.
 *   2. The package implementer shall remove the Relationships namespace prefix, if it is present.
 *   3. The package implementer shall sort relationship elements by Id value in lexicographical
 *   order, considering Id values as case-sensitive Unicode strings.
 *   4. The package implementer shall remove all Relationship elements that do not have either an Id
 *   value that matches any SourceId value or a Type value that matches any SourceType value, among
 *   the SourceId and SourceType values specified in the transform definition. Producers and consumers
 *   shall compare values as case-sensitive Unicode strings. [M6.27] The resulting XML document holds
 *   all Relationship elements that either have an Id value that matches a SourceId value or a Type value
 *   that matches a SourceType value specified in the transform definition.
 *
 * Step 3: Prepare for canonicalization
 *   1. The package implementer shall remove all characters between the Relationships start tag and
 *   the first Relationship start tag.
 *   2. The package implementer shall remove any contents of the Relationship element.
 *   3. The package implementer shall remove all characters between the last Relationship end tag and
 *   the Relationships end tag.
 *   4. If there are no Relationship elements, the package implementer shall remove all characters
 *   between the Relationships start tag and the Relationships end tag.
 *   5. The package implementer shall remove comments from the Relationships XML content.
 *   6. The package implementer shall add a TargetMode attribute with its default value, if this
 *   optional attribute is missing from the Relationship element.
 *   7. The package implementer can generate Relationship elements as start-tag/end-tag pairs with
 *   empty content, or as empty elements. A canonicalization transform, applied immediately after the
 *   Relationships Transform, converts all XML elements into start-tag/end-tag pairs.
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
