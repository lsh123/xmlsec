/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_NODESET_H__
#define __XMLSEC_NODESET_H__

/**
 * @defgroup xmlsec_core_nodeset XML Node Sets
 * @ingroup xmlsec_core
 * @brief XML node-set implementation used during transformations.
 * @{
 */

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _xmlSecNodeSet   xmlSecNodeSet, *xmlSecNodeSetPtr;

/**
 * @brief The basic nodes sets types.
 */
typedef enum {
    xmlSecNodeSetNormal = 0,  /**< nodes set = nodes in the list. */
    xmlSecNodeSetInvert,  /**< nodes set = all document nodes minus nodes in the list. */
    xmlSecNodeSetTree,  /**< nodes set = nodes in the list and all their subtress. */
    xmlSecNodeSetTreeWithoutComments,  /**< nodes set = nodes in the list and all their subtress but no comment nodes. */
    xmlSecNodeSetTreeInvert,  /**< nodes set = all document nodes minus nodes in the list and all their subtress. */
    xmlSecNodeSetTreeWithoutCommentsInvert,  /**< nodes set = all document nodes minus (nodes in the list and all their subtress plus all comment nodes). */
    xmlSecNodeSetList  /**< nodes set = all nodes in the children list of nodes sets. */
} xmlSecNodeSetType;

/**
 * @brief The simple nodes sets operations.
 */
typedef enum {
    xmlSecNodeSetIntersection = 0,  /**< intersection. */
    xmlSecNodeSetSubtraction,  /**< subtraction. */
    xmlSecNodeSetUnion  /**< union. */
} xmlSecNodeSetOp;

/**
 * @brief The enhanced nodes set.
 */
struct _xmlSecNodeSet {
    xmlNodeSetPtr       nodes;  /**< the nodes list. */
    xmlDocPtr           doc;  /**< the parent XML document. */
    int                 destroyDoc;  /**< the flag: if set to 1 then @p doc will be destroyed when node set is destroyed. */
    xmlSecNodeSetType   type;  /**< the nodes set type. */
    xmlSecNodeSetOp     op;  /**< the operation type. */
    xmlSecNodeSetPtr    next;  /**< the next nodes set. */
    xmlSecNodeSetPtr    prev;  /**< the previous nodes set. */
    xmlSecNodeSetPtr    children;  /**< the children list (valid only if type equal to #xmlSecNodeSetList). */
};

/**
 * @brief Node walk callback, called once per node in the nodes set.
 * @details The callback function called once per each node in the nodes set.
 * @param nset the pointer to xmlSecNodeSet structure.
 * @param cur the pointer current XML node.
 * @param parent the pointer to the @p cur parent node.
 * @param data the pointer to application specific data.
 * @return 0 on success or a negative value if an error occurs
 * an walk procedure should be interrupted.
 */
typedef int (*xmlSecNodeSetWalkCallback)                (xmlSecNodeSetPtr nset,
                                                         xmlNodePtr cur,
                                                         xmlNodePtr parent,
                                                         void* data);

XMLSEC_EXPORT xmlSecNodeSetPtr  xmlSecNodeSetCreate     (xmlDocPtr doc,
                                                         xmlNodeSetPtr nodes,
                                                         xmlSecNodeSetType type);
XMLSEC_EXPORT void              xmlSecNodeSetDestroy    (xmlSecNodeSetPtr nset);
XMLSEC_EXPORT void              xmlSecNodeSetDocDestroy (xmlSecNodeSetPtr nset);
XMLSEC_EXPORT int               xmlSecNodeSetContains   (xmlSecNodeSetPtr nset,
                                                         xmlNodePtr node,
                                                         xmlNodePtr parent);
XMLSEC_EXPORT xmlSecNodeSetPtr  xmlSecNodeSetAdd        (xmlSecNodeSetPtr nset,
                                                         xmlSecNodeSetPtr newNSet,
                                                         xmlSecNodeSetOp op);
XMLSEC_EXPORT xmlSecNodeSetPtr  xmlSecNodeSetAddList    (xmlSecNodeSetPtr nset,
                                                         xmlSecNodeSetPtr newNSet,
                                                         xmlSecNodeSetOp op);
XMLSEC_EXPORT xmlSecNodeSetPtr  xmlSecNodeSetGetChildren(xmlDocPtr doc,
                                                         const xmlNodePtr parent,
                                                         int withComments,
                                                         int invert);
XMLSEC_EXPORT int               xmlSecNodeSetWalk       (xmlSecNodeSetPtr nset,
                                                         xmlSecNodeSetWalkCallback walkFunc,
                                                         void* data);
XMLSEC_EXPORT int               xmlSecNodeSetDumpTextNodes(xmlSecNodeSetPtr nset,
                                                        xmlOutputBufferPtr out);
XMLSEC_EXPORT void              xmlSecNodeSetDebugDump  (xmlSecNodeSetPtr nset,
                                                         FILE *output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_nodeset */

#endif /* __XMLSEC_NODESET_H__ */
