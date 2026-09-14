/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef XMLSEC_NODESET_H
#define XMLSEC_NODESET_H

/**
 * @defgroup xmlsec_core_nodeset XML Node Sets
 * @ingroup xmlsec_core
 * @brief XML node-set implementation used during transformations.
 * @{
 */

#include <stdio.h>

#include <libxml/tree.h>
#include <libxml/xmlIO.h>
#include <libxml/xpath.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _xmlSecNodeSet   xmlSecNodeSet, *xmlSecNodeSetPtr;

/**
 * @brief The basic node set types.
 */
typedef enum {
    xmlSecNodeSetNormal = 0,  /**< node set = nodes in the list. */
    xmlSecNodeSetInvert,  /**< node set = all document nodes minus nodes in the list. */
    xmlSecNodeSetTree,  /**< node set = nodes in the list and all their subtrees. */
    xmlSecNodeSetTreeWithoutComments,  /**< node set = nodes in the list and all their subtrees but no comment nodes. */
    xmlSecNodeSetTreeInvert,  /**< node set = all document nodes minus nodes in the list and all their subtrees. */
    xmlSecNodeSetTreeWithoutCommentsInvert,  /**< node set = all document nodes minus (nodes in the list and all their subtrees plus all comment nodes). */
    xmlSecNodeSetList  /**< DEPRECATED: node set = all nodes in the children list of node sets. */
} xmlSecNodeSetType;

/**
 * @brief The simple node set operations.
 */
typedef enum {
    xmlSecNodeSetIntersection = 0,  /**< intersection. */
    xmlSecNodeSetSubtraction,  /**< subtraction. */
    xmlSecNodeSetUnion  /**< union. */
} xmlSecNodeSetOp;

/**
 * @brief The enhanced node set.
 * @details The node set adopts the node list and the document passed to
 * #xmlSecNodeSetCreate: the caller must not free them. Node sets are linked
 * into a chain via #next and #prev; #xmlSecNodeSetDestroy destroys the entire
 * chain, frees each member's node list and, if #xmlSecNodeSetDocDestroy was
 * called, frees the document. Destroying a member that is also reachable
 * through a second pointer double-frees the chain.
 */
struct _xmlSecNodeSet {
    xmlNodeSetPtr       nodes;  /**< the nodes list (adopted from the caller; NULL means the whole document). */
    xmlDocPtr           doc;  /**< the parent XML document (adopted from the caller). */
    int                 destroyDoc;  /**< the flag: if set to 1 then @p doc will be destroyed when node set is destroyed. */
    xmlSecNodeSetType   type;  /**< the node set type. */
    xmlSecNodeSetOp     op;  /**< the operation type. */
    xmlSecNodeSetPtr    next;  /**< the next node set. */
    xmlSecNodeSetPtr    prev;  /**< the previous node set. */
    void*               reserved;  /**< the reserved pointer. DEPRECATED: the children list (valid only if type is equal to #xmlSecNodeSetList). */
};

/**
 * @brief Node walk callback, called once per node in the node set.
 * @details The callback function called once per node in the node set.
 * @param nset the pointer to xmlSecNodeSet structure.
 * @param cur the pointer to the current XML node.
 * @param parent the pointer to the parent node of @p cur.
 * @param data the pointer to application specific data.
 * @return a non-negative value to continue the walk, or a negative value
 * if the walk procedure should be interrupted.
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

XMLSEC_EXPORT XMLSEC_DEPRECATED xmlSecNodeSetPtr  xmlSecNodeSetAddList(xmlSecNodeSetPtr nset,
                                                          xmlSecNodeSetPtr newNSet,
                                                          xmlSecNodeSetOp op);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /* xmlsec_core_nodeset */

#endif /* XMLSEC_NODESET_H */
