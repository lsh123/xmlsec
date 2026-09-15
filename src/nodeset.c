/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_core_nodeset
 * @brief XML nodes set functions
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include "cast_helpers.h"

#define xmlSecGetParent(node)           \
    (((node)->type != XML_NAMESPACE_DECL) ? \
        (node)->parent : \
        (xmlNodePtr)((xmlNsPtr)(node))->next)


static int      xmlSecNodeSetContainsNode                (xmlSecNodeSetPtr nset,
                                                         xmlNodePtr node,
                                                         xmlNodePtr parent);
static int      xmlSecNodeSetWalkRecursive              (xmlSecNodeSetPtr nset,
                                                         xmlNodePtr startNode,
                                                         xmlSecNodeSetWalkCallback walkFunc,
                                                         void* data);

/**
 * @brief Creates a new nodes set.
 * @details Creates new nodes set. Caller is responsible for freeing returned object
 * by calling #xmlSecNodeSetDestroy function.
 * @param doc the pointer to parent XML document.
 * @param nodes the list of nodes.
 * @param type the nodes set type.
 * @return pointer to newly allocated node set or NULL if an error occurs.
 */
xmlSecNodeSetPtr
xmlSecNodeSetCreate(xmlDocPtr doc, xmlNodeSetPtr nodes, xmlSecNodeSetType type) {
    xmlSecNodeSetPtr nset;

    nset = (xmlSecNodeSetPtr)xmlMalloc(sizeof(xmlSecNodeSet));
    if(nset == NULL) {
        xmlSecMallocError(sizeof(xmlSecNodeSet), NULL);
        return(NULL);
    }
    memset(nset, 0, sizeof(xmlSecNodeSet));

    nset->doc   = doc;
    nset->nodes = nodes;
    nset->type  = type;
    nset->next  = nset->prev = nset;
    return(nset);
}

/**
 * @brief Destroys a nodes set.
 * @details Destroys the nodes set created with #xmlSecNodeSetCreate function.
 * @param nset the pointer to node set.
 */
void
xmlSecNodeSetDestroy(xmlSecNodeSetPtr nset) {
    xmlSecNodeSetPtr tmp;
    xmlDocPtr destroyDoc = NULL;

    xmlSecAssert(nset != NULL);

    while((tmp = nset) != NULL) {
        if((nset->next != NULL) && (nset->next != nset)) {
            nset->next->prev = nset->prev;
            nset->prev->next = nset->next;
            nset = nset->next;
        } else {
            nset = NULL;
        }

        if(tmp->nodes != NULL) {
            xmlXPathFreeNodeSet(tmp->nodes);
        }
        if((tmp->doc != NULL) && (tmp->destroyDoc != 0)) {
            /* all nodesets should belong to the same doc */
            xmlSecAssert((destroyDoc == NULL) || (tmp->doc == destroyDoc));
            destroyDoc = tmp->doc; /* can't destroy here because other node sets can refer to it */
        }
        xmlFree(tmp);
    }

    /* finally, destroy the doc if needed */
    if(destroyDoc != NULL) {
        xmlFreeDoc(destroyDoc);
    }
}

/**
 * @brief Marks node set to destroy the parent document.
 * @details Instructs node set to destroy the node's parent doc when node set is destroyed.
 * @param nset the pointer to node set.
 */
void
xmlSecNodeSetDocDestroy(xmlSecNodeSetPtr nset) {
    xmlSecAssert(nset != NULL);

    nset->destroyDoc = 1;
}

/* checks node against LibXML2 nodeset */
static int
xmlSecNodeSetCheckNode(xmlNodeSetPtr nodes, xmlNodePtr node, xmlNodePtr parent) {
    xmlSecAssert2(node != NULL, 0);

    /* assume whole tree is included if nodes is NULL */
    if(nodes == NULL) {
        return(1);
    }

    if(node->type != XML_NAMESPACE_DECL) {
        return(xmlXPathNodeSetContains(nodes, node));
    } else {
        xmlNsPtr ns;
        xmlNodePtr hostingNode;
        int ii;

        /* the "hosting" element the namespace is in scope on (this is a libxml hack! check xpath.c for details) */
        if((parent != NULL) && (parent->type == XML_ATTRIBUTE_NODE)) {
            hostingNode = parent->parent;
        } else {
            hostingNode = parent;
        }
        if(hostingNode == NULL) {
            return(0);
        }

        /** If the input is an XPath node-set, then the node-set must explicitly
         * contain every node to be rendered to the canonical form.
         */
        /*
         * libxml2 stores namespace nodes in XPath node sets as copies whose
         * ->next field points at the hosting element; match on that plus the
         * prefix. This is done manually (instead of relying on
         * xmlXPathNodeSetContains) because older libxml2 versions compare
         * namespace nodes by pointer only, which would never match.
         */
        for(ii = 0; ii < nodes->nodeNr; ii++) {
            if(nodes->nodeTab[ii]->type != XML_NAMESPACE_DECL) {
                continue;
            }
            ns = (xmlNsPtr)nodes->nodeTab[ii];
            if((ns->next == (xmlNsPtr)hostingNode) &&
               (xmlStrEqual(ns->prefix, ((xmlNsPtr)node)->prefix))) {
                return(1);
            }
        }
        return(0);
    }
}

/* checks node or parents against LibXML2 nodeset */
static int
xmlSecNodeSetCheckNodeOrParent(xmlNodeSetPtr nodes, xmlNodePtr node, xmlNodePtr parent) {
    xmlSecAssert2(node != NULL, 0);

    /* assume whole tree is included if nodes is NULL */
    if(nodes == NULL) {
        return(1);
    }
    do {
        if(xmlSecNodeSetCheckNode(nodes, node, parent)) {
            return(1);
        }

        /* traverse up the tree, only element nodes can have children
         * (we explicitly do not include the doc itself to avoid duplicates) */
        if((parent != NULL) && (parent->type == XML_ELEMENT_NODE)) {
            node = parent;
            parent = parent->parent;
        } else {
            node = NULL;
            parent = NULL;
        }
    } while(node != NULL);

    /* done */
    return(0);
}

/* checks node against THIS nodeset only */
static int
xmlSecNodeSetContainsNode(xmlSecNodeSetPtr nset, xmlNodePtr node, xmlNodePtr parent) {
    xmlSecAssert2(nset != NULL, 0);
    xmlSecAssert2(node != NULL, 0);

    switch(nset->type) {
    case xmlSecNodeSetNormal:
        /* simple case */
        return(xmlSecNodeSetCheckNode(nset->nodes, node, parent));
    case xmlSecNodeSetInvert:
        /* simple case: return inverted result */
        return(!xmlSecNodeSetCheckNode(nset->nodes, node, parent));
    case xmlSecNodeSetTree:
        /* just traverse up the tree to see if any parents are in the nodeset */
        return(xmlSecNodeSetCheckNodeOrParent(nset->nodes, node, parent));
    case xmlSecNodeSetTreeWithoutComments:
        /* drop comments */
        if(node->type == XML_COMMENT_NODE) {
            return(0);
        }
        /* just traverse up the tree to see if any parents are in the nodeset */
        return(xmlSecNodeSetCheckNodeOrParent(nset->nodes, node, parent));
    case xmlSecNodeSetTreeInvert:
        /* just traverse up the tree to see if any parents are in the nodeset and invert result */
        return(!xmlSecNodeSetCheckNodeOrParent(nset->nodes, node, parent));
    case xmlSecNodeSetTreeWithoutCommentsInvert:
        /* drop comments */
        if(node->type == XML_COMMENT_NODE) {
            return(0);
        }
        /* just traverse up the tree to see if any parents are in the nodeset and invert result */
        return(!xmlSecNodeSetCheckNodeOrParent(nset->nodes, node, parent));
    default:
        xmlSecUnsupportedEnumValueError("node set type", nset->type, NULL);
        return(0);
    }
}

/**
 * @brief Checks if a node is in the nodes set.
 * @details Checks whether the @p node is in the nodes set or not.
 * @param nset the pointer to node set.
 * @param node the pointer to XML node to check.
 * @param parent the pointer to @p node parent node.
 * @return 1 if the @p node is in the nodes set @p nset, 0 if it is not
 * or if @p node is NULL, and a negative value if an error occurs.
 */
int
xmlSecNodeSetContains(xmlSecNodeSetPtr nset, xmlNodePtr node, xmlNodePtr parent) {
    int status;
    int first = 1;
    xmlSecNodeSetPtr curNset;

    xmlSecAssert2(node != NULL, 0);

    /* special cases: */
    if(nset == NULL) {
        return(1);
    }

    /* iterate through the nodesets list */
    status = 1;
    curNset = nset;
    do {
        /* the first element defines the base set */
        if(first) {
            status = xmlSecNodeSetContainsNode(curNset, node, parent);
            first = 0;
        } else {
            switch(curNset->op) {
            case xmlSecNodeSetIntersection:
                if(status && !xmlSecNodeSetContainsNode(curNset, node, parent)) {
                    status = 0;
                }
                break;
            case xmlSecNodeSetSubtraction:
                if(status && xmlSecNodeSetContainsNode(curNset, node, parent)) {
                    status = 0;
                }
                break;
            case xmlSecNodeSetUnion:
                if(!status && xmlSecNodeSetContainsNode(curNset, node, parent)) {
                    status = 1;
                }
                break;
            default:
                xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION, NULL,
                    "node set operation=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(curNset->op));
                return(-1);
            }
        }
        curNset = curNset->next;
        xmlSecAssert2(curNset != NULL, -1);
    } while(curNset != nset);

    /* done */
    return(status);
}

/**
 * @brief Adds a nodes set to another with an operation.
 * @details Adds @p newNSet to the @p nset using operation @p op.
 * @param nset the pointer to current nodes set (or NULL).
 * @param newNSet the pointer to new nodes set.
 * @param op the operation type.
 * @return the pointer to combined nodes set or NULL if an error
 * occurs.
 */
xmlSecNodeSetPtr
xmlSecNodeSetAdd(xmlSecNodeSetPtr nset, xmlSecNodeSetPtr newNSet, xmlSecNodeSetOp op) {
    xmlSecAssert2(newNSet != NULL, NULL);
    xmlSecAssert2(newNSet->next == newNSet, NULL);

    newNSet->op = op;
    if(nset == NULL) {
        return(newNSet);
    }

    /* all nodesets should belong to the same doc */
    xmlSecAssert2(nset->doc == newNSet->doc, NULL);

    newNSet->next = nset;
    newNSet->prev = nset->prev;
    nset->prev->next = newNSet;
    nset->prev       = newNSet;
    return(nset);
}

/**
 * @brief DEPRECATED: Adds a nodes set as a child list.
 * @details Adds @p newNSet to the @p nset as child using operation @p op.
 * @param nset the pointer to current nodes set (or NULL).
 * @param newNSet the pointer to new nodes set.
 * @param op the operation type.
 * @return the pointer to combined nodes set or NULL if an error
 * occurs.
 */
xmlSecNodeSetPtr
xmlSecNodeSetAddList(xmlSecNodeSetPtr nset XMLSEC_ATTRIBUTE_UNUSED,
    xmlSecNodeSetPtr newNSet XMLSEC_ATTRIBUTE_UNUSED,
    xmlSecNodeSetOp op XMLSEC_ATTRIBUTE_UNUSED
) {
    XMLSEC_UNREFERENCED(nset);
    XMLSEC_UNREFERENCED(newNSet);
    XMLSEC_UNREFERENCED(op);

    xmlSecNotImplementedError("xmlSecNodeSetAddList is deprecated");
    return(NULL);
}

/* checks if any of the walk roots is a strict ancestor of the node */
static int
xmlSecNodeSetWalkRootIsAncestor(xmlNodeSetPtr roots, xmlNodePtr node) {
    xmlNodePtr cur;

    xmlSecAssert2(roots != NULL, 0);
    xmlSecAssert2(node != NULL, 0);

    for(cur = xmlSecGetParent(node); (cur != NULL) && (cur->type != XML_NAMESPACE_DECL); cur = cur->parent) {
        if(xmlXPathNodeSetContains(roots, cur)) {
            return(1);
        }
    }
    return(0);
}

/*
 * Returns the node list to use as the fast-path walk roots for @p nset, or
 * NULL if the fast path cannot be used.
 *
 * The fast path walks the subtrees rooted at the returned nodes, so it is only
 * valid when every node of the combined set is guaranteed to lie inside those
 * subtrees:
 *   - a single Normal/Tree/TreeWithoutComments set: its own nodes; or
 *
 *   - a combined set whose operations are all intersections: the nodes of the
 *     first member that has a non-NULL node list. The intersection is a subset
 *     of every member, so it is fully covered by that member's subtrees.
 *     Members with a NULL node list (the whole document, e.g. the Normal input
 *     set of a "#fragment" reference) are skipped.
 */
static xmlNodeSetPtr
xmlSecNodeSetGetFastPathNodes(xmlSecNodeSetPtr nset) {
    xmlSecNodeSetPtr cur;
    xmlNodeSetPtr res = NULL;

    xmlSecAssert2(nset != NULL, NULL);

    /* a single set */
    if(nset->next == nset) {
        switch(nset->type) {
        case xmlSecNodeSetNormal:
        case xmlSecNodeSetTree:
        case xmlSecNodeSetTreeWithoutComments:
            return(nset->nodes);
        default:
            return(NULL);
        }
    }

    /* an intersections only list of sets */
    cur = nset;
    do {
        if(cur->op != xmlSecNodeSetIntersection) {
            return(NULL);
        }
        /* use the first member that has a non-NULL node list; a NULL node list
         * represents the whole document and provides no walk roots */
        if((res == NULL) && (cur->nodes != NULL)) {
            switch(cur->type) {
            case xmlSecNodeSetNormal:
            case xmlSecNodeSetTree:
            case xmlSecNodeSetTreeWithoutComments:
                res = cur->nodes;
                break;
            default:
                break;
            }
        }
        cur = cur->next;
    } while(cur != nset);

    /* done */
    return(res);
}

/**
 * @brief Walks all nodes in a set calling a callback function.
 * @details Calls the function @p walkFunc for each node in the nodes set @p nset.
 * Element and attribute nodes are reported once each. Namespace nodes, however,
 * are reported once per descendant element in which they are in scope (the walk
 * revisits the namespace declarations along each element's ancestor chain), so a
 * namespace declared on a common ancestor may be reported more than once.
 * If the @p walkFunc returns a negative value, then the walk procedure
 * is interrupted.
 * @param nset the pointer to node set.
 * @param walkFunc the callback function.
 * @param data the application specific data passed to the @p walkFunc.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecNodeSetWalk(xmlSecNodeSetPtr nset, xmlSecNodeSetWalkCallback walkFunc, void* data) {
    xmlNodeSetPtr fastPathNodes;
    xmlNodePtr cur;
    int ret = 0;

    xmlSecAssert2(nset != NULL, -1);
    xmlSecAssert2(nset->doc != NULL, -1);
    xmlSecAssert2(walkFunc != NULL, -1);


    /* try fast path first if we can iterate through a subset of nodes */
    fastPathNodes = xmlSecNodeSetGetFastPathNodes(nset);
    if(fastPathNodes != NULL) {
        int ii;

        for(ii = 0; (ret >= 0) && (ii < fastPathNodes->nodeNr); ++ii) {
            cur = fastPathNodes->nodeTab[ii];

            /* skip nodes that are covered by an ancestor walk root: that
             * ancestor's walk covers this node's entire subtree, so
             * starting a second walk here would visit the overlapping
             * nodes more than once. For a combined set the walk roots are
             * the first member's nodes, which are not all part of the set,
             * so the check must be against the walk roots rather than the
             * set itself */
            if(xmlSecNodeSetWalkRootIsAncestor(fastPathNodes, cur)) {
                continue;
            }
            ret = xmlSecNodeSetWalkRecursive(nset, cur, walkFunc, data);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNodeSetWalkRecursive", NULL);
                return(ret);
            }
        }
        return(ret);
    }

    /* if we can't do fast path, fall back to the slow path iterating through all doc nodes */
    for(cur = nset->doc->children; (cur != NULL) && (ret >= 0); cur = cur->next) {
        ret = xmlSecNodeSetWalkRecursive(nset, cur, walkFunc, data);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNodeSetWalkRecursive", NULL);
            return(ret);
        }
    }
    return(ret);
}

typedef struct {
    xmlSecNodeSetPtr nset;
    xmlSecNodeSetWalkCallback walkFunc;
    void* data;
} xmlSecNodeSetWalkCtx;

static int
xmlSecNodeSetWalkRecursiveCallback(xmlNodePtr cur, void* data) {
    xmlSecNodeSetWalkCtx* ctx = (xmlSecNodeSetWalkCtx*)data;
    xmlNodePtr parent = xmlSecGetParent(cur);
    int ret;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(ctx->nset != NULL, -1);
    xmlSecAssert2(ctx->walkFunc != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);

    /* the node itself */
    if(xmlSecNodeSetContains(ctx->nset, cur, parent) == 1) {
        ret = ctx->walkFunc(ctx->nset, cur, parent, ctx->data);
        if(ret < 0) {
            return(-1);
        }
    }

    /* element and document nodes have children */
    if((cur->type == XML_ELEMENT_NODE) || (cur->type == XML_DOCUMENT_NODE)) {
        xmlAttrPtr attr;
        xmlNodePtr node;
        xmlNsPtr ns, tmp;

        attr = (xmlAttrPtr)cur->properties;
        while(attr != NULL) {
            if(xmlSecNodeSetContains(ctx->nset, (xmlNodePtr)attr, cur) == 1) {
                ret = ctx->walkFunc(ctx->nset, (xmlNodePtr)attr, cur, ctx->data);
                if(ret < 0) {
                    return(-1);
                }
            }
            attr = attr->next;
        }

        node = cur;
        while(node != NULL) {
            ns = node->nsDef;
            while(ns != NULL) {
                tmp = xmlSearchNs(ctx->nset->doc, cur, ns->prefix);
                if((tmp == ns) && (xmlSecNodeSetContains(ctx->nset, (xmlNodePtr)ns, cur) == 1)) {
                    ret = ctx->walkFunc(ctx->nset, (xmlNodePtr)ns, cur, ctx->data);
                    if(ret < 0) {
                        return(-1);
                    }
                }
                ns = ns->next;
            }
            node = node->parent;
        }
    }

    /* done and continue the walk */
    return(1);
}

static int
xmlSecNodeSetWalkRecursive(xmlSecNodeSetPtr nset, xmlNodePtr startNode, xmlSecNodeSetWalkCallback walkFunc, void* data) {
    xmlSecNodeSetWalkCtx ctx;
    int ret;

    xmlSecAssert2(nset != NULL, -1);
    xmlSecAssert2(startNode != NULL, -1);
    xmlSecAssert2(walkFunc != NULL, -1);

    ctx.nset = nset;
    ctx.walkFunc = walkFunc;
    ctx.data = data;

    ret = xmlSecDepthFirstTreeWalk(startNode, xmlSecNodeSetWalkRecursiveCallback, &ctx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecDepthFirstTreeWalk", NULL);
        return(-1);
    }

    return(0);
}

/**
 * @brief Creates a nodes set from parent subtree children.
 * @details Creates a new nodes set that contains:
 *  - if @p withComments is not 0 and @p invert is 0:
 *    all nodes in the @p parent subtree;
 *  - if @p withComments is 0 and @p invert is 0:
 *    all nodes in the @p parent subtree except comment nodes;
 *  - if @p withComments is not 0 and @p invert is not 0:
 *    all nodes in the @p doc except nodes in the @p parent subtree;
 *  - if @p withComments is 0 and @p invert is not 0:
 *    all nodes in the @p doc except nodes in the @p parent subtree
 *    and comment nodes.
 * @param doc the pointer to an XML document.
 * @param parent the pointer to parent XML node or NULL if we want to include all document nodes.
 * @param withComments the flag to include comments or not.
 * @param invert the "invert" flag.
 * @return pointer to the newly created xmlSecNodeSet structure
 * or NULL if an error occurs.
 */
xmlSecNodeSetPtr
xmlSecNodeSetGetChildren(xmlDocPtr doc, const xmlNodePtr parent, int withComments, int invert) {
    xmlSecNodeSetPtr nset;
    xmlNodeSetPtr nodes;
    xmlSecNodeSetType type;

    xmlSecAssert2(doc != NULL, NULL);

    nodes = xmlXPathNodeSetCreate(parent);
    if(nodes == NULL) {
        xmlSecXmlError("xmlXPathNodeSetCreate", NULL);
        return(NULL);
    }

    /* if parent is NULL then we add all the doc children */
    if(parent == NULL) {
        xmlNodePtr cur;
        for(cur = doc->children; cur != NULL; cur = cur->next) {
            if(withComments || (cur->type != XML_COMMENT_NODE)) {
                int ret;

                ret = xmlXPathNodeSetAdd(nodes, cur);
                if(ret < 0) {
                    xmlSecXmlError("xmlXPathNodeSetAdd", NULL);
                    xmlXPathFreeNodeSet(nodes);
                    return(NULL);
                }
            }
        }
    }

    if(withComments && invert) {
        type = xmlSecNodeSetTreeInvert;
    } else if(withComments && !invert) {
        type = xmlSecNodeSetTree;
    } else if(!withComments && invert) {
        type = xmlSecNodeSetTreeWithoutCommentsInvert;
    } else { /* if(!withComments && !invert) */
        type = xmlSecNodeSetTreeWithoutComments;
    }

    nset = xmlSecNodeSetCreate(doc, nodes, type);
    if(nset == NULL) {
        xmlSecInternalError("xmlSecNodeSetCreate", NULL);
        xmlXPathFreeNodeSet(nodes);
        return(NULL);
    }
    return(nset);
}

static int
xmlSecNodeSetDumpTextNodesWalkCallback(xmlSecNodeSetPtr nset, xmlNodePtr cur,
                                   xmlNodePtr parent XMLSEC_ATTRIBUTE_UNUSED,
                                   void* data) {
    int ret;
    xmlSecAssert2(nset != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(data != NULL, -1);

    XMLSEC_UNREFERENCED(parent);

    if(cur->type != XML_TEXT_NODE) {
        return(0);
    }
    if(cur->content == NULL) {
        return(0);
    }
    ret = xmlOutputBufferWriteString((xmlOutputBufferPtr)data,
            (char*)(cur->content));
    if(ret < 0) {
        xmlSecXmlError("xmlOutputBufferWriteString", NULL);
        return(-1);
    }
    return(0);
}

/**
 * @brief Dumps text node content from a nodes set.
 * @details Dumps content of all the text nodes from @p nset to @p out.
 * @param nset the pointer to node set.
 * @param out the output buffer.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecNodeSetDumpTextNodes(xmlSecNodeSetPtr nset, xmlOutputBufferPtr out) {
    xmlSecAssert2(nset != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    return(xmlSecNodeSetWalk(nset, xmlSecNodeSetDumpTextNodesWalkCallback, out));
}
/**
 * @brief Prints information about @p nset to the @p output.
 * @param nset the pointer to node set.
 * @param output the pointer to output FILE.
 */
void
xmlSecNodeSetDebugDump(xmlSecNodeSetPtr nset, FILE *output) {
    int len;

    xmlSecAssert(nset != NULL);
    xmlSecAssert(output != NULL);

    fprintf(output, "== Nodes set ");
    switch(nset->type) {
    case xmlSecNodeSetNormal:
        fprintf(output, "(xmlSecNodeSetNormal)\n");
        break;
    case xmlSecNodeSetInvert:
        fprintf(output, "(xmlSecNodeSetInvert)\n");
        break;
    case xmlSecNodeSetTree:
        fprintf(output, "(xmlSecNodeSetTree)\n");
        break;
    case xmlSecNodeSetTreeWithoutComments:
        fprintf(output, "(xmlSecNodeSetTreeWithoutComments)\n");
        break;
    case xmlSecNodeSetTreeInvert:
        fprintf(output, "(xmlSecNodeSetTreeInvert)\n");
        break;
    case xmlSecNodeSetTreeWithoutCommentsInvert:
        fprintf(output, "(xmlSecNodeSetTreeWithoutCommentsInvert)\n");
        break;
    case xmlSecNodeSetList:
        xmlSecNotImplementedError("xmlSecNodeSetList is deprecated");
        fprintf(output, "(xmlSecNodeSetList)\n");
        break;
    default:
        xmlSecUnsupportedEnumValueError("node set type", nset->type, NULL);
        break;
    }

    if(nset->next == nset) {
        /* a single set has no operation (the op field is only used for combined sets) */
        fprintf(output, "  operation: (none)\n");
    } else {
        switch(nset->op) {
        case xmlSecNodeSetUnion:
            fprintf(output, "  operation: xmlSecNodeSetUnion\n");
            break;
        case xmlSecNodeSetIntersection:
            fprintf(output, "  operation: xmlSecNodeSetIntersection\n");
            break;
        case xmlSecNodeSetSubtraction:
            fprintf(output, "  operation: xmlSecNodeSetSubtraction\n");
            break;
        default:
            xmlSecUnsupportedEnumValueError("node set operation", nset->op, NULL);
            break;
        }
    }

    len = xmlXPathNodeSetGetLength(nset->nodes);
    fprintf(output, "  nodes: %d\n", len);
}
