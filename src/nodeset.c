/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:nodeset
 * @Short_description: XML nodes set functions
 * @Stability: Stable
 *
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

static int      xmlSecNodeSetCheckNode                  (xmlNodeSetPtr nodes,
                                                         xmlNodePtr node,
                                                         xmlNodePtr parent);
static int      xmlSecNodeSetCheckNodeOrParent          (xmlNodeSetPtr nodes,
                                                         xmlNodePtr node,
                                                         xmlNodePtr parent);
static int      xmlSecNodeSetOneContains                (xmlSecNodeSetPtr nset,
                                                         xmlNodePtr node,
                                                         xmlNodePtr parent);
static int      xmlSecNodeSetWalkRecursive              (xmlSecNodeSetPtr nset,
                                                         xmlNodePtr startNode,
                                                         xmlSecNodeSetWalkCallback walkFunc,
                                                         void* data);

/**
 * xmlSecNodeSetCreate:
 * @doc:                the pointer to parent XML document.
 * @nodes:              the list of nodes.
 * @type:               the nodes set type.
 *
 * Creates new nodes set. Caller is responsible for freeing returned object
 * by calling #xmlSecNodeSetDestroy function.
 *
 * Returns: pointer to newly allocated node set or NULL if an error occurs.
 */
xmlSecNodeSetPtr
xmlSecNodeSetCreate(xmlDocPtr doc, xmlNodeSetPtr nodes, xmlSecNodeSetType type) {
    xmlSecNodeSetPtr nset;

    nset = (xmlSecNodeSetPtr)xmlMalloc(sizeof(xmlSecNodeSet));
    if(nset == NULL) {
        xmlSecMallocError(sizeof(xmlSecNodeSet), NULL);
        return(NULL);
    }
    memset(nset, 0,  sizeof(xmlSecNodeSet));

    nset->doc   = doc;
    nset->nodes = nodes;
    nset->type  = type;
    nset->next  = nset->prev = nset;
    return(nset);
}

/**
 * xmlSecNodeSetDestroy:
 * @nset:               the pointer to node set.
 *
 * Destroys the nodes set created with #xmlSecNodeSetCreate function.
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
        xmlSecAssert(tmp->children == NULL); /* deprecated */

        if((tmp->doc != NULL) && (tmp->destroyDoc != 0)) {
            /* all nodesets should belong to the same doc */
            xmlSecAssert((destroyDoc == NULL) || (tmp->doc == destroyDoc));
            destroyDoc = tmp->doc; /* can't destroy here because other node sets can refer to it */
        }
        memset(tmp, 0,  sizeof(xmlSecNodeSet));
        xmlFree(tmp);
    }

    /* finally, destroy the doc if needed */
    if(destroyDoc != NULL) {
        xmlFreeDoc(destroyDoc);
    }
}

/**
 * xmlSecNodeSetDocDestroy:
 * @nset:               the pointer to node set.
 *
 * Instructs node set to destroy nodes parent doc when node set is destroyed.
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
        xmlNs ns;

        memcpy(&ns, node, sizeof(ns));

        /* this is a libxml hack! check xpath.c for details */
        if((parent != NULL) && (parent->type == XML_ATTRIBUTE_NODE)) {
            ns.next = (xmlNsPtr)parent->parent;
        } else {
            ns.next = (xmlNsPtr)parent;
        }

        /*
         * If the input is an XPath node-set, then the node-set must explicitly
         * contain every node to be rendered to the canonical form.
         */
        return(xmlXPathNodeSetContains(nodes, (xmlNodePtr)&ns));
    }
}

/* checks node or its parents against LibXML2 nodeset */
static int
xmlSecNodeSetCheckNodeOrParent(xmlNodeSetPtr nodes, xmlNodePtr node, xmlNodePtr parent) {
    int ret;

    xmlSecAssert2(node != NULL, -1);

    do {
        ret = xmlSecNodeSetCheckNode(nodes, node, parent);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNodeSetCheckNode", NULL);
            return(-1);
        }
        if(ret) {
            return(1);
        }

        /* traverse up the tree, only element nodes can have children */
        if((parent != NULL) && (parent->type == XML_ELEMENT_NODE)) {
            node = parent;
            parent = parent->parent;
        } else {
            node = NULL;
        }
    } while(node != NULL);

    /* done */
    return(0);
}

/* checks node against THIS nodeset only */
static int
xmlSecNodeSetOneContains(xmlSecNodeSetPtr nset, xmlNodePtr node, xmlNodePtr parent) {
    int ret;

    xmlSecAssert2(nset != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* special cases: */
    switch(nset->type) {
        case xmlSecNodeSetTreeWithoutComments:
        case xmlSecNodeSetTreeWithoutCommentsInvert:
            if(node->type == XML_COMMENT_NODE) {
                return(0);
            }
            break;
        case xmlSecNodeSetList:
            xmlSecOtherError(XMLSEC_ERRORS_R_NOT_IMPLEMENTED, NULL, "xmlSecNodeSetList is deprecated");
            return(-1);
        default:
            break;
    }

    switch(nset->type) {
    case xmlSecNodeSetNormal:
        /* simple case */
        ret = xmlSecNodeSetCheckNode(nset->nodes, node, parent);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNodeSetCheckNode", NULL);
            return(-1);
        }
        return(ret);
    case xmlSecNodeSetInvert:
        /* simple case: return inverted result */
        ret = xmlSecNodeSetCheckNode(nset->nodes, node, parent);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNodeSetCheckNode", NULL);
            return(-1);
        }
        return(!ret);
    case xmlSecNodeSetTree:
    case xmlSecNodeSetTreeWithoutComments:
        /* just traverse up the tree to see if any of the parents are in the nodeset */
        ret = xmlSecNodeSetCheckNodeOrParent(nset->nodes, node, parent);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNodeSetCheckNodeOrParent", NULL);
            return(-1);
        }
        return(ret);
    case xmlSecNodeSetTreeInvert:
    case xmlSecNodeSetTreeWithoutCommentsInvert:
        /* just traverse up the tree to see if any of the parents are in the nodeset and invert the result */
        ret = xmlSecNodeSetCheckNodeOrParent(nset->nodes, node, parent);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNodeSetCheckNodeOrParent", NULL);
            return(-1);
        }
        return(!ret);
    default:
        xmlSecUnsupportedEnumValueError("node set type", nset->type, NULL);
        return(0);
    }
}

/**
 * xmlSecNodeSetContains:
 * @nset:               the pointer to node set.
 * @node:               the pointer to XML node to check.
 * @parent:             the pointer to @node parent node.
 *
 * Checks whether the @node is in the nodes set or not.
 *
 * Returns: 1 if the @node is in the nodes set @nset or 0 if it is not.
 * There is no return value for errors.
 */
int
xmlSecNodeSetContains(xmlSecNodeSetPtr nset, xmlNodePtr node, xmlNodePtr parent) {
    xmlSecNodeSetPtr cur;
    int status = 1;
    int ret;

    xmlSecAssert2(node != NULL, 0);  /* no return value for error */

    /* special cases: */
    if(nset == NULL) {
        return(1);
    }

    status = 1;
    cur = nset;
    do {
        switch(cur->op) {
        case xmlSecNodeSetIntersection:
            ret = xmlSecNodeSetOneContains(cur, node, parent);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNodeSetOneContains", NULL);
                return(0); /* no return value for error */
            }
            if(status && !ret) {
                status = 0;
            }
            break;
        case xmlSecNodeSetSubtraction:
            ret = xmlSecNodeSetOneContains(cur, node, parent);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNodeSetOneContains", NULL);
                return(0); /* no return value for error */
            }
            if(status && ret) {
                status = 0;
            }
            break;
        case xmlSecNodeSetUnion:
            ret = xmlSecNodeSetOneContains(cur, node, parent);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNodeSetOneContains", NULL);
                return(0); /* no return value for error */
            }
            if(!status && ret) {
                status = 1;
            }
            break;
        default:
            xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_OPERATION, NULL,
                "node set operation=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(cur->op));
            return(0); /* no return value for error */
        }
        cur = cur->next;
    } while(cur != nset);

    return(status);
}

/**
 * xmlSecNodeSetAdd:
 * @nset:               the pointer to current nodes set (or NULL).
 * @newNSet:            the pointer to new nodes set.
 * @op:                 the operation type.
 *
 * Adds @newNSet to the @nset using operation @op.
 *
 * Returns: the pointer to combined nodes set or NULL if an error
 * occurs.
 */
xmlSecNodeSetPtr
xmlSecNodeSetAdd(xmlSecNodeSetPtr nset, xmlSecNodeSetPtr newNSet,
                 xmlSecNodeSetOp op) {
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
 * xmlSecNodeSetAddList:
 * @nset:               the pointer to current nodes set (or NULL).
 * @newNSet:            the pointer to new nodes set.
 * @op:                 the operation type.
 *
 * Deprecated. Adds @newNSet to the @nset as child using operation @op.
 *
 * Returns: the pointer to combined nodes set or NULL if an error
 * occurs.
 */
xmlSecNodeSetPtr
xmlSecNodeSetAddList(
    xmlSecNodeSetPtr nset XMLSEC_ATTRIBUTE_UNUSED,
    xmlSecNodeSetPtr newNSet XMLSEC_ATTRIBUTE_UNUSED,
    xmlSecNodeSetOp op XMLSEC_ATTRIBUTE_UNUSED
) {
    UNREFERENCED_PARAMETER(nset);
    UNREFERENCED_PARAMETER(newNSet);
    UNREFERENCED_PARAMETER(op);

    xmlSecOtherError(XMLSEC_ERRORS_R_NOT_IMPLEMENTED, NULL, "xmlSecNodeSetAddList is deprecated");
    return(NULL);
}


/**
 * xmlSecNodeSetWalk:
 * @nset:               the pointer to node set.
 * @walkFunc:           the callback functions.
 * @data:               the application specific data passed to the @walkFunc.
 *
 * Calls the function @walkFunc once per each node in the nodes set @nset.
 * If the @walkFunc returns a negative value, then the walk procedure
 * is interrupted.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNodeSetWalk(xmlSecNodeSetPtr nset, xmlSecNodeSetWalkCallback walkFunc, void* data) {
    xmlNodePtr cur;
    int ret = 0;

    xmlSecAssert2(nset != NULL, -1);
    xmlSecAssert2(nset->doc != NULL, -1);
    xmlSecAssert2(walkFunc != NULL, -1);

    /* special cases */
    if(nset->nodes != NULL) {
        int i;

        switch(nset->type) {
        case xmlSecNodeSetNormal:
        case xmlSecNodeSetTree:
        case xmlSecNodeSetTreeWithoutComments:
            for(i = 0; (ret >= 0) && (i < nset->nodes->nodeNr); ++i) {
                ret = xmlSecNodeSetWalkRecursive(nset, nset->nodes->nodeTab[i], walkFunc, data);
            }
            return(ret);
        default:
            break;
        }
    }

    for(cur = nset->doc->children; (cur != NULL) && (ret >= 0); cur = cur->next) {
        ret = xmlSecNodeSetWalkRecursive(nset, cur, walkFunc, data);
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
    if(xmlSecNodeSetContains(ctx->nset, cur, parent)) {
        ret = ctx->walkFunc(ctx->nset, cur, parent, ctx->data);

        if(ret < 0) {
            return(-1);
        }
    }

    /* element node has attributes, namespaces  */
    if(cur->type == XML_ELEMENT_NODE) {
        xmlAttrPtr attr;
        xmlNodePtr node;
        xmlNsPtr ns, tmp;

        attr = (xmlAttrPtr)cur->properties;
        while(attr != NULL) {
            if(xmlSecNodeSetContains(ctx->nset, (xmlNodePtr)attr, cur)) {
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
                if((tmp == ns) && xmlSecNodeSetContains(ctx->nset, (xmlNodePtr)ns, cur)) {
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

    /* continue the walk */
    return(1);
}

static int
xmlSecNodeSetWalkRecursive(xmlSecNodeSetPtr nset, xmlNodePtr startNode,
                           xmlSecNodeSetWalkCallback walkFunc, void* data) {
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

    /* done */
    return(0);
}

/**
 * xmlSecNodeSetGetChildren:
 * @doc:                the pointer to an XML document.
 * @parent:             the pointer to parent XML node or NULL if we want to include all document nodes.
 * @withComments:       the flag include  comments or not.
 * @invert:             the "invert" flag.
 *
 * Creates a new nodes set that contains:
 *  - if @withComments is not 0 and @invert is 0:
 *    all nodes in the @parent subtree;
 *  - if @withComments is 0 and @invert is 0:
 *    all nodes in the @parent subtree except comment nodes;
 *  - if @withComments is not 0 and @invert not is 0:
 *    all nodes in the @doc except nodes in the @parent subtree;
 *  - if @withComments is 0 and @invert is 0:
 *    all nodes in the @doc except nodes in the @parent subtree
 *    and comment nodes.
 *
 * Returns: pointer to the newly created #xmlSecNodeSet structure
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

    UNREFERENCED_PARAMETER(parent);

    if(cur->type != XML_TEXT_NODE) {
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
 * xmlSecNodeSetDumpTextNodes:
 * @nset:               the pointer to node set.
 * @out:                the output buffer.
 *
 * Dumps content of all the text nodes from @nset to @out.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNodeSetDumpTextNodes(xmlSecNodeSetPtr nset, xmlOutputBufferPtr out) {
    xmlSecAssert2(nset != NULL, -1);
    xmlSecAssert2(out != NULL, -1);

    return(xmlSecNodeSetWalk(nset, xmlSecNodeSetDumpTextNodesWalkCallback, out));
}

/**
 * xmlSecNodeSetDebugDump:
 * @nset:               the pointer to node set.
 * @output:             the pointer to output FILE.
 *
 * Prints information about @nset to the @output.
 */
void
xmlSecNodeSetDebugDump(xmlSecNodeSetPtr nset, FILE *output) {
    int ii, len;
    xmlNodePtr cur;

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
        fprintf(output, "(xmlSecNodeSetList, deprecated)\n");
        fprintf(output, ">>>\n");
        fprintf(output, "<<<\n");
        return;
    }

    len = xmlXPathNodeSetGetLength(nset->nodes);
    for(ii = 0; ii < len; ++ii) {
        cur = xmlXPathNodeSetItem(nset->nodes, ii);
        xmlSecAssert(cur != NULL);

        if(cur->type != XML_NAMESPACE_DECL) {
            fprintf(output, XMLSEC_ENUM_FMT ": %s\n",
                XMLSEC_ENUM_CAST(cur->type),
                (cur->name) ? cur->name : BAD_CAST "null");
        } else {
            xmlNsPtr ns = (xmlNsPtr)cur;
            fprintf(output, XMLSEC_ENUM_FMT ": %s=%s (%s:%s)\n",
                XMLSEC_ENUM_CAST(cur->type),
                (ns->prefix) ? ns->prefix : BAD_CAST "null",
                (ns->href) ? ns->href : BAD_CAST "null",
                (ns->next != NULL && ((xmlNodePtr)ns->next)->ns &&
                 ((xmlNodePtr)ns->next)->ns->prefix) ?
                   ((xmlNodePtr)ns->next)->ns->prefix : BAD_CAST "null",
                (ns->next != NULL) ? ((xmlNodePtr)ns->next)->name : BAD_CAST "null");
        }
    }
}
