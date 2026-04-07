/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_core_xmltree
 * @brief XML tree functions.
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libxml/tree.h>
#include <libxml/valid.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlversion.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/parser.h>
#include <xmlsec/private.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>

#include "cast_helpers.h"

static const xmlChar*    g_xmlsec_xmltree_default_linefeed = xmlSecStringCR;

/**
 * @brief Gets the current default linefeed.
 * @return the current default linefeed.
 */
const xmlChar*
xmlSecGetDefaultLineFeed(void)
{
    return g_xmlsec_xmltree_default_linefeed;
}

/**
 * @brief Sets the current default linefeed.
 * @details The caller must ensure that the linefeed
 * string exists for the lifetime of the program or until the new linefeed is set.
 * @param linefeed default linefeed.
 */
void
xmlSecSetDefaultLineFeed(const xmlChar *linefeed)
{
    g_xmlsec_xmltree_default_linefeed = linefeed;
}


/**
 * @brief Reads and trims XML node content.
 * @details Reads @p cur node content and trims it (both sides).
 * @param cur the pointer to XML node.
 * @return trimmed node content or NULL if an error occurs.
 */
xmlChar*
xmlSecGetNodeContentAndTrim(const xmlNodePtr cur) {
    xmlChar * content;
    xmlChar * bb;
    xmlChar * ee;

    content = xmlNodeGetContent(cur);
    if(content == NULL) {
        return(NULL);
    }

    /* ltrim */
    bb = content;
    while(((*bb) != '\0') && isspace(*bb)) { ++bb; }

    /* rtrim */
    ee = bb + xmlStrlen(bb) - 1;
    while((bb <= ee) && isspace(*ee)) { --ee; }
    *(ee + 1) = '\0';

    /* move string to the beggining */
    if(content != bb) {
        memmove(content, bb, (size_t)xmlStrlen(bb) + 1);
    }
    return(content);
}

/**
 * @brief Reads node content and hex-decodes it into a buffer.
 * @details Reads @p cur node content (whitespace-trimmed), hex-decodes it, and stores
 * the result in @p res. The buffer is emptied before writing.
 * @param cur the pointer to XML node.
 * @param res the output buffer to store the decoded bytes.
 * @return 0 on success or -1 on error.
 */
int
xmlSecGetNodeContentAsHex(const xmlNodePtr cur, xmlSecBufferPtr res) {
    xmlChar* content;
    int ret;

    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    content = xmlSecGetNodeContentAndTrim(cur);
    if(content == NULL) {
        xmlSecInvalidNodeContentError(cur, NULL, "empty");
        return(-1);
    }

    ret = xmlSecBufferHexRead(res, content);
    xmlFree(content);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferHexRead", NULL);
        return(-1);
    }

    return(0);
}

/**
 * @brief Hex-encodes data and sets it as node content.
 * @details Hex-encodes @p data and stores the result as node content for @p node.
 * @param node the pointer to XML node.
 * @param data the input bytes.
 * @param size the input data size.
 * @return 0 on success or -1 on error.
 */
int
xmlSecSetNodeContentAsHex(xmlNodePtr node, const xmlSecByte* data, xmlSecSize size) {
    static const xmlChar hexDigits[] = "0123456789abcdef";
    xmlChar* content;
    xmlSecSize contentSize;
    xmlSecSize ii;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(data != NULL, -1);

    contentSize = (2 * size) + 1;
    content = (xmlChar*)xmlMalloc(contentSize);
    if(content == NULL) {
        xmlSecMallocError(contentSize, NULL);
        return(-1);
    }

    for(ii = 0; ii < size; ++ii) {
        content[(2 * ii)] = hexDigits[(data[ii] >> 4) & 0x0F];
        content[(2 * ii) + 1] = hexDigits[data[ii] & 0x0F];
    }
    content[2 * size] = '\0';

    xmlNodeSetContent(node, content);
    xmlFree(content);
    return(0);
}

/**
 * @brief Reads node content and converts it to an xmlSecSize.
 * @details Reads @p cur node content and converts it to xmlSecSize value.
 * @param cur the pointer to XML node.
 * @param defValue the default value that will be returned in @p res if there is no node content.
 * @param res the pointer to the result value.
 * @return 0 on success or -1 on error.
 */
int
xmlSecGetNodeContentAsSize(const xmlNodePtr cur, xmlSecSize defValue, xmlSecSize* res) {
    xmlChar *content;
    long int val;
    char* endptr = NULL;

    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    content = xmlSecGetNodeContentAndTrim(cur);
    if(content == NULL) {
        (*res) = defValue;
        return(0);
    }

    val = strtol((char*)content, &endptr, 10);
    if((val < 0) || (val == LONG_MAX) || (endptr == NULL)) {
        xmlSecInvalidNodeContentError(cur, NULL, "can't parse node content as size");
        xmlFree(content);
        return(-1);
    }

    /* skip spaces at the end */
    while(isspace((int)(*endptr))) {
        ++endptr;
    }
    if((content + xmlStrlen(content)) != BAD_CAST endptr) {
        xmlSecInvalidNodeContentError(cur, NULL, "can't parse node content as size (extra characters at the end)");
        xmlFree(content);
        return(-1);
    }
    xmlFree(content);

    /* success */
    XMLSEC_SAFE_CAST_LONG_TO_SIZE(val, (*res), return(-1), NULL);
    return(0);
}

/**
 * @brief Searches a node and its next siblings by name and namespace.
 * @details Searches @p cur and the next siblings of the @p cur node having given name and
 * namespace href.
 * @param cur the pointer to XML node.
 * @param name the name.
 * @param ns the namespace href (may be NULL).
 * @return the pointer to the found node or NULL if an error occurs or
 * node is not found.
 */
xmlNodePtr
xmlSecFindSibling(const xmlNodePtr cur, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr tmp;
    xmlSecAssert2(name != NULL, NULL);

    for(tmp = cur; tmp != NULL; tmp = tmp->next) {
        if(tmp->type == XML_ELEMENT_NODE) {
            if(xmlSecCheckNodeName(tmp, name, ns)) {
                return(tmp);
            }
        }
    }
    return(NULL);
}

/**
 * @brief Finds a direct child node by name and namespace.
 * @details Searches a direct child of the @p parent node having given name and
 * namespace href.
 * @param parent the pointer to XML node.
 * @param name the name.
 * @param ns the namespace href (may be NULL).
 * @return the pointer to the found node or NULL if an error occurs or
 * node is not found.
 */
xmlNodePtr
xmlSecFindChild(const xmlNodePtr parent, const xmlChar *name, const xmlChar *ns) {
    xmlSecAssert2(parent != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    return(xmlSecFindSibling(parent->children, name, ns));
}

/**
 * @brief Searches ancestor nodes by name and namespace.
 * @details Searches the ancestors axis of the @p cur node for a node having given name
 * and namespace href.
 * @param cur the pointer to an XML node.
 * @param name the name.
 * @param ns the namespace href (may be NULL).
 * @return the pointer to the found node or NULL if an error occurs or
 * node is not found.
 */
xmlNodePtr
xmlSecFindParent(const xmlNodePtr cur, const xmlChar *name, const xmlChar *ns) {
    xmlSecAssert2(cur != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    if(xmlSecCheckNodeName(cur, name, ns)) {
        return(cur);
    } else if(cur->parent != NULL) {
        return(xmlSecFindParent(cur->parent, name, ns));
    }
    return(NULL);
}

/**
 * @brief Recursively searches child nodes by name and namespace.
 * @details Searches all children of the @p parent node having given name and
 * namespace href.
 * @param parent the pointer to XML node.
 * @param name the name.
 * @param ns the namespace href (may be NULL).
 * @return the pointer to the found node or NULL if an error occurs or
 * node is not found.
 */
xmlNodePtr
xmlSecFindNode(const xmlNodePtr parent, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur;
    xmlNodePtr ret;

    xmlSecAssert2(name != NULL, NULL);

    cur = parent;
    while(cur != NULL) {
        if((cur->type == XML_ELEMENT_NODE) && xmlSecCheckNodeName(cur, name, ns)) {
            return(cur);
        }
        if(cur->children != NULL) {
            ret = xmlSecFindNode(cur->children, name, ns);
            if(ret != NULL) {
                return(ret);
            }
        }
        cur = cur->next;
    }
    return(NULL);
}

/**
 * @brief Gets the node's namespace href.
 * @param cur the pointer to node.
 * @return node's namespace href.
 */
const xmlChar*
xmlSecGetNodeNsHref(const xmlNodePtr cur) {
    xmlNsPtr ns;

    xmlSecAssert2(cur != NULL, NULL);

    /* do we have a namespace in the node? */
    if(cur->ns != NULL) {
        return(cur->ns->href);
    }

    /* search for default namespace */
    ns = xmlSearchNs(cur->doc, cur, NULL);
    if(ns != NULL) {
        return(ns->href);
    }

    return(NULL);
}

/**
 * @brief Checks if a node has the given name and namespace.
 * @details Checks that the node has a given name and a given namespace href.
 * @param cur the pointer to an XML node.
 * @param name the name,
 * @param ns the namespace href.
 * @return 1 if the node matches or 0 otherwise.
 */
int
xmlSecCheckNodeName(const xmlNodePtr cur, const xmlChar *name, const xmlChar *ns) {
    xmlSecAssert2(cur != NULL, 0);

    return(xmlStrEqual(cur->name, name) &&
           xmlStrEqual(xmlSecGetNodeNsHref(cur), ns));
}

/**
 * @brief Adds a new child element with the given name and namespace.
 * @details Adds a child to the node @p parent with given @p name and namespace @p ns.
 * @param parent the pointer to an XML node.
 * @param name the new node name.
 * @param ns the new node namespace.
 * @return pointer to the new node or NULL if an error occurs.
 */
xmlNodePtr
xmlSecAddChild(xmlNodePtr parent, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur;
    xmlNodePtr text;

    xmlSecAssert2(parent != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    if(parent->children == NULL) {
        /* TODO: add indents */
        text = xmlNewText(xmlSecGetDefaultLineFeed());
        if(text == NULL) {
            xmlSecXmlError("xmlNewText", NULL);
            return(NULL);
        }
        xmlAddChild(parent, text);
    }

    cur = xmlNewChild(parent, NULL, name, NULL);
    if(cur == NULL) {
        xmlSecXmlError("xmlNewChild", NULL);
        return(NULL);
    }

    /* namespaces support */
    if(ns != NULL) {
        xmlNsPtr nsPtr;

        /* find namespace by href and check that its prefix is not overwritten */
        nsPtr = xmlSearchNsByHref(cur->doc, cur, ns);
        if((nsPtr == NULL) || (xmlSearchNs(cur->doc, cur, nsPtr->prefix) != nsPtr)) {
            nsPtr = xmlNewNs(cur, ns, NULL);
            if(nsPtr == NULL) {
                xmlSecXmlError("xmlNewNs", NULL);
                return(NULL);
            }
        }
        xmlSetNs(cur, nsPtr);
    }

    /* TODO: add indents */
    text = xmlNewText(xmlSecGetDefaultLineFeed());
    if(text == NULL) {
        xmlSecXmlError("xmlNewText", NULL);
        return(NULL);
    }
    xmlAddChild(parent, text);

    return(cur);
}

/**
 * @brief Adds @p child node to the @p parent node.
 * @param parent the pointer to an XML node.
 * @param child the new node.
 * @return pointer to the new node or NULL if an error occurs.
 */
xmlNodePtr
xmlSecAddChildNode(xmlNodePtr parent, xmlNodePtr child) {
    xmlNodePtr text;

    xmlSecAssert2(parent != NULL, NULL);
    xmlSecAssert2(child != NULL, NULL);

    if(parent->children == NULL) {
        /* TODO: add indents */
        text = xmlNewText(xmlSecGetDefaultLineFeed());
        if(text == NULL) {
            xmlSecXmlError("xmlNewText", NULL);
            return(NULL);
        }
        xmlAddChild(parent, text);
    }

    xmlAddChild(parent, child);

    /* TODO: add indents */
    text = xmlNewText(xmlSecGetDefaultLineFeed());
    if(text == NULL) {
        xmlSecXmlError("xmlNewText", NULL);
        return(NULL);
    }
    xmlAddChild(parent, text);

    return(child);
}

/**
 * @brief Finds or creates an empty child element by name and namespace.
 * @details Searches a direct child of the @p parent node having given name and
 * namespace href. If not found then element node with given name / namespace
 * is added.
 * @param parent the pointer to XML node.
 * @param name the name.
 * @param ns the namespace href (may be NULL).
 * @return the pointer to the found or created node; or NULL if an error occurs.
 */
xmlNodePtr
xmlSecEnsureEmptyChild(xmlNodePtr parent, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur = NULL;
    xmlNodePtr tmp;

    xmlSecAssert2(parent != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    /* try to find an empty node first */
    tmp = xmlSecFindNode(parent, name, ns);
    while(tmp != NULL) {
        cur = tmp;
        if(xmlSecIsEmptyNode(cur) == 1) {
            return(cur);
        }
        tmp = xmlSecFindSibling(cur->next, name, ns);
    }

    /* if not found then either add next or add at the end */
    if(cur == NULL) {
        cur = xmlSecAddChild(parent, name, ns);
    } else {
        cur = xmlSecAddNextSibling(cur, name, ns);
    }
    if(cur == NULL) {
        xmlSecInternalError2("xmlSecAddChild or xmlSecAddNextSibling", NULL,
                             "node=%s", xmlSecErrorsSafeString(name));
        return(NULL);
    }
    return(cur);
}

/**
 * @brief Adds a new next-sibling element with the given name and namespace.
 * @details Adds next sibling to the node @p node with given @p name and namespace @p ns.
 * @param node the pointer to an XML node.
 * @param name the new node name.
 * @param ns the new node namespace.
 * @return pointer to the new node or NULL if an error occurs.
 */
xmlNodePtr
xmlSecAddNextSibling(xmlNodePtr node, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur;
    xmlNodePtr text;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    cur = xmlNewNode(NULL, name);
    if(cur == NULL) {
        xmlSecXmlError("xmlNewNode", NULL);
        return(NULL);
    }
    xmlAddNextSibling(node, cur);

    /* namespaces support */
    if(ns != NULL) {
        xmlNsPtr nsPtr;

        /* find namespace by href and check that its prefix is not overwritten */
        nsPtr = xmlSearchNsByHref(cur->doc, cur, ns);
        if((nsPtr == NULL) || (xmlSearchNs(cur->doc, cur, nsPtr->prefix) != nsPtr)) {
            nsPtr = xmlNewNs(cur, ns, NULL);
        }
        xmlSetNs(cur, nsPtr);
    }

    /* TODO: add indents */
    text = xmlNewText(xmlSecGetDefaultLineFeed());
    if(text == NULL) {
        xmlSecXmlError("xmlNewText", NULL);
        return(NULL);
    }
    xmlAddNextSibling(node, text);

    return(cur);
}

/**
 * @brief Adds a new previous-sibling element with the given name and namespace.
 * @details Adds prev sibling to the node @p node with given @p name and namespace @p ns.
 * @param node the pointer to an XML node.
 * @param name the new node name.
 * @param ns the new node namespace.
 * @return pointer to the new node or NULL if an error occurs.
 */
xmlNodePtr
xmlSecAddPrevSibling(xmlNodePtr node, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur;
    xmlNodePtr text;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);

    cur = xmlNewNode(NULL, name);
    if(cur == NULL) {
        xmlSecXmlError("xmlNewNode", NULL);
        return(NULL);
    }
    xmlAddPrevSibling(node, cur);

    /* namespaces support */
    if(ns != NULL) {
        xmlNsPtr nsPtr;

        /* find namespace by href and check that its prefix is not overwritten */
        nsPtr = xmlSearchNsByHref(cur->doc, cur, ns);
        if((nsPtr == NULL) || (xmlSearchNs(cur->doc, cur, nsPtr->prefix) != nsPtr)) {
            nsPtr = xmlNewNs(cur, ns, NULL);
        }
        xmlSetNs(cur, nsPtr);
    }

    /* TODO: add indents */
    text = xmlNewText(xmlSecGetDefaultLineFeed());
    if(text == NULL) {
        xmlSecXmlError("xmlNewText", NULL);
        return(NULL);
    }
    xmlAddPrevSibling(node, text);

    return(cur);
}

/**
 * @brief Searches for the next element node.
 * @param cur the pointer to an XML node.
 * @return the pointer to next element node or NULL if it is not found.
 */
xmlNodePtr
xmlSecGetNextElementNode(xmlNodePtr cur) {

    while((cur != NULL) && (cur->type != XML_ELEMENT_NODE)) {
        cur = cur->next;
    }
    return(cur);
}

/**
 * @brief Swaps a node with a new node in the XML tree.
 * @details Swaps the @p node and @p newNode in the XML tree.
 * @param node the current node.
 * @param newNode the new node.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceNode(xmlNodePtr node, xmlNodePtr newNode) {
    return xmlSecReplaceNodeAndReturn(node, newNode, NULL);
}

/**
 * @brief Swaps a node with another and optionally returns the replaced node.
 * @details Swaps the @p node and @p newNode in the XML tree.
 * @param node the current node.
 * @param newNode the new node.
 * @param replaced the replaced node, or release it if NULL is given
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceNodeAndReturn(xmlNodePtr node, xmlNodePtr newNode, xmlNodePtr* replaced) {
    xmlNodePtr oldNode;
    int restoreRoot = 0;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(newNode != NULL, -1);

    /* fix documents children if necessary first */
    if((node->doc != NULL) && (node->doc->children == node)) {
        node->doc->children = node->next;
        restoreRoot = 1;
    }
    if((newNode->doc != NULL) && (newNode->doc->children == newNode)) {
        newNode->doc->children = newNode->next;
    }

    oldNode = xmlReplaceNode(node, newNode);
    if(oldNode == NULL) {
        xmlSecXmlError("xmlReplaceNode", NULL);
        return(-1);
    }

    if(restoreRoot != 0) {
        xmlDocSetRootElement(oldNode->doc, newNode);
    }

    /* return the old node if requested */
    if(replaced != NULL) {
        (*replaced) = oldNode;
    } else {
        xmlFreeNode(oldNode);
    }

    return(0);
}

/**
 * @brief Swaps the content of @p node and @p newNode.
 * @param node the current node.
 * @param newNode the new node.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceContent(xmlNodePtr node, xmlNodePtr newNode) {
     return xmlSecReplaceContentAndReturn(node, newNode, NULL);
}

/**
 * @brief Swaps the content of @p node and @p newNode, optionally returning replaced nodes.
 * @param node the current node.
 * @param newNode the new node.
 * @param replaced the replaced nodes, or release them if NULL is given
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceContentAndReturn(xmlNodePtr node, xmlNodePtr newNode, xmlNodePtr *replaced) {
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(newNode != NULL, -1);

    /* return the old nodes if requested */
    if(replaced != NULL) {
        xmlNodePtr cur, next, tail;

        (*replaced) = tail = NULL;
        for(cur = node->children; (cur != NULL); cur = next) {
            next = cur->next;
            if((*replaced) != NULL) {
                /* cur is unlinked in this function */
                xmlAddNextSibling(tail, cur);
                tail = cur;
            } else {
                /* this is the first node, (*replaced) is the head */
                xmlUnlinkNode(cur);
                (*replaced) = tail = cur;
          }
        }
    } else {
        /* just delete the content */
        xmlNodeSetContent(node, NULL);
    }

    /* swap nodes */
    xmlUnlinkNode(newNode);
    xmlAddChildList(node, newNode);

    return(0);
}

/**
 * @brief Replaces a node with parsed XML data from a buffer.
 * @details Swaps the @p node and the parsed XML data from the @p buffer in the XML tree.
 * @param node the current node.
 * @param buffer the XML data.
 * @param size the XML data size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceNodeBuffer(xmlNodePtr node, const xmlSecByte *buffer, xmlSecSize size) {
    return xmlSecReplaceNodeBufferAndReturn(node, buffer, size, NULL);
}

/**
 * @brief Replaces a node with parsed XML data from a buffer, optionally returning replaced nodes.
 * @details Swaps the @p node and the parsed XML data from the @p buffer in the XML tree.
 * @param node the current node.
 * @param buffer the XML data.
 * @param size the XML data size.
 * @param replaced the replaced nodes, or release them if NULL is given
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceNodeBufferAndReturn(xmlNodePtr node, const xmlSecByte *buffer, xmlSecSize size, xmlNodePtr *replaced) {
    xmlNodePtr results = NULL;
    xmlNodePtr next = NULL;
#if (LIBXML_VERSION >= 21500)
    xmlChar *oldenc;
#else  /* (LIBXML_VERSION >= 21500) */
    const xmlChar *oldenc;
#endif /* (LIBXML_VERSION >= 21500) */
    int len;
    xmlParserErrors ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(node->parent != NULL, -1);

    /* parse buffer in the context of node's parent */
    XMLSEC_SAFE_CAST_SIZE_TO_INT(size, len, return(-1), NULL);
    oldenc = node->doc->encoding;
    node->doc->encoding = NULL;
    ret = xmlParseInNodeContext(node->parent, (const char*)buffer, len,
            xmlSecParserGetDefaultOptions(), &results);
    node->doc->encoding = oldenc;
    if(ret != XML_ERR_OK) {
        xmlSecXmlError("xmlParseInNodeContext", NULL);
        return(-1);
    }

    /* add new nodes */
    while (results != NULL) {
        next = results->next;
        xmlAddPrevSibling(node, results);
        results = next;
    }

    /* remove old node */
    xmlUnlinkNode(node);

    /* return the old node if requested */
    if(replaced != NULL) {
        (*replaced) = node;
    } else {
        xmlFreeNode(node);
    }

    return(0);
}

/**
 * @brief Encodes special characters in a buffer and sets it as node content.
 * @details Encodes "special" characters in the @p buffer and sets the result
 * as the node content.
 * @param node the pointer to an XML node.
 * @param buffer the pointer to the node content.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecNodeEncodeAndSetContent(xmlNodePtr node, const xmlChar * buffer) {
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(node->doc != NULL, -1);

    if(buffer != NULL) {
        xmlChar * tmp;
        tmp = xmlEncodeSpecialChars(node->doc, buffer);
        if (tmp == NULL) {
            xmlSecXmlError("xmlEncodeSpecialChars", NULL);
            return(-1);
        }
        xmlNodeSetContent(node, tmp);
        xmlFree(tmp);
    } else {
        xmlNodeSetContent(node, NULL);
    }
    return(0);
}

/**
 * @brief Registers ID attributes from a node subtree in the document's ID table.
 * @details Walks thru all children of the @p cur node and adds all attributes
 * from the @p ids list to the @p doc document IDs attributes hash.
 * @param doc the pointer to an XML document.
 * @param cur the pointer to an XML node.
 * @param ids the pointer to a NULL terminated list of ID attributes.
 */
void
xmlSecAddIDs(xmlDocPtr doc, xmlNodePtr cur, const xmlChar** ids) {
    xmlNodePtr children = NULL;

    xmlSecAssert(doc != NULL);
    xmlSecAssert(ids != NULL);

    if((cur != NULL) && (cur->type == XML_ELEMENT_NODE)) {
        xmlAttrPtr attr;
        xmlAttrPtr tmp;
        int i;
        xmlChar* name;

        for(attr = cur->properties; attr != NULL; attr = attr->next) {
            for(i = 0; ids[i] != NULL; ++i) {
                if(xmlStrEqual(attr->name, ids[i])) {
                    name = xmlNodeListGetString(doc, attr->children, 1);
                    if(name != NULL) {
                        tmp = xmlGetID(doc, name);
                        if(tmp == NULL) {
                            xmlAddID(NULL, doc, name, attr);
                        } else if(tmp != attr) {
                            xmlSecInvalidStringDataError("id", name, "unique id (id already defined)", NULL);
                            /* ignore error */
                        }
                        xmlFree(name);
                    }
                }
            }
        }

        children = cur->children;
    } else if(cur == NULL) {
        children = doc->children;
    }

    while(children != NULL) {
        if(children->type == XML_ELEMENT_NODE) {
            xmlSecAddIDs(doc, children, ids);
        }
        children = children->next;
    }
}

/**
 * @brief Creates a new XML document with a single root node.
 * @details Creates a new XML tree with one root node @p rootNodeName.
 * @param rootNodeName the root node name.
 * @param rootNodeNs the root node namespace (optional).
 * @return pointer to the newly created tree or NULL if an error occurs.
 */
xmlDocPtr
xmlSecCreateTree(const xmlChar* rootNodeName, const xmlChar* rootNodeNs) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNsPtr ns;

    xmlSecAssert2(rootNodeName != NULL, NULL);

    /* create doc */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
        xmlSecXmlError("xmlNewDoc", NULL);
        return(NULL);
    }

    /* create root node */
    root = xmlNewDocNode(doc, NULL, rootNodeName, NULL);
    if(root == NULL) {
        xmlSecXmlError2("xmlNewDocNode", NULL,
                        "node=%s", rootNodeName);
        xmlFreeDoc(doc);
        return(NULL);
    }
    xmlDocSetRootElement(doc, root);

    /* and set root node namespace */
    ns = xmlNewNs(root, rootNodeNs, NULL);
    if(ns == NULL) {
        xmlSecXmlError2("xmlNewNs", NULL,
                        "ns=%s", xmlSecErrorsSafeString(rootNodeNs));
        xmlFreeDoc(doc);
        return(NULL);
    }
    xmlSetNs(root, ns);

    return(doc);
}

/**
 * @brief Checks whether a node is empty (whitespace only).
 * @details Checks whether the @p node is empty (i.e. has only whitespaces children).
 * @param node the node to check
 * @return 1 if @p node is empty, 0 otherwise or a negative value if an error occurs.
 */
int
xmlSecIsEmptyNode(xmlNodePtr node) {
    xmlChar* content;
    int res;

    xmlSecAssert2(node != NULL, -1);

    if(xmlSecGetNextElementNode(node->children) != NULL) {
        return(0);
    }

    content = xmlNodeGetContent(node);
    if(content == NULL) {
        return(1);
    }

    res = xmlSecIsEmptyString(content);
    xmlFree(content);
    return(res);
}

/**
 * @brief Checks whether a string contains only whitespace.
 * @details Checks whether the @p str is empty (i.e. has only whitespaces children).
 * @param str the string to check
 * @return 1 if @p str is empty, 0 otherwise or a negative value if an error occurs.
 */
int
xmlSecIsEmptyString(const xmlChar* str) {
    xmlSecAssert2(str != NULL, -1);

    for( ;*str != '\0'; ++str) {
        if(!isspace((*str))) {
            return(0);
        }
    }
    return(1);
}

/**
 * @brief Encodes an XML string and writes it to a file descriptor.
 * @details Encodes the @p str (e.g. replaces '&' with '&amp;') and writes it to @p fd.
 * @param fd the file descriptor to write the XML string to
 * @param str the string
 * @return he number of bytes transmitted or a negative value if an error occurs.
 */
int
xmlSecPrintXmlString(FILE * fd, const xmlChar * str) {
    int res;

    if(str != NULL) {
        xmlChar * encoded_str = NULL;
        encoded_str = xmlEncodeSpecialChars(NULL, str);
        if(encoded_str == NULL) {
            xmlSecXmlError2("xmlEncodeSpecialChars", NULL,
                            "string=%s", xmlSecErrorsSafeString(str));
            return(-1);
        }

        res = fprintf(fd, "%s", (const char*)encoded_str);
        xmlFree(encoded_str);
    } else {
        res = fprintf(fd, "NULL");
    }

    if(res < 0) {
        xmlSecIOError("fprintf", NULL, NULL);
        return(-1);
    }
    return(res);
}

/**
 * @brief Creates a QName string from a namespace href and a local name.
 * @details Creates QName (prefix:local) from @p href and @p local in the context of the @p node.
 * Caller is responsible for freeing returned string with xmlFree.
 * @param node the context node.
 * @param href the QName href (can be NULL).
 * @param local the QName local part.
 * @return qname or NULL if an error occurs.
 */
xmlChar*
xmlSecGetQName(xmlNodePtr node, const xmlChar* href, const xmlChar* local) {
    xmlChar* qname;
    xmlNsPtr ns;
    int ret;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(local != NULL, NULL);

    /* we don't want to create namespace node ourselves because
     * it might cause collisions */
    ns = xmlSearchNsByHref(node->doc, node, href);
    if((ns == NULL) && (href != NULL)) {
        xmlSecXmlError2("xmlSearchNsByHref", NULL,
                        "node=%s", xmlSecErrorsSafeString(node->name));
        return(NULL);
    }

    if((ns != NULL) && (ns->prefix != NULL)) {
        xmlSecSize size;
        int len;

        len = xmlStrlen(local) + xmlStrlen(ns->prefix) + 4;
        XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(NULL), NULL);

        qname = (xmlChar *)xmlMalloc(size);
        if(qname == NULL) {
            xmlSecMallocError(size, NULL);
            return(NULL);
        }

        ret = xmlStrPrintf(qname, len, "%s:%s", ns->prefix, local);
        if(ret < 0) {
            xmlSecXmlError("xmlStrPrintf", NULL);
            xmlFree(qname);
            return(NULL);
        }
    } else {
        qname = xmlStrdup(local);
        if(qname == NULL) {
            xmlSecStrdupError(local, NULL);
            return(NULL);
        }
    }


    return(qname);
}


/******************************************************************************
 *
 * QName <-> Integer mapping
 *
  *****************************************************************************/
/**
 * @brief Maps integer @p intValue to a QName prefix.
 * @param info the qname<->integer mapping information.
 * @param intValue the integer value.
 * @return the QName info that is mapped to @p intValue or NULL if such value
 * is not found.
 */
xmlSecQName2IntegerInfoConstPtr
xmlSecQName2IntegerGetInfo(xmlSecQName2IntegerInfoConstPtr info, int intValue) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, NULL);

    for(ii = 0; info[ii].qnameLocalPart != NULL; ii++) {
        if(info[ii].intValue == intValue) {
            return(&info[ii]);
        }
    }

    return(NULL);
}

/**
 * @brief Maps a QName to an integer value.
 * @details Maps qname qname to an integer and returns it in @p intValue.
 * @param info the qname<->integer mapping information.
 * @param qnameHref the qname href value.
 * @param qnameLocalPart the qname local part value.
 * @param intValue the pointer to result integer value.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2IntegerGetInteger(xmlSecQName2IntegerInfoConstPtr info,
                             const xmlChar* qnameHref, const xmlChar* qnameLocalPart,
                             int* intValue) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(qnameLocalPart != NULL, -1);
    xmlSecAssert2(intValue != NULL, -1);

    for(ii = 0; info[ii].qnameLocalPart != NULL; ii++) {
        if(xmlStrEqual(info[ii].qnameLocalPart, qnameLocalPart) &&
           xmlStrEqual(info[ii].qnameHref, qnameHref)) {
            (*intValue) = info[ii].intValue;
            return(0);
        }
    }

    return(-1);
}

/**
 * @brief Converts a QName string to an integer value.
 * @details Converts @p qname into integer in context of @p node.
 * @param info the qname<->integer mapping information.
 * @param node the pointer to node.
 * @param qname the qname string.
 * @param intValue the pointer to result integer value.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2IntegerGetIntegerFromString(xmlSecQName2IntegerInfoConstPtr info,
                                        xmlNodePtr node, const xmlChar* qname,
                                        int* intValue) {
    const xmlChar* qnameLocalPart = NULL;
    xmlChar* qnamePrefix = NULL;
    const xmlChar* qnameHref;
    xmlNsPtr ns;
    int ret;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(qname != NULL, -1);
    xmlSecAssert2(intValue != NULL, -1);

    qnameLocalPart = xmlStrchr(qname, ':');
    if(qnameLocalPart != NULL) {
        int qnameLen;

        XMLSEC_SAFE_CAST_PTRDIFF_TO_INT((qnameLocalPart - qname), qnameLen, return(-1), NULL);
        qnamePrefix = xmlStrndup(qname, qnameLen);
        if(qnamePrefix == NULL) {
            xmlSecStrdupError(qname, NULL);
            return(-1);
        }
        qnameLocalPart++;
    } else {
        qnamePrefix = NULL;
        qnameLocalPart = qname;
    }

    /* search namespace href */
    ns = xmlSearchNs(node->doc, node, qnamePrefix);
    if((ns == NULL) && (qnamePrefix != NULL)) {
        xmlSecXmlError2("xmlSearchNs", NULL,
                        "node=%s", xmlSecErrorsSafeString(node->name));
        if(qnamePrefix != NULL) {
            xmlFree(qnamePrefix);
        }
        return(-1);
    }
    qnameHref = (ns != NULL) ? ns->href : BAD_CAST NULL;

    /* and finally search for integer */
    ret = xmlSecQName2IntegerGetInteger(info, qnameHref, qnameLocalPart, intValue);
    if(ret < 0) {
        xmlSecInternalError4("xmlSecQName2IntegerGetInteger", NULL,
                             "node=%s,qnameLocalPart=%s,qnameHref=%s",
                             xmlSecErrorsSafeString(node->name),
                             xmlSecErrorsSafeString(qnameLocalPart),
                             xmlSecErrorsSafeString(qnameHref));
        if(qnamePrefix != NULL) {
            xmlFree(qnamePrefix);
        }
        return(-1);
    }

    if(qnamePrefix != NULL) {
        xmlFree(qnamePrefix);
    }
    return(0);
}


/**
 * @brief Creates a QName string from an integer value.
 * @details Creates qname string for @p intValue in context of given @p node. Caller
 * is responsible for freeing returned string with @p xmlFree.
 * @param info the qname<->integer mapping information.
 * @param node the pointer to node.
 * @param intValue the integer value.
 * @return pointer to newly allocated string on success or NULL if an error occurs,
 */
xmlChar*
xmlSecQName2IntegerGetStringFromInteger(xmlSecQName2IntegerInfoConstPtr info,
                                        xmlNodePtr node, int intValue) {
    xmlSecQName2IntegerInfoConstPtr qnameInfo;

    xmlSecAssert2(info != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);

    qnameInfo = xmlSecQName2IntegerGetInfo(info, intValue);
    if(qnameInfo == NULL) {
        xmlSecInternalError3("xmlSecQName2IntegerGetInfo", NULL,
                             "node=%s,intValue=%d",
                             xmlSecErrorsSafeString(node->name),
                             intValue);
        return(NULL);
    }

    return (xmlSecGetQName(node, qnameInfo->qnameHref, qnameInfo->qnameLocalPart));
}

/**
 * @brief Reads a node's content and converts it to an integer using QName mapping.
 * @details Reads the content of @p node and converts it to an integer using mapping
 * from @p info.
 * @param info the qname<->integer mapping information.
 * @param node the pointer to node.
 * @param intValue the pointer to result integer value.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2IntegerNodeRead(xmlSecQName2IntegerInfoConstPtr info, xmlNodePtr node, int* intValue) {
    xmlChar* content = NULL;
    int ret;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(intValue != NULL, -1);

    content = xmlSecGetNodeContentAndTrim(node);
    if(content == NULL) {
        xmlSecInternalError2("xmlSecGetNodeContentAndTrim", NULL,
                        "node=%s", xmlSecErrorsSafeString(node->name));
        return(-1);
    }

    ret = xmlSecQName2IntegerGetIntegerFromString(info, node, content, intValue);
    if(ret < 0) {
        xmlSecInternalError3("xmlSecQName2IntegerGetIntegerFromString", NULL,
                             "node=%s,value=%s",
                             xmlSecErrorsSafeString(node->name),
                             xmlSecErrorsSafeString(content));
        xmlFree(content);
        return(-1);
    }

    xmlFree(content);
    return(0);
}

/**
 * @brief Creates a child node holding a QName string for an integer value.
 * @details Creates new child node in @p node and sets its value to @p intValue.
 * @param info the qname<->integer mapping information.
 * @param node the parent node.
 * @param nodeName the child node name.
 * @param nodeNs the child node namespace.
 * @param intValue the integer value.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2IntegerNodeWrite(xmlSecQName2IntegerInfoConstPtr info, xmlNodePtr node,
                            const xmlChar* nodeName, const xmlChar* nodeNs, int intValue) {
    xmlNodePtr cur;
    xmlChar* qname = NULL;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(nodeName != NULL, -1);

    /* find and build qname */
    qname = xmlSecQName2IntegerGetStringFromInteger(info, node, intValue);
    if(qname == NULL) {
        xmlSecInternalError3("xmlSecQName2IntegerGetStringFromInteger", NULL,
                             "node=%s,intValue=%d",
                             xmlSecErrorsSafeString(node->name),
                             intValue);
        return(-1);
    }

    cur = xmlSecAddChild(node, nodeName, nodeNs);
    if(cur == NULL) {
        xmlSecInternalError3("xmlSecAddChild", NULL,
                             "node=%s,intValue=%d",
                             xmlSecErrorsSafeString(nodeName),
                             intValue);
        xmlFree(qname);
        return(-1);
    }

    xmlNodeSetContent(cur, qname);
    xmlFree(qname);
    return(0);
}

/**
 * @brief Reads an attribute's QName value and converts it to an integer.
 * @details Gets the value of @p attrName atrtibute from @p node and converts it to integer
 * according to @p info.
 * @param info the qname<->integer mapping information.
 * @param node the element node.
 * @param attrName the attribute name.
 * @param intValue the pointer to result integer value.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2IntegerAttributeRead(xmlSecQName2IntegerInfoConstPtr info, xmlNodePtr node,
                            const xmlChar* attrName, int* intValue) {
    xmlChar* attrValue;
    int ret;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(attrName != NULL, -1);
    xmlSecAssert2(intValue != NULL, -1);

    attrValue = xmlGetProp(node, attrName);
    if(attrValue == NULL) {
        xmlSecXmlError2("xmlGetProp", NULL, "node=%s", xmlSecErrorsSafeString(node->name));
        return(-1);
    }
    /* todo: trim value? */

    ret = xmlSecQName2IntegerGetIntegerFromString(info, node, attrValue, intValue);
    if(ret < 0) {
        xmlSecInternalError4("xmlSecQName2IntegerGetIntegerFromString", NULL,
                             "node=%s,attrName=%s,attrValue=%s",
                             xmlSecErrorsSafeString(node->name),
                             xmlSecErrorsSafeString(attrName),
                             xmlSecErrorsSafeString(attrValue));
        xmlFree(attrValue);
        return(-1);
    }

    xmlFree(attrValue);
    return(0);
}

/**
 * @brief Converts an integer to a QName and sets it as an attribute value.
 * @details Converts @p intValue to a qname and sets it to the value of
 * attribute @p attrName in @p node.
 * @param info the qname<->integer mapping information.
 * @param node the parent node.
 * @param attrName the name of attribute.
 * @param intValue the integer value.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2IntegerAttributeWrite(xmlSecQName2IntegerInfoConstPtr info, xmlNodePtr node,
                            const xmlChar* attrName, int intValue) {
    xmlChar* qname;
    xmlAttrPtr attr;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(attrName != NULL, -1);

    /* find and build qname */
    qname = xmlSecQName2IntegerGetStringFromInteger(info, node, intValue);
    if(qname == NULL) {
        xmlSecInternalError4("xmlSecQName2IntegerGetStringFromInteger", NULL,
                             "node=%s,attrName=%s,intValue=%d",
                             xmlSecErrorsSafeString(node->name),
                             xmlSecErrorsSafeString(attrName),
                             intValue);
        return(-1);
    }

    attr = xmlSetProp(node, attrName, qname);
    if(attr == NULL) {
        xmlSecInternalError4("xmlSetProp", NULL,
                             "node=%s,attrName=%s,intValue=%d",
                             xmlSecErrorsSafeString(node->name),
                             xmlSecErrorsSafeString(attrName),
                             intValue);
        xmlFree(qname);
        return(-1);
    }

    xmlFree(qname);
    return(0);
}

/**
 * @brief Prints @p intValue into @p output.
 * @param info the qname<->integer mapping information.
 * @param intValue the integer value.
 * @param name the value name to print.
 * @param output the pointer to output FILE.
 */
void
xmlSecQName2IntegerDebugDump(xmlSecQName2IntegerInfoConstPtr info, int intValue,
                            const xmlChar* name, FILE* output) {
    xmlSecQName2IntegerInfoConstPtr qnameInfo;

    xmlSecAssert(info != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    qnameInfo = xmlSecQName2IntegerGetInfo(info, intValue);
    if(qnameInfo != NULL) {
        fprintf(output, "== %s: %d (name=\"%s\", href=\"%s\")\n", name, intValue,
            (qnameInfo->qnameLocalPart) ? qnameInfo->qnameLocalPart : BAD_CAST NULL,
            (qnameInfo->qnameHref) ? qnameInfo->qnameHref : BAD_CAST NULL);
    }
}

/**
 * @brief Prints @p intValue into @p output in XML format.
 * @param info the qname<->integer mapping information.
 * @param intValue the integer value.
 * @param name the value name to print.
 * @param output the pointer to output FILE.
 */
void
xmlSecQName2IntegerDebugXmlDump(xmlSecQName2IntegerInfoConstPtr info, int intValue,
                            const xmlChar* name, FILE* output) {
    xmlSecQName2IntegerInfoConstPtr qnameInfo;

    xmlSecAssert(info != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    qnameInfo = xmlSecQName2IntegerGetInfo(info, intValue);
    if(qnameInfo != NULL) {
        fprintf(output, "<%s value=\"%d\" href=\"%s\">%s<%s>\n", name, intValue,
            (qnameInfo->qnameHref) ? qnameInfo->qnameHref : BAD_CAST NULL,
            (qnameInfo->qnameLocalPart) ? qnameInfo->qnameLocalPart : BAD_CAST NULL,
            name);
    }
}


/******************************************************************************
 *
 * QName <-> Bits mask mapping
 *
  *****************************************************************************/
/**
 * @brief Converts @p mask to qname.
 * @param info the qname<->bit mask mapping information.
 * @param mask the bit mask.
 * @return pointer to the qname info for @p mask or NULL if mask is unknown.
 */
xmlSecQName2BitMaskInfoConstPtr
xmlSecQName2BitMaskGetInfo(xmlSecQName2BitMaskInfoConstPtr info, xmlSecBitMask mask) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, NULL);

    for(ii = 0; info[ii].qnameLocalPart != NULL; ii++) {
        xmlSecAssert2(info[ii].mask != 0, NULL);
        if(info[ii].mask == mask) {
            return(&info[ii]);
        }
    }

    return(NULL);
}

/**
 * @brief Converts @p qnameLocalPart to @p mask.
 * @param info the qname<->bit mask mapping information.
 * @param qnameHref the qname Href value.
 * @param qnameLocalPart the qname LocalPart value.
 * @param mask the pointer to result mask.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2BitMaskGetBitMask(xmlSecQName2BitMaskInfoConstPtr info,
                            const xmlChar* qnameHref, const xmlChar* qnameLocalPart,
                            xmlSecBitMask* mask) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(qnameLocalPart != NULL, -1);
    xmlSecAssert2(mask != NULL, -1);

    for(ii = 0; info[ii].qnameLocalPart != NULL; ii++) {
        xmlSecAssert2(info[ii].mask != 0, -1);
        if(xmlStrEqual(info[ii].qnameLocalPart, qnameLocalPart) &&
           xmlStrEqual(info[ii].qnameHref, qnameHref)) {

            (*mask) = info[ii].mask;
            return(0);
        }
    }

    return(-1);
}

/**
 * @brief Converts a QName string to a bit mask value.
 * @details Converts @p qname into integer in context of @p node.
 * @param info the qname<->integer mapping information.
 * @param node the pointer to node.
 * @param qname the qname string.
 * @param mask the pointer to result msk value.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2BitMaskGetBitMaskFromString(xmlSecQName2BitMaskInfoConstPtr info,
                                        xmlNodePtr node, const xmlChar* qname,
                                        xmlSecBitMask* mask) {
    const xmlChar* qnameLocalPart = NULL;
    xmlChar* qnamePrefix = NULL;
    const xmlChar* qnameHref;
    xmlNsPtr ns;
    int ret;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(qname != NULL, -1);
    xmlSecAssert2(mask != NULL, -1);

    qnameLocalPart = xmlStrchr(qname, ':');
    if(qnameLocalPart != NULL) {
        int qnameLen;

        XMLSEC_SAFE_CAST_PTRDIFF_TO_INT((qnameLocalPart - qname), qnameLen, return(-1), NULL);
        qnamePrefix = xmlStrndup(qname, qnameLen);
        if(qnamePrefix == NULL) {
            xmlSecStrdupError(qname, NULL);
            return(-1);
        }
        qnameLocalPart++;
    } else {
        qnamePrefix = NULL;
        qnameLocalPart = qname;
    }

    /* search namespace href */
    ns = xmlSearchNs(node->doc, node, qnamePrefix);
    if((ns == NULL) && (qnamePrefix != NULL)) {
        xmlSecXmlError2("xmlSearchNs", NULL,
                        "node=%s", xmlSecErrorsSafeString(node->name));
        if(qnamePrefix != NULL) {
            xmlFree(qnamePrefix);
        }
        return(-1);
    }
    qnameHref = (ns != NULL) ? ns->href : BAD_CAST NULL;

    /* and finally search for integer */
    ret = xmlSecQName2BitMaskGetBitMask(info, qnameHref, qnameLocalPart, mask);
    if(ret < 0) {
        xmlSecInternalError4("xmlSecQName2BitMaskGetBitMask", NULL,
                             "node=%s,qnameLocalPart=%s,qnameHref=%s",
                             xmlSecErrorsSafeString(node->name),
                             xmlSecErrorsSafeString(qnameLocalPart),
                             xmlSecErrorsSafeString(qnameHref));
        if(qnamePrefix != NULL) {
            xmlFree(qnamePrefix);
        }
        return(-1);
    }

    if(qnamePrefix != NULL) {
        xmlFree(qnamePrefix);
    }
    return(0);
}


/**
 * @brief Creates a QName string from a bit mask value.
 * @details Creates qname string for @p mask in context of given @p node. Caller
 * is responsible for freeing returned string with xmlFree.
 * @param info the qname<->integer mapping information.
 * @param node the pointer to node.
 * @param mask the mask.
 * @return pointer to newly allocated string on success or NULL if an error occurs,
 */
xmlChar*
xmlSecQName2BitMaskGetStringFromBitMask(xmlSecQName2BitMaskInfoConstPtr info,
                                        xmlNodePtr node, xmlSecBitMask mask) {
    xmlSecQName2BitMaskInfoConstPtr qnameInfo;

    xmlSecAssert2(info != NULL, NULL);
    xmlSecAssert2(node != NULL, NULL);

    qnameInfo = xmlSecQName2BitMaskGetInfo(info, mask);
    if(qnameInfo == NULL) {
        xmlSecInternalError3("xmlSecQName2BitMaskGetInfo", NULL,
            "node=%s,mask=%u", xmlSecErrorsSafeString(node->name), mask);
        return(NULL);
    }

    return(xmlSecGetQName(node, qnameInfo->qnameHref, qnameInfo->qnameLocalPart));
}

/**
 * @brief Reads QName elements and accumulates their values into a bit mask.
 * @details Reads <@p nodeNs:@p nodeName> elements and puts the result bit mask
 * into @p mask. When function exits, @p node points to the first element node
 * after all the <@p nodeNs:@p nodeName> elements.
 * @param info the qname<->bit mask mapping information.
 * @param node the start.
 * @param nodeName the mask nodes name.
 * @param nodeNs the mask nodes namespace.
 * @param stopOnUnknown if this flag is set then function exits if unknown
 *                      value was found.
 * @param mask the pointer to result mask.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2BitMaskNodesRead(xmlSecQName2BitMaskInfoConstPtr info, xmlNodePtr* node,
                            const xmlChar* nodeName, const xmlChar* nodeNs,
                            int stopOnUnknown, xmlSecBitMask* mask) {
    xmlNodePtr cur;
    xmlChar* content;
    xmlSecBitMask tmp;
    int ret;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(mask != NULL, -1);

    (*mask) = 0;
    cur = (*node);
    while((cur != NULL) && (xmlSecCheckNodeName(cur, nodeName, nodeNs))) {
        content = xmlSecGetNodeContentAndTrim(cur);
        if(content == NULL) {
            xmlSecInternalError2("xmlSecGetNodeContentAndTrim", NULL,
                            "node=%s", xmlSecErrorsSafeString(cur->name));
            return(-1);
        }

        ret = xmlSecQName2BitMaskGetBitMaskFromString(info, cur, content, &tmp);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecQName2BitMaskGetBitMaskFromString", NULL,
                                 "value=%s", xmlSecErrorsSafeString(content));
            xmlFree(content);
            return(-1);
        }
        xmlFree(content);

        if((stopOnUnknown != 0) && (tmp == 0)) {
            /* todo: better error */
            xmlSecInternalError2("xmlSecQName2BitMaskGetBitMaskFromString", NULL,
                                 "value=%s", xmlSecErrorsSafeString(content));
            return(-1);
        }

        (*mask) |= tmp;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    (*node) = cur;
    return(0);
}

/**
 * @brief Writes bit mask values as QName child elements.
 * @details Writes <@p nodeNs:@p nodeName> elemnts with values from @p mask to @p node.
 * @param info the qname<->bit mask mapping information.
 * @param node the parent element for mask nodes.
 * @param nodeName the mask nodes name.
 * @param nodeNs the mask nodes namespace.
 * @param mask the bit mask.
 * @return 0 on success or a negative value if an error occurs,
 */
int
xmlSecQName2BitMaskNodesWrite(xmlSecQName2BitMaskInfoConstPtr info, xmlNodePtr node,
                            const xmlChar* nodeName, const xmlChar* nodeNs,
                            xmlSecBitMask mask) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(nodeName != NULL, -1);

    for(ii = 0; (mask != 0) && (info[ii].qnameLocalPart != NULL); ii++) {
        xmlSecAssert2(info[ii].mask != 0, -1);

        if((mask & info[ii].mask) != 0) {
            xmlNodePtr cur;
            xmlChar* qname;

            qname = xmlSecGetQName(node, info[ii].qnameHref, info[ii].qnameLocalPart);
            if(qname == NULL) {
                xmlSecXmlError2("xmlSecGetQName", NULL,
                                "node=%s", xmlSecErrorsSafeString(nodeName));
                return(-1);
            }

            cur = xmlSecAddChild(node, nodeName, nodeNs);
            if(cur == NULL) {
                xmlSecXmlError2("xmlSecAddChild", NULL,
                                "node=%s", xmlSecErrorsSafeString(nodeName));
                xmlFree(qname);
                return(-1);
            }

            xmlNodeSetContent(cur, qname);
            xmlFree(qname);
        }
    }
    return(0);
}

/**
 * @brief Prints debug information about a bit mask.
 * @details Prints debug information about @p mask to @p output.
 * @param info the qname<->bit mask mapping information.
 * @param mask the bit mask.
 * @param name the value name to print.
 * @param output the pointer to output FILE.
 */
void
xmlSecQName2BitMaskDebugDump(xmlSecQName2BitMaskInfoConstPtr info, xmlSecBitMask mask,
                            const xmlChar* name, FILE* output) {
    unsigned int ii;

    xmlSecAssert(info != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    if(mask == 0) {
        return;
    }

    fprintf(output, "== %s (0x%08x): ", name, mask);
    for(ii = 0; (mask != 0) && (info[ii].qnameLocalPart != NULL); ii++) {
        xmlSecAssert(info[ii].mask != 0);

        if((mask & info[ii].mask) != 0) {
            fprintf(output, "name=\"%s\" (href=\"%s\"),", info[ii].qnameLocalPart, info[ii].qnameHref);
        }
    }
    fprintf(output, "\n");
}

/**
 * @brief Prints debug information about a bit mask in XML format.
 * @details Prints debug information about @p mask to @p output in XML format.
 * @param info the qname<->bit mask mapping information.
 * @param mask the bit mask.
 * @param name the value name to print.
 * @param output the pointer to output FILE.
 */
void
xmlSecQName2BitMaskDebugXmlDump(xmlSecQName2BitMaskInfoConstPtr info, xmlSecBitMask mask,
                            const xmlChar* name, FILE* output) {
    unsigned int ii;

    xmlSecAssert(info != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    if(mask == 0) {
        return;
    }

    fprintf(output, "<%sList>\n", name);
    for(ii = 0; (mask != 0) && (info[ii].qnameLocalPart != NULL); ii++) {
        xmlSecAssert(info[ii].mask != 0);

        if((mask & info[ii].mask) != 0) {
            fprintf(output, "<%s href=\"%s\">%s</%s>\n", name,
                    info[ii].qnameHref, info[ii].qnameLocalPart, name);
        }
    }
    fprintf(output, "</%sList>\n", name);
}

/******************************************************************************
 *
 * Windows string conversions
 *
  *****************************************************************************/
#if defined(XMLSEC_WINDOWS)

/**
 * @brief Converts input string from UTF8 to Unicode.
 * @param str the string to convert.
 * @return a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
LPWSTR
xmlSecWin32ConvertUtf8ToUnicode(const xmlChar* str) {
    LPWSTR res = NULL;
    xmlSecSize size;
    int len;
    int ret;

    xmlSecAssert2(str != NULL, NULL);

    /* call MultiByteToWideChar first to get the buffer size */
    ret = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, -1, NULL, 0);
    if(ret <= 0) {
        return(NULL);
    }
    len = ret + 1;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(NULL), NULL);

    /* allocate buffer */
    res = (LPWSTR)xmlMalloc(sizeof(WCHAR) * size);
    if(res == NULL) {
        xmlSecMallocError(sizeof(WCHAR) * size, NULL);
        return(NULL);
    }

    /* convert */
    ret = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)str, -1, res, len);
    if(ret <= 0) {
        xmlFree(res);
        return(NULL);
    }

    /* done */
    return(res);
}

/**
 * @brief Converts input string from Unicode to UTF8.
 * @param str the string to convert.
 * @return a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
xmlChar*
xmlSecWin32ConvertUnicodeToUtf8(LPCWSTR str) {
    xmlChar * res = NULL;
    xmlSecSize size;
    int len;
    int ret;

    xmlSecAssert2(str != NULL, NULL);

    /* call WideCharToMultiByte first to get the buffer size */
    ret = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    if(ret <= 0) {
        return(NULL);
    }
    len = ret + 1;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(NULL), NULL);

    /* allocate buffer */
    res = (xmlChar*)xmlMalloc(sizeof(xmlChar) * size);
    if(res == NULL) {
        xmlSecMallocError(sizeof(xmlChar) * size, NULL);
        return(NULL);
    }

    /* convert */
    ret = WideCharToMultiByte(CP_UTF8, 0, str, -1, (LPSTR)res, len, NULL, NULL);
    if(ret <= 0) {
        xmlFree(res);
        return(NULL);
    }

    /* done */
    return(res);
}

/**
 * @brief Converts input string from current system locale to Unicode.
 * @param str the string to convert.
 * @return a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
LPWSTR
xmlSecWin32ConvertLocaleToUnicode(const char* str) {
    LPWSTR res = NULL;
    xmlSecSize size;
    int len;
    int ret;

    xmlSecAssert2(str != NULL, NULL);

    /* call MultiByteToWideChar first to get the buffer size */
    ret = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    if(ret <= 0) {
        return(NULL);
    }
    len = ret + 1;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(NULL), NULL);

    /* allocate buffer */
    res = (LPWSTR)xmlMalloc(sizeof(WCHAR) * size);
    if(res == NULL) {
        xmlSecMallocError(sizeof(WCHAR) * size, NULL);
        return(NULL);
    }

    /* convert */
    ret = MultiByteToWideChar(CP_ACP, 0, str, -1, res, len);
    if(ret <= 0) {
        xmlFree(res);
        return(NULL);
    }

    /* done */
    return(res);
}

/**
 * @brief Converts input string from locale to UTF8.
 * @param str the string to convert.
 * @return a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
xmlChar*
xmlSecWin32ConvertLocaleToUtf8(const char * str) {
    LPWSTR strW = NULL;
    xmlChar * res = NULL;
    xmlSecSize size;
    int len;
    int ret;

    xmlSecAssert2(str != NULL, NULL);

    strW = xmlSecWin32ConvertLocaleToUnicode(str);
    if(strW == NULL) {
        return(NULL);
    }

    /* call WideCharToMultiByte first to get the buffer size */
    ret = WideCharToMultiByte(CP_ACP, 0, strW, -1, NULL, 0, NULL, NULL);
    if(ret <= 0) {
        xmlFree(strW);
        return(NULL);
    }
    len = ret + 1;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(NULL), NULL);

    /* allocate buffer */
    res = (xmlChar*)xmlMalloc(sizeof(xmlChar) * size);
    if(res == NULL) {
        xmlSecMallocError(sizeof(xmlChar) * size, NULL);
        xmlFree(strW);
        return(NULL);
    }

    /* convert */
    ret = WideCharToMultiByte(CP_ACP, 0, strW, -1, (LPSTR)res, len, NULL, NULL);
    if(ret <= 0) {
        xmlFree(strW);
        xmlFree(res);
        return(NULL);
    }

    /* done */
    xmlFree(strW);
    return(res);
}

/**
 * @brief Converts input string from UTF8 to locale.
 * @param str the string to convert.
 * @return a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
char *
xmlSecWin32ConvertUtf8ToLocale(const xmlChar* str) {
    LPWSTR strW = NULL;
    char * res = NULL;
    xmlSecSize size;
    int len;
    int ret;

    xmlSecAssert2(str != NULL, NULL);

    strW = xmlSecWin32ConvertUtf8ToUnicode(str);
    if(strW == NULL) {
        return(NULL);
    }

    /* call WideCharToMultiByte first to get the buffer size */
    ret = WideCharToMultiByte(CP_ACP, 0, strW, -1, NULL, 0, NULL, NULL);
    if(ret <= 0) {
        xmlFree(strW);
        return(NULL);
    }
    len = ret + 1;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(NULL), NULL);

    /* allocate buffer */
    res = (char*)xmlMalloc(sizeof(char) * size);
    if(res == NULL) {
        xmlSecMallocError(sizeof(char) * size, NULL);
        xmlFree(strW);
        return(NULL);
    }

    /* convert */
    ret = WideCharToMultiByte(CP_ACP, 0, strW, -1, res, len, NULL, NULL);
    if(ret <= 0) {
        xmlFree(strW);
        xmlFree(res);
        return(NULL);
    }

    /* done */
    xmlFree(strW);
    return(res);
}

/**
 * @brief Converts a TSTR string (locale or Unicode) to UTF-8.
 * @details Converts input string from TSTR (locale or Unicode) to UTF8.
 * @param str the string to convert.
 * @return a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
xmlChar*
xmlSecWin32ConvertTstrToUtf8(LPCTSTR str) {
#ifdef UNICODE
    return xmlSecWin32ConvertUnicodeToUtf8(str);
#else  /* UNICODE */
    return xmlSecWin32ConvertLocaleToUtf8(str);
#endif /* UNICODE */
}

/**
 * @brief Converts a UTF-8 string to TSTR (locale or Unicode).
 * @details Converts input string from UTF8 to TSTR (locale or Unicode).
 * @param str the string to convert.
 * @return a pointer to newly allocated string (must be freed with xmlFree) or NULL if an error occurs.
 */
LPTSTR
xmlSecWin32ConvertUtf8ToTstr(const xmlChar*  str) {
#ifdef UNICODE
    return xmlSecWin32ConvertUtf8ToUnicode(str);
#else  /* UNICODE */
    return xmlSecWin32ConvertUtf8ToLocale(str);
#endif /* UNICODE */
}

#endif /* defined(XMLSEC_WINDOWS) */
