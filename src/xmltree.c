/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Common XML Doc utility functions
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
 
#include <libxml/tree.h>
#include <libxml/valid.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/parser.h>
#include <xmlsec/errors.h>

/**
 * xmlSecFindChild:
 * @parent: 		the pointer to XML node.
 * @name: 		the name.
 * @ns: 		the namespace href (may be NULL).
 *
 * Searches a direct child of the @parent node having given name and 
 * namespace href.
 * 
 * Returns the pointer to the found node or NULL if an error occurs or 
 * node is not found.
 */
xmlNodePtr
xmlSecFindChild(const xmlNodePtr parent, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur;
        
    xmlSecAssert2(parent != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);
    
    cur = parent->children;
    while(cur != NULL) {
        if(cur->type == XML_ELEMENT_NODE) {
	    if(xmlSecCheckNodeName(cur, name, ns)) {
		return(cur);
	    }
	}
	cur = cur->next;
    }
    return(NULL);
}

/**
 * xmlSecFindParent:
 * @cur: 		the pointer to an XML node.
 * @name: 		the name.
 * @ns: 		the namespace href (may be NULL).
 *
 * Searches the ancestors axis of the @cur node for a node having given name 
 * and namespace href.
 * 
 * Returns the pointer to the found node or NULL if an error occurs or 
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
 * xmlSecFindNode:
 * @parent: 		the pointer to XML node.
 * @name: 		the name.
 * @ns: 		the namespace href (may be NULL).
 *
 * Searches all children of the @parent node having given name and 
 * namespace href.
 * 
 * Returns the pointer to the found node or NULL if an error occurs or 
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
 * xmlSecGetNodeNsHref:
 * @cur:		the pointer to node.
 *
 * Get's node's namespace href.
 *
 * Returns node's namespace href.
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
 * xmlSecCheckNodeName:
 * @cur: 		the pointer to an XML node.
 * @name: 		the name,
 * @ns: 		the namespace href.
 *
 * Checks that the node has a given name and a given namespace href.
 *
 * Returns 1 if the node matches or 0 otherwise.
 */
int
xmlSecCheckNodeName(const xmlNodePtr cur, const xmlChar *name, const xmlChar *ns) {
    xmlSecAssert2(cur != NULL, 0);
    
    return(xmlStrEqual(cur->name, name) && 
	   xmlStrEqual(xmlSecGetNodeNsHref(cur), ns));
}

/**
 * xmlSecAddChild:
 * @parent: 		the pointer to an XML node.
 * @name: 		the new node name.
 * @ns: 		the new node namespace.
 *
 * Adds a child to the node @parent with given @name and namespace @ns.
 *
 * Returns pointer to the new node or NULL if an error occurs.
 */
xmlNodePtr		
xmlSecAddChild(xmlNodePtr parent, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur;
    xmlNodePtr text;

    xmlSecAssert2(parent != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);        

    if(parent->children == NULL) {
        /* TODO: add indents */
	text = xmlNewText(BAD_CAST "\n"); 
        if(text == NULL) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlNewText",
			XMLSEC_ERRORS_R_XML_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(NULL);
	}
	xmlAddChild(parent, text);
    }

    cur = xmlNewChild(parent, NULL, name, NULL);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewChild",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    /* namespaces support */
    if(ns != NULL) {
	xmlNsPtr nsPtr;
	
	nsPtr = xmlSearchNs(cur->doc, cur, NULL);
	if((nsPtr == NULL) || !xmlStrEqual(nsPtr->href, ns)) {
	    nsPtr = xmlNewNs(cur, ns, NULL);
	    xmlSetNs(cur, nsPtr);
	}
    }
    
    /* TODO: add indents */
    text = xmlNewText(BAD_CAST "\n"); 
    if(text == NULL) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewText",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    xmlAddChild(parent, text);

    return(cur);
}

/**
 * xmlSecAddChildNode:
 * @parent: 		the pointer to an XML node.
 * @child: 		the new node.
 *
 * Adds @child node to the @parent node.
 *
 * Returns pointer to the new node or NULL if an error occurs.
 */
xmlNodePtr		
xmlSecAddChildNode(xmlNodePtr parent, xmlNodePtr child) {
    xmlNodePtr text;

    xmlSecAssert2(parent != NULL, NULL);
    xmlSecAssert2(child != NULL, NULL);        

    if(parent->children == NULL) {
        /* TODO: add indents */
	text = xmlNewText(BAD_CAST "\n"); 
        if(text == NULL) {	
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlNewText",
			XMLSEC_ERRORS_R_XML_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(NULL);
	}
	xmlAddChild(parent, text);
    }

    xmlAddChild(parent, child);

    /* TODO: add indents */
    text = xmlNewText(BAD_CAST "\n"); 
    if(text == NULL) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewText",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    xmlAddChild(parent, text);

    return(child);
}

/**
 * xmlSecAddNextSibling
 * @node: 		the pointer to an XML node.
 * @name: 		the new node name.
 * @ns: 		the new node namespace.
 *
 * Adds next sibling to the node @node with given @name and namespace @ns.
 *
 * Returns pointer to the new node or NULL if an error occurs.
 */
xmlNodePtr
xmlSecAddNextSibling(xmlNodePtr node, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur;
    xmlNodePtr text;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);    

    cur = xmlNewNode(NULL, name);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    xmlAddNextSibling(node, cur);

    /* namespaces support */
    if(ns != NULL) {
	xmlNsPtr nsPtr;
	
	nsPtr = xmlSearchNs(cur->doc, cur, NULL);
	if((nsPtr == NULL) || !xmlStrEqual(nsPtr->href, ns)) {
	    nsPtr = xmlNewNs(cur, ns, NULL);
	}
    }

    /* TODO: add indents */
    text = xmlNewText(BAD_CAST "\n");
    if(text == NULL) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewText",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    xmlAddNextSibling(node, text);
    
    return(cur);
}

/**
 * xmlSecAddPrevSibling
 * @node: 		the pointer to an XML node.
 * @name: 		the new node name.
 * @ns: 		the new node namespace.
 *
 * Adds prev sibling to the node @node with given @name and namespace @ns.
 *
 * Returns pointer to the new node or NULL if an error occurs.
 */
xmlNodePtr
xmlSecAddPrevSibling(xmlNodePtr node, const xmlChar *name, const xmlChar *ns) {
    xmlNodePtr cur;
    xmlNodePtr text;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(name != NULL, NULL);    

    cur = xmlNewNode(NULL, name);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    xmlAddPrevSibling(node, cur);

    /* namespaces support */
    if(ns != NULL) {
	xmlNsPtr nsPtr;
	
	nsPtr = xmlSearchNs(cur->doc, cur, NULL);
	if((nsPtr == NULL) || !xmlStrEqual(nsPtr->href, ns)) {
	    nsPtr = xmlNewNs(cur, ns, NULL);
	}
    }

    /* TODO: add indents */
    text = xmlNewText(BAD_CAST "\n");
    if(text == NULL) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewText",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    xmlAddPrevSibling(node, text);

    return(cur);
}

/**
 * xmlSecGetNextElementNode:
 * @cur: 		the pointer to an XML node.
 *
 * Seraches for the next element node.
 *
 * Returns the pointer to next element node or NULL if it is not found.
 */
xmlNodePtr
xmlSecGetNextElementNode(xmlNodePtr cur) {
    
    while((cur != NULL) && (cur->type != XML_ELEMENT_NODE)) {
	cur = cur->next;
    }
    return(cur);
}

/**
 * xmlSecReplaceNode:
 * @node: 		the current node.
 * @newNode: 		the new node.
 * 
 * Swaps the @node and @newNode in the XML tree.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceNode(xmlNodePtr node, xmlNodePtr newNode) {
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
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
                    "xmlReplaceNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    if(restoreRoot != 0) {
	xmlDocSetRootElement(oldNode->doc, newNode);
    }

    xmlFreeNode(oldNode);
    return(0);
}

/**
 * xmlSecReplaceContent
 * @node: 		the current node.
 * @newNode: 		the new node.
 * 
 * Swaps the content of @node and @newNode.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceContent(xmlNodePtr node, xmlNodePtr newNode) {
    xmlNodePtr dummy;
    xmlNodePtr ptr;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(newNode != NULL, -1);  
	    
    dummy = xmlNewDocNode(newNode->doc, NULL, BAD_CAST "dummy", NULL);
    if(dummy == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewDocNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "node=dummy");
	return(-1);
    }
	    
    if(newNode == xmlDocGetRootElement(newNode->doc)) {
	ptr = xmlDocSetRootElement(newNode->doc, dummy);
    } else {
	ptr = xmlReplaceNode(newNode, dummy);
    }
    if(ptr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlDocSetRootElement or xmlReplaceNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFreeNode(dummy);
	return(-1);
    }
	    
    xmlNodeSetContent(node, NULL);
    xmlAddChild(node, ptr);
    xmlSetTreeDoc(ptr, node->doc);
    return(0);
}


/**
 * xmlSecReplaceNodeBuffer:
 * @node: 		the current node.
 * @buffer: 		the XML data.
 * @size: 		the XML data size.
 * 
 * Swaps the @node and the parsed XML data from the @buffer in the XML tree.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceNodeBuffer(xmlNodePtr node, 
			const xmlSecByte *buffer, xmlSecSize size) {
    static const char dummyPrefix[] = "<dummy>";
    static const char dummyPostfix[] = "</dummy>";
    xmlDocPtr doc;
    xmlNodePtr ptr1, ptr2;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);    
    
    doc = xmlSecParseMemoryExt((xmlSecByte*)dummyPrefix, strlen(dummyPrefix),
			       buffer, size,
			       (xmlSecByte*)dummyPostfix, strlen(dummyPostfix));
    if(doc == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecParseMemoryExt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    	
    }
	    
    ptr1 = xmlDocGetRootElement(doc);
    if(ptr1 == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlDocGetRootElement",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "root is null");
	xmlFreeDoc(doc);
	return(-1);	    	
    }
    
    ptr1 = ptr1->children;
    while(ptr1 != NULL) {
	ptr2 = ptr1->next;
	xmlUnlinkNode(ptr1);
	xmlAddPrevSibling(node, ptr1);
	ptr1 = ptr2;
    }
	    
    xmlUnlinkNode(node);
    xmlFreeNode(node);  
    xmlFreeDoc(doc);
    return(0);
}

/**
 * xmlSecAddIDs:
 * @doc: 		the pointer to an XML document.
 * @cur: 		the pointer to an XML node.
 * @ids: 		the pointer to a NULL terminated list of ID attributes.
 *
 * Walks thru all children of the @cur node and adds all attributes 
 * from the @ids list to the @doc document IDs attributes hash.
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
			    xmlSecError(XMLSEC_ERRORS_HERE,
					NULL,
					NULL,
					XMLSEC_ERRORS_R_INVALID_DATA,
					"id=%s already defined", 
					xmlSecErrorsSafeString(name));
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
 * xmlSecCreateTree:
 * @rootNodeName:	the root node name.
 * @rootNodeNs:		the root node namespace (otpional).
 *
 * Creates a new XML tree with one root node @rootNodeName.
 *
 * Returns pointer to the newly created tree or NULL if an error occurs.
 */
xmlDocPtr 
xmlSecCreateTree(const xmlChar* rootNodeName, const xmlChar* rootNodeNs) {
    xmlDocPtr doc;
    xmlNodePtr root;

    xmlSecAssert2(rootNodeName != NULL, NULL);

    /* create doc */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewDoc",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }
    
    /* create root node */
    root = xmlNewDocNode(doc, NULL, rootNodeName, NULL); 
    if(root == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,	
		    NULL,
		    "xmlNewDocNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "node=Keys");
	xmlFreeDoc(doc);
	return(NULL);
    }
    xmlDocSetRootElement(doc, root);

    /* and set root node namespace */
    if(xmlNewNs(root, rootNodeNs, NULL) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNewNs",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "ns=%s",
		    xmlSecErrorsSafeString(rootNodeNs));
	xmlFreeDoc(doc); 
	return(NULL);
    }

    return(doc);
}

/**
 * xmlSecIsEmptyNode:
 * @node:		the node to check
 *
 * Checks whethere the @node is empty (i.e. has only whitespaces children).
 *
 * Returns 1 if @node is empty, 0 otherwise or a negative value if an error occurs.
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
 * xmlSecIsEmptyString:
 * @str:		the string to check
 *
 * Checks whethere the @str is empty (i.e. has only whitespaces children).
 *
 * Returns 1 if @str is empty, 0 otherwise or a negative value if an error occurs.
 */
int 
xmlSecIsEmptyString(const xmlChar* str) {
    xmlSecAssert2(str != NULL, -1);
    
    for( ;*str != '\0'; ++str) {
	if(!isspace((int)(*str))) {
	    return(0);
	}
    }
    return(1);
}


/*************************************************************************
 *
 * String <-> Integer mapping
 *
 ************************************************************************/
/** 
 * xmlSecString2IntegerGetString:
 * @info:               the string<->integer mapping information.
 * @intValue:           the integer value.
 *
 * Maps integer @intValue to a string.
 * 
 * Returns the string that is mapped to @intValue or NULL if such value
 * is not found.
 */
const xmlChar* 
xmlSecString2IntegerGetString(xmlSecString2IntegerInfoConstPtr info, int intValue) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, NULL);

    for(ii = 0; info[ii].strValue != NULL; ii++) {
        if(info[ii].intValue == intValue) {
            return(info[ii].strValue);
        }
    }

    return(NULL);
}

/** 
 * xmlSecString2IntegerGetInteger:
 * @info:               the string<->integer mapping information.
 * @strValue:           the string value.
 * @intValue:           the pointer to result integer value.
 * 
 * Maps string @strValue to an integer and returns it in @intValue.
 * 
 * Returns 0 on success or a negative value if an error occurs,
 */
int 
xmlSecString2IntegerGetInteger(xmlSecString2IntegerInfoConstPtr info, const xmlChar* strValue, int* intValue) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(strValue != NULL, -1);
    xmlSecAssert2(intValue != NULL, -1);

    for(ii = 0; info[ii].strValue != NULL; ii++) {
        if(xmlStrcmp(info[ii].strValue, strValue) == 0) {
            (*intValue) = info[ii].intValue;
            return(0);
        }
    }

    return(-1);
}

/** 
 * xmlSecString2IntegerNodeRead:
 * @info:               the string<->integer mapping information.
 * @node:               the pointer to node.
 * @intValue:           the pointer to result integer value.
 * 
 * Reads the content of @node and converts it to an integer using mapping 
 * from @info.
 * 
 * Returns 0 on success or a negative value if an error occurs,
 */
int 
xmlSecString2IntegerNodeRead(xmlSecString2IntegerInfoConstPtr info, xmlNodePtr node, int* intValue) {
    xmlChar* content;
    int ret;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(intValue != NULL, -1);

    content = xmlNodeGetContent(node);
    if(content == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNodeGetContent",
	    	    XMLSEC_ERRORS_R_XML_FAILED,
		    "node=%s",
		    xmlSecErrorsSafeString(node->name));
	return(-1);	
    }

    ret = xmlSecString2IntegerGetInteger(info, content, intValue);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecString2IntegerGetInteger",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s,content=%s",
		    xmlSecErrorsSafeString(node->name),
                    xmlSecErrorsSafeString(content));
        xmlFree(content);
	return(-1);	
    }

    xmlFree(content);
    return(0);
}

/** 
 * xmlSecString2IntegerNodeWrite:
 * @info:               the string<->integer mapping information.
 * @parent:             the parent node.
 * @nodeName:           the child node name.
 * @nodeNs:             the child node namespace.
 * @intValue:           the integer value.
 * 
 * Creates new child node in @parent and sets its value to @intValue.
 * 
 * Returns 0 on success or a negative value if an error occurs,
 */
int 
xmlSecString2IntegerNodeWrite(xmlSecString2IntegerInfoConstPtr info, xmlNodePtr parent,
			    const xmlChar* nodeName, const xmlChar* nodeNs, int intValue) {
    const xmlChar* strValue;
    xmlNodePtr cur;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(parent != NULL, -1);
    xmlSecAssert2(nodeName != NULL, -1);

    strValue = xmlSecString2IntegerGetString(info, intValue);
    if(strValue == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecString2IntegerGetString",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s,intValue=%d",
		    xmlSecErrorsSafeString(nodeName),
                    intValue);
        return(-1);
    }

    cur = xmlSecAddChild(parent, nodeName, nodeNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChild",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s,intValue=%d",
		    xmlSecErrorsSafeString(nodeName),
                    intValue);
        return(-1);
    }

    xmlNodeSetContent(cur, strValue);
    return(0);
}

/** 
 * xmlSecString2IntegerAttributeRead:
 * @info:               the string<->integer mapping information.
 * @node:               the element node. 
 * @attrName:           the attribute name.
 * @intValue:           the pointer to result integer value.
 * 
 * Gets the value of @attrName atrtibute from @node and converts it to integer
 * according to @info.
 * 
 * Returns 0 on success or a negative value if an error occurs,
 */
int 
xmlSecString2IntegerAttributeRead(xmlSecString2IntegerInfoConstPtr info, xmlNodePtr node,
			    const xmlChar* attrName, int* intValue) {
    xmlChar* attrValue;
    int ret;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(attrName != NULL, -1);
    xmlSecAssert2(intValue != NULL, -1);

    attrValue = xmlGetProp(node, attrName);
    if(attrValue == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlGetProp",
	    	    XMLSEC_ERRORS_R_XML_FAILED,
		    "node=%s,attrValue=%s",
		    xmlSecErrorsSafeString(node->name),
                    xmlSecErrorsSafeString(attrName));
	return(-1);	
    }

    ret = xmlSecString2IntegerGetInteger(info, attrValue, intValue);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecString2IntegerGetInteger",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
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
 * xmlSecString2IntegerAttributeWrite:
 * @info:               the string<->integer mapping information.
 * @parent:             the parent node.
 * @attrName:           the name of attribute.
 * @intValue:           the integer value.
 * 
 * Converts @intValue to a string and sets it to the value of 
 * attribute @attrName in @parent.
 * 
 * Returns 0 on success or a negative value if an error occurs,
 */
int
xmlSecString2IntegerAttributeWrite(xmlSecString2IntegerInfoConstPtr info, xmlNodePtr parent,
                            const xmlChar* attrName, int intValue) {
    const xmlChar* strValue;
    xmlAttrPtr attr;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(parent != NULL, -1);
    xmlSecAssert2(attrName != NULL, -1);

    strValue = xmlSecString2IntegerGetString(info, intValue);
    if(strValue == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecString2IntegerGetString",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s,attrName=%s,intValue=%d",
		    xmlSecErrorsSafeString(parent->name),
		    xmlSecErrorsSafeString(attrName),
                    intValue);
        return(-1);
    }

    attr = xmlSetProp(parent, attrName, strValue);
    if(attr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecAddChildNode",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "node=%s,attrName=%s,intValue=%d",
		    xmlSecErrorsSafeString(parent->name),
		    xmlSecErrorsSafeString(attrName),
                    intValue);
        return(-1);
    }

    return(0);
}

/** 
 * xmlSecString2IntegerDebugDump:
 * @info:               the string<->integer mapping information.
 * @intValue:           the integer value.
 * @output:             the pointer to output FILE.
 * 
 * Prints @intValue into @output.
 */
void 
xmlSecString2IntegerDebugDump(xmlSecString2IntegerInfoConstPtr info, int intValue,
                            const xmlChar* name, FILE* output) {
    const xmlChar* strValue;

    xmlSecAssert(info != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    strValue = xmlSecString2IntegerGetString(info, intValue);
    if(strValue != NULL) {
        fprintf(output, "== %s: %d (\"%s\")\n", name, intValue, strValue);
    }    
}

/** 
 * xmlSecString2IntegerDebugXmlDump:
 * @info:               the string<->integer mapping information.
 * @intValue:           the integer value.
 * @output:             the pointer to output FILE.
 * 
 * Prints @intValue into @output in XML format. 
 */
void 
xmlSecString2IntegerDebugXmlDump(xmlSecString2IntegerInfoConstPtr info, int intValue,
			    const xmlChar* name, FILE* output) {
    const xmlChar* strValue;

    xmlSecAssert(info != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    strValue = xmlSecString2IntegerGetString(info, intValue);
    if(strValue != NULL) {
        fprintf(output, "<%s value=\"%d\">%s</%s>\n", name, intValue, strValue, name);
    }    
}
								 

/*************************************************************************
 *
 * String <-> Bits mask mapping
 *
 ************************************************************************/
/** 
 * xmlSecString2BitMaskGetString:
 * @info:               the string<->bit mask mapping information.
 * @mask:               the bit mask.
 * 
 * Converts @mask to string.
 *
 * Returns the string that is mapped to @mask.
 */
const xmlChar*	
xmlSecString2BitMaskGetString(xmlSecString2BitMaskInfoConstPtr info, xmlSecBitMask mask) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, NULL);

    for(ii = 0; info[ii].strValue != NULL; ii++) {
        xmlSecAssert2(info[ii].mask != 0, NULL);
        if(info[ii].mask == mask) {
            return(info[ii].strValue);
        }
    }

    return(NULL);
}

/** 
 * xmlSecString2BitMaskGetBitMask:
 * @info:               the string<->bit mask mapping information.
 * @strValue:           the string value.
 * @mask:               the pointer to result mask.
 * 
 * Converts @strValue to @mask.
 * 
 * Returns 0 on success or a negative value if an error occurs,
 */
int 
xmlSecString2BitMaskGetBitMask(xmlSecString2BitMaskInfoConstPtr info, const xmlChar* strValue,
			    xmlSecBitMask* mask) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(strValue != NULL, -1);
    xmlSecAssert2(mask != NULL, -1);

    for(ii = 0; info[ii].strValue != NULL; ii++) {
        xmlSecAssert2(info[ii].mask != 0, -1);
        if(xmlStrcmp(info[ii].strValue, strValue) == 0) {
            (*mask) = info[ii].mask;
            return(0);
        }
    }

    return(-1);
}

/** 
 * xmlSecString2BitMaskNodesRead:
 * @info:               the string<->bit mask mapping information.
 * @node:               the start.
 * @nodeName:           the mask nodes name.
 * @nodeNs:             the mask nodes namespace.
 * @mask:               the pointer to result mask.
 * 
 * Reads <@nodeNs:@nodeName> elements and puts the result bit mask
 * into @mask. When function exits, @node points to the first element node
 * after all the <@nodeNs:@nodeName> elements.
 * 
 * Returns 0 on success or a negative value if an error occurs,
 */
int 
xmlSecString2BitMaskNodesRead(xmlSecString2BitMaskInfoConstPtr info, xmlNodePtr* node,
			    const xmlChar* nodeName, const xmlChar* nodeNs, 
                            xmlSecBitMask* mask) {
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
        content = xmlNodeGetContent(cur);
        if(content == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
		        "xmlNodeGetContent",
	    	        XMLSEC_ERRORS_R_XML_FAILED,
		        "node=%s",
		        xmlSecErrorsSafeString(cur->name));
	    return(-1);	
        }
        
        ret = xmlSecString2BitMaskGetBitMask(info, content, &tmp);
        if(tmp == 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        NULL,
		        "xmlSecString2BitMaskGetBitMask",
	    	        XMLSEC_ERRORS_R_XMLSEC_FAILED,
		        "value=%s",
		        xmlSecErrorsSafeString(content));
            xmlFree(content);
	    return(-1);	
        }
        xmlFree(content);

        xmlSecAssert2(tmp != 0, -1);
        (*mask) |= tmp;
	cur = xmlSecGetNextElementNode(cur->next);
    }

    (*node) = cur;    
    return(0); 
}

/** 
 * xmlSecString2BitMaskNodesWrite:
 * @info:               the string<->bit mask mapping information.
 * @parent:             the parent element for mask nodes.
 * @nodeName:           the mask nodes name.
 * @nodeNs:             the mask nodes namespace.
 * @mask:               the bit mask.
 * 
 * Writes <@nodeNs:@nodeName> elemnts with values from @mask to @parent.
 * 
 * Returns 0 on success or a negative value if an error occurs,
 */
int 
xmlSecString2BitMaskNodesWrite(xmlSecString2BitMaskInfoConstPtr info, xmlNodePtr parent,
			    const xmlChar* nodeName, const xmlChar* nodeNs, 
                            xmlSecBitMask mask) {
    unsigned int ii;

    xmlSecAssert2(info != NULL, -1);
    xmlSecAssert2(parent != NULL, -1);
    xmlSecAssert2(nodeName != NULL, -1);

    for(ii = 0; (mask != 0) && (info[ii].strValue != NULL); ii++) {
        xmlSecAssert2(info[ii].mask != 0, -1);

        if((mask & info[ii].mask) != 0) {
            xmlNodePtr cur;
            
            cur = xmlSecAddChild(parent, nodeName, nodeNs);
            if(cur == NULL) {
	        xmlSecError(XMLSEC_ERRORS_HERE,
		            NULL,
		            "xmlSecAddChild",
	    	            XMLSEC_ERRORS_R_XML_FAILED,
		            "node=%s",
		            xmlSecErrorsSafeString(nodeName));
	        return(-1);	
            }
            
            xmlNodeSetContent(cur, info[ii].strValue);
        }
    }
    return(0);
}

/** 
 * xmlSecString2BitMaskDebugDump:
 * @info:               the string<->bit mask mapping information.
 * @mask:               the bit mask.
 * @output:             the pointer to output FILE.
 * 
 * Prints debug information about @mask to @output.
 */
void 
xmlSecString2BitMaskDebugDump(xmlSecString2BitMaskInfoConstPtr info, xmlSecBitMask mask,
			    const xmlChar* name, FILE* output) {
    unsigned int ii;

    xmlSecAssert(info != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    if(mask == 0) {
        return;
    }

    fprintf(output, "== %s: ", name);
    for(ii = 0; (mask != 0) && (info[ii].strValue != NULL); ii++) {
        xmlSecAssert(info[ii].mask != 0);

        if((mask & info[ii].mask) != 0) {
            fprintf(output, "%s,", info[ii].strValue);
        }
    }
    fprintf(output, "\n");
}

/** 
 * xmlSecString2BitMaskDebugXmlDump:
 * @info:               the string<->bit mask mapping information.
 * @mask:               the bit mask.
 * @output:             the pointer to output FILE.
 * 
 * Prints debug information about @mask to @output in XML format.
 */
void 
xmlSecString2BitMaskDebugXmlDump(xmlSecString2BitMaskInfoConstPtr info, xmlSecBitMask mask,
			    const xmlChar* name, FILE* output) {
    unsigned int ii;

    xmlSecAssert(info != NULL);
    xmlSecAssert(name != NULL);
    xmlSecAssert(output != NULL);

    if(mask == 0) {
        return;
    }

    fprintf(output, "<%sList>\n", name);
    for(ii = 0; (mask != 0) && (info[ii].strValue != NULL); ii++) {
        xmlSecAssert(info[ii].mask != 0);

        if((mask & info[ii].mask) != 0) {
            fprintf(output, "<%s>%s</%s>\n", name, info[ii].strValue, name);
        }
    }
    fprintf(output, "</%sList>\n", name);
}
								 



