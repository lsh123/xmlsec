/** 
 * XMLSec library
 *
 * Common XML Doc utility functions
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>
#include <libxml/valid.h>
#include <libxml/xpath.h>
#include <libxml/parser.h>
#include <libxml/xpathInternals.h>
#include <libxml/parserInternals.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/errors.h>

typedef struct _xmlSecExtMemoryParserCtx {
    const unsigned char 	*prefix;
    size_t 			prefixSize;
    const unsigned char 	*buffer;
    size_t			bufferSize;
    const unsigned char 	*postfix;
    size_t 			postfixSize;
} xmlSecExtMemoryParserCtx, *xmlSecExtMemoryParserCtxPtr;

/** 
 * xmlSecParseFile:
 * @filename: the filename.
 *
 * Loads XML Doc from file @filename. We need a special version because of 
 * c14n issue. The code is copied from xmlSAXParseFileWithData() function.
 *
 * Returns pointer to the loaded XML document or NULL if an error occurs.
 */
xmlDocPtr
xmlSecParseFile(const char *filename) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;
    char *directory = NULL;
    
    xmlSecAssert2(filename != NULL, NULL);

    xmlInitParser();
    ctxt = xmlCreateFileParserCtxt(filename);
    if (ctxt == NULL) {
	return(NULL);
    }

    /* todo: set directories from current doc? */    
    if ((ctxt->directory == NULL) && (directory == NULL))
        directory = xmlParserGetDirectory(filename);
    if ((ctxt->directory == NULL) && (directory != NULL))
        ctxt->directory = (char *) xmlStrdup((xmlChar *) directory);

    /* required for c14n! */
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS; 
    ctxt->replaceEntities = 1;
    
    xmlParseDocument(ctxt);

    if(ctxt->wellFormed) { 
	ret = ctxt->myDoc;
    } else {
       ret = NULL;
       xmlFreeDoc(ctxt->myDoc);
       ctxt->myDoc = NULL;
    }
    xmlFreeParserCtxt(ctxt);    
    return(ret);
    
}

static int 
xmlSecExtMemoryParserRead(void * context, char * buffer, int len) {
    xmlSecExtMemoryParserCtxPtr ctx;
    size_t size;

    xmlSecAssert2(context != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(len > 0, -1);
        
    ctx = (xmlSecExtMemoryParserCtxPtr)context;
    
    if((ctx->prefix != NULL) && (ctx->prefixSize > 0)) {
	size = (ctx->prefixSize < (size_t)len) ? ctx->prefixSize : (size_t)len; 
	memcpy(buffer, ctx->prefix, size);
	ctx->prefix += size;
	ctx->prefixSize -= size;
	return(size);
    } else if((ctx->buffer != NULL) && (ctx->bufferSize > 0)) {
	size = (ctx->bufferSize < (size_t)len) ? ctx->bufferSize : (size_t)len; 
	memcpy(buffer, ctx->buffer, size);
	ctx->buffer += size;
	ctx->bufferSize -= size;
	return(size);
    } else if((ctx->postfix != NULL) && (ctx->postfixSize > 0)) {
	size = (ctx->postfixSize < (size_t)len) ? ctx->postfixSize : (size_t)len; 
	memcpy(buffer, ctx->postfix, size);
	ctx->postfix += size;
	ctx->postfixSize -= size;
	return(size);
    }
    return(0);
}

/**
 * xmlSecParseMemoryExt:
 * @prefix: the first part of the input.
 * @prefixSize: the size of the first part of the input.
 * @buffer: the second part of the input.
 * @bufferSize: the size of the second part of the input.
 * @postfix: the third part of the input.
 * @postfixSize: the size of the third part of the input.
 *
 * Loads XML Doc from 3 chunks of memory: @prefix, @buffer and @postfix. '
 *
 * Returns pointer to the loaded XML document or NULL if an error occurs.
 */
xmlDocPtr
xmlSecParseMemoryExt(const unsigned char *prefix, size_t prefixSize,
		     const unsigned char *buffer, size_t bufferSize, 
		     const unsigned char *postfix, size_t postfixSize) {
    xmlSecExtMemoryParserCtx extCtx;
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;
    
    xmlSecAssert2(buffer != NULL, NULL);

    extCtx.prefix = prefix;
    extCtx.prefixSize = prefixSize;
    extCtx.buffer = buffer;
    extCtx.bufferSize = bufferSize;
    extCtx.postfix = postfix;
    extCtx.postfixSize = postfixSize;
        
    
    ctxt = xmlCreateIOParserCtxt(NULL, NULL, xmlSecExtMemoryParserRead, 
				 NULL, &extCtx, XML_CHAR_ENCODING_NONE);
    if (ctxt == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlCreateIOParserCtxt",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    /* required for c14n! */
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS; 
    ctxt->replaceEntities = 1;

    xmlParseDocument(ctxt);
    ret = ctxt->myDoc; 
    xmlFreeParserCtxt(ctxt);    
    return(ret);
}


/**
 * xmlSecParseMemory:
 * @buffer: the input buffer.
 * @size: the input buffer size.
 * @recovery: the flag.
 *
 * Loads XML Doc from memory. We need a special version because of 
 * c14n issue. The code is copied from xmlSAXParseMemory() function.
 *
 * Returns pointer to the loaded XML document or NULL if an error occurs.
 */
xmlDocPtr
xmlSecParseMemory(const unsigned char *buffer, size_t size, int recovery) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    xmlSecAssert2(buffer != NULL, NULL);
    
    ctxt = xmlCreateMemoryParserCtxt((char*)buffer, size);
    if (ctxt == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlCreateMemoryParserCtxt",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(NULL);
    }

    /* required for c14n! */
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS; 
    ctxt->replaceEntities = 1;

    xmlParseDocument(ctxt);

    if((ctxt->wellFormed) || recovery) {
	ret = ctxt->myDoc; 
    } else {
       ret = NULL;
       xmlFreeDoc(ctxt->myDoc);
       ctxt->myDoc = NULL;
    }
    xmlFreeParserCtxt(ctxt);    
    return(ret);
}

/**
 * xmlSecFindChild:
 * @parent: the pointer to XML node.
 * @name: the name.
 * @ns: the namespace href (may be NULL).
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
 * @cur: the pointer to an XML node.
 * @name: the name.
 * @ns: the namespace href (may be NULL).
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
 * @parent: the pointer to XML node.
 * @name: the name.
 * @ns: the namespace href (may be NULL).
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
 * @cur: the pointer to an XML node.
 * @name: the name,
 * @ns: the namespace href.
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
 * @parent: the pointer to an XML node.
 * @name: the new node name.
 * @ns: the new node namespace.
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
 * xmlSecAddNextSibling
 * @node: the pointer to an XML node.
 * @name: the new node name.
 * @ns: the new node namespace.
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
 * @node: the pointer to an XML node.
 * @name: the new node name.
 * @ns: the new node namespace.
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
 * @cur: the pointer to an XML node.
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
 * @node: the current node.
 * @newNode: the new node.
 * 
 * Swaps the @node and @newNode in the XML tree.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceNode(xmlNodePtr node, xmlNodePtr newNode) {
    xmlNodePtr old;
    xmlNodePtr ptr;
    xmlNodePtr dummy;

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
	    
    if(node == xmlDocGetRootElement(node->doc)) {
	old = xmlDocSetRootElement(node->doc, ptr);		
    } else {
	old = xmlReplaceNode(node, ptr);
    }
    if(old == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
                    "xmlDocSetRootElement or xmlReplaceNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFreeNode(ptr);
	return(-1);
    }
    xmlFreeNode(old);
    return(0);
}

/**
 * xmlSecReplaceContent
 * @node: the current node.
 * @newNode: the new node.
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
 * @node: the current node.
 * @buffer: the XML data.
 * @size: the XML data size.
 * 
 * Swaps the @node and the parsed XML data from the @buffer in the XML tree.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecReplaceNodeBuffer(xmlNodePtr node, 
			const unsigned char *buffer, size_t size) {
    static const char dummyPrefix[] = "<dummy>";
    static const char dummyPostfix[] = "</dummy>";
    xmlDocPtr doc;
    xmlNodePtr ptr1, ptr2;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);    
    
    doc = xmlSecParseMemoryExt((unsigned char*)dummyPrefix, strlen(dummyPrefix),
			       buffer, size,
			       (unsigned char*)dummyPostfix, strlen(dummyPostfix));
    if(doc == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecParseMemoryExt",
		    XMLSEC_ERRORS_R_XML_FAILED,
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
 * @doc: the pointer to an XML document.
 * @cur: the pointer to an XML node.
 * @ids: the pointer to a NULL terminated list of ID attributes.
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
					"xmlGetID",
					XMLSEC_ERRORS_R_INVALID_DATA,
					"id=%s already defined", name);
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

