/** 
 * XMLSec library
 *
 * Nodes set
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/nodeset.h>

#define xmlSecGetParent(node) 		\
    (((node)->type != XML_NAMESPACE_DECL) ? \
	(node)->parent : \
        (xmlNodePtr)((xmlNsPtr)(node))->next)


static int	xmlSecNodeSetWalkRecursive		(xmlSecNodeSetPtr nset, 
							 xmlSecNodeSetWalkCallback walkFunc, 
							 void* data, 
							 xmlNodePtr cur, 
							 xmlNodePtr parent);

xmlSecNodeSetPtr
xmlSecNodeSetCreate(xmlDocPtr doc, xmlNodeSetPtr nodes, xmlSecNodeSetType type) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetCreate";
    xmlSecNodeSetPtr nset;

    nset = (xmlSecNodeSetPtr)xmlMalloc(sizeof(xmlSecNodeSet));
    if(nset == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to allocate xmlSecNodeSet \n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(nset, 0,  sizeof(xmlSecNodeSet));
    
    nset->doc 	= doc;
    nset->nodes = nodes;
    nset->type	= type;

    return(nset);
}

void
xmlSecNodeSetDestroy(xmlSecNodeSetPtr nset) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetDestroy";
    
    if(nset != NULL){
	if(nset->nodes != NULL) {
    	    xmlXPathFreeNodeSet(nset->nodes);
	}
	memset(nset, 0,  sizeof(xmlSecNodeSet));
        xmlFree(nset);
    }
}

int
xmlSecNodeSetContain(xmlSecNodeSetPtr nset, xmlNodePtr node, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetContain";
    int in_nodes_set = 1;
    
    if(node == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nset is null\n",
	    func);	
#endif 	    
	return(0);
    }
    
    /* special cases: */
    if(nset == NULL) {
	return(1);
    }    
    if((node->type == XML_COMMENT_NODE) && 
	((nset->type == xmlSecNodeSetTreeWithoutComments) ||  
	 (nset->type == xmlSecNodeSetTreeWithoutCommentsInvert))) {

	return(0);
    }
        
    if(nset->nodes != NULL) {
	if(node->type != XML_NAMESPACE_DECL) {
	    in_nodes_set = xmlXPathNodeSetContains(nset->nodes, node);
	} else {
	    xmlNs ns;
	    
	    memcpy(&ns, node, sizeof(ns)); 
	    ns.next = (xmlNsPtr)parent; /* this is a libxml hack! check xpath.c for details */

	    /* 
	     * If the input is an XPath node-set, then the node-set must explicitly 
	     * contain every node to be rendered to the canonical form.
	     */
	    in_nodes_set = (xmlXPathNodeSetContains(nset->nodes, (xmlNodePtr)&ns));
	}
    }
    
    switch(nset->type) {
    case xmlSecNodeSetNormal:
	return(in_nodes_set);
    case xmlSecNodeSetInvert:
	return(!in_nodes_set);
    case xmlSecNodeSetTree:
    case xmlSecNodeSetTreeWithoutComments:
	if(in_nodes_set) {
	    return(1);
	}
	if((parent != NULL) && (parent->type == XML_ELEMENT_NODE)) {
	    return(xmlSecNodeSetContain(nset, parent, parent->parent));
	}
	return(0);
    case xmlSecNodeSetTreeInvert:
    case xmlSecNodeSetTreeWithoutCommentsInvert:
	if(in_nodes_set) {
	    return(0);
	}
	if((parent != NULL) && (parent->type == XML_ELEMENT_NODE)) {
	    return(xmlSecNodeSetContain(nset, parent, parent->parent));
	}
	return(1);
    default:
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unknown nodes set type %d\n",
	    func, nset->type);	
#endif 	    
    }
    
    return(0);
}

xmlSecNodeSetPtr	
xmlSecNodeSetIntersect(xmlSecNodeSetPtr nset, xmlNodeSetPtr nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetIntersect";
    xmlNodeSetPtr res;
    int i;
    
    if((nset == NULL) || (nodes == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nset or func is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    res = xmlXPathNodeSetCreate(NULL);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create nodes set\n",
	    func);	
#endif 	    
	return(NULL);
    }

    for(i = 0; i < nodes->nodeNr; ++i) {
	if(xmlSecNodeSetContain(nset, nodes->nodeTab[i], xmlSecGetParent(nodes->nodeTab[i]))) {
	    if(nodes->nodeTab[i]->type == XML_NAMESPACE_DECL) {
		xmlNsPtr ns = (xmlNsPtr)nodes->nodeTab[i];
	    
		xmlXPathNodeSetAddNs(res, (xmlNodePtr)ns->next, ns);
	    } else {
		xmlXPathNodeSetAddUnique(res, nodes->nodeTab[i]);
	    }
	}
    }    
    return(xmlSecNodeSetCreate(nset->doc, res, xmlSecNodeSetNormal));
}

static int
xmlSecNodeSetIntersectRecursive(xmlSecNodeSetPtr nset, xmlNodePtr cur, xmlNodePtr parent, void** data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetIntersectRecursive";
    
    if((nset == NULL) || (cur == NULL) || (data == NULL) || (data[0] == NULL) || (data[1] == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: something is wrong\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    if(xmlSecNodeSetContain((xmlSecNodeSetPtr)data[0], cur, parent)) {
	if(cur->type == XML_NAMESPACE_DECL) {
	    xmlNsPtr ns = (xmlNsPtr)cur;
	    
	    xmlXPathNodeSetAddNs((xmlNodeSetPtr)data[1], parent, ns);
	} else {
	    xmlXPathNodeSetAddUnique((xmlNodeSetPtr)data[1], cur);
	}
    }
    return(0);
}


xmlSecNodeSetPtr	
xmlSecNodeSetIntersect2(xmlSecNodeSetPtr nset1, xmlSecNodeSetPtr nset2) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetIntersect2";
    xmlNodeSetPtr res;
    void* data[2];
    
    if((nset1 == NULL) || (nset2 == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nset1 or nset2 is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    /* special cases */
    if(nset1->type == xmlSecNodeSetNormal) {
	return(xmlSecNodeSetIntersect(nset2, nset1->nodes));
    } else if(nset2->type == xmlSecNodeSetNormal) {
	return(xmlSecNodeSetIntersect(nset1, nset2->nodes));
    } 
	    
    res = xmlXPathNodeSetCreate(NULL);
    if(res == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to create nodes set\n",
	    func);	
#endif 	    
	return(NULL);
    }

    data[0] = nset2;
    data[1] = res;
    
    if(xmlSecNodeSetWalk(nset1, (xmlSecNodeSetWalkCallback)xmlSecNodeSetIntersectRecursive, data) < 0) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to get nodes\n",
	    func);	
#endif 	    
    	xmlXPathFreeNodeSet(res);
	return(NULL);
    }
    return(xmlSecNodeSetCreate(nset1->doc, res, xmlSecNodeSetNormal));
}
 
int
xmlSecNodeSetWalk(xmlSecNodeSetPtr nset, xmlSecNodeSetWalkCallback walkFunc, void* data) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetWalk";
    
    if((nset == NULL) || (walkFunc == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nset or func is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    /* special cases */
    if(nset->nodes != NULL) {
        int ret = 0;
	int i;

	switch(nset->type) {
	case xmlSecNodeSetNormal:
	    for(i = 0; (ret >= 0) && (i < nset->nodes->nodeNr); ++i) {
		ret = walkFunc(nset, nset->nodes->nodeTab[i], 
			       xmlSecGetParent(nset->nodes->nodeTab[i]), 
			       data);
	    }
	    return(ret);
	case xmlSecNodeSetTree:
	case xmlSecNodeSetTreeWithoutComments:
	    for(i = 0; (ret >= 0) && (i < nset->nodes->nodeNr); ++i) {
		ret = xmlSecNodeSetWalkRecursive(nset, walkFunc, data, 
		    nset->nodes->nodeTab[i], 
		    xmlSecGetParent(nset->nodes->nodeTab[i]));
	    }
	    return(ret);
	default:
	    break;
	}
    }

    /* other cases */	
    if(nset->doc == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: doc is null\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    return(xmlSecNodeSetWalkRecursive(nset, walkFunc, data, (xmlNodePtr)nset->doc, NULL));
}

static int
xmlSecNodeSetWalkRecursive(xmlSecNodeSetPtr nset, xmlSecNodeSetWalkCallback walkFunc, 
			    void* data, xmlNodePtr cur, xmlNodePtr parent) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetWalkRecursive";
    int ret;
    
    if((cur == NULL) || (nset == NULL) || (walkFunc == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: cur, nset or walkFunc is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    /* the node itself */
    if(xmlSecNodeSetContain(nset, cur, parent)) {
	ret = walkFunc(nset, cur, parent, data);
	
	if(ret < 0) {
	    return(ret);
	}
    }
	
    /* element node has attributes, namespaces  */	
    if(cur->type == XML_ELEMENT_NODE) {
        xmlAttrPtr attr;
	xmlNodePtr node;
	xmlNsPtr ns, tmp;
	
        attr = (xmlAttrPtr)cur->properties;
        while(attr != NULL) {
	    if(xmlSecNodeSetContain(nset, (xmlNodePtr)attr, cur)) {
		ret = walkFunc(nset, (xmlNodePtr)attr, cur, data);
		if(ret < 0) {
		    return(ret);
		}
	    }
	    attr = attr->next;
	}

	node = cur;
	while(node != NULL) {
    	    ns = node->nsDef;
    	    while(ns != NULL) {
		tmp = xmlSearchNs(nset->doc, cur, ns->prefix);
		if((tmp == ns) && xmlSecNodeSetContain(nset, (xmlNodePtr)ns, cur)) {
		    ret = walkFunc(nset, (xmlNodePtr)ns, cur, data);
		    if(ret < 0) {
			return(ret);
		    }
		}
		ns = ns->next;
	    }
	    node = node->parent;
	}
    }

    /* element and document nodes have children */
    if((cur->type == XML_ELEMENT_NODE) || (cur->type == XML_DOCUMENT_NODE)) {
	xmlNodePtr node;
	
	node = cur->children;
	while(node != NULL) {
	    ret = xmlSecNodeSetWalkRecursive(nset, walkFunc, data, node, cur);
	    if(ret < 0) {
		return(ret);
	    }
	    node = node->next;
	}
    }
    return(0);
}

xmlSecNodeSetPtr	
xmlSecNodeSetGetChilds(xmlDocPtr doc, const xmlNodePtr parent, int withComments, int invert) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetGetChilds";
    xmlNodeSetPtr nodes;
    xmlSecNodeSetType type;
        
    if((doc == NULL) || (parent == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: parent is null\n",
	    func);	
#endif 	    
	return(NULL);
    }

    nodes = xmlXPathNodeSetCreate(parent);
    if(nodes == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create node set\n",
	    func);
#endif
	return(NULL);
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

    return(xmlSecNodeSetCreate(doc, nodes, type));
}

void
xmlSecNodeSetDebugDump(xmlSecNodeSetPtr nset, FILE *output) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecNodeSetDebugDump";    
    int i, l;
    xmlNodePtr cur;

    if((nset == NULL) || (output == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: nodes or output is null\n",
	    func);	
#endif 	    
	return;
    }

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
    default:
	fprintf(output, "(unknown=%d)\n", nset->type);
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unknown nodes set type %d\n",
	    func, nset->type);	
#endif 	    
    }
        
    l = xmlXPathNodeSetGetLength(nset->nodes);
    for(i = 0; i < l; ++i) {
	cur = xmlXPathNodeSetItem(nset->nodes, i);
	fprintf(output, "%d: %s\n", cur->type, 
	    (cur->name) ? cur->name : BAD_CAST "null");
    }
}
