/** 
 * XMLSec library
 *
 * Nodes Set
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_NODESET_H__
#define __XMLSEC_NODESET_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>

typedef struct _xmlSecNodeSet 	xmlSecNodeSet, *xmlSecNodeSetPtr;

/** 
 * enum xmlSecNodeSetType:
 * 
 * The simple nodes sets types.
 */
typedef enum {
    xmlSecNodeSetNormal = 0,		/* nodes set = nodes in the list */
    xmlSecNodeSetInvert,		/* nodes set = all document nodes 
    					   minus nodes in the list */
    xmlSecNodeSetTree,			/* nodes set = nodes in the list and 
					   all their subtress */
    xmlSecNodeSetTreeWithoutComments,   /* nodes set = nodes in the list and 
                                           all their subtress but no comment 
					   nodes */
    xmlSecNodeSetTreeInvert,		/* nodes set = all document nodes 
					   minus nodes in the list and all 
					   their subtress */
    xmlSecNodeSetTreeWithoutCommentsInvert, /* nodes set = all document nodes 
					    minus (nodes in the list and all 
					    their subtress plus all comment nodes) */
    xmlSecNodeSetList			/* nodes set = all nodes in the 
					    chidren list of nodes sets */
} xmlSecNodeSetType;

/**
 * enum xmlSecNodeSetOp:
 *
 * The simple nodes sets operations.
 */
typedef enum {
    xmlSecNodeSetIntersection = 0,	/* intersection */
    xmlSecNodeSetSubtraction,		/* subtraction */
    xmlSecNodeSetUnion			/* union */
} xmlSecNodeSetOp;

/**
 * struct _xmlSecNodeSet:
 *
 * The enchanced nodes set.
 */
struct _xmlSecNodeSet {
    xmlNodeSetPtr	nodes;		/* nodes list */
    xmlDocPtr		doc;		/* the parent XML document */
    xmlSecNodeSetType	type;		/* nodes set type */
    xmlSecNodeSetOp	op;		/* the operation type */    
    xmlSecNodeSetPtr	next;		/* next nodes set */
    xmlSecNodeSetPtr	prev;		/* previous nodes set */
    xmlSecNodeSetPtr	children;	/* the children list (valid only 
					   if type equal to xmlSecNodeSetList */
};

/**
 * xmlSecNodeSetWalkCallback:
 * @nset: the pointer to #xmlSecNodeSet structure.
 * @cur: the pointer current XML node.
 * @parent: the pointer to the @cur parent node.
 * @data: the pointer to application specific data.
 *
 * The callback function called once per each node in the nodes set.
 *
 * Returns 0 on success or a negative value if an error occurs
 * an walk procedure should be interrupted.
 */
typedef int (*xmlSecNodeSetWalkCallback)		(xmlSecNodeSetPtr nset,
							 xmlNodePtr cur,
							 xmlNodePtr parent,
							 void* data);

XMLSEC_EXPORT xmlSecNodeSetPtr	xmlSecNodeSetCreate	(xmlDocPtr doc,
							 xmlNodeSetPtr nodes,
							 xmlSecNodeSetType type);
XMLSEC_EXPORT void		xmlSecNodeSetDestroy	(xmlSecNodeSetPtr nset);
XMLSEC_EXPORT int		xmlSecNodeSetContains	(xmlSecNodeSetPtr nset,
							 xmlNodePtr node,
							 xmlNodePtr parent);
XMLSEC_EXPORT xmlSecNodeSetPtr	xmlSecNodeSetAdd	(xmlSecNodeSetPtr nset,
							 xmlSecNodeSetPtr newNSet,
							 xmlSecNodeSetOp op);
XMLSEC_EXPORT xmlSecNodeSetPtr	xmlSecNodeSetAddList	(xmlSecNodeSetPtr nset,
							 xmlSecNodeSetPtr newNSet,
							 xmlSecNodeSetOp op);
XMLSEC_EXPORT xmlSecNodeSetPtr	xmlSecNodeSetGetChildren(xmlDocPtr doc,
							 const xmlNodePtr parent,
							 int withComments,
							 int invert);
XMLSEC_EXPORT int		xmlSecNodeSetWalk	(xmlSecNodeSetPtr nset,
							 xmlSecNodeSetWalkCallback walkFunc,
							 void* data);
XMLSEC_EXPORT void		xmlSecNodeSetDebugDump	(xmlSecNodeSetPtr nset,
							 FILE *output);
							 
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NODESET_H__ */

