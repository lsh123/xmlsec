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

typedef enum {
    xmlSecNodeSetNormal = 0,
    xmlSecNodeSetInvert,
    xmlSecNodeSetTree,
    xmlSecNodeSetTreeWithoutComments,
    xmlSecNodeSetTreeInvert,
    xmlSecNodeSetTreeWithoutCommentsInvert
} xmlSecNodeSetType;

typedef struct _xmlSecNodeSet 	xmlSecNodeSet, *xmlSecNodeSetPtr;
struct _xmlSecNodeSet {
    xmlNodeSetPtr	nodes;
    xmlDocPtr		doc;
    xmlSecNodeSetType	type;
};

typedef int (*xmlSecNodeSetWalkCallback)		(xmlSecNodeSetPtr nset,
							 xmlNodePtr cur,
							 xmlNodePtr parent,
							 void* data);

XMLSEC_EXPORT xmlSecNodeSetPtr	xmlSecNodeSetCreate	(xmlDocPtr doc,
							 xmlNodeSetPtr nodes,
							 xmlSecNodeSetType type);
XMLSEC_EXPORT void		xmlSecNodeSetDestroy	(xmlSecNodeSetPtr nset);
XMLSEC_EXPORT int		xmlSecNodeSetContain	(xmlSecNodeSetPtr nset,
							 xmlNodePtr node,
							 xmlNodePtr parent);
XMLSEC_EXPORT int		xmlSecNodeSetWalk	(xmlSecNodeSetPtr nset,
							 xmlSecNodeSetWalkCallback func,
							 void* data);
XMLSEC_EXPORT void		xmlSecNodeSetDebugDump	(xmlSecNodeSetPtr nset,
							 FILE *output);


XMLSEC_EXPORT xmlSecNodeSetPtr	xmlSecNodeSetIntersect	(xmlSecNodeSetPtr nset,
							 xmlNodeSetPtr nodes);
XMLSEC_EXPORT xmlSecNodeSetPtr	xmlSecNodeSetIntersect2	(xmlSecNodeSetPtr nset1,
							 xmlSecNodeSetPtr nset2);
XMLSEC_EXPORT xmlSecNodeSetPtr	xmlSecNodeSetGetChilds	(xmlDocPtr doc,
							 const xmlNodePtr parent,
							 int withComments,
							 int invert);
							 
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NODESET_H__ */

