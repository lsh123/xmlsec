/** 
 * XMLSec library
 *
 * Common XML Doc utility functions
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TREE_H__
#define __XMLSEC_TREE_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>

XMLSEC_EXPORT xmlDocPtr		xmlSecParseFile		(const char *filename);
XMLSEC_EXPORT xmlDocPtr		xmlSecParseMemory	(const unsigned char *buffer, 
							 size_t size,
							 int recovery);
XMLSEC_EXPORT xmlDocPtr		xmlSecParseMemoryExt	(const unsigned char *prefix, 
							 size_t prefixSize,
							 const unsigned char *buffer, 
							 size_t bufferSize, 
							 const unsigned char *postfix, 
							 size_t postfixSize);

XMLSEC_EXPORT int		xmlSecCheckNodeName	(const xmlNodePtr cur, 
							 const xmlChar *name, 
							 const xmlChar *ns);
XMLSEC_EXPORT xmlNodePtr	xmlSecGetNextElementNode(xmlNodePtr cur);
XMLSEC_EXPORT xmlNodePtr	xmlSecFindChild		(const xmlNodePtr parent,
							 const xmlChar *name,
							 const xmlChar *ns);
XMLSEC_EXPORT xmlNodePtr	xmlSecFindParent	(const xmlNodePtr cur, 
							 const xmlChar *name, 
							 const xmlChar *ns);
XMLSEC_EXPORT xmlNodePtr	xmlSecFindNode		(const xmlNodePtr parent,
							 const xmlChar *name,
							 const xmlChar *ns);
XMLSEC_EXPORT xmlNodePtr	xmlSecFindNodeById	(const xmlNodePtr parent,
							 const xmlChar *id);
XMLSEC_EXPORT xmlNodeSetPtr	xmlSecGetChildNodeSet	(const xmlNodePtr parent,
							 xmlNodeSetPtr nodeSet,
							 int withComments);
XMLSEC_EXPORT xmlNodePtr	xmlSecAddChild		(xmlNodePtr parent, 
							 const xmlChar *name,
							 const xmlChar *ns);
XMLSEC_EXPORT xmlNodePtr	xmlSecAddNextSibling	(xmlNodePtr node, 
							 const xmlChar *name,
							 const xmlChar *ns);
XMLSEC_EXPORT xmlNodePtr	xmlSecAddPrevSibling	(xmlNodePtr node, 
							 const xmlChar *name,
							 const xmlChar *ns);

XMLSEC_EXPORT int		xmlSecReplaceNode	(xmlNodePtr node,
						         xmlNodePtr newNode);
XMLSEC_EXPORT int		xmlSecReplaceContent	(xmlNodePtr node,
							 xmlNodePtr newNode);
XMLSEC_EXPORT int		xmlSecReplaceNodeBuffer	(xmlNodePtr node,
							 const unsigned char *buffer, 
							 size_t size);

/* 
 * hack for specifying ID attributes names for xml documents
 * w/o schemas or DTD 
 */
XMLSEC_EXPORT int		xmlSecAddIdAttributeName(const xmlChar *id);
XMLSEC_EXPORT void		xmlSecClearIdAttributeNames(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TREE_H__ */

