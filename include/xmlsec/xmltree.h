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

xmlDocPtr		xmlSecParseFile			(const char *filename);
xmlDocPtr		xmlSecParseMemory		(const unsigned char *buffer, 
							 size_t size,
							 int recovery);
xmlDocPtr		xmlSecParseMemoryExt		(const unsigned char *prefix, 
							 size_t prefixSize,
							 const unsigned char *buffer, 
							 size_t bufferSize, 
							 const unsigned char *postfix, 
							 size_t postfixSize);

int			xmlSecCheckNodeName		(const xmlNodePtr cur, 
							 const xmlChar *name, 
							 const xmlChar *ns);
xmlNodePtr		xmlSecGetNextElementNode	(xmlNodePtr cur);
xmlNodePtr		xmlSecFindChild			(const xmlNodePtr parent,
							 const xmlChar *name,
							 const xmlChar *ns);
xmlNodePtr		xmlSecFindNode			(const xmlNodePtr parent,
							 const xmlChar *name,
							 const xmlChar *ns);
xmlNodePtr		xmlSecFindNodeById		(const xmlNodePtr parent,
							 const xmlChar *id);

xmlNodeSetPtr		xmlSecGetChildNodeSet		(const xmlNodePtr parent,
							 xmlNodeSetPtr nodeSet,
							 int withComments);
xmlNodePtr		xmlSecAddChild			(xmlNodePtr parent, 
							 const xmlChar *name,
							 const xmlChar *ns);
xmlNodePtr		xmlSecAddNextSibling		(xmlNodePtr node, 
							 const xmlChar *name,
							 const xmlChar *ns);
xmlNodePtr		xmlSecAddPrevSibling		(xmlNodePtr node, 
							 const xmlChar *name,
							 const xmlChar *ns);

int			xmlSecReplaceNode		(xmlNodePtr node,
						         xmlNodePtr newNode);
int			xmlSecReplaceContent		(xmlNodePtr node,
							 xmlNodePtr newNode);
int			xmlSecReplaceNodeBuffer		(xmlNodePtr node,
							 const unsigned char *buffer, 
							 size_t size);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TREE_H__ */

