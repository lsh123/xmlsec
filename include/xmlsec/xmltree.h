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

#define xmlSecNodeGetName(node) \
    (((node)) ? ((const char*)((node)->name)) : NULL)

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

XMLSEC_EXPORT const xmlChar* 	xmlSecGetNodeNsHref	(const xmlNodePtr cur);
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


XMLSEC_EXPORT void		xmlSecAddIDs		(xmlDocPtr doc,
							 xmlNodePtr cur,
							 const xmlChar** ids);
/**
 * xmlSecIsHex:
 * @c: the character.
 * 
 * Macro. Returns 1 if @c is a hex digit or 0 other wise.
 */
#define xmlSecIsHex(c) \
    (( (('0' <= (c)) && ((c) <= '9')) || \
       (('a' <= (c)) && ((c) <= 'f')) || \
       (('A' <= (c)) && ((c) <= 'F')) ) ? 1 : 0)

/**
 * xmlSecGetHex:
 * @c: the character,
 *
 * Macro. Returns the hex value of the @c.
 */
#define xmlSecGetHex(c) \
    ( (('0' <= (c)) && ((c) <= '9')) ? (c) - '0' : \
    ( (('a' <= (c)) && ((c) <= 'f')) ? (c) - 'a' + 10 :  \
    ( (('A' <= (c)) && ((c) <= 'F')) ? (c) - 'A' + 10 : 0 )))


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TREE_H__ */

