/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Common XML utility functions
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TREE_H__
#define __XMLSEC_TREE_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <xmlsec/xmlsec.h>

/**
 * xmlSecNodeGetName:
 * @node:		the pointer to node.
 *
 * Macro. Returns node's name.
 */
#define xmlSecNodeGetName(node) \
    (((node)) ? ((const char*)((node)->name)) : NULL)

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
							 const xmlSecByte *buffer, 
							 xmlSecSize size);


XMLSEC_EXPORT void		xmlSecAddIDs		(xmlDocPtr doc,
							 xmlNodePtr cur,
							 const xmlChar** ids);

XMLSEC_EXPORT xmlDocPtr		xmlSecCreateTree	(const xmlChar* rootNodeName,
							 const xmlChar* rootNodeNs);
XMLSEC_EXPORT int		xmlSecIsEmptyNode	(xmlNodePtr node);
XMLSEC_EXPORT int		xmlSecIsEmptyString	(const xmlChar* str);

/**
 * xmlSecIsHex:
 * @c: 			the character.
 * 
 * Macro. Returns 1 if @c is a hex digit or 0 other wise.
 */
#define xmlSecIsHex(c) \
    (( (('0' <= (c)) && ((c) <= '9')) || \
       (('a' <= (c)) && ((c) <= 'f')) || \
       (('A' <= (c)) && ((c) <= 'F')) ) ? 1 : 0)

/**
 * xmlSecGetHex:
 * @c: 			the character,
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

