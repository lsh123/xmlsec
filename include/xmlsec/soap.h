/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Simple SOAP messages parsing/creation.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_SOAP_H__
#define __XMLSEC_SOAP_H__    

#ifndef XMLSEC_NO_SOAP

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>


/***********************************************************************
 *
 * SOAP 1.1 envelope creation
 *
 **********************************************************************/
XMLSEC_EXPORT xmlNodePtr	xmlSecSoap11CreateEnvelope	(xmlDocPtr doc);
XMLSEC_EXPORT xmlNodePtr	xmlSecSoap11EnsureHeader	(xmlNodePtr envNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecSoap11AddBodyEntry	(xmlNodePtr envNode,
								 xmlNodePtr entryNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecSoap11AddFaultEntry	(xmlNodePtr envNode,
								 const xmlChar* faultCodeHref,
								 const xmlChar* faultCodeLocalPart,
								 const xmlChar* faultString,
								 const xmlChar* faultActor);

/***********************************************************************
 *
 * SOAP 1.1 envelope parsing
 *
 **********************************************************************/
XMLSEC_EXPORT int		xmlSecSoap11CheckEnvelope	(xmlNodePtr envNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecSoap11GetHeader		(xmlNodePtr envNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecSoap11GetBody		(xmlNodePtr envNode);
XMLSEC_EXPORT xmlSecSize	xmlSecSoap11GetBodyEntriesNumber(xmlNodePtr envNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecSoap11GetBodyEntry	(xmlNodePtr envNode,
								 xmlSecSize pos);
XMLSEC_EXPORT xmlNodePtr	xmlSecSoap11GetFaultEntry	(xmlNodePtr envNode);

								 
#endif /* XMLSEC_NO_SOAP */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_SOAP_H__ */

