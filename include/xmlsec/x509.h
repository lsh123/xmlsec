/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_X509_H__
#define __XMLSEC_X509_H__    

#ifndef XMLSEC_NO_X509
	
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 
#include <stdio.h>		

#include <libxml/tree.h>
#include <libxml/parser.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>

#define XMLSEC_X509DATA_CERTIFICATE_NODE			0x00000001
#define XMLSEC_X509DATA_SUBJECTNAME_NODE			0x00000002
#define XMLSEC_X509DATA_ISSUERSERIAL_NODE			0x00000004
#define XMLSEC_X509DATA_SKI_NODE				0x00000008
#define XMLSEC_X509DATA_CRL_NODE				0x00000010
#define XMLSEC_X509DATA_DEFAULT	\
	(XMLSEC_X509DATA_CERTIFICATE_NODE | XMLSEC_X509DATA_CRL_NODE)
	    
XMLSEC_EXPORT int		xmlSecX509DataGetNodeContent 	(xmlNodePtr node, 
								 int deleteChildren,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_X509 */

#endif /* __XMLSEC_X509_H__ */

