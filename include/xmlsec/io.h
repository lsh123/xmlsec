/** 
 * XMLSec library
 *
 * Input Uri transform
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_IO_H__
#define __XMLSEC_IO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xmlIO.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>

XMLSEC_EXPORT void	xmlSecIOInit				(void);
XMLSEC_EXPORT void	xmlSecIOShutdown			(void);
XMLSEC_EXPORT void	xmlSecIOCleanupCallbacks		(void);
XMLSEC_EXPORT void	xmlSecIORegisterDefaultCallbacks 	(void);
XMLSEC_EXPORT int     	xmlSecIORegisterCallbacks		(xmlInputMatchCallback matchFunc,
								 xmlInputOpenCallback openFunc,
								 xmlInputReadCallback readFunc,
								 xmlInputCloseCallback closeFunc);

/********************************************************************
 *
 * Input URI transform 
 *
 *******************************************************************/
/**
 * xmlSecTransformInputURIId:
 * 
 * The Input URI transform id.
 */
#define xmlSecTransformInputURIId \
	xmlSecTransformInputURIGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformInputURIGetKlass		(void);
XMLSEC_EXPORT int 	xmlSecTransformInputURIOpen			(xmlSecTransformPtr transform,
									 const char *uri);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_IO_H__ */

