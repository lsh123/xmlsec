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

XMLSEC_EXPORT void	xmlSecIOInit			(void);
XMLSEC_EXPORT void	xmlSecIOShutdown		(void);

XMLSEC_EXPORT_VAR xmlSecTransformId xmlSecInputUri;
XMLSEC_EXPORT int 	xmlSecInputUriTransformOpen	(xmlSecTransformPtr transform,
							 const char *uri);

XMLSEC_EXPORT void	xmlSecCleanupInputCallbacks	(void);
XMLSEC_EXPORT void	xmlSecRegisterDefaultInputCallbacks (void);
XMLSEC_EXPORT int     	xmlSecRegisterInputCallbacks	(xmlInputMatchCallback matchFunc,
							 xmlInputOpenCallback openFunc,
							 xmlInputReadCallback readFunc,
							 xmlInputCloseCallback closeFunc);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_IO_H__ */

