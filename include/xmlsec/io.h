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

#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>

void		xmlSecIOInit				(void);
void		xmlSecIOShutdown			(void);

extern xmlSecTransformId xmlSecInputUri;

typedef void* (*xmlSecInputUriTransformOpenCallback)	(const char *uri, 
							 void *context);
typedef int   (*xmlSecInputUriTransformReadCallback)	(void *data,
							 unsigned char *buffer,
							 size_t size);
typedef void  (*xmlSecInputUriTransformCloseCallback)	(void *data);							 

int		xmlSecInputUriTransformOpen		(xmlSecTransformPtr transform,
							 const char *uri);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_IO_H__ */

