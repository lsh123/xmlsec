/** 
 * XMLSec library
 *
 * Memory buffer transform
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_MEMBUF_H__
#define __XMLSEC_MEMBUF_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>

/********************************************************************
 *
 * Memory Buffer transform 
 *
 *******************************************************************/
/**
 * xmlSecTransformMemBufId:
 * 
 * The Memory Buffer transform id.
 */
#define xmlSecTransformMemBufId \
	xmlSecTransformMemBufGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformMemBufGetKlass		(void);
XMLSEC_EXPORT xmlSecBufferPtr	xmlSecTransformMemBufGetBuffer		(xmlSecTransformPtr transform, 
									 int removeBuffer);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MEMBUF_H__ */

