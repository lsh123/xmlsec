/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_SKELETON_CRYPTO_H__
#define __XMLSEC_SKELETON_CRYPTO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>

/**
 * Init shutdown
 */
XMLSEC_CRYPTO_EXPORT int		xmlSecSkeletonInit		(void);
XMLSEC_CRYPTO_EXPORT int		xmlSecSkeletonShutdown		(void);

XMLSEC_CRYPTO_EXPORT int		xmlSecSkeletonKeysMngrInit	(xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int		xmlSecSkeletonGenerateRandom	(xmlSecBufferPtr buffer,
									 size_t size);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_SKELETON_CRYPTO_H__ */

#define __XMLSEC_SKELETON_CRYPTO_H__    
