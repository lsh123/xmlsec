/** 
 * XMLSec library
 *
 * PGP support
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_PGP_H__
#define __XMLSEC_PGP_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#ifndef XMLSEC_NO_PGP

#include <xmlsec/xmlsec.h>
#include <xmlsec/object.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>


typedef struct _xmlSecPgpStoreKlass		xmlSecPgpStoreKlass,
						*xmlSecPgpStoreKlassPtr;
typedef struct _xmlSecPgpStore			xmlSecPgpStore,
						*xmlSecPgpStorePtr;

typedef struct _xmlSecPgpDataKlass		xmlSecPgpDataKlass,
						*xmlSecPgpDataKlassPtr;
typedef struct _xmlSecPgpData			xmlSecPgpData,
						*xmlSecPgpDataPtr;

#else  /* XMLSEC_NO_PGP */
typedef void*					xmlSecPgpStorePtr;
typedef void*					xmlSecPgpDataPtr;
#endif /* XMLSEC_NO_PGP */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_PGP_H__ */

