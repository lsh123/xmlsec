/** 
 * XMLSec library
 *
 * Map
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_MAP_H__
#define __XMLSEC_MAP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/object.h>
#include <xmlsec/serializable.h>

typedef struct _xmlSecObjMapKlass			xmlSecObjMapKlass,
						        *xmlSecObjMapKlassPtr;
typedef struct _xmlSecObjMap				xmlSecObjMap,
							*xmlSecObjMapPtr;

/*********************************************************************
 *
 * Map
 *
 *********************************************************************/
#define xmlSecObjMapKlassId 				xmlSecObjMapKlassGet()
#define xmlSecObjMapKlassCast(klass) 			xmlSecObjKlassCastMacro((klass), xmlSecObjMapKlassId, xmlSecObjMapKlassPtr)
#define xmlSecObjMapKlassCheckCast(klass) 		xmlSecObjKlassCheckCastMacro((klass), xmlSecObjMapKlassId)
#define xmlSecObjMapCast(obj) 				xmlSecObjCastMacro((obj), xmlSecObjMapKlassId, xmlSecObjMapPtr)
#define xmlSecObjMapCheckCast(obj) 			xmlSecObjCheckCastMacro((obj), xmlSecObjMapKlassId)

typedef struct _xmlSecObjMapItem			xmlSecObjMapItem,
							*xmlSecObjMapItemPtr;

struct _xmlSecObjMapKlass {
    xmlSecObjKlass			parent;
};
		
struct _xmlSecObjMap {
    xmlSecObj				parent;
    
    /* private data */
    xmlSecObjMapItem*		data;
    size_t				size;
    size_t				maxSize;
};

#define xmlSecObjMapNew()	((xmlSecObjMapPtr)xmlSecObjNew(xmlSecObjMapKlassId))
XMLSEC_EXPORT xmlSecObjKlassPtr		xmlSecObjMapKlassGet(void);
XMLSEC_EXPORT xmlSecObjPtr		xmlSecObjMapGet		(xmlSecObjMapPtr map,
								 const xmlChar* name);
XMLSEC_EXPORT int			xmlSecObjMapSet		(xmlSecObjMapPtr map,
								 const xmlChar* name,
								 xmlSecObjPtr data);
XMLSEC_EXPORT void			xmlSecObjMapRemove	(xmlSecObjMapPtr map,
								 const xmlChar* name);
XMLSEC_EXPORT void			xmlSecObjMapEmpty	(xmlSecObjMapPtr map);
XMLSEC_EXPORT size_t			xmlSecObjMapGetSize	(xmlSecObjMapPtr map);
XMLSEC_EXPORT xmlSecObjPtr		xmlSecObjMapGetData	(xmlSecObjMapPtr map,
								 size_t pos);
XMLSEC_EXPORT const xmlChar*		xmlSecObjMapGetName	(xmlSecObjMapPtr map,
								 size_t pos);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MAP_H__ */
