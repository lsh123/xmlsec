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

typedef struct _xmlSecMapKlass			xmlSecMapKlass,
						*xmlSecMapKlassPtr;
typedef struct _xmlSecMap			xmlSecMap,
						*xmlSecMapPtr;
typedef struct _xmlSecMapItem			xmlSecMapItem,
						*xmlSecMapItemPtr;

/*********************************************************************
 *
 * Map
 *
 *********************************************************************/
#define xmlSecMapKlassId 			xmlSecMapKlassGet()
#define xmlSecMapKlassCast(klass) 		xmlSecObjKlassCastMacro((klass), xmlSecMapKlassId, xmlSecMapKlassPtr)
#define xmlSecMapKlassCheckCast(klass) 		xmlSecObjKlassCheckCastMacro((klass), xmlSecMapKlassId)
#define xmlSecMapCast(obj) 			xmlSecObjCastMacro((obj), xmlSecMapKlassId, xmlSecMapPtr)
#define xmlSecMapCheckCast(obj) 		xmlSecObjCheckCastMacro((obj), xmlSecMapKlassId)

struct _xmlSecMapKlass {
    xmlSecObjKlass			parent;
};
		
struct _xmlSecMap {
    xmlSecObj				parent;
    
    /* private data */
    xmlSecMapItem*			data;
    size_t				size;
    size_t				maxSize;
};

#define xmlSecMapNew()			((xmlSecMapPtr)xmlSecObjNew(xmlSecMapKlassId))
XMLSEC_EXPORT xmlSecObjKlassPtr		xmlSecMapKlassGet	(void);
XMLSEC_EXPORT xmlSecObjPtr		xmlSecMapGet		(xmlSecMapPtr map,
								 const xmlChar* name);
XMLSEC_EXPORT int			xmlSecMapSet		(xmlSecMapPtr map,
								 const xmlChar* name,
								 xmlSecObjPtr data);
XMLSEC_EXPORT void			xmlSecMapRemove		(xmlSecMapPtr map,
								 const xmlChar* name);
XMLSEC_EXPORT void			xmlSecMapEmpty		(xmlSecMapPtr map);
XMLSEC_EXPORT size_t			xmlSecMapGetSize	(xmlSecMapPtr map);
XMLSEC_EXPORT xmlSecObjPtr		xmlSecMapGetData	(xmlSecMapPtr map,
								 size_t pos);
XMLSEC_EXPORT const xmlChar*		xmlSecMapGetName	(xmlSecMapPtr map,
								 size_t pos);

#ifdef __cplusplus
	}
#endif /* __cplusplus */

#endif /* __XMLSEC_MAP_H__ */
