/** 
 * XMLSec library
 *
 * List
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_LIST_H__
#define __XMLSEC_LIST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/object.h>

typedef struct _xmlSecListKlass				xmlSecListKlass,
							*xmlSecListKlassPtr;
typedef struct _xmlSecList				xmlSecList,
							*xmlSecListPtr;
/*********************************************************************
 *
 * List
 *
 *********************************************************************/
#define xmlSecListKlassId 		xmlSecObjKlassGet()
#define xmlSecListKlassCast(klass) 	xmlSecObjKlassCastMacro((klass), xmlSecListKlassId, xmlSecListKlassPtr)
#define xmlSecListKlassCheckCast(klass) xmlSecObjKlassCheckCastMacro((klass), xmlSecListKlassId)
#define xmlSecListCast(obj) 		xmlSecObjCastMacro((obj), xmlSecListKlassId, xmlSecListPtr)
#define xmlSecListCheckCast(obj) 	xmlSecObjCheckCastMacro((obj), xmlSecListKlassId)

struct _xmlSecListKlass {
    xmlSecObjKlass			parent;
};
		
struct _xmlSecList {
    xmlSecObj				parent;
    
    /* private data */
    xmlSecPtr*				data;
    size_t				size;
    size_t				maxSize;
};

#define xmlSecListNew()			((xmlSecListPtr)xmlSecObjNew(xmlSecListKlassId))
XMLSEC_EXPORT xmlSecObjKlassPtr		xmlSecListKlassGet	(void);
XMLSEC_EXPORT xmlSecPtr			xmlSecListGetData	(xmlSecListPtr list,
								 size_t pos);
XMLSEC_EXPORT size_t			xmlSecListGetSize	(xmlSecListPtr list);
XMLSEC_EXPORT int			xmlSecListFind		(xmlSecListPtr list,
								 xmlSecPtr data);
XMLSEC_EXPORT int			xmlSecListAppend	(xmlSecListPtr list,
								 xmlSecPtr data);
XMLSEC_EXPORT int			xmlSecListPrepend	(xmlSecListPtr list,
								 xmlSecPtr data);
XMLSEC_EXPORT int			xmlSecListInsert	(xmlSecListPtr list,
								 size_t pos,
								 xmlSecPtr data);
XMLSEC_EXPORT void			xmlSecListRemove	(xmlSecListPtr list,
								 size_t pos);
XMLSEC_EXPORT void			xmlSecListEmpty		(xmlSecListPtr list);

#ifdef __cplusplus
	}
#endif /* __cplusplus */

#endif /* __XMLSEC_LIST_H__ */
