/** 
 * XMLSec library
 *
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

#include <xmlsec/xmlsec.h>

typedef void*	xmlSecPtr;
typedef const struct _xmlSecPtrListKlass	xmlSecPtrListKlass, *xmlSecPtrListId;
typedef struct _xmlSecPtrList 			xmlSecPtrList, *xmlSecPtrListPtr;


struct _xmlSecPtrList {
    xmlSecPtrListId		id;        

    xmlSecPtr*			data;
    size_t			use;
    size_t			max;
};

XMLSEC_EXPORT int		xmlSecPtrListInitialize	(xmlSecPtrListPtr list,
							 xmlSecPtrListId id);
XMLSEC_EXPORT void		xmlSecPtrListFinalize	(xmlSecPtrListPtr list);
XMLSEC_EXPORT xmlSecPtrListPtr	xmlSecPtrListCreate	(xmlSecPtrListId id);
XMLSEC_EXPORT void		xmlSecPtrListDestroy	(xmlSecPtrListPtr list);
XMLSEC_EXPORT xmlSecPtrListPtr	xmlSecPtrListDuplicate	(xmlSecPtrListPtr list);

XMLSEC_EXPORT size_t		xmlSecPtrListGetSize	(xmlSecPtrListPtr list);
XMLSEC_EXPORT xmlSecPtr		xmlSecPtrListGetItem	(xmlSecPtrListPtr list,
							 size_t pos);
XMLSEC_EXPORT int		xmlSecPtrListAdd	(xmlSecPtrListPtr list,
							 xmlSecPtr item);
XMLSEC_EXPORT int		xmlSecPtrListSet	(xmlSecPtrListPtr list,
							 xmlSecPtr item,
							 size_t pos);
XMLSEC_EXPORT int		xmlSecPtrListRemove	(xmlSecPtrListPtr list,
							 size_t pos);
XMLSEC_EXPORT void		xmlSecPtrListDebugDump	(xmlSecPtrListPtr list,
    							 FILE* output);
XMLSEC_EXPORT void		xmlSecPtrListDebugXmlDump(xmlSecPtrListPtr list,
							 FILE* output);
#define xmlSecPtrListGetName(list) \
	(((list) != NULL) ? xmlSecPtrListKlassGetName((list)->id) : NULL)

/**
 * xmlSecPtrListIsValid:
 * @list: the pointer to list.
 *
 * Macro. Returns 1 if @list is not NULL and @list->id is not NULL
 * or 0 otherwise.
 */ 
#define xmlSecPtrListIsValid(list) \
	((( list ) != NULL) && ((( list )->id) != NULL))
/**
 * xmlSecPtrListCheckId:
 * @list: the pointer to list.
 * @dataId: the list Id.
 *
 * Macro. Returns 1 if @list is valid and @list's id is equal to @dataId.
 */
#define xmlSecPtrListCheckId(list, dataId) \
 	(xmlSecPtrListIsValid(( list )) && \
	((( list )->id) == ( dataId )))


/**************************************************************************
 *
 * xmlSecPtrListKlass
 *
 *************************************************************************/
/**
 * xmlSecPtrListIdUnknown:
 *
 * The "unknown" id.
 */
#define xmlSecPtrListIdUnknown 			NULL

typedef xmlSecPtr		(*xmlSecPtrDuplicateItemMethod)	(xmlSecPtr ptr);
typedef void			(*xmlSecPtrDestroyItemMethod)	(xmlSecPtr ptr);
typedef void			(*xmlSecPtrDebugDumpItemMethod)	(xmlSecPtr ptr,
								 FILE* output);

struct _xmlSecPtrListKlass {
    const xmlChar*			name;
    xmlSecPtrDuplicateItemMethod	duplicateItem;
    xmlSecPtrDestroyItemMethod		destroyItem;
    xmlSecPtrDebugDumpItemMethod	debugDumpItem;
    xmlSecPtrDebugDumpItemMethod	debugXmlDumpItem;
};
#define xmlSecPtrListKlassGetName(klass) \
	(((klass) != NULL) ? ((klass)->name) : NULL)


/**************************************************************************
 *
 * xmlSecStringListKlass
 *
 *************************************************************************/
#define xmlSecStringListId \
	xmlSecStringListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecStringListGetKlass	(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_LIST_H__ */

