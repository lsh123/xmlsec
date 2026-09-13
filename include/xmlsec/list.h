/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef XMLSEC_LIST_H
#define XMLSEC_LIST_H

/**
 * @defgroup xmlsec_core_list Generic List
 * @ingroup xmlsec_core
 * @brief Generic dynamic array (vector) of pointers.
 * @{
 */

#include <stdio.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief The pointer list klass.
 */
typedef const struct _xmlSecPtrListKlass                        xmlSecPtrListKlass;
/**
 * @brief Pointer to #xmlSecPtrListKlass.
 */
typedef const struct _xmlSecPtrListKlass                        *xmlSecPtrListId;
typedef struct _xmlSecPtrList                                   xmlSecPtrList,
                                                                *xmlSecPtrListPtr;

/**
 * @brief The pointer list.
 */
struct _xmlSecPtrList {
    xmlSecPtrListId             id;  /**< the list klass. */

    xmlSecPtr*                  data;  /**< the list data. */
    xmlSecSize                  use;  /**< the current list size. */
    xmlSecSize                  max;  /**< the max (allocated) list size. */
    xmlSecAllocMode             allocMode;  /**< the memory allocation mode. */
};

XMLSEC_EXPORT void              xmlSecPtrListSetDefaultAllocMode(xmlSecAllocMode defAllocMode,
                                                                 xmlSecSize defInitialSize);


XMLSEC_EXPORT int               xmlSecPtrListInitialize         (xmlSecPtrListPtr list,
                                                                 xmlSecPtrListId id);
XMLSEC_EXPORT void              xmlSecPtrListFinalize           (xmlSecPtrListPtr list);
XMLSEC_EXPORT xmlSecPtrListPtr  xmlSecPtrListCreate             (xmlSecPtrListId id);
XMLSEC_EXPORT void              xmlSecPtrListDestroy            (xmlSecPtrListPtr list);
XMLSEC_EXPORT void              xmlSecPtrListEmpty              (xmlSecPtrListPtr list);

XMLSEC_EXPORT int               xmlSecPtrListCopy               (xmlSecPtrListPtr dst,
                                                                 xmlSecPtrListPtr src);
XMLSEC_EXPORT xmlSecPtrListPtr  xmlSecPtrListDuplicate          (xmlSecPtrListPtr list);

XMLSEC_EXPORT xmlSecSize        xmlSecPtrListGetSize            (xmlSecPtrListPtr list);
XMLSEC_EXPORT xmlSecPtr         xmlSecPtrListGetItem            (xmlSecPtrListPtr list,
                                                                 xmlSecSize pos);
XMLSEC_EXPORT int               xmlSecPtrListAdd                (xmlSecPtrListPtr list,
                                                                 xmlSecPtr item);
XMLSEC_EXPORT int               xmlSecPtrListInsert             (xmlSecPtrListPtr list,
                                                                 xmlSecPtr item,
                                                                 xmlSecSize pos);
XMLSEC_EXPORT int               xmlSecPtrListSet                (xmlSecPtrListPtr list,
                                                                 xmlSecPtr item,
                                                                 xmlSecSize pos);
XMLSEC_EXPORT int               xmlSecPtrListRemove             (xmlSecPtrListPtr list,
                                                                 xmlSecSize pos);
XMLSEC_EXPORT xmlSecPtr         xmlSecPtrListRemoveAndReturn    (xmlSecPtrListPtr list,
                                                                 xmlSecSize pos);
XMLSEC_EXPORT xmlSecPtr         xmlSecPtrListPopLast            (xmlSecPtrListPtr list);
XMLSEC_EXPORT void              xmlSecPtrListDebugDump          (xmlSecPtrListPtr list,
                                                                 FILE* output);
XMLSEC_EXPORT void              xmlSecPtrListDebugXmlDump       (xmlSecPtrListPtr list,
                                                                 FILE* output);

/**
 * @brief Macro. Returns list's name.
 * @param list the pointer to list.
 */
#define xmlSecPtrListGetName(list) \
        (((list) != NULL) ? xmlSecPtrListKlassGetName((list)->id) : NULL)

/**
 * @brief Macro. Returns 1 if @p list is valid.
 * @details Macro. Returns 1 if @p list is not NULL and @p list->id is not NULL,
 * or 0 otherwise.
 * @param list the pointer to list.
 */
#define xmlSecPtrListIsValid(list) \
        ((( list ) != NULL) && ((( list )->id) != NULL))
/**
 * @brief Macro. Returns 1 if @p list's id equals @p listId.
 * @details Macro. Returns 1 if @p list is valid and @p list's id is equal to @p listId.
 * @param list the pointer to list.
 * @param listId the list Id.
 */
#define xmlSecPtrListCheckId(list, listId) \
        (xmlSecPtrListIsValid(( list )) && \
        ((( list )->id) == ( listId )))


/******************************************************************************
 *
 * List klass
 *
 *****************************************************************************/
/**
 * @brief The "unknown" id.
 */
#define xmlSecPtrListIdUnknown                  NULL

/**
 * @brief Duplicates item @p ptr.
 * @details If this method is not NULL then the list klass must also provide
 * #xmlSecPtrDestroyItemMethod to release items duplicated by this method,
 * including partial copies rolled back after an error.
 * @param ptr the pointer to list item.
 * @return pointer to new item copy or NULL if an error occurs.
 */
typedef xmlSecPtr               (*xmlSecPtrDuplicateItemMethod) (xmlSecPtr ptr);

/**
 * @brief Destroys list item @p ptr.
 * @param ptr the pointer to list item.
 */
typedef void                    (*xmlSecPtrDestroyItemMethod)   (xmlSecPtr ptr);

/**
 * @brief Prints debug information about @p ptr to @p output.
 * @param ptr the pointer to list item.
 * @param output the output FILE.
 */
typedef void                    (*xmlSecPtrDebugDumpItemMethod) (xmlSecPtr ptr,
                                                                 FILE* output);

/**
 * @brief List klass.
 * @details If #duplicateItem is NULL then #xmlSecPtrListCopy shares the raw item
 * pointers between the source and the destination lists. In that case, if
 * #destroyItem is not NULL, finalizing both lists will free each shared item
 * twice.
 */
struct _xmlSecPtrListKlass {
    const xmlChar*                      name;  /**< the list klass name. */
    xmlSecPtrDuplicateItemMethod        duplicateItem;  /**< the duplicate item method; requires destroyItem when not NULL. */
    xmlSecPtrDestroyItemMethod          destroyItem;  /**< the destroy item method for list-owned items, including duplicated items. */
    xmlSecPtrDebugDumpItemMethod        debugDumpItem;  /**< the debug dump item method. */
    xmlSecPtrDebugDumpItemMethod        debugXmlDumpItem;  /**< the method for printing debug item information in XML format. */
};

/**
 * @brief Macro. Returns the list klass name.
 * @param klass the list klass.
 */
#define xmlSecPtrListKlassGetName(klass) \
        (((klass) != NULL) ? ((klass)->name) : NULL)

/******************************************************************************
 *
 * xmlSecStringListKlass
 *
 *****************************************************************************/
/**
 * @brief Strings list klass.
 */
#define xmlSecStringListId \
        xmlSecStringListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId   xmlSecStringListGetKlass        (void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_list */

#endif /* XMLSEC_LIST_H */
