/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Internal header only used during the compilation,
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_CAST_HELPERS_H__
#define __XMLSEC_CAST_HELPERS_H__

#include <limits.h>
#include "errors_helpers.h"


/* if it is missing */
#ifndef SIZE_MAX
#define SIZE_MAX (~(size_t)0)
#endif /* SIZE_MAX */


/**
 * XMLSEC_UL_BAD_CAST:
 * @val:        the value to cast
 *
 * Bad cast to 'unsigned long' (very useful for printing with '%lu').
 */
#define XMLSEC_UL_BAD_CAST(val)               ((unsigned long)(val))

/**
 * Helpers for printing out enum values (mostly debugging).
 */
#define XMLSEC_ENUM_CAST(val)                ((int)(val))
#define XMLSEC_ENUM_FMT                      "%d"


 /******************************************************************************
  *
  * Main macros to help with casting, we assume that LL and ULL are the largest
  * possible types.
  *
  *****************************************************************************/
#define XMLSEC_LL_BAD_CAST(val)    ((long long)(val))
#define XMLSEC_ULL_BAD_CAST(val)   ((unsigned long long)(val))

#define XMLSEC_SAFE_CAST_MIN_MAX_CHECK(srcType, srcVal, srcFmt, dstType, dstVal, dstFmt, dstMin, dstMax, errorAction, errorObject) \
    if((XMLSEC_LL_BAD_CAST(srcVal) < XMLSEC_LL_BAD_CAST(dstMin)) || (XMLSEC_ULL_BAD_CAST(srcVal) > XMLSEC_ULL_BAD_CAST(dstMax))) { \
        xmlSecImpossibleCastError(srcType, (srcVal), srcFmt,                   \
            dstType, dstMin, dstMax, dstFmt, (errorObject));                   \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (dstType)(srcVal);                                              \

#define XMLSEC_SAFE_CAST_MIN_CHECK(srcType, srcVal, srcFmt, dstType, dstVal, dstFmt, dstMin, dstMax, errorAction, errorObject) \
    if(XMLSEC_LL_BAD_CAST(srcVal) < XMLSEC_LL_BAD_CAST(dstMin)) {              \
        xmlSecImpossibleCastError(srcType, (srcVal), srcFmt,                   \
            dstType, dstMin, dstMax, dstFmt, (errorObject));                   \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (dstType)(srcVal);                                              \


/* we assume that dstType_min <= srcType_min and srcType_max >= dstType_max */
#define XMLSEC_SAFE_CAST_MAX_CHECK(srcType, srcVal, srcFmt, dstType, dstVal, dstFmt, dstMin, dstMax, errorAction, errorObject) \
    if(XMLSEC_ULL_BAD_CAST(srcVal) > XMLSEC_ULL_BAD_CAST(dstMax)) {            \
        xmlSecImpossibleCastError(srcType, (srcVal), srcFmt,                   \
            dstType, dstMin, dstMax, dstFmt, (errorObject));                   \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (dstType)(srcVal);                                              \


/******************************************************************************
 *
 *  TO_BYTE
 *
 *****************************************************************************/

/* Safe cast with limits check: int -> xmlSecByte */
#define XMLSEC_SAFE_CAST_INT_TO_BYTE(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MIN_MAX_CHECK(int, (srcVal), "%d",                        \
        xmlSecByte, (dstVal), "%d", 0, 255,                                    \
        errorAction, (errorObject))

/* Safe cast with limits check: xmlSecSize -> xmlSecByte (assume xmlSecSize > 0) */
#define XMLSEC_SAFE_CAST_SIZE_TO_BYTE(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(xmlSecSize, (srcVal), XMLSEC_SIZE_FMT,           \
        xmlSecByte, (dstVal), "%d", 0, 255,                                     \
        errorAction, (errorObject))

/******************************************************************************
 *
 *  TO_INT
 * 
 *****************************************************************************/

/* Safe cast with limits check: unsigned int -> int (assume uint >= 0 and uint_max >= int_max) */
#define XMLSEC_SAFE_CAST_UINT_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(unsigned int, (srcVal), "%u",                   \
        int, (dstVal), "%d", INT_MIN, INT_MAX,                                 \
        errorAction, (errorObject))

/* Safe cast with limits check: unsigned long -> int (assume ulong >= 0 and ulong_max >= int_max) */
#define XMLSEC_SAFE_CAST_ULONG_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(unsigned long, (srcVal), "%lu",                 \
        int, (dstVal), "%d", INT_MIN, INT_MAX,                                 \
        errorAction, (errorObject))

/* Safe cast with limits check: long -> int (assume long >= int) */
#define XMLSEC_SAFE_CAST_LONG_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MIN_MAX_CHECK(long, (srcVal), "%ld",                      \
        int, (dstVal), "%d", INT_MIN, INT_MAX,                                 \
        errorAction, (errorObject))

/* Safe cast with limits check: ptrdiff_t -> int (assume ptrdiff_t >= int) */
#if defined(__APPLE__)

#define XMLSEC_SAFE_CAST_PTRDIFF_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_LONG_TO_INT(srcVal, dstVal, errorAction, errorObject)

#else /* defined(__APPLE__) */

#define XMLSEC_SAFE_CAST_PTRDIFF_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MIN_MAX_CHECK(ptrdiff_t, (srcVal), "%lld",                 \
        int, (dstVal), "%d", INT_MIN, INT_MAX,                                  \
        errorAction, (errorObject))

#endif /* defined(__APPLE__) */

/* Safe cast with limits check: size_t -> int (assume size_t >= 0) */
#if (SIZE_MAX > INT_MAX)

#define XMLSEC_SAFE_CAST_SIZE_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(size_t, (srcVal), XMLSEC_SIZE_T_FMT,             \
        int, (dstVal), "%d", INT_MIN, INT_MAX,                                  \
        errorAction, (errorObject))

#else /* (SIZE_MAX > INT_MAX) */

#define XMLSEC_SAFE_CAST_SIZE_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (SIZE_MAX > INT_MAX) */

/* Safe cast with limits check: xmlSecSize -> int (assume xmlSecSize >= 0) */
#if (XMLSEC_SIZE_MAX > INT_MAX)

#define XMLSEC_SAFE_CAST_SIZE_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(xmlSecSize, (srcVal), XMLSEC_SIZE_FMT,          \
        int, (dstVal), "%d", INT_MIN, INT_MAX,                                 \
        errorAction, (errorObject))

#else /* (XMLSEC_SIZE_MAX > INT_MAX) */

#define XMLSEC_SAFE_CAST_SIZE_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (XMLSEC_SIZE_MAX > INT_MAX) */

/******************************************************************************
 *
 *  TO_UINT
 *
 *****************************************************************************/

/* Safe cast with limits check: int -> unsigned int (assume uint >= 0 and uint_max >= int_max) */
#define XMLSEC_SAFE_CAST_INT_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MIN_MAX_CHECK(int, (srcVal), "%d",                        \
        unsigned int, (dstVal), "%u", 0U, UINT_MAX,                            \
        errorAction, (errorObject))

/* Safe cast with limits check: size_t -> unsigned int (assume uint >= 0) */
#if (SIZE_MAX > UINT_MAX)

#define XMLSEC_SAFE_CAST_SIZE_T_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(size_t, (srcVal), XMLSEC_SIZE_T_FMT,            \
        unsigned int, (dstVal), "%u", 0U, UINT_MAX,                            \
        errorAction, (errorObject))

#else /* (SIZE_MAX > UINT_MAX) */

#define XMLSEC_SAFE_CAST_SIZE_T_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (SIZE_MAX > UINT_MAX) */

/* Safe cast with limits check: xmlSecSize -> unsigned int (assume uint >= 0) */
#if (XMLSEC_SIZE_MAX > UINT_MAX)

#define XMLSEC_SAFE_CAST_SIZE_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(xmlSecSize, (srcVal), XMLSEC_SIZE_FMT,          \
        unsigned int, (dstVal), "%u", 0U, UINT_MAX,                            \
        errorAction, (errorObject))

#else /* (XMLSEC_SIZE_MAX > UINT_MAX) */

#define XMLSEC_SAFE_CAST_SIZE_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (XMLSEC_SIZE_MAX > UINT_MAX) */

/******************************************************************************
 *
 *  TO_LONG
 * 
 *****************************************************************************/

/* Safe cast with limits check: size_t -> long (assume size_t >= 0) */
#if (SIZE_MAX > LONG_MAX)

#define XMLSEC_SAFE_CAST_SIZE_T_TO_LONG(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(size_t, (srcVal), XMLSEC_SIZE_T_FMT,            \
        long, (dstVal), "%ld", LONG_MIN, LONG_MAX,                             \
        errorAction, (errorObject))

#else /* (SIZE_MAX > LONG_MAX) */

#define XMLSEC_SAFE_CAST_SIZE_T_TO_LONG(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (SIZE_MAX > LONG_MAX) */


/* Safe cast with limits check: xmlSecSize -> long (assume xmlSecSize >= 0) */
#if (XMLSEC_SIZE_MAX > LONG_MAX)

#define XMLSEC_SAFE_CAST_SIZE_TO_LONG(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(xmlSecSize, (srcVal), XMLSEC_SIZE_FMT,          \
        long, (dstVal), "%ld", LONG_MIN, LONG_MAX,                             \
        errorAction, (errorObject))

#else /* (XMLSEC_SIZE_MAX > LONG_MAX) */

#define XMLSEC_SAFE_CAST_SIZE_TO_LONG(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (XMLSEC_SIZE_MAX > LONG_MAX) */

/******************************************************************************
 *
 *  TO_ULONG
 *
 *****************************************************************************/

/* Safe cast with limits check: xmlSecSize -> unsigned int (assume ulong >= 0) */
#if (XMLSEC_SIZE_MAX > ULONG_MAX)

#define XMLSEC_SAFE_CAST_SIZE_TO_ULONG(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(xmlSecSize, (srcVal), XMLSEC_SIZE_FMT,           \
        unisgned long, (dstVal), "%lu", 0UL, ULONG_MAX,                         \
        errorAction, (errorObject))

#else /* (XMLSEC_SIZE_MAX > ULONG_MAX) */

#define XMLSEC_SAFE_CAST_SIZE_TO_ULONG(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (XMLSEC_SIZE_MAX > ULONG_MAX) */

/******************************************************************************
 *
 *  TO_SIZE (to xmlSecSize)
 * 
 *****************************************************************************/

/* Safe cast with limits check: int -> xmlSecSize (assume xmlSecSize >= 0) */
#if (INT_MAX > XMLSEC_SIZE_MAX)

#define XMLSEC_SAFE_CAST_INT_TO_SIZE(srcVal, dstVal, errorAction, errorObject)   \
    XMLSEC_SAFE_CAST_MIN_MAX_CHECK(int, (srcVal), "%d",                          \
        xmlSecSize, (dstVal), XMLSEC_SIZE_FMT, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, \
        errorAction, (errorObject))

#else /* (INT_MAX > XMLSEC_SIZE_MAX) */

#define XMLSEC_SAFE_CAST_INT_TO_SIZE(srcVal, dstVal, errorAction, errorObject)   \
    XMLSEC_SAFE_CAST_MIN_CHECK(int, (srcVal), "%d",                              \
        xmlSecSize, (dstVal), XMLSEC_SIZE_FMT, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, \
        errorAction, (errorObject))

#endif /* (INT_MAX > XMLSEC_SIZE_MAX) */

/* Safe cast with limits check: uint -> xmlSecSize (assume xmlSecSize >= 0). */
#if (UINT_MAX > XMLSEC_SIZE_MAX)

#define XMLSEC_SAFE_CAST_UINT_TO_SIZE(srcVal, dstVal, errorAction, errorObject)  \
    XMLSEC_SAFE_CAST_MAX_CHECK(unsigned int, (srcVal), "%u",                     \
        xmlSecSize, (dstVal), XMLSEC_SIZE_FMT, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, \
        errorAction, (errorObject))

#else /* (UINT_MAX > XMLSEC_SIZE_MAX) */

#define XMLSEC_SAFE_CAST_UINT_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (UINT_MAX > XMLSEC_SIZE_MAX) */

/* Safe cast with limits check: long -> xmlSecSize (assume xmlSecSize >= 0) */
#if (LONG_MAX > XMLSEC_SIZE_MAX)

#define XMLSEC_SAFE_CAST_LONG_TO_SIZE(srcVal, dstVal, errorAction, errorObject)  \
    XMLSEC_SAFE_CAST_MIN_MAX_CHECK(long, (srcVal), "%ld",                        \
        xmlSecSize, (dstVal), XMLSEC_SIZE_FMT, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, \
        errorAction, (errorObject))

#else /* (LONG_MAX > XMLSEC_SIZE_MAX) */

#define XMLSEC_SAFE_CAST_LONG_TO_SIZE(srcVal, dstVal, errorAction, errorObject)  \
    XMLSEC_SAFE_CAST_MIN_CHECK(long, (srcVal), "%ld",                            \
        xmlSecSize, (dstVal), XMLSEC_SIZE_FMT, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, \
        errorAction, (errorObject))

#endif /* (LONG_MAX > XMLSEC_SIZE_MAX) */


/* Safe cast with limits check: unsigned long -> xmlSecSize (assume ulong >= 0) */
#if (ULONG_MAX > XMLSEC_SIZE_MAX)

#define XMLSEC_SAFE_CAST_ULONG_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(unsigned long, (srcVal), "%lu",                   \
        xmlSecSize, (dstVal), XMLSEC_SIZE_FMT, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, \
        errorAction, (errorObject))

#else /* (ULONG_MAX > XMLSEC_SIZE_MAX) */

#define XMLSEC_SAFE_CAST_ULONG_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (ULONG_MAX > XMLSEC_SIZE_MAX) */

/* Safe cast with limits check: size_t -> xmlSecSize (assume size_t >= 0) */
#if (SIZE_MAX > XMLSEC_SIZE_MAX)

#define XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_MAX_CHECK(size_t, (srcVal), XMLSEC_SIZE_T_FMT,              \
        xmlSecSize, (dstVal), XMLSEC_SIZE_FMT, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, \
        errorAction, (errorObject))

#else /* (SIZE_MAX > XMLSEC_SIZE_MAX) */

#define XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);

#endif /* (SIZE_MAX > XMLSEC_SIZE_MAX) */

/******************************************************************************
 *
 *  Helpers to create child struct with context
 * 
 *****************************************************************************/
#define XMLSEC_CHILD_STRUCT_DECLARE(name, postfix, baseType, ctxType, checkSizeFunc) \
typedef struct _ ## xmlSec ## name ## postfix {                                    \
    baseType base;                                                                 \
    ctxType ctx;                                                                   \
} xmlSec ## name ## postfix;                                                       \
                                                                                   \
static inline ctxType* xmlSec ## name ## GetCtx(baseType* obj) {                   \
    if(checkSizeFunc(obj, sizeof(xmlSec ## name ## postfix))) {                    \
        return((ctxType *)(&( ((xmlSec ## name ## postfix *)obj)->ctx )));         \
    } else {                                                                       \
        return(NULL);                                                              \
    }                                                                              \
}                                                                                  \

#define XMLSEC_CHILD_STRUCT_SIZE(name, postfix)                                    \
    (sizeof(xmlSec ## name ## postfix))                                            \

/******************************************************************************
 *
 *  Helpers to create transform struct and cast to transform context
 * 
 *****************************************************************************/
#define XMLSEC_TRANSFORM_DECLARE(name, ctxType)  \
    XMLSEC_CHILD_STRUCT_DECLARE(name, Transform, xmlSecTransform, ctxType, xmlSecTransformCheckSize)
#define XMLSEC_TRANSFORM_SIZE(name) \
    XMLSEC_CHILD_STRUCT_SIZE(name, Transform)

/******************************************************************************
 *
 *  Helpers to create key data struct and cast to key data context
 * 
 *****************************************************************************/
#define XMLSEC_KEY_DATA_DECLARE(name, ctxType)  \
    XMLSEC_CHILD_STRUCT_DECLARE(name, KeyData, xmlSecKeyData, ctxType, xmlSecKeyDataCheckSize)
#define XMLSEC_KEY_DATA_SIZE(name) \
    XMLSEC_CHILD_STRUCT_SIZE(name, KeyData)

/******************************************************************************
 *
 *  Helpers to create key data store struct and cast to key store context
 * 
 *****************************************************************************/
#define XMLSEC_KEY_DATA_STORE_DECLARE(name, ctxType)  \
    XMLSEC_CHILD_STRUCT_DECLARE(name, KeyDataStore, xmlSecKeyDataStore, ctxType, xmlSecKeyDataStoreCheckSize)
#define XMLSEC_KEY_DATA_STORE_SIZE(name) \
    XMLSEC_CHILD_STRUCT_SIZE(name, KeyDataStore)

/******************************************************************************
 *
 *  Helpers to create key store struct and cast to key store context
 * 
 *****************************************************************************/
#define XMLSEC_KEY_STORE_DECLARE(name, ctxType) \
    XMLSEC_CHILD_STRUCT_DECLARE(name, KeyStore, xmlSecKeyStore, ctxType, xmlSecKeyStoreCheckSize)
#define XMLSEC_KEY_STORE_SIZE(name) \
    XMLSEC_CHILD_STRUCT_SIZE(name, KeyStore)

#endif /* __XMLSEC_CAST_HELPERS_H__ */
