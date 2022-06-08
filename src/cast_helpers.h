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


/******************************************************************************
 *
 *  TO_BYTE
 *
 *****************************************************************************/

 /* Safe cast with limits check: int -> xmlSecByte */
#define XMLSEC_SAFE_CAST_INT_TO_BYTE(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < 0) || ((srcVal) > 255)) {                                   \
        xmlSecImpossibleCastError(int, (srcVal), "%d",                         \
            xmlSecByte, 0, 255, "%d", (errorObject));                          \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (xmlSecByte)(srcVal);                                           \


 /* Safe cast with limits check: xmlSecSize -> xmlSecByte (assume xmlSecSize > 0) */
#define XMLSEC_SAFE_CAST_SIZE_TO_BYTE(srcVal, dstVal, errorAction, errorObject) \
    if((srcVal) > 255)  {                                                      \
        xmlSecImpossibleCastError(xmlSecSize, srcVal, XMLSEC_SIZE_FMT,         \
            xmlSecByte, 0, 255, "%d", (errorObject));                          \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (xmlSecByte)(srcVal);                                           \


/******************************************************************************
 *
 *  TO_INT
 * 
 *****************************************************************************/

/* Safe cast with limits check: xmlSecSize -> int (assume xmlSecSize >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(INT_MAX)) {             \
        xmlSecImpossibleCastError(xmlSecSize, (srcVal), XMLSEC_SIZE_FMT,       \
            int, INT_MIN, INT_MAX, "%d", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (int)(srcVal);                                                  \

/* Safe cast with limits check: size_t -> int (assume size_t >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(INT_MAX)) {             \
        xmlSecImpossibleCastError(size_t, (srcVal), "%zu",                     \
            int, INT_MIN, INT_MAX, "%d", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (int)(srcVal);                                                  \

/* Safe cast with limits check: unsigned int -> int (assume uint >= 0) */
#define XMLSEC_SAFE_CAST_UINT_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(INT_MAX)) {             \
        xmlSecImpossibleCastError(unsigned int, (srcVal), "%u",                \
            int, INT_MIN, INT_MAX, "%d", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (int)(srcVal);                                                  \


/* Safe cast with limits check: long -> int */
#define XMLSEC_SAFE_CAST_LONG_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < (long)INT_MIN) || ((long)INT_MAX < (srcVal))) {             \
        xmlSecImpossibleCastError(long, (srcVal), "%ld",                       \
            int, INT_MIN, INT_MAX, "%d", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (int)(srcVal);                                                  \

/* Safe cast with limits check: unsigned long -> int  (assume ulong >= 0) */
#define XMLSEC_SAFE_CAST_ULONG_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(INT_MAX) < XMLSEC_UL_BAD_CAST(srcVal)) {             \
        xmlSecImpossibleCastError(unsigned long, (srcVal), "%lu",              \
            int, INT_MIN, INT_MAX, "%d", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (int)(srcVal);                                                  \


/* Safe cast with limits check: ptrdiff_t -> int (assume ptrdiff_t >= int) */
#if defined(__APPLE__)

#define XMLSEC_SAFE_CAST_PTRDIFF_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_LONG_TO_INT(srcVal, dstVal, errorAction, errorObject)

#else /* defined(__APPLE__) */

#define XMLSEC_SAFE_CAST_PTRDIFF_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < (ptrdiff_t)INT_MIN) || ((ptrdiff_t)INT_MAX < (srcVal))) {   \
        xmlSecImpossibleCastError(ptrdiff_t, (long)(srcVal), "%ld",            \
            int, INT_MIN, INT_MAX, "%d", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (int)(srcVal);                                                  \

#endif /* defined(__APPLE__) */

/******************************************************************************
 *
 *  TO_UINT
 *
 *****************************************************************************/

/* Safe cast with limits check: int -> unsigned int (assume uint >= 0) */
#define XMLSEC_SAFE_CAST_INT_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < 0) || (XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(UINT_MAX))) { \
        xmlSecImpossibleCastError(int, (srcVal), "%d",                         \
            unisgned int, 0U, UINT_MAX, "%u", (errorObject));                  \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (unsigned int)(srcVal);                                         \


/* Safe cast with limits check: size_t -> unsigned int (assume uint >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(UINT_MAX)) {            \
        xmlSecImpossibleCastError(size_t, (srcVal), "%zu",                     \
            unisgned int, 0U, UINT_MAX, "%u", (errorObject));                  \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (unsigned int)(srcVal);                                         \

/* Safe cast with limits check: xmlSecSize -> unsigned int (assume uint >= 0) */
#if !defined(XMLSEC_NO_SIZE_T)
#define XMLSEC_SAFE_CAST_SIZE_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(UINT_MAX)) {            \
        xmlSecImpossibleCastError(xmlSecSize, (srcVal), XMLSEC_SIZE_FMT,       \
            unisgned int, 0U, UINT_MAX, "%u", (errorObject));                  \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (unsigned int)(srcVal);                                         \

#else /* !defined(XMLSEC_NO_SIZE_T) */
#define XMLSEC_SAFE_CAST_SIZE_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);                                                        \

#endif /* !defined(XMLSEC_NO_SIZE_T) */



/******************************************************************************
 *
 *  TO_LONG
 * 
 *****************************************************************************/

/* Safe cast with limits check: xmlSecSize -> long (assume xmlSecSize >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_TO_LONG(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(LONG_MAX)) {            \
        xmlSecImpossibleCastError(xmlSecSize, (srcVal), XMLSEC_SIZE_FMT,       \
            long, LONG_MIN, LONG_MAX, "%ld", (errorObject));                   \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (long)(srcVal);                                                 \

/* Safe cast with limits check: size_t -> long (assume size_t >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_LONG(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(LONG_MAX)) {            \
        xmlSecImpossibleCastError(size_t, (srcVal), "%zu",                     \
            long, LONG_MIN, LONG_MAX, "%ld", (errorObject));                    \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (long)(srcVal);                                                 \


/******************************************************************************
 *
 *  TO_SIZE (to xmlSecSize)
 * 
 *****************************************************************************/

/* Safe cast with limits check: size_t -> xmlSecSize (assume size_t >= 0) */
#if defined(XMLSEC_NO_SIZE_T)
#define XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX)) {     \
        xmlSecImpossibleCastError(size_t, (srcVal), "%zu",                     \
            xmlSecSize, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, XMLSEC_SIZE_FMT,     \
            (errorObject));                                                    \
        errorAction;                                                           \
    }                                                                          \
    (dstVal) = (xmlSecSize)(srcVal);                                           \

#else /* defined(XMLSEC_NO_SIZE_T) */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    (dstVal) = (srcVal);                                                        \

#endif /* defined(XMLSEC_NO_SIZE_T) */

/* Safe cast with limits check: unsigned long -> xmlSecSize (assume ulong >= 0) */
#define XMLSEC_SAFE_CAST_ULONG_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX)) {      \
        xmlSecImpossibleCastError(unsigned long, (srcVal), "%lu",               \
            xmlSecSize, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, XMLSEC_SIZE_FMT,      \
            (errorObject));                                                     \
        errorAction;                                                            \
    }                                                                           \
    (dstVal) = (xmlSecSize)(srcVal);                                            \


/* Safe cast with limits check: long -> xmlSecSize (assume xmlSecSize >= 0) */
#define XMLSEC_SAFE_CAST_LONG_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < 0) || (XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX) < XMLSEC_UL_BAD_CAST(srcVal))) { \
        xmlSecImpossibleCastError(long, (srcVal), "%ld",                        \
            xmlSecSize, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, XMLSEC_SIZE_FMT,      \
            (errorObject));                                                     \
        errorAction;                                                            \
    }                                                                           \
    (dstVal) = (xmlSecSize)(srcVal);                                            \


/* Safe cast with limits check: int -> xmlSecSize (assume xmlSecSize >= 0) */
#define XMLSEC_SAFE_CAST_INT_TO_SIZE(srcVal, dstVal, errorAction, errorObject)  \
    if(((srcVal) < 0) || (XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX) < XMLSEC_UL_BAD_CAST(srcVal))) { \
        xmlSecImpossibleCastError(int, (srcVal), "%d",                          \
            xmlSecSize, XMLSEC_SIZE_MIN, XMLSEC_SIZE_MAX, XMLSEC_SIZE_FMT,      \
            (errorObject));                                                     \
        errorAction;                                                            \
    }                                                                           \
    (dstVal) = (xmlSecSize)(srcVal);                                            \


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
