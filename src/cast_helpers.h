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

/******************************************************************************
 *
 *  TO_INT
 * 
 *****************************************************************************/

/* Safe cast with limits check: xmlSecSize -> int (assume xmlSecSize >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(INT_MAX)) {             \
        xmlSecImpossibleCastError(xmlSecSize, XMLSEC_UL_BAD_CAST(srcVal), "%lu", \
                                 int, INT_MIN, INT_MAX, "%d", (errorObject));  \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \

/* Safe cast with limits check: size_t -> int (assume size_t >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(INT_MAX)) {             \
        xmlSecImpossibleCastError(size_t, XMLSEC_UL_BAD_CAST(srcVal), "%lu",   \
                                 int, INT_MIN, INT_MAX, "%d", (errorObject));  \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \

/* Safe cast with limits check: unsigned int -> int (assume uint >= 0) */
#define XMLSEC_SAFE_CAST_UINT_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(INT_MAX)) {             \
        xmlSecImpossibleCastError(unsigned int, (srcVal), "%du",               \
                                 int, INT_MIN, INT_MAX, "%d", (errorObject));  \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \


/* Safe cast with limits check: long -> int */
#define XMLSEC_SAFE_CAST_LONG_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < (long)INT_MIN) || ((long)INT_MAX < (srcVal))) {   \
        xmlSecImpossibleCastError(long, XMLSEC_UL_BAD_CAST(srcVal), "%ld",     \
                                 int, INT_MIN, INT_MAX, "%d", (errorObject));  \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \


/* Safe cast with limits check: ptrdiff_t -> int (assume ptrdiff_t >= int) */
#if defined(__APPLE__)

#define XMLSEC_SAFE_CAST_PTRDIFF_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    XMLSEC_SAFE_CAST_LONG_TO_INT(srcVal, dstVal, errorAction, errorObject)

#else /* defined(__APPLE__) */

#define XMLSEC_SAFE_CAST_PTRDIFF_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < (ptrdiff_t)INT_MIN) || ((ptrdiff_t)INT_MAX < (srcVal))) {   \
        xmlSecImpossibleCastError(ptrdiff_t, (long)(srcVal), "%ld",            \
                                 int, INT_MIN, INT_MAX, "%d", (errorObject));  \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \

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
                                  unisgned int, 0, UINT_MAX, "%du",            \
                                  (errorObject));                              \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (unsigned int)(srcVal);                                           \


/* Safe cast with limits check: size_t -> unsigned int (assume uint >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_UINT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(UINT_MAX)) {            \
        xmlSecImpossibleCastError(size_t, XMLSEC_UL_BAD_CAST(srcVal), "%lu",   \
                                  unisgned int, 0, UINT_MAX, "%du",            \
                                  (errorObject));                              \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (unsigned int)(srcVal);                                           \


/******************************************************************************
 *
 *  TO_LONG
 * 
 *****************************************************************************/

/* Safe cast with limits check: xmlSecSize -> long (assume xmlSecSize >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_TO_LONG(srcVal, dstVal, errorAction, errorObject)   \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(LONG_MAX)) {            \
        xmlSecImpossibleCastError(xmlSecSize, XMLSEC_UL_BAD_CAST(srcVal), "%lu",  \
                                 long, LONG_MIN, LONG_MAX, "%ld", (errorObject)); \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (long)(srcVal);                                                   \

/* Safe cast with limits check: size_t -> long (assume size_t >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_LONG(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(LONG_MAX)) {            \
        xmlSecImpossibleCastError(size_t, XMLSEC_UL_BAD_CAST(srcVal), "%lu",   \
                                 long, LONG_MIN, LONG_MAX, "%ld", (errorObject)); \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (long)(srcVal);                                                   \


/******************************************************************************
 *
 *  TO_SIZE (to xmlSecSize)
 * 
 *****************************************************************************/

/* Safe cast with limits check: size_t -> xmlSecSize (assume size_t >= 0) */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX)) {     \
        xmlSecImpossibleCastError(size_t, XMLSEC_UL_BAD_CAST(srcVal), "%lu",   \
                                  xmlSecSize, XMLSEC_UL_BAD_CAST(0),           \
                                  XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX),         \
                                  "%lu", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (xmlSecSize)(srcVal);                                             \

/* Safe cast with limits check: unsigned long -> xmlSecSize (assume ulong >= 0) */
#define XMLSEC_SAFE_CAST_ULONG_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX)) {     \
        xmlSecImpossibleCastError(unsigned long, (srcVal), "%lu",              \
                                  xmlSecSize, XMLSEC_UL_BAD_CAST(0),           \
                                  XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX),         \
                                  "%lu", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (xmlSecSize)(srcVal);                                             \


/* Safe cast with limits check: long -> xmlSecSize (assume xmlSecSize >= 0) */
#define XMLSEC_SAFE_CAST_LONG_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < 0) || (XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX) < XMLSEC_UL_BAD_CAST(srcVal))) { \
        xmlSecImpossibleCastError(long, (srcVal), "%ld",                       \
                                  xmlSecSize, XMLSEC_UL_BAD_CAST(0),           \
                                  XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX),         \
                                  "%lu", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (xmlSecSize)(srcVal);                                             \


/* Safe cast with limits check: int -> xmlSecSize (assume xmlSecSize >= 0) */
#define XMLSEC_SAFE_CAST_INT_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if(((srcVal) < 0) || (XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX) < XMLSEC_UL_BAD_CAST(srcVal))) { \
        xmlSecImpossibleCastError(int, (srcVal), "%d",                         \
                                  xmlSecSize, XMLSEC_UL_BAD_CAST(0),           \
                                  XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX),         \
                                  "%lu", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (xmlSecSize)(srcVal);                                             \


#endif /* __XMLSEC_CAST_HELPERS_H__ */
