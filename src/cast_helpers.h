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

/* Safe cast with limits check: xmlSecSize -> int */
#define XMLSEC_SAFE_CAST_SIZE_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(INT_MAX)) {             \
        xmlSecImpossibleCastError(xmlSecSize, XMLSEC_UL_BAD_CAST(srcVal), "%lu", \
                                 int, INT_MIN, INT_MAX, "%d", (errorObject));  \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \

/* Safe cast with limits check: size_t -> xmlSecSize */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX)) {     \
        xmlSecImpossibleCastError(size_t, XMLSEC_UL_BAD_CAST(srcVal), "%lu",   \
                                  xmlSecSize, XMLSEC_UL_BAD_CAST(0),           \
                                  XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX),         \
                                  "%lu", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \


/* Safe cast with limits check: size_t -> int */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(INT_MAX)) {             \
        xmlSecImpossibleCastError(size_t, XMLSEC_UL_BAD_CAST(srcVal), "%lu",   \
                                 int, INT_MIN, INT_MAX, "%d", (errorObject));  \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \


/* Safe cast with limits check: size_t -> long */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_LONG(srcVal, dstVal, errorAction, errorObject) \
    if(XMLSEC_UL_BAD_CAST(srcVal) > XMLSEC_UL_BAD_CAST(LONG_MAX)) {            \
        xmlSecImpossibleCastError(size_t, XMLSEC_UL_BAD_CAST(srcVal), "%lu",   \
                                 long, LONG_MIN, LONG_MAX, "%ld", (errorObject)); \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \


/* Safe cast with limits check: int -> xmlSecSize */
#define XMLSEC_SAFE_CAST_INT_TO_SIZE(srcVal, dstVal, errorAction, errorObject) \
    if((srcVal) < 0) {                                                         \
        xmlSecImpossibleCastError(int, (srcVal), "%d",                         \
                                  xmlSecSize, XMLSEC_UL_BAD_CAST(0),           \
                                  XMLSEC_UL_BAD_CAST(XMLSEC_SIZE_MAX),         \
                                  "%lu", (errorObject));                       \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \


/* Safe cast with limits check: int -> size_t */
#define XMLSEC_SAFE_CAST_INT_TO_SIZE_T(srcVal, dstVal, errorAction, errorObject) \
    if((srcVal) < 0) {                                                         \
        xmlSecImpossibleCastError(int, (srcVal), "%d",                         \
                                 size_t,XMLSEC_UL_BAD_CAST(0),                 \
                                 XMLSEC_UL_BAD_CAST(SIZE_MAX),                 \
                                 "%lu", (errorObject));                        \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \

#endif /* __XMLSEC_CAST_HELPERS_H__ */
