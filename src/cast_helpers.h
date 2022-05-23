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

/* Include common error helper macros. */
#include "errors_helpers.h"


/* Safe cast with limits check: xmlSecSize -> int */
#define XMLSEC_SAFE_CAST_SIZE_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if((srcVal) > INT_MAX) {                                                   \
        xmlSecImpossibleCastError(xmlSecSize, (unsigned long)(srcVal), "%lu",  \
                                 int, INT_MIN, INT_MAX,"%d", (errorObject));   \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \

/* Safe cast with limits check: size_t -> int */
#define XMLSEC_SAFE_CAST_SIZE_T_TO_INT(srcVal, dstVal, errorAction, errorObject) \
    if((srcVal) > INT_MAX) {                                                   \
        xmlSecImpossibleCastError(size_t, (unsigned long)(srcVal), "%lu",      \
                                 int, INT_MIN, INT_MAX,"%d", (errorObject));   \
        errorAction;                                                           \
    }                                                                          \
    dstVal = (int)(srcVal);                                                    \



#endif /* __XMLSEC_CAST_HELPERS_H__ */
