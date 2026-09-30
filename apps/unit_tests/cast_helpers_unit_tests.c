/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library safe cast helper macro unit tests.
 */
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <libxml/tree.h>

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include "../../src/cast_helpers.h"

/******************************************************************************
 *
 * Helper wrappers. The safe cast macros require the errorAction to transfer
 * control out of the block (return or goto), so each macro is wrapped in a
 * small function that returns -1 when the cast was rejected and 0 otherwise.
 * This allows the test bodies to check the rejection without duplicating
 * goto labels.
 *
 *****************************************************************************/
static int
castTestIntToByte(int src, xmlSecByte* dst) {
    XMLSEC_SAFE_CAST_INT_TO_BYTE(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestUintToByte(unsigned int src, xmlSecByte* dst) {
    XMLSEC_SAFE_CAST_UINT_TO_BYTE(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestSizeToByte(xmlSecSize src, xmlSecByte* dst) {
    XMLSEC_SAFE_CAST_SIZE_TO_BYTE(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestUintToInt(unsigned int src, int* dst) {
    XMLSEC_SAFE_CAST_UINT_TO_INT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestUlongToInt(unsigned long src, int* dst) {
    XMLSEC_SAFE_CAST_ULONG_TO_INT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestLongToInt(long src, int* dst) {
    XMLSEC_SAFE_CAST_LONG_TO_INT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestSizeTToInt(size_t src, int* dst) {
    XMLSEC_SAFE_CAST_SIZE_T_TO_INT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestSizeToInt(xmlSecSize src, int* dst) {
    XMLSEC_SAFE_CAST_SIZE_TO_INT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestPtrdiffToInt(ptrdiff_t src, int* dst) {
    XMLSEC_SAFE_CAST_PTRDIFF_TO_INT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestPtrdiffToSize(ptrdiff_t src, xmlSecSize* dst) {
    XMLSEC_SAFE_CAST_PTRDIFF_TO_SIZE(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestIntToUint(int src, unsigned int* dst) {
    XMLSEC_SAFE_CAST_INT_TO_UINT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestSizeTToUint(size_t src, unsigned int* dst) {
    XMLSEC_SAFE_CAST_SIZE_T_TO_UINT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestSizeToUint(xmlSecSize src, unsigned int* dst) {
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestUintToLong(unsigned int src, long* dst) {
    XMLSEC_SAFE_CAST_UINT_TO_LONG(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestSizeTToLong(size_t src, long* dst) {
    XMLSEC_SAFE_CAST_SIZE_T_TO_LONG(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestSizeToLong(xmlSecSize src, long* dst) {
    XMLSEC_SAFE_CAST_SIZE_TO_LONG(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestSizeToUlong(xmlSecSize src, unsigned long* dst) {
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestIntToUlong(int src, unsigned long* dst) {
    XMLSEC_SAFE_CAST_INT_TO_ULONG(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestIntToSize(int src, xmlSecSize* dst) {
    XMLSEC_SAFE_CAST_INT_TO_SIZE(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestUintToSize(unsigned int src, xmlSecSize* dst) {
    XMLSEC_SAFE_CAST_UINT_TO_SIZE(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestLongToSize(long src, xmlSecSize* dst) {
    XMLSEC_SAFE_CAST_LONG_TO_SIZE(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestUlongToSize(unsigned long src, xmlSecSize* dst) {
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(src, (*dst), return(-1), NULL);
    return(0);
}

static int
castTestUlongLongToSize(unsigned long long src, xmlSecSize* dst) {
    XMLSEC_SAFE_CAST_ULLONG_TO_SIZE(src, (*dst), return(-1), NULL);
    return(0);
}

/******************************************************************************
 *
 *  TO_BYTE
 *
 *****************************************************************************/
static void
test_safe_cast_int_to_byte(void) {
    xmlSecByte dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_INT_TO_BYTE");

    /* valid values: min, middle and max */
    ret = castTestIntToByte(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestIntToByte(128, &dst);
    if((ret != 0) || (dst != 128)) {
        testLog("Error: valid value 128 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestIntToByte(255, &dst);
    if((ret != 0) || (dst != 255)) {
        testLog("Error: valid value 255 was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestIntToByte(-1, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value -1 (below the destination min) was not rejected\n");
        goto failed;
    }
    ret = castTestIntToByte(256, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value 256 (above the destination max) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_uint_to_byte(void) {
    xmlSecByte dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_UINT_TO_BYTE");

    /* valid values: min, middle and max */
    ret = castTestUintToByte(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestUintToByte(128, &dst);
    if((ret != 0) || (dst != 128)) {
        testLog("Error: valid value 128 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestUintToByte(255, &dst);
    if((ret != 0) || (dst != 255)) {
        testLog("Error: valid value 255 was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestUintToByte(256, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value 256 (above the destination max) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_size_to_byte(void) {
    xmlSecByte dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_SIZE_TO_BYTE");

    /* valid values: min, middle and max */
    ret = castTestSizeToByte(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestSizeToByte(128, &dst);
    if((ret != 0) || (dst != 128)) {
        testLog("Error: valid value 128 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestSizeToByte(255, &dst);
    if((ret != 0) || (dst != 255)) {
        testLog("Error: value 255 was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestSizeToByte(256, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value 256 (above the destination max) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

/******************************************************************************
 *
 *  TO_INT
 *
 *****************************************************************************/
static void
test_safe_cast_uint_to_int(void) {
    int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_UINT_TO_INT");

    /* valid values: min and max */
    ret = castTestUintToInt(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestUintToInt((unsigned int)INT_MAX, &dst);
    if((ret != 0) || (dst != INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestUintToInt(((unsigned int)INT_MAX) + 1, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value INT_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_ulong_to_int(void) {
    int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_ULONG_TO_INT");

    /* valid values: min and max */
    ret = castTestUlongToInt(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestUlongToInt((unsigned long)INT_MAX, &dst);
    if((ret != 0) || (dst != INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestUlongToInt(((unsigned long)INT_MAX) + 1UL, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value INT_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_long_to_int(void) {
#if (LONG_MIN < INT_MIN) || (LONG_MAX > INT_MAX)
    long src;
#endif /* (LONG_MIN < INT_MIN) || (LONG_MAX > INT_MAX) */
    int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_LONG_TO_INT");

    /* valid values: min and max */
    ret = castTestLongToInt(INT_MIN, &dst);
    if((ret != 0) || (dst != INT_MIN)) {
        testLog("Error: valid value INT_MIN was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestLongToInt(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestLongToInt(INT_MAX, &dst);
    if((ret != 0) || (dst != INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when long is wider than int so that the values are representable) */
    dst = 0;
#if (LONG_MIN < INT_MIN)
    src = (long)INT_MIN - 1L;
    ret = castTestLongToInt(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value INT_MIN-1 (below the destination min) was not rejected\n");
        goto failed;
    }
#endif /* (LONG_MIN < INT_MIN) */
#if (LONG_MAX > INT_MAX)
    src = (long)INT_MAX + 1L;
    ret = castTestLongToInt(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value INT_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (LONG_MAX > INT_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_size_t_to_int(void) {
    size_t src;
    int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_SIZE_T_TO_INT");

    /* valid values: min and max */
    ret = castTestSizeTToInt(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestSizeTToInt((size_t)INT_MAX, &dst);
    if((ret != 0) || (dst != INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when size_t is wider than int so that the value is representable) */
#if (SIZE_MAX > INT_MAX)
    dst = 0;
    src = (size_t)INT_MAX + 1;
    ret = castTestSizeTToInt(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value INT_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (SIZE_MAX > INT_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_size_to_int(void) {
    xmlSecSize src;
    int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_SIZE_TO_INT");

    /* valid values: min and max */
    ret = castTestSizeToInt(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestSizeToInt((xmlSecSize)INT_MAX, &dst);
    if((ret != 0) || (dst != INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when xmlSecSize is wider than int so that the value is representable) */
#if (XMLSEC_SIZE_MAX > INT_MAX)
    dst = 0;
    src = (xmlSecSize)INT_MAX + 1;
    ret = castTestSizeToInt(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value INT_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (XMLSEC_SIZE_MAX > INT_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_ptrdiff_to_int(void) {
    ptrdiff_t src;
    int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_PTRDIFF_TO_INT");

    /* valid values: min and max */
    ret = castTestPtrdiffToInt((ptrdiff_t)INT_MIN, &dst);
    if((ret != 0) || (dst != INT_MIN)) {
        testLog("Error: valid value INT_MIN was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestPtrdiffToInt(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestPtrdiffToInt((ptrdiff_t)INT_MAX, &dst);
    if((ret != 0) || (dst != INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when ptrdiff_t is wider than int so that the values are representable) */
    dst = 0;
#if (PTRDIFF_MIN < INT_MIN)
    src = (ptrdiff_t)((long long)INT_MIN - 1);
    ret = castTestPtrdiffToInt(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value INT_MIN-1 (below the destination min) was not rejected\n");
        goto failed;
    }
#endif /* (PTRDIFF_MIN < INT_MIN) */
#if (PTRDIFF_MAX > INT_MAX)
    src = (ptrdiff_t)((long long)INT_MAX + 1);
    ret = castTestPtrdiffToInt(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value INT_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (PTRDIFF_MAX > INT_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_ptrdiff_to_size(void) {
    xmlSecSize dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_PTRDIFF_TO_SIZE");

    /* valid values: min and a positive value */
    ret = castTestPtrdiffToSize(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestPtrdiffToSize(1024, &dst);
    if((ret != 0) || (dst != 1024)) {
        testLog("Error: valid value 1024 was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestPtrdiffToSize(-1, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value -1 (below the destination min) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

/******************************************************************************
 *
 *  TO_UINT
 *
 *****************************************************************************/
static void
test_safe_cast_int_to_uint(void) {
    unsigned int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_INT_TO_UINT");

    /* valid values: min and max */
    ret = castTestIntToUint(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestIntToUint(INT_MAX, &dst);
    if((ret != 0) || (dst != (unsigned int)INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestIntToUint(-1, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value -1 (below the destination min) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_size_t_to_uint(void) {
    size_t src;
    unsigned int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_SIZE_T_TO_UINT");

    /* valid values: min and max */
    ret = castTestSizeTToUint(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestSizeTToUint((size_t)UINT_MAX, &dst);
    if((ret != 0) || (dst != UINT_MAX)) {
        testLog("Error: valid value UINT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when size_t is wider than unsigned int so that the value is representable) */
#if (SIZE_MAX > UINT_MAX)
    dst = 0;
    src = (size_t)UINT_MAX + 1;
    ret = castTestSizeTToUint(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value UINT_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (SIZE_MAX > UINT_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_size_to_uint(void) {
    xmlSecSize src;
    unsigned int dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_SIZE_TO_UINT");

    /* valid values: min and max */
    ret = castTestSizeToUint(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestSizeToUint((xmlSecSize)UINT_MAX, &dst);
    if((ret != 0) || (dst != UINT_MAX)) {
        testLog("Error: value UINT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when xmlSecSize is wider than unsigned int so that the value is representable) */
#if (XMLSEC_SIZE_MAX > UINT_MAX)
    dst = 0;
    src = (xmlSecSize)UINT_MAX + 1;
    ret = castTestSizeToUint(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value UINT_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (XMLSEC_SIZE_MAX > UINT_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

/******************************************************************************
 *
 *  TO_LONG
 *
 *****************************************************************************/
static void
test_safe_cast_uint_to_long(void) {
    unsigned int src;
    long dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_UINT_TO_LONG");

    /* valid values: min and max */
    ret = castTestUintToLong(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
#if (UINT_MAX > LONG_MAX)
    src = (unsigned int)LONG_MAX;
#else /* (UINT_MAX > LONG_MAX) */
    src = UINT_MAX;
#endif /* (UINT_MAX > LONG_MAX) */
    ret = castTestUintToLong(src, &dst);
    if((ret != 0) || (dst != (long)src)) {
        testLog("Error: the max valid value was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when unsigned int is wider than long so that the value is representable) */
#if (UINT_MAX > LONG_MAX)
    dst = 0;
    src = (unsigned int)LONG_MAX + 1U;
    ret = castTestUintToLong(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value LONG_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (UINT_MAX > LONG_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_size_t_to_long(void) {
    size_t src;
    long dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_SIZE_T_TO_LONG");

    /* valid values: min and max */
    ret = castTestSizeTToLong(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
#if (SIZE_MAX > LONG_MAX)
    src = (size_t)LONG_MAX;
#else /* (SIZE_MAX > LONG_MAX) */
    src = SIZE_MAX;
#endif /* (SIZE_MAX > LONG_MAX) */
    ret = castTestSizeTToLong(src, &dst);
    if((ret != 0) || (dst != (long)src)) {
        testLog("Error: the max valid value was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when size_t is wider than long so that the value is representable) */
#if (SIZE_MAX > LONG_MAX)
    dst = 0;
    src = (size_t)LONG_MAX + 1;
    ret = castTestSizeTToLong(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value LONG_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (SIZE_MAX > LONG_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_size_to_long(void) {
    xmlSecSize src;
    long dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_SIZE_TO_LONG");

    /* valid values: min and max */
    ret = castTestSizeToLong(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
#if (XMLSEC_SIZE_MAX > LONG_MAX)
    src = (xmlSecSize)LONG_MAX;
#else /* (XMLSEC_SIZE_MAX > LONG_MAX) */
    src = XMLSEC_SIZE_MAX;
#endif /* (XMLSEC_SIZE_MAX > LONG_MAX) */
    ret = castTestSizeToLong(src, &dst);
    if((ret != 0) || (dst != (long)src)) {
        testLog("Error: the max valid value was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when xmlSecSize is wider than long so that the value is representable) */
#if (XMLSEC_SIZE_MAX > LONG_MAX)
    dst = 0;
    src = (xmlSecSize)LONG_MAX + 1;
    ret = castTestSizeToLong(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value LONG_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (XMLSEC_SIZE_MAX > LONG_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

/******************************************************************************
 *
 *  TO_ULONG
 *
 *****************************************************************************/
static void
test_safe_cast_size_to_ulong(void) {
    xmlSecSize src;
    unsigned long dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_SIZE_TO_ULONG");

    /* valid values: min and max */
    ret = castTestSizeToUlong(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
#if (XMLSEC_SIZE_MAX > ULONG_MAX)
    src = (xmlSecSize)ULONG_MAX;
#else /* (XMLSEC_SIZE_MAX > ULONG_MAX) */
    src = XMLSEC_SIZE_MAX;
#endif /* (XMLSEC_SIZE_MAX > ULONG_MAX) */
    ret = castTestSizeToUlong(src, &dst);
    if((ret != 0) || (dst != (unsigned long)src)) {
        testLog("Error: the max valid value was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when xmlSecSize is wider than unsigned long so that the value is representable) */
#if (XMLSEC_SIZE_MAX > ULONG_MAX)
    dst = 0;
    src = (xmlSecSize)ULONG_MAX + 1;
    ret = castTestSizeToUlong(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value ULONG_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (XMLSEC_SIZE_MAX > ULONG_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_int_to_ulong(void) {
    unsigned long dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_INT_TO_ULONG");

    /* valid values: min and max */
    ret = castTestIntToUlong(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestIntToUlong(INT_MAX, &dst);
    if((ret != 0) || (dst != (unsigned long)INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestIntToUlong(-1, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value -1 (below the destination min) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

/******************************************************************************
 *
 *  TO_SIZE (to xmlSecSize)
 *
 *****************************************************************************/
static void
test_safe_cast_int_to_size(void) {
    xmlSecSize dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_INT_TO_SIZE");

    /* valid values: min and max */
    ret = castTestIntToSize(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
    ret = castTestIntToSize(INT_MAX, &dst);
    if((ret != 0) || (dst != (xmlSecSize)INT_MAX)) {
        testLog("Error: valid value INT_MAX was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
    ret = castTestIntToSize(-1, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value -1 (below the destination min) was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_uint_to_size(void) {
    unsigned int src;
    xmlSecSize dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_UINT_TO_SIZE");

    /* valid values: min and max */
    ret = castTestUintToSize(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
#if (UINT_MAX > XMLSEC_SIZE_MAX)
    src = (unsigned int)XMLSEC_SIZE_MAX;
#else /* (UINT_MAX > XMLSEC_SIZE_MAX) */
    src = UINT_MAX;
#endif /* (UINT_MAX > XMLSEC_SIZE_MAX) */
    ret = castTestUintToSize(src, &dst);
    if((ret != 0) || (dst != (xmlSecSize)src)) {
        testLog("Error: the max valid value was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when unsigned int is wider than xmlSecSize so that the value is representable) */
#if (UINT_MAX > XMLSEC_SIZE_MAX)
    dst = 0;
    src = (unsigned int)XMLSEC_SIZE_MAX + 1U;
    ret = castTestUintToSize(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value XMLSEC_SIZE_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (UINT_MAX > XMLSEC_SIZE_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_long_to_size(void) {
    long src;
    xmlSecSize dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_LONG_TO_SIZE");

    /* valid values: min and max */
    ret = castTestLongToSize(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
#if (LONG_MAX > XMLSEC_SIZE_MAX)
    src = (long)XMLSEC_SIZE_MAX;
#else /* (LONG_MAX > XMLSEC_SIZE_MAX) */
    src = LONG_MAX;
#endif /* (LONG_MAX > XMLSEC_SIZE_MAX) */
    ret = castTestLongToSize(src, &dst);
    if((ret != 0) || (dst != (xmlSecSize)src)) {
        testLog("Error: the max valid value was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified */
    dst = 0;
#if (LONG_MAX > XMLSEC_SIZE_MAX)
    src = (long)XMLSEC_SIZE_MAX + 1L;
#else /* (LONG_MAX > XMLSEC_SIZE_MAX) */
    src = -1;
#endif /* (LONG_MAX > XMLSEC_SIZE_MAX) */
    ret = castTestLongToSize(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: an out-of-range value was not rejected\n");
        goto failed;
    }

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_ulong_to_size(void) {
    unsigned long src;
    xmlSecSize dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_ULONG_TO_SIZE");

    /* valid values: min and max */
    ret = castTestUlongToSize(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
#if (ULONG_MAX > XMLSEC_SIZE_MAX)
    src = (unsigned long)XMLSEC_SIZE_MAX;
#else /* (ULONG_MAX > XMLSEC_SIZE_MAX) */
    src = ULONG_MAX;
#endif /* (ULONG_MAX > XMLSEC_SIZE_MAX) */
    ret = castTestUlongToSize(src, &dst);
    if((ret != 0) || (dst != (xmlSecSize)src)) {
        testLog("Error: the max valid value was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when unsigned long is wider than xmlSecSize so that the value is representable) */
#if (ULONG_MAX > XMLSEC_SIZE_MAX)
    dst = 0;
    src = (unsigned long)XMLSEC_SIZE_MAX + 1UL;
    ret = castTestUlongToSize(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value XMLSEC_SIZE_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (ULONG_MAX > XMLSEC_SIZE_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

static void
test_safe_cast_ulonglong_to_size(void) {
    unsigned long long src;
    xmlSecSize dst = 0;
    int ret;

    testStart("XMLSEC_SAFE_CAST_ULLONG_TO_SIZE");

    /* valid values: min and max */
    ret = castTestUlongLongToSize(0, &dst);
    if((ret != 0) || (dst != 0)) {
        testLog("Error: valid value 0 was rejected or mis-cast\n");
        goto failed;
    }
#if (ULLONG_MAX > XMLSEC_SIZE_MAX)
    src = (unsigned long long)XMLSEC_SIZE_MAX;
#else /* (ULLONG_MAX > XMLSEC_SIZE_MAX) */
    src = ULLONG_MAX;
#endif /* (ULLONG_MAX > XMLSEC_SIZE_MAX) */
    ret = castTestUlongLongToSize(src, &dst);
    if((ret != 0) || (dst != (xmlSecSize)src)) {
        testLog("Error: the max valid value was rejected or mis-cast\n");
        goto failed;
    }

    /* out-of-range values must be rejected and leave dst unmodified (only
     * testable when unsigned long long is wider than xmlSecSize so that the
     * value is representable) */
#if (ULLONG_MAX > XMLSEC_SIZE_MAX)
    dst = 0;
    src = (unsigned long long)XMLSEC_SIZE_MAX + 1ULL;
    ret = castTestUlongLongToSize(src, &dst);
    if((ret == 0) || (dst != 0)) {
        testLog("Error: value XMLSEC_SIZE_MAX+1 (above the destination max) was not rejected\n");
        goto failed;
    }
#endif /* (ULLONG_MAX > XMLSEC_SIZE_MAX) */

    testFinishedSuccess();
    return;

failed:
    testFinishedFailure();
}

/******************************************************************************
 *
 *  XMLSEC_BITS_TO_BYTES
 *
 *****************************************************************************/
static void
test_bits_to_bytes(void) {
    testStart("XMLSEC_BITS_TO_BYTES");

    /* 0 and negative values give 0 bytes */
    if(XMLSEC_BITS_TO_BYTES(0) != 0) {
        testLog("Error: XMLSEC_BITS_TO_BYTES(0) should be 0\n");
        testFinishedFailure();
        return;
    }
    if(XMLSEC_BITS_TO_BYTES(-1) != 0) {
        testLog("Error: XMLSEC_BITS_TO_BYTES(-1) should be 0\n");
        testFinishedFailure();
        return;
    }

    /* 1..8 bits give 1 byte */
    if((XMLSEC_BITS_TO_BYTES(1) != 1) || (XMLSEC_BITS_TO_BYTES(8) != 1)) {
        testLog("Error: XMLSEC_BITS_TO_BYTES(1)/XMLSEC_BITS_TO_BYTES(8) should be 1\n");
        testFinishedFailure();
        return;
    }

    /* 9..16 bits give 2 bytes */
    if((XMLSEC_BITS_TO_BYTES(9) != 2) || (XMLSEC_BITS_TO_BYTES(16) != 2)) {
        testLog("Error: XMLSEC_BITS_TO_BYTES(9)/XMLSEC_BITS_TO_BYTES(16) should be 2\n");
        testFinishedFailure();
        return;
    }

    /* larger values */
    if((XMLSEC_BITS_TO_BYTES(32) != 4) || (XMLSEC_BITS_TO_BYTES(64) != 8)) {
        testLog("Error: XMLSEC_BITS_TO_BYTES(32)/XMLSEC_BITS_TO_BYTES(64) should be 4/8\n");
        testFinishedFailure();
        return;
    }

    testFinishedSuccess();
}

/******************************************************************************
 *
 *  test runner
 *
 *****************************************************************************/
int
test_cast_helpers(void) {
    testGroupStart("cast helpers");

    /* to xmlSecByte */
    test_safe_cast_int_to_byte();
    test_safe_cast_uint_to_byte();
    test_safe_cast_size_to_byte();

    /* to int */
    test_safe_cast_uint_to_int();
    test_safe_cast_ulong_to_int();
    test_safe_cast_long_to_int();
    test_safe_cast_size_t_to_int();
    test_safe_cast_size_to_int();
    test_safe_cast_ptrdiff_to_int();
    test_safe_cast_ptrdiff_to_size();

    /* to unsigned int */
    test_safe_cast_int_to_uint();
    test_safe_cast_size_t_to_uint();
    test_safe_cast_size_to_uint();

    /* to long */
    test_safe_cast_uint_to_long();
    test_safe_cast_size_t_to_long();
    test_safe_cast_size_to_long();

    /* to unsigned long */
    test_safe_cast_size_to_ulong();
    test_safe_cast_int_to_ulong();

    /* to xmlSecSize */
    test_safe_cast_int_to_size();
    test_safe_cast_uint_to_size();
    test_safe_cast_long_to_size();
    test_safe_cast_ulong_to_size();
    test_safe_cast_ulonglong_to_size();

    /* bits to bytes */
    test_bits_to_bytes();

    return(testGroupFinished());
}
