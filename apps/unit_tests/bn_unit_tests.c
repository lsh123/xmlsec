/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library big number unit tests.
 */
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include <xmlsec/bn.h>

/******************************************************************************
 * helpers
 *****************************************************************************/
static int
bnTestCheckData(xmlSecBnPtr bn, const xmlSecByte* expected, xmlSecSize expectedSize) {
    const xmlSecByte* actual;
    xmlSecSize actualSize;

    xmlSecAssert2(bn != NULL, 0);

    actual = xmlSecBnGetData(bn);
    actualSize = xmlSecBnGetSize(bn);
    if(actualSize != expectedSize) {
        testLog("Error: expected size=%u, got size=%u\n",
            (unsigned int)expectedSize, (unsigned int)actualSize);
        return(0);
    }

    if(expectedSize > 0) {
        if((actual == NULL) || (expected == NULL) || (memcmp(actual, expected, expectedSize) != 0)) {
            testLog("Error: BN data mismatch\n");
            return(0);
        }
    }

    return(1);
}

static int
bnTestCheckString(xmlChar* actual, const char* expected) {
    xmlSecAssert2(expected != NULL, 0);

    if((actual == NULL) || (xmlStrcmp(actual, BAD_CAST expected) != 0)) {
        testLog("Error: expected string='%s', got '%s'\n",
            expected,
            (actual != NULL) ? (const char*)actual : "NULL");
        return(0);
    }

    return(1);
}

static xmlDocPtr
bnTestCreateDoc(const xmlChar* rootName) {
    xmlDocPtr doc;
    xmlNodePtr root;

    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
        return(NULL);
    }

    root = xmlNewDocNode(doc, NULL, rootName, NULL);
    if(root == NULL) {
        xmlFreeDoc(doc);
        return(NULL);
    }

    xmlDocSetRootElement(doc, root);
    return(doc);
}

/******************************************************************************
 * basic buffer helpers
 *****************************************************************************/
static void
test_xmlSecBnCreateSetGetZero(void) {
    static const xmlSecByte expected[] = { 0x01, 0x02, 0x03 };
    xmlSecBnPtr bn;
    int ret;

    testStart("xmlSecBnCreate/xmlSecBnSetData/xmlSecBnGetData/xmlSecBnZero");

    bn = xmlSecBnCreate(2);
    if(bn == NULL) {
        testLog("Error: xmlSecBnCreate failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnSetData(bn, expected, sizeof(expected));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnDestroy(bn);
        testFinishedFailure();
        return;
    }

    if(!bnTestCheckData(bn, expected, sizeof(expected))) {
        xmlSecBnDestroy(bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnZero(bn);
    if(xmlSecBnGetSize(bn) != 0) {
        testLog("Error: xmlSecBnZero did not clear the buffer\n");
        xmlSecBnDestroy(bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnDestroy(bn);
    testFinishedSuccess();
}

/******************************************************************************
 * string conversions
 *****************************************************************************/
static void
test_xmlSecBnFromHexString_roundTripWithPrefix(void) {
    static const xmlSecByte expected[] = { 0x00, 0x80 };
    xmlSecBn bn;
    xmlChar* str;
    int ret;

    testStart("xmlSecBnFromHexString/xmlSecBnToHexString: preserve MSB sign prefix");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnFromHexString(&bn, BAD_CAST "  80 ");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(!bnTestCheckData(&bn, expected, sizeof(expected))) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    str = xmlSecBnToHexString(&bn);
    if(!bnTestCheckString(str, "80")) {
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnFromString_invalidCharFails(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnFromString: invalid digit fails");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnFromString(&bn, BAD_CAST "1G", 16);
    if(ret >= 0) {
        testLog("Error: xmlSecBnFromString unexpectedly succeeded for invalid hex digit\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnFromString_signIsRejected(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnFromString: sign characters are rejected");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* a leading '-' must be rejected as an invalid digit */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "-80");
    if(ret >= 0) {
        testLog("Error: xmlSecBnFromHexString unexpectedly succeeded for '-80'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* a leading '+' must be rejected as an invalid digit too */
    ret = xmlSecBnFromDecString(&bn, BAD_CAST "+255");
    if(ret >= 0) {
        testLog("Error: xmlSecBnFromDecString unexpectedly succeeded for '+255'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnFromString_replacesExistingValue(void) {
    static const xmlSecByte expected[] = { 0x0A };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnFromString: replaces existing value (no accumulation)");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* seed the buffer with a non-zero value first */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "5");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for seed '5'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* parsing a new value must replace, not accumulate onto, the old one */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "A");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for 'A'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* expected is 0x0A (10), NOT 0x5A (90) which accumulation would produce */
    if(!bnTestCheckData(&bn, expected, sizeof(expected))) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnFromString_emptyAndWhitespaceBothZero(void) {
    static const xmlSecByte expected[] = { 0x00 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnFromString: empty and whitespace-only both yield zero");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* empty string must normalize to zero */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for empty string\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(!bnTestCheckData(&bn, expected, sizeof(expected))) {
        testLog("Error: empty string did not yield zero\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* whitespace-only must normalize to the same zero representation */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "   ");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for whitespace\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(!bnTestCheckData(&bn, expected, sizeof(expected))) {
        testLog("Error: whitespace-only did not yield the same zero as empty\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnAdd_mulProduceCanonicalPrefix(void) {
    static const xmlSecByte expectedAdd[] = { 0x00, 0x80 };
    static const xmlSecByte expectedMul[] = { 0x00, 0xFE };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnAdd/xmlSecBnMul: produce canonical 0x00 prefix when MSB set");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* 0x7F + 1 = 0x80 (MSB set) must carry the 0x00 prefix */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "7F");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '7F'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnAdd(&bn, 1);
    if(ret < 0) {
        testLog("Error: xmlSecBnAdd failed for 0x7F + 1\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(!bnTestCheckData(&bn, expectedAdd, sizeof(expectedAdd))) {
        testLog("Error: 0x7F + 1 did not produce the canonical 0x00-prefixed form\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* 0x7F * 2 = 0xFE (MSB set) must carry the 0x00 prefix */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "7F");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '7F'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnMul(&bn, 2);
    if(ret < 0) {
        testLog("Error: xmlSecBnMul failed for 0x7F * 2\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(!bnTestCheckData(&bn, expectedMul, sizeof(expectedMul))) {
        testLog("Error: 0x7F * 2 did not produce the canonical 0x00-prefixed form\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnFromString_base2AndBase8_roundTrip(void) {
    xmlSecBn bn;
    xmlChar* str;
    int ret;

    testStart("xmlSecBnFromString/xmlSecBnToString: base 2 and base 8 round trip");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* base 2: "1011" == 11 == 0xB */
    ret = xmlSecBnFromString(&bn, BAD_CAST "1011", 2);
    if(ret < 0) {
        testLog("Error: xmlSecBnFromString failed for base 2\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    str = xmlSecBnToHexString(&bn);
    if(!bnTestCheckString(str, "B")) {
        testLog("Error: base-2 value did not equal 0xB\n");
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    str = xmlSecBnToString(&bn, 2);
    if(!bnTestCheckString(str, "1011")) {
        testLog("Error: base-2 round trip mismatch\n");
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    /* base 8: "15" == 13 == 0xD */
    ret = xmlSecBnFromString(&bn, BAD_CAST "15", 8);
    if(ret < 0) {
        testLog("Error: xmlSecBnFromString failed for base 8\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    str = xmlSecBnToHexString(&bn);
    if(!bnTestCheckString(str, "D")) {
        testLog("Error: base-8 value did not equal 0xD\n");
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    str = xmlSecBnToString(&bn, 8);
    if(!bnTestCheckString(str, "15")) {
        testLog("Error: base-8 round trip mismatch\n");
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnFromString_baseBoundsRejected(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnFromString/xmlSecBnToString: base out of [2,16] is rejected");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* base must be > 1 */
    ret = xmlSecBnFromString(&bn, BAD_CAST "A", 1);
    if(ret >= 0) {
        testLog("Error: xmlSecBnFromString unexpectedly succeeded for base=1\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* base must be <= 16 (XMLSEC_BN_REV_MAX) */
    ret = xmlSecBnFromString(&bn, BAD_CAST "A", 17);
    if(ret >= 0) {
        testLog("Error: xmlSecBnFromString unexpectedly succeeded for base=17\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* ToString enforces the same bounds */
    if(xmlSecBnToString(&bn, 1) != NULL) {
        testLog("Error: xmlSecBnToString unexpectedly succeeded for base=1\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(xmlSecBnToString(&bn, 17) != NULL) {
        testLog("Error: xmlSecBnToString unexpectedly succeeded for base=17\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnToString_largeMultiByte_roundTrip(void) {
    static const xmlSecByte expected[] = { 0x01, 0x23, 0x45, 0x67, 0x89 };
    xmlSecBn bn;
    xmlChar* str;
    int ret;

    testStart("xmlSecBnToString: large multi-byte hex/decimal round trip");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* 0x123456789 == 4886718345 */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "123456789");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '123456789'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    str = xmlSecBnToHexString(&bn);
    if(!bnTestCheckString(str, "123456789")) {
        testLog("Error: hex round trip mismatch\n");
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    str = xmlSecBnToDecString(&bn);
    if(!bnTestCheckString(str, "4886718345")) {
        testLog("Error: decimal round trip mismatch\n");
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    /* parsing the decimal form back must reproduce the exact bytes */
    ret = xmlSecBnFromDecString(&bn, BAD_CAST "4886718345");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromDecString failed for '4886718345'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(!bnTestCheckData(&bn, expected, sizeof(expected))) {
        testLog("Error: decimal parse did not reproduce the original bytes\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

/******************************************************************************
 * arithmetic helpers
 *****************************************************************************/
static int
testBnAdd(xmlSecBn* bn, const char * hexStart, int delta, const char * hexExpected) {
    xmlChar* str;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(hexStart != NULL, -1);
    xmlSecAssert2(hexExpected != NULL, -1);

    xmlSecBnZero(bn);

    ret = xmlSecBnFromHexString(bn, BAD_CAST hexStart);
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '%s'\n", hexStart);
        return(-1);
    }

    ret = xmlSecBnAdd(bn, delta);
    if(ret < 0) {
        testLog("Error: xmlSecBnAdd failed for delta=%d\n", delta);
        return(-1);
    }

    str = xmlSecBnToHexString(bn);
    if(!bnTestCheckString(str, hexExpected)) {
        testLog("Error: xmlSecBnAdd result mismatch for start='%s' delta=%d, expected='%s', got='%s'\n", hexStart, delta, hexExpected, str);
        xmlFree(str);
        return(-1);
    }

    /* done */
    xmlFree(str);
    return(0);
}

static int
testBnAddWithData(xmlSecBn* bn, const char * hexStart, int delta, const char * hexExpected,
        const xmlSecByte* expectedData, xmlSecSize expectedDataSize) {
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(hexStart != NULL, -1);
    xmlSecAssert2(hexExpected != NULL, -1);

    ret = testBnAdd(bn, hexStart, delta, hexExpected);
    if(ret < 0) {
        return(-1);
    }

    if(!bnTestCheckData(bn, expectedData, expectedDataSize)) {
        testLog("Error: xmlSecBnAdd raw data mismatch for start='%s' delta=%d\n",
            hexStart, delta);
        return(-1);
    }

    return(0);
}

static void
test_xmlSecBnAdd_updatesValue(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnAdd: updates decimal value");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* all strings are hexadecimal */
    if(testBnAdd(&bn, "0100", -1, "FF") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnAdd(&bn, "FF", 1, "100") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnAdd(&bn, "100", 0x101, "201") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnAdd(&bn, "201", -0x102, "FF") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static int
testBnMul(xmlSecBn* bn, const char * hexStart, int multiplier, const char * hexExpected) {
    xmlChar* str;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(hexStart != NULL, -1);
    xmlSecAssert2(hexExpected != NULL, -1);

    xmlSecBnZero(bn);

    ret = xmlSecBnFromHexString(bn, BAD_CAST hexStart);
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '%s'\n", hexStart);
        return(-1);
    }

    ret = xmlSecBnMul(bn, multiplier);
    if(ret < 0) {
        testLog("Error: xmlSecBnMul failed for multiplier=%d\n", multiplier);
        return(-1);
    }

    str = xmlSecBnToHexString(bn);
    if(!bnTestCheckString(str, hexExpected)) {
        testLog("Error: xmlSecBnMul result mismatch for start='%s' multiplier=%d, expected='%s', got='%s'\n", hexStart, multiplier, hexExpected, str);
        xmlFree(str);
        return(-1);
    }

    xmlFree(str);
    return(0);
}

static void
test_xmlSecBnAdd_underflowReturnsError(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnAdd: underflow (result below zero) returns an error");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* all strings are hexadecimal */

    /* 5 - 10 = -5: underflow must be rejected */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "5");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '5'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnAdd(&bn, -10);
    if(ret >= 0) {
        testLog("Error: xmlSecBnAdd unexpectedly succeeded for 5 - 10 (underflow)\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* FF - 256 = -1: underflow must be rejected */
    xmlSecBnZero(&bn);
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "FF");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for 'FF'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnAdd(&bn, -256);
    if(ret >= 0) {
        testLog("Error: xmlSecBnAdd unexpectedly succeeded for FF - 256 (underflow)\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* a negative delta on an empty (zero) BN must be rejected */
    xmlSecBnZero(&bn);
    ret = xmlSecBnAdd(&bn, -5);
    if(ret >= 0) {
        testLog("Error: xmlSecBnAdd unexpectedly succeeded for 0 - 5 (underflow)\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* a multi-byte (>= 4 byte) value smaller than |delta| must also be rejected */
    xmlSecBnZero(&bn);
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "01000000");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '01000000'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnAdd(&bn, -20000000);
    if(ret >= 0) {
        testLog("Error: xmlSecBnAdd unexpectedly succeeded for 0x01000000 - 20000000 (underflow)\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnAdd_zeroResultAndTrimBoundaries(void) {
    static const xmlSecByte zero[] = { 0x00 };
    static const xmlSecByte plus127[] = { 0x7F };
    static const xmlSecByte plus128[] = { 0x00, 0x80 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnAdd: zero result and 127/128 trim boundaries");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* exact zero result keeps a single zero byte */
    if(testBnAddWithData(&bn, "5", -5, "0", zero, sizeof(zero)) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* 0x80 - 1 = 127: the 0x00 sign prefix is trimmed away */
    if(testBnAddWithData(&bn, "80", -1, "7F", plus127, sizeof(plus127)) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* 0x81 - 1 = 128: the 0x00 sign prefix must be preserved */
    if(testBnAddWithData(&bn, "81", -1, "80", plus128, sizeof(plus128)) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnAdd_bnValueUndefinedAfterUnderflow(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnAdd: bn value is undefined after underflow error");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* Set bn to 10 */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "0A");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '0A'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* Attempt 10 - 20 = -10 which should fail */
    ret = xmlSecBnAdd(&bn, -20);
    if(ret >= 0) {
        testLog("Error: xmlSecBnAdd unexpectedly succeeded for underflow (10 - 20)\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* After underflow error, bn value is undefined - we only verify the function
     * returned an error as documented. Do NOT use bn after this point as its
     * state is indeterminate. */

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnAdd_intMinDelta(void) {
    xmlSecBn bn;
    xmlChar* str;
    int ret;

    testStart("xmlSecBnAdd: INT_MIN delta (valid subtraction and underflow)");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* valid: 0xFFFFFFFF - INT_MIN == 0xFFFFFFFF - 2^31 == 0x7FFFFFFF */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "FFFFFFFF");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for 'FFFFFFFF'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnAdd(&bn, INT_MIN);
    if(ret < 0) {
        testLog("Error: xmlSecBnAdd failed for 0xFFFFFFFF + INT_MIN\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    str = xmlSecBnToHexString(&bn);
    if(!bnTestCheckString(str, "7FFFFFFF")) {
        testLog("Error: 0xFFFFFFFF + INT_MIN did not equal 0x7FFFFFFF\n");
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    /* underflow: 0x7FFFFFFF < 2^31, so 0x7FFFFFFF - INT_MIN must be rejected */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "7FFFFFFF");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '7FFFFFFF'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnAdd(&bn, INT_MIN);
    if(ret >= 0) {
        testLog("Error: xmlSecBnAdd unexpectedly succeeded for 0x7FFFFFFF + INT_MIN (underflow)\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnMul_updatesValue(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnMul: updates hex value");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* all strings are hexadecimal */
    if(testBnMul(&bn, "ABCD", 1, "ABCD") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnMul(&bn, "80", 2, "100") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnMul(&bn, "FF", 2, "1FE") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnMul(&bn, "1234", 0x10, "12340") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnMul_largeMultiplier(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnMul: large multipliers do not overflow");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* all strings are hexadecimal */
    if(testBnMul(&bn, "10000", 0x10000, "100000000") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(testBnMul(&bn, "FF", 0x8000000, "7F8000000") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}


static int
testBnDiv(xmlSecBn* bn, const char * hexStart, int divider, const char * hexExpected, int expectedMod) {
    xmlChar* str;
    int mod;
    int ret;

    xmlSecAssert2(bn != NULL, -1);
    xmlSecAssert2(hexStart != NULL, -1);
    xmlSecAssert2(hexExpected != NULL, -1);

    xmlSecBnZero(bn);

    ret = xmlSecBnFromHexString(bn, BAD_CAST hexStart);
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '%s'\n", hexStart);
        return(-1);
    }

    mod = -1;
    ret = xmlSecBnDiv(bn, divider, &mod);
    if(ret < 0) {
        testLog("Error: xmlSecBnDiv failed for divider=%d\n", divider);
        return(-1);
    }
    if(mod != expectedMod) {
        testLog("Error: xmlSecBnDiv modulus mismatch for start='%s' divider=%d, expected=%d, got=%d\n",
            hexStart, divider, expectedMod, mod);
        return(-1);
    }

    str = xmlSecBnToHexString(bn);
    if(!bnTestCheckString(str, hexExpected)) {
        testLog("Error: xmlSecBnDiv result mismatch for start='%s' divider=%d, expected='%s', got='%s'\n",
            hexStart, divider, hexExpected, str);
        xmlFree(str);
        return(-1);
    }

    xmlFree(str);
    return(0);
}

static void
test_xmlSecBnDiv_updatesValue(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnDiv: updates hex value and modulus");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* all strings are hexadecimal */
    if(testBnDiv(&bn, "FF", 2, "7F", 1) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnDiv(&bn, "100", 0x10, "10", 0) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnDiv(&bn, "1234", 0x10, "123", 4) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(testBnDiv(&bn, "1", 2, "0", 1) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnDiv_largeDivider(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnDiv: large dividers do not overflow");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* all strings are hexadecimal */
    if(testBnDiv(&bn, "123456789", 0x8000000, "24", 0x3456789) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(testBnDiv(&bn, "80000000000", 0x8000000, "10000", 0) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnMulAddDiv_sequence(void) {
    xmlSecBn bn;
    xmlChar* str;
    int mod;
    int ret;

    testStart("xmlSecBnMul/xmlSecBnAdd/xmlSecBnDiv: arithmetic sequence");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnFromDecString(&bn, BAD_CAST "255");
    if((ret < 0) || (xmlSecBnMul(&bn, 2) < 0) || (xmlSecBnAdd(&bn, 5) < 0)) {
        testLog("Error: BN arithmetic setup failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    str = xmlSecBnToDecString(&bn);
    if(!bnTestCheckString(str, "515")) {
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    mod = -1;
    ret = xmlSecBnDiv(&bn, 10, &mod);
    if((ret < 0) || (mod != 5)) {
        testLog("Error: xmlSecBnDiv failed, ret=%d mod=%d\n", ret, mod);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    str = xmlSecBnToDecString(&bn);
    if(!bnTestCheckString(str, "51")) {
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnDiv_byOneKeepsValueAndSetsZeroMod(void) {
    xmlSecBn bn;
    xmlChar* str;
    int mod;
    int ret;

    testStart("xmlSecBnDiv: divider one keeps value and returns zero modulus");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnFromDecString(&bn, BAD_CAST "513");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromDecString failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    mod = -1;
    ret = xmlSecBnDiv(&bn, 1, &mod);
    if(ret < 0) {
        testLog("Error: xmlSecBnDiv failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    if(mod != 0) {
        testLog("Error: expected modulus=0 for divider=1, got %d\n", mod);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    str = xmlSecBnToDecString(&bn);
    if(!bnTestCheckString(str, "513")) {
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

/******************************************************************************
 * compare/reverse helpers
 *****************************************************************************/
static void
test_xmlSecBnReverse_reversesBytes(void) {
    static const xmlSecByte initial[] = { 0x01, 0x02, 0x03 };
    static const xmlSecByte reversed[] = { 0x03, 0x02, 0x01 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnReverse: reverse bytes");

    ret = xmlSecBnInitialize(&bn, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnSetData(&bn, initial, sizeof(initial));
    if((ret < 0) || (xmlSecBnReverse(&bn) < 0)) {
        testLog("Error: xmlSecBnReverse failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    if(!bnTestCheckData(&bn, reversed, sizeof(reversed))) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnCompare_ignoresLeadingZeroes(void) {
    static const xmlSecByte initial[] = { 0x00, 0x01, 0x02 };
    static const xmlSecByte expected[] = { 0x01, 0x02 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnCompare: ignores leading zeroes");

    ret = xmlSecBnInitialize(&bn, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnSetData(&bn, initial, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnCompare(&bn, expected, sizeof(expected));
    if(ret != 0) {
        testLog("Error: expected compare result 0, got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnCompare_greaterThanShorterData(void) {
    static const xmlSecByte initial[] = { 0x01, 0x00 };
    static const xmlSecByte smaller[] = { 0xFF };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnCompare: greater value with longer data");

    ret = xmlSecBnInitialize(&bn, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnSetData(&bn, initial, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnCompare(&bn, smaller, sizeof(smaller));
    if(ret <= 0) {
        testLog("Error: expected positive compare result, got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnCompareReverse_greaterThanShorterData(void) {
    static const xmlSecByte initial[] = { 0x01, 0x00 };
    static const xmlSecByte smallerReverse[] = { 0xFF };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnCompareReverse: greater value with longer data");

    ret = xmlSecBnInitialize(&bn, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnSetData(&bn, initial, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnCompareReverse(&bn, smallerReverse, sizeof(smallerReverse));
    if(ret <= 0) {
        testLog("Error: expected positive compare result, got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnCompare_sameSizeDifferentBytes(void) {
    static const xmlSecByte dataLess[] = { 0x01 };
    static const xmlSecByte dataGreater[] = { 0x02 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnCompare: equal-size buffers with different bytes");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* bn = 0x02 > data = 0x01 (same size, different bytes) */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "02");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '02'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnCompare(&bn, dataLess, sizeof(dataLess));
    if(ret <= 0) {
        testLog("Error: expected bn(0x02) > data(0x01), got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* bn = 0x01 < data = 0x02 (same size, different bytes) */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "01");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '01'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnCompare(&bn, dataGreater, sizeof(dataGreater));
    if(ret >= 0) {
        testLog("Error: expected bn(0x01) < data(0x02), got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnCompare_emptyAndNullBranches(void) {
    static const xmlSecByte data[] = { 0x01 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnCompare: empty and NULL branches");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* both empty -> equal */
    ret = xmlSecBnCompare(&bn, NULL, 0);
    if(ret != 0) {
        testLog("Error: expected compare result 0 for two empty values, got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* bn empty, data non-empty -> bn less */
    ret = xmlSecBnCompare(&bn, data, sizeof(data));
    if(ret >= 0) {
        testLog("Error: expected negative compare result (empty < data), got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* bn non-empty, data empty -> bn greater */
    ret = xmlSecBnFromHexString(&bn, BAD_CAST "01");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromHexString failed for '01'\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnCompare(&bn, NULL, 0);
    if(ret <= 0) {
        testLog("Error: expected positive compare result (data empty < bn), got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnReverse_emptyAndSingleByte(void) {
    static const xmlSecByte single[] = { 0x05 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnReverse: empty and single-byte buffers");

    /* empty buffer reverse is a no-op */
    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnReverse(&bn);
    if((ret < 0) || (xmlSecBnGetSize(&bn) != 0)) {
        testLog("Error: empty buffer reverse should be a no-op\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* single-byte buffer reverse is a no-op */
    ret = xmlSecBnSetData(&bn, single, sizeof(single));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnReverse(&bn);
    if((ret < 0) || !bnTestCheckData(&bn, single, sizeof(single))) {
        testLog("Error: single-byte buffer reverse should be a no-op\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

/******************************************************************************
 * XML node helpers
 *****************************************************************************/
static void
test_xmlSecBnSetGetNodeValue_hexRoundTrip(void) {
    static const xmlSecByte initial[] = { 0x01, 0xAB };
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;
    xmlSecBn bn;
    xmlSecBn bn2;
    int ret;

    testStart("xmlSecBnSetNodeValue/xmlSecBnGetNodeValue: hex round trip");

    doc = bnTestCreateDoc(BAD_CAST "Value");
    if(doc == NULL) {
        testLog("Error: failed to create XML document\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecBnInitialize(&bn, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnSetData(&bn, initial, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnSetNodeValue(&bn, root, xmlSecBnHex, 0, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnSetNodeValue failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    content = xmlNodeGetContent(root);
    if(!bnTestCheckString(content, "1AB")) {
        xmlFree(content);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);

    ret = xmlSecBnInitialize(&bn2, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed for bn2\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnGetNodeValue(&bn2, root, xmlSecBnHex, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnGetNodeValue failed\n");
        xmlSecBnFinalize(&bn2);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if(!bnTestCheckData(&bn2, initial, sizeof(initial))) {
        xmlSecBnFinalize(&bn2);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn2);
    xmlSecBnFinalize(&bn);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecBnBlobSetNodeValue_base64ReverseRoundTrip(void) {
    static const xmlSecByte initial[] = { 0x01, 0x02, 0x03 };
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnBlobSetNodeValue/xmlSecBnGetNodeValue: base64 reverse round trip");

    doc = bnTestCreateDoc(BAD_CAST "Value");
    if(doc == NULL) {
        testLog("Error: failed to create XML document\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecBnBlobSetNodeValue(initial, sizeof(initial), root, xmlSecBnBase64, 1, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnBlobSetNodeValue failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    content = xmlNodeGetContent(root);
    if(!bnTestCheckString(content, "AwIB")) {
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnGetNodeValue(&bn, root, xmlSecBnBase64, 1);
    if(ret < 0) {
        testLog("Error: xmlSecBnGetNodeValue failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if(!bnTestCheckData(&bn, initial, sizeof(initial))) {
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecBnSetNodeValue_base64AndBlob_hexDec(void) {
    static const xmlSecByte b64Initial[] = { 0x01, 0x02, 0x03 };
    static const xmlSecByte hexInitial[] = { 0x01, 0xAB };
    static const xmlSecByte decInitial[] = { 0x01, 0x2A };
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnSetNodeValue base64 and BlobSetNodeValue hex/dec round trips");

    doc = bnTestCreateDoc(BAD_CAST "Value");
    if(doc == NULL) {
        testLog("Error: failed to create XML document\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* --- SetNodeValue with base64 (reverse=0): [01 02 03] -> "AQID" --- */
    ret = xmlSecBnSetData(&bn, b64Initial, sizeof(b64Initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnSetNodeValue(&bn, root, xmlSecBnBase64, 0, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnSetNodeValue (base64) failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    content = xmlNodeGetContent(root);
    if(!bnTestCheckString(content, "AQID")) {
        xmlFree(content);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);

    /* read the base64 value back */
    xmlSecBnFinalize(&bn);
    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed for base64 read-back\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnGetNodeValue(&bn, root, xmlSecBnBase64, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnGetNodeValue (base64) failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(!bnTestCheckData(&bn, b64Initial, sizeof(b64Initial))) {
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* --- BlobSetNodeValue with hex (reverse=0): [01 AB] -> "1AB" --- */
    xmlSecBnFinalize(&bn);
    ret = xmlSecBnBlobSetNodeValue(hexInitial, sizeof(hexInitial), root, xmlSecBnHex, 0, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnBlobSetNodeValue (hex) failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    content = xmlNodeGetContent(root);
    if(!bnTestCheckString(content, "1AB")) {
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed for hex read-back\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnGetNodeValue(&bn, root, xmlSecBnHex, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnGetNodeValue (hex) failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(!bnTestCheckData(&bn, hexInitial, sizeof(hexInitial))) {
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* --- BlobSetNodeValue with dec (reverse=0): [01 2A] == 298 -> "298" --- */
    xmlSecBnFinalize(&bn);
    ret = xmlSecBnBlobSetNodeValue(decInitial, sizeof(decInitial), root, xmlSecBnDec, 0, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnBlobSetNodeValue (dec) failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    content = xmlNodeGetContent(root);
    if(!bnTestCheckString(content, "298")) {
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed for dec read-back\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnGetNodeValue(&bn, root, xmlSecBnDec, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnGetNodeValue (dec) failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(!bnTestCheckData(&bn, decInitial, sizeof(decInitial))) {
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecBnToString_zeroBnProducesZero(void) {
    xmlSecBn bn;
    xmlChar* str;
    int ret;

    testStart("xmlSecBnToHexString/xmlSecBnToDecString: empty BN produces '0'");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    str = xmlSecBnToHexString(&bn);
    if(!bnTestCheckString(str, "0")) {
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    str = xmlSecBnToDecString(&bn);
    if(!bnTestCheckString(str, "0")) {
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnAdd_cascadingBorrow(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnAdd: 3-byte cascading borrow 0x010000 - 1 = 0xFFFF");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    if(testBnAdd(&bn, "010000", -1, "FFFF") < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnAdd_toEmptyBn(void) {
    xmlSecBn bn;
    xmlChar* str;
    int ret;

    testStart("xmlSecBnAdd: positive delta to empty BN");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnAdd(&bn, 5);
    if(ret < 0) {
        testLog("Error: xmlSecBnAdd failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    str = xmlSecBnToDecString(&bn);
    if(!bnTestCheckString(str, "5")) {
        xmlFree(str);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    xmlFree(str);

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnCompare_lessThanLongerData(void) {
    static const xmlSecByte initial[] = { 0x01 };
    static const xmlSecByte larger[] = { 0x01, 0x00 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnCompare: less than value with longer data");

    ret = xmlSecBnInitialize(&bn, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnSetData(&bn, initial, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnCompare(&bn, larger, sizeof(larger));
    if(ret >= 0) {
        testLog("Error: expected negative compare result, got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnCompareReverse_equalAndLessThan(void) {
    static const xmlSecByte initial_eq[] = { 0x01, 0x02 };
    static const xmlSecByte dataReverse_eq[] = { 0x02, 0x01 };
    static const xmlSecByte initial_lt[] = { 0x01 };
    static const xmlSecByte dataReverse_lt[] = { 0x00, 0x01 };
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnCompareReverse: equal and less-than cases");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* equal case: BN {0x01, 0x02} vs reverse data {0x02, 0x01} */
    ret = xmlSecBnSetData(&bn, initial_eq, sizeof(initial_eq));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnCompareReverse(&bn, dataReverse_eq, sizeof(dataReverse_eq));
    if(ret != 0) {
        testLog("Error: expected compare result 0 (equal), got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    /* less-than case: BN {0x01} (=1) vs reverse data {0x00, 0x01} (=256) */
    ret = xmlSecBnSetData(&bn, initial_lt, sizeof(initial_lt));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnCompareReverse(&bn, dataReverse_lt, sizeof(dataReverse_lt));
    if(ret >= 0) {
        testLog("Error: expected negative compare result (less-than), got %d\n", ret);
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnDiv_zeroBn(void) {
    xmlSecBn bn;
    int ret;

    testStart("xmlSecBnDiv: zero BN divided gives zero quotient and zero modulus");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    if(testBnDiv(&bn, "0", 2, "0", 0) < 0) {
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn);
    testFinishedSuccess();
}

static void
test_xmlSecBnSetGetNodeValue_decRoundTrip(void) {
    static const xmlSecByte initial[] = { 0x01, 0x02 };
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlChar* content;
    xmlSecBn bn;
    xmlSecBn bn2;
    int ret;

    testStart("xmlSecBnSetNodeValue/xmlSecBnGetNodeValue: decimal round trip");

    doc = bnTestCreateDoc(BAD_CAST "Value");
    if(doc == NULL) {
        testLog("Error: failed to create XML document\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecBnInitialize(&bn, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnSetData(&bn, initial, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnSetNodeValue(&bn, root, xmlSecBnDec, 0, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnSetNodeValue failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    content = xmlNodeGetContent(root);
    if(!bnTestCheckString(content, "258")) {
        xmlFree(content);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);

    ret = xmlSecBnInitialize(&bn2, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed for bn2\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnGetNodeValue(&bn2, root, xmlSecBnDec, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnGetNodeValue failed\n");
        xmlSecBnFinalize(&bn2);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if(!bnTestCheckData(&bn2, initial, sizeof(initial))) {
        xmlSecBnFinalize(&bn2);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn2);
    xmlSecBnFinalize(&bn);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecBnGetNodeValue_hexReverse(void) {
    static const xmlSecByte initial[] = { 0x01, 0x02, 0x03 };
    static const xmlSecByte expected_reversed[] = { 0x03, 0x02, 0x01 };
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSecBn bn;
    xmlSecBn bn2;
    int ret;

    testStart("xmlSecBnGetNodeValue: hex with reverse=1");

    doc = bnTestCreateDoc(BAD_CAST "Value");
    if(doc == NULL) {
        testLog("Error: failed to create XML document\n");
        testFinishedFailure();
        return;
    }
    root = xmlDocGetRootElement(doc);

    ret = xmlSecBnInitialize(&bn, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    ret = xmlSecBnSetData(&bn, initial, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBnSetData failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* write node with reverse=0 so content is the straight hex "10203" */
    ret = xmlSecBnSetNodeValue(&bn, root, xmlSecBnHex, 0, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnSetNodeValue failed\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnInitialize(&bn2, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed for bn2\n");
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    /* read with reverse=1: parses hex then reverses the byte array */
    ret = xmlSecBnGetNodeValue(&bn2, root, xmlSecBnHex, 1);
    if(ret < 0) {
        testLog("Error: xmlSecBnGetNodeValue failed\n");
        xmlSecBnFinalize(&bn2);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    if(!bnTestCheckData(&bn2, expected_reversed, sizeof(expected_reversed))) {
        xmlSecBnFinalize(&bn2);
        xmlSecBnFinalize(&bn);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    xmlSecBnFinalize(&bn2);
    xmlSecBnFinalize(&bn);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

int
test_bn(void) {
    testGroupStart("bn");

    test_xmlSecBnCreateSetGetZero();
    test_xmlSecBnFromHexString_roundTripWithPrefix();
    test_xmlSecBnFromString_invalidCharFails();
    test_xmlSecBnFromString_signIsRejected();
    test_xmlSecBnFromString_replacesExistingValue();
    test_xmlSecBnFromString_emptyAndWhitespaceBothZero();
    test_xmlSecBnFromString_base2AndBase8_roundTrip();
    test_xmlSecBnFromString_baseBoundsRejected();
    test_xmlSecBnToString_largeMultiByte_roundTrip();
    test_xmlSecBnToString_zeroBnProducesZero();
    test_xmlSecBnAdd_updatesValue();
    test_xmlSecBnAdd_cascadingBorrow();
    test_xmlSecBnAdd_toEmptyBn();
    test_xmlSecBnAdd_underflowReturnsError();
    test_xmlSecBnAdd_zeroResultAndTrimBoundaries();
    test_xmlSecBnAdd_bnValueUndefinedAfterUnderflow();
    test_xmlSecBnAdd_intMinDelta();
    test_xmlSecBnMul_updatesValue();
    test_xmlSecBnMul_largeMultiplier();
    test_xmlSecBnAdd_mulProduceCanonicalPrefix();
    test_xmlSecBnDiv_updatesValue();
    test_xmlSecBnDiv_largeDivider();
    test_xmlSecBnDiv_zeroBn();
    test_xmlSecBnMulAddDiv_sequence();
    test_xmlSecBnDiv_byOneKeepsValueAndSetsZeroMod();
    test_xmlSecBnReverse_reversesBytes();
    test_xmlSecBnReverse_emptyAndSingleByte();
    test_xmlSecBnCompare_ignoresLeadingZeroes();
    test_xmlSecBnCompare_greaterThanShorterData();
    test_xmlSecBnCompare_lessThanLongerData();
    test_xmlSecBnCompareReverse_greaterThanShorterData();
    test_xmlSecBnCompareReverse_equalAndLessThan();
    test_xmlSecBnCompare_sameSizeDifferentBytes();
    test_xmlSecBnCompare_emptyAndNullBranches();
    test_xmlSecBnSetGetNodeValue_hexRoundTrip();
    test_xmlSecBnSetGetNodeValue_decRoundTrip();
    test_xmlSecBnGetNodeValue_hexReverse();
    test_xmlSecBnBlobSetNodeValue_base64ReverseRoundTrip();
    test_xmlSecBnSetNodeValue_base64AndBlob_hexDec();

    return(testGroupFinished());
}
