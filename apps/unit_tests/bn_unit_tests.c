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

    testStart("xmlSecBnFromHexString/xmlSecBnToHexString: preserve sign prefix");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnFromHexString(&bn, BAD_CAST "  +80 ");
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
test_xmlSecBnFromDecString_negativeRoundTrip(void) {
    xmlSecBn bn;
    xmlChar* str;
    int ret;

    testStart("xmlSecBnFromDecString/xmlSecBnToDecString: negative round trip");

    ret = xmlSecBnInitialize(&bn, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBnInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBnFromDecString(&bn, BAD_CAST "  -255 ");
    if(ret < 0) {
        testLog("Error: xmlSecBnFromDecString failed\n");
        xmlSecBnFinalize(&bn);
        testFinishedFailure();
        return;
    }

    str = xmlSecBnToDecString(&bn);
    if(!bnTestCheckString(str, "-255")) {
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
    test_xmlSecBnFromDecString_negativeRoundTrip();
    test_xmlSecBnFromString_invalidCharFails();
    test_xmlSecBnToString_zeroBnProducesZero();
    test_xmlSecBnAdd_updatesValue();
    test_xmlSecBnAdd_cascadingBorrow();
    test_xmlSecBnAdd_toEmptyBn();
    test_xmlSecBnMul_updatesValue();
    test_xmlSecBnDiv_updatesValue();
    test_xmlSecBnDiv_zeroBn();
    test_xmlSecBnMulAddDiv_sequence();
    test_xmlSecBnDiv_byOneKeepsValueAndSetsZeroMod();
    test_xmlSecBnReverse_reversesBytes();
    test_xmlSecBnCompare_ignoresLeadingZeroes();
    test_xmlSecBnCompare_greaterThanShorterData();
    test_xmlSecBnCompare_lessThanLongerData();
    test_xmlSecBnCompareReverse_greaterThanShorterData();
    test_xmlSecBnCompareReverse_equalAndLessThan();
    test_xmlSecBnSetGetNodeValue_hexRoundTrip();
    test_xmlSecBnSetGetNodeValue_decRoundTrip();
    test_xmlSecBnGetNodeValue_hexReverse();
    test_xmlSecBnBlobSetNodeValue_base64ReverseRoundTrip();

    return(testGroupFinished());
}
