/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library base64 encode/decode unit tests.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libxml/tree.h>

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include <xmlsec/base64.h>

/*
XMLSEC_EXPORT xmlChar*           xmlSecBase64Encode             (const xmlSecByte* in,
                                                                 xmlSecSize inSize,
                                                                 int columns);
XMLSEC_EXPORT int                xmlSecBase64Decode_ex          (const xmlChar* str,
                                                                 xmlSecByte* out,
                                                                 xmlSecSize outSize,
                                                                 xmlSecSize* outWritten);
*/
static void
test_base64_success(
    const char * name,
    const char * str,
    int columns,
    const char * expected
) {
    xmlSecByte decoded[256];
    xmlSecSize decodedSize = 0;
    xmlChar * encoded;
    int ret;

    xmlSecAssert(name != NULL);
    xmlSecAssert(str != NULL);

    testStart(name);

    ret = xmlSecBase64Decode_ex(BAD_CAST str, decoded, sizeof(decoded), &decodedSize);
    if(ret < 0) {
        testLog("Error: base64 decode failed for '%s'\n", str);
        testFinishedFailure();
        return;
    }

    encoded = xmlSecBase64Encode(decoded, decodedSize, columns);
    if(encoded == NULL) {
        testLog("Error: base64 encode failed for '%s'\n", str);
        testFinishedFailure();
        return;
    }

    /* check results */
    if(xmlStrcmp(encoded, (expected != NULL) ? BAD_CAST expected: BAD_CAST str) != 0) {
        testLog("Error: base64 encode returned in='%s' (expected: '%s')\n", (const char*)encoded, (expected != NULL) ? expected : str);
        xmlFree(encoded);
        testFinishedFailure();
        return;
    }

    /* DONE */
    xmlFree(encoded);
    testFinishedSuccess();
}

static void
test_base64_failure(
    const char * name,
    const char * str
) {
    xmlSecByte decoded[16];
    xmlSecSize decodedSize = 0;
    int ret;

    xmlSecAssert(name != NULL);

    testStart(name);

    ret = xmlSecBase64Decode_ex(BAD_CAST str, decoded, sizeof(decoded), &decodedSize);
    if(ret >= 0) {
        testLog("Error: base64 decode expected to fail for '%s'\n", (str != NULL) ? str : "NULL");
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}

/*
 * Decodes @p str into a buffer of exactly @p expectedSize bytes and checks
 * that the result matches @p expected. This covers the case where the caller
 * allocates precisely the decoded length (no extra room for trailing
 * '='/whitespace consumption or the NUL terminator).
 */
static void
test_base64_decode_exact_size(
    const char * name,
    const char * str,
    const char * expected,
    xmlSecSize expectedSize
) {
    xmlSecByte decoded[256];
    xmlSecSize decodedSize = 0;
    int ret;

    xmlSecAssert(name != NULL);
    xmlSecAssert(str != NULL);
    xmlSecAssert(expected != NULL);
    xmlSecAssert(expectedSize <= sizeof(decoded));

    testStart(name);

    memset(decoded, 0xAA, expectedSize);
    ret = xmlSecBase64Decode_ex(BAD_CAST str, decoded, expectedSize, &decodedSize);
    if(ret < 0) {
        testLog("Error: base64 decode into exactly-sized buffer (%d bytes) failed for '%s'\n",
            (int)expectedSize, str);
        testFinishedFailure();
        return;
    }

    if(decodedSize != expectedSize) {
        testLog("Error: base64 decode returned size=%d (expected: %d) for '%s'\n",
            (int)decodedSize, (int)expectedSize, str);
        testFinishedFailure();
        return;
    }

    if(memcmp(decoded, expected, expectedSize) != 0) {
        testLog("Error: base64 decode returned wrong data for '%s'\n", str);
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}

static void
test_base64_decode_too_small(
    const char * name,
    const char * str,
    xmlSecSize outSize
) {
    xmlSecByte decoded[16];
    xmlSecSize decodedSize = 0;
    int ret;

    xmlSecAssert(name != NULL);
    xmlSecAssert(str != NULL);
    xmlSecAssert(outSize <= sizeof(decoded));

    testStart(name);

    ret = xmlSecBase64Decode_ex(BAD_CAST str, decoded, outSize, &decodedSize);
    if(ret >= 0) {
        testLog("Error: base64 decode expected to fail for '%s' with outSize=%d\n", str, (int)outSize);
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}

static void
test_base64_decode_in_place(
    const char * name,
    const char * str,
    const char * expected,
    xmlSecSize expectedSize
) {
    xmlChar* buf;
    xmlSecSize decodedSize = 0;
    int ret;

    xmlSecAssert(name != NULL);
    xmlSecAssert(str != NULL);
    xmlSecAssert(expected != NULL);

    testStart(name);

    buf = (xmlChar*)xmlStrdup(BAD_CAST str);
    if(buf == NULL) {
        testLog("Error: failed to allocate buffer\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBase64DecodeInPlace(buf, &decodedSize);
    if(ret < 0) {
        testLog("Error: base64 in-place decode failed for '%s'\n", str);
        xmlFree(buf);
        testFinishedFailure();
        return;
    }

    if((decodedSize != expectedSize) || (memcmp(buf, expected, expectedSize) != 0)) {
        testLog("Error: base64 in-place decode returned wrong result for '%s' (size=%d)\n", str, (int)decodedSize);
        xmlFree(buf);
        testFinishedFailure();
        return;
    }

    /* DONE */
    xmlFree(buf);
    testFinishedSuccess();
}


int test_base64(void) {
    /* start */
    testGroupStart("base64");

    /* positive tests */
    test_base64_success("check 1 char", "Rg==", 0, NULL);
    test_base64_success("check 2 chars", "Rm8=", 0, NULL);
    test_base64_success("check 3 chars", "Rm9v", 0, NULL);
    test_base64_success("check 4 chars", "Rm9vQg==", 0, NULL);
    test_base64_success("check 5 chars", "Rm9vQmE=", 0, NULL);
    test_base64_success("check 6 chars", "Rm9vQmFy", 0, NULL);
    test_base64_success("check multiline", "Rm9vQmFyIE\nZvb0JhciBG\nb29CYXI=", 10, NULL);
    test_base64_success("check multiline with space characters", "Rm9vQmFyIE\n   Zvb0JhciBG\n   b29CYXI=", 10, "Rm9vQmFyIE\nZvb0JhciBG\nb29CYXI=");

    /* decode into a buffer of exactly the decoded size */
    test_base64_decode_exact_size("decode exact size 1 byte", "Rg==", "F", 1);
    test_base64_decode_exact_size("decode exact size 2 bytes", "Rm8=", "Fo", 2);
    test_base64_decode_exact_size("decode exact size 3 bytes", "Rm9v", "Foo", 3);
    test_base64_decode_exact_size("decode exact size 6 bytes", "Rm9vQmFy", "FooBar", 6);
    test_base64_decode_exact_size("decode exact size with trailing newline", "Rg==\n", "F", 1);
    test_base64_decode_exact_size("decode exact size with trailing spaces", "Rg==   \t", "F", 1);
    test_base64_decode_exact_size("decode exact size with trailing CRLF", "Rg==\r\n", "F", 1);

    /* decode into an undersized buffer must still fail */
    test_base64_decode_too_small("decode too small 2 of 3 bytes", "Rm9v", 2);
    test_base64_decode_too_small("decode zero-size buffer", "Rg==", 0);

    /* in-place decode */
    test_base64_decode_in_place("in-place decode 1 byte", "Rg==", "F", 1);
    test_base64_decode_in_place("in-place decode 3 bytes", "Rm9v", "Foo", 3);

    /* negative tests */
    test_base64_failure("check NULL", NULL);
    test_base64_failure("check missing both '='", "Rg");
    test_base64_failure("check missing second '='", "Rg=");
    test_base64_failure("check missing first '='", "Rm8");
    test_base64_failure("check output buffer too small", "Rm9vQmFyIEZvb0JhciBGb29CYXIgRm9vQmFyIEZvb0JhciBGb29CYXIgRm9vQmFyIEZvb0JhciBGb29CYXIgRm9vQmFyIA==");
    test_base64_failure("check non base64 chars", "Rm9v;g==");

    /* done */
    return (testGroupFinished());
}
