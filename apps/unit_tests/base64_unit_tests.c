/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * base64 util unit tests
 *
 * See Copyright for the status of this software.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
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
        fprintf(stderr, "Error: base64 decode failed for '%s'\n", str);
        testFinishedFailure();
        return;
    }

    encoded = xmlSecBase64Encode(decoded, decodedSize, columns);
    if(encoded == NULL) {
        fprintf(stderr, "Error: base64 encode failed for '%s'\n", str);
        testFinishedFailure();
        return;
    }

    /* check results */
    if(xmlStrcmp(encoded, (expected != NULL) ? BAD_CAST expected: BAD_CAST str) != 0) {
        fprintf(stderr, "Error: base64 encode returned in='%s' (expected: '%s')\n", (const char*)encoded, (expected != NULL) ? expected : str);
        testFinishedFailure();
        return;
    }

    /* DONE */
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
        fprintf(stderr, "Error: base64 decode expected to fail for '%s'\n", (str != NULL) ? str : "NULL");
        testFinishedFailure();
        return;
    }

    /* DONE */
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
