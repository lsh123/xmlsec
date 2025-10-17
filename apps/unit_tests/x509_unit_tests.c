/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * x509 utils unit tests
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
#include "../src/x509_helpers.h"

/*********************************** test_xmlSecX509EscapedStringRead ***********************************/
static void
test_xmlSecX509EscapedStringRead_success(
    const char * name,
    const char * str,
    const char delim,
    int ingoreTrailingSpaces,
    const char* expectedIn,
    const char* expectedOut
) {
    const xmlChar *inStr;
    xmlSecSize size, inSize;
    int len;
    xmlChar out[256];
    xmlSecSize outSize;
    int ret;

    xmlSecAssert(name != NULL);
    xmlSecAssert(str != NULL);

    testStart(name);

    len = xmlStrlen(BAD_CAST str);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return, NULL);
    inStr = BAD_CAST str;
    inSize = size;
    outSize = 0;

    ret = xmlSecX509EscapedStringRead(&inStr, &inSize, out, sizeof(out) - 1, &outSize, (xmlChar)delim, ingoreTrailingSpaces);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecX509EscapedStringRead failed for '%s'\n", str);
        testFinishedFailure();
        return;
    }
    out[outSize] = '\0';

    /* check results */
    if(xmlStrcmp(inStr, BAD_CAST expectedIn) != 0) {
        fprintf(stderr, "Error: xmlSecX509EscapedStringRead returned in='%s' (expected: '%s')\n", (const char*)inStr, expectedIn);
        testFinishedFailure();
        return;
    }

    if(xmlStrcmp(out, BAD_CAST expectedOut) != 0) {
        fprintf(stderr, "Error: xmlSecX509EscapedStringRead returned out='%s' (expected: '%s')\n", (const char*)out, expectedOut);
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}

static void
test_xmlSecX509EscapedStringRead_failure(
    const char * name,
    const char * str,
    const char delim,
    int ingoreTrailingSpaces
) {
    const xmlChar *inStr;
    xmlSecSize size, inSize;
    int len;
    xmlChar out[16];
    xmlSecSize outSize;
    int ret;

    xmlSecAssert(name != NULL);

    testStart(name);

    len = xmlStrlen(BAD_CAST str);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return, NULL);
    inStr = BAD_CAST str;
    inSize = size;
    outSize = 0;

    ret = xmlSecX509EscapedStringRead(&inStr, &inSize, out, sizeof(out) - 1, &outSize, (xmlChar)delim, ingoreTrailingSpaces);
    if(ret >= 0) {
        fprintf(stderr, "Error: xmlSecX509EscapedStringRead expected to fail for '%s'\n", (str != NULL) ? str : "NULL");
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}


int
test_xmlSecX509EscapedStringRead(void) {
    /* start */
    testGroupStart("xmlSecX509EscapedStringRead");

    /* positive tests */
    test_xmlSecX509EscapedStringRead_success("check empty string", "=", '=', 0, "=", "");
    test_xmlSecX509EscapedStringRead_success("check end of line with trailing spaces", "Foo Bar  ", '=', 0, "", "Foo Bar  ");
    test_xmlSecX509EscapedStringRead_success("check end of line without trailing spaces", "Foo Bar  ", '=', 1, "", "Foo Bar");
    test_xmlSecX509EscapedStringRead_success("check with trailing spaces", "Foo Bar  =Value", '=', 0, "=Value", "Foo Bar  ");
    test_xmlSecX509EscapedStringRead_success("check without trailing spaces", "Foo Bar  =Value", '=', 1, "=Value", "Foo Bar");
    test_xmlSecX509EscapedStringRead_success("check \\<char> converted to <char> ", "Fo\\o Bar=Value", '=', 0, "=Value", "Foo Bar");
    test_xmlSecX509EscapedStringRead_success("check \\XXX converted to <char> ", "Fo\\6F Bar=Value", '=', 0, "=Value", "Foo Bar");

    /* negative tests */
    test_xmlSecX509EscapedStringRead_failure("check NULL", NULL, '=', 0);
    test_xmlSecX509EscapedStringRead_failure("check bad hex char", "Foo\\6XBar", '=', 0);
    test_xmlSecX509EscapedStringRead_failure("check output buffer too small", "FooBarFooBarFooBarFooBarFooBarFooBarFooBarFooBarFooBar=Value", '=', 0);

    /* done */
    return (testGroupFinished());
}


/*********************************** test_xmlSecX509AttrValueStringRead ***********************************/
static void
test_xmlSecX509AttrValueStringRead_success(
    const char * name,
    const char * str,
    const char delim,
    int ingoreTrailingSpaces,
    const char* expectedIn,
    const char* expectedOut,
    int expectedType
) {
    const xmlChar *inStr;
    xmlSecSize size, inSize;
    int len;
    xmlChar out[256];
    xmlSecSize outSize;
    int type = -1;
    int ret;

    xmlSecAssert(name != NULL);
    xmlSecAssert(str != NULL);

    testStart(name);

    len = xmlStrlen(BAD_CAST str);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return, NULL);
    inStr = BAD_CAST str;
    inSize = size;
    outSize = 0;

    ret = xmlSecX509AttrValueStringRead(&inStr, &inSize, out, sizeof(out) - 1, &outSize, &type, (xmlChar)delim, ingoreTrailingSpaces);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecX509AttrValueStringRead failed for '%s'\n", str);
        testFinishedFailure();
        return;
    }
    out[outSize] = '\0';

    /* check results */
    if(xmlStrcmp(inStr, BAD_CAST expectedIn) != 0) {
        fprintf(stderr, "Error: xmlSecX509AttrValueStringRead returned in='%s' (expected: '%s')\n", (const char*)inStr, expectedIn);
        testFinishedFailure();
        return;
    }
    if(xmlStrcmp(out, BAD_CAST expectedOut) != 0) {
        fprintf(stderr, "Error: xmlSecX509AttrValueStringRead returned out='%s' (expected: '%s')\n", (const char*)out, expectedOut);
        testFinishedFailure();
        return;
    }
    if(type != expectedType) {
        fprintf(stderr, "Error: xmlSecX509AttrValueStringRead returned type='%d' (expected: '%d')\n", type, expectedType);
        testFinishedFailure();
        return;
    }
    /* DONE */
    testFinishedSuccess();
}

static void
test_xmlSecX509AttrValueStringRead_failure(
    const char * name,
    const char * str,
    const char delim,
    int ingoreTrailingSpaces
) {
    const xmlChar *inStr;
    xmlSecSize size, inSize;
    int len;
    xmlChar out[16];
    xmlSecSize outSize;
    int type = -1;
    int ret;

    xmlSecAssert(name != NULL);

    testStart(name);

    len = xmlStrlen(BAD_CAST str);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return, NULL);
    inStr = BAD_CAST str;
    inSize = size;
    outSize = 0;

    ret = xmlSecX509AttrValueStringRead(&inStr, &inSize, out, sizeof(out) - 1, &outSize, &type, (xmlChar)delim, ingoreTrailingSpaces);
    if(ret >= 0) {
        fprintf(stderr, "Error: xmlSecX509AttrValueStringRead expected to fail for '%s'\n", (str != NULL) ? str : "NULL");
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}


int
test_xmlSecX509AttrValueStringRead(void) {
    /* start */
    testGroupStart("xmlSecX509AttrValueStringRead");

    /* positive tests */
    test_xmlSecX509AttrValueStringRead_success("check empty string", ",", ',', 0, ",", "", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check end of line with trailing spaces", "Foo Bar  ", ',', 0, "", "Foo Bar  ", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check end of line without trailing spaces", "Foo Bar  ", ',', 1, "", "Foo Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check with trailing spaces", "Foo Bar  ,name=value", ',', 0, ",name=value", "Foo Bar  ", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check without trailing spaces", "Foo Bar ,name=value", ',', 1, ",name=value", "Foo Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check quoted end of line", "\"Foo Bar  \"", ',', 0, "", "Foo Bar  ", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check quoted with trailing spaces inside quotes", "\"Foo Bar  \",name=value", ',', 0, ",name=value", "Foo Bar  ", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check quoted without trailing spaces inside quotes", "\"Foo Bar  \",name=value", ',', 1, ",name=value", "Foo Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check quoted with trailing spaces outside quotes", "\"Foo Bar  \"  ,name=value", ',', 0, "  ,name=value", "Foo Bar  ", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check quoted without trailing spaces outside quotes", "\"Foo Bar  \"  ,name=value", ',', 1, ",name=value", "Foo Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509AttrValueStringRead_success("check octet/hex", "#466F6F20426172,name=value", ',', 1, ",name=value", "Foo Bar", XMLSEC_X509_VALUE_TYPE_OCTET_STRING);
    test_xmlSecX509AttrValueStringRead_success("check octet/hex end of line", "#466F6F20426172", ',', 1, "", "Foo Bar", XMLSEC_X509_VALUE_TYPE_OCTET_STRING);
    test_xmlSecX509AttrValueStringRead_success("check octet/hex with trailing spaces", "#466F6F20426172  ,name=value", ',', 0, "  ,name=value", "Foo Bar", XMLSEC_X509_VALUE_TYPE_OCTET_STRING);
    test_xmlSecX509AttrValueStringRead_success("check octet/hex without trailing spaces", "#466F6F20426172  ,name=value", ',', 1, ",name=value", "Foo Bar", XMLSEC_X509_VALUE_TYPE_OCTET_STRING);

    /* negative tests */
    test_xmlSecX509AttrValueStringRead_failure("check NULL", NULL, ',', 0);
    test_xmlSecX509AttrValueStringRead_failure("check bad escaping", "\"Foo\6XBar  ,name=value", ',', 0);
    test_xmlSecX509AttrValueStringRead_failure("check missing closing quote", "\"Foo Bar  ,name=value", ',', 0);
    test_xmlSecX509AttrValueStringRead_failure("check output buffer too small", "FooBarFooBarFooBarFooBarFooBarFooBarFooBarFooBarFooBar=Value", ',', 0);
    test_xmlSecX509AttrValueStringRead_failure("check octet/hex with missing char end of line", "#4", ',', 0);
    test_xmlSecX509AttrValueStringRead_failure("check octet/hex with missing chars", "#4,name=value", ',', 0);
    test_xmlSecX509AttrValueStringRead_failure("check octet/hex with non-hex chars", "#4X,name=value", ',', 0);

    /* done */
    return (testGroupFinished());
}
