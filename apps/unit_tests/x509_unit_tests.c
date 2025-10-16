/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * x509 util Unit tests
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

static void
test_xmlSec509NameStringRead_success(
    const char* name,
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

    testStart(name);

    len = xmlStrlen(BAD_CAST str);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return, NULL);
    inStr = BAD_CAST str;
    inSize = size;
    outSize = 0;

    ret = xmlSec509NameStringRead(&inStr, &inSize, out, sizeof(out) - 1, &outSize, (xmlChar)delim, ingoreTrailingSpaces);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead failed for '%s'\n", (const char*)str);
        testFinishedFailure();
        return;
    }
    out[outSize] = '\0';

    /* check results */
    if(xmlStrcmp(inStr, BAD_CAST  expectedIn) != 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead retruned in='%s' (expected: '%s')\n", (const char*)inStr, (const char*)expectedIn);
        testFinishedFailure();
        return;
    }

    if(xmlStrcmp(out, BAD_CAST expectedOut) != 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead retruned out='%s' (expected: '%s')\n", (const char*)out, (const char*)expectedOut);
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}

static void
test_xmlSec509NameStringRead_failure(
    const char* name,
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

    testStart(name);

    len = xmlStrlen(BAD_CAST str);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return, NULL);
    inStr = BAD_CAST str;
    inSize = size;
    outSize = 0;

    ret = xmlSec509NameStringRead(&inStr, &inSize, out, sizeof(out) - 1, &outSize, (xmlChar)delim, ingoreTrailingSpaces);
    if(ret >= 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead expected to fail for '%s'\n", (const char*)str);
        testFinishedFailure();
        return;
    }
    if(inSize != size) {
        fprintf(stderr, "Error: xmlSec509NameStringRead retruned inSize='%d' (expected: '%d')\n", (int)inSize, (int)size);
        testFinishedFailure();
        return;
    }
    if(outSize != 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead retruned outSize='%d' (expected: '%d')\n", (int)outSize, (int)0);
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}


int test_xmlSec509NameStringRead(void) {
    /* start */
    testGroupStart("xmlSec509NameStringRead");

    /* positive tests */
    test_xmlSec509NameStringRead_success("check empty string", "=", '=', 0, "=", "");
    test_xmlSec509NameStringRead_success("check end of line with trailing spaces", "Foo Bar  ", '=', 0, "", "Foo Bar  ");
    test_xmlSec509NameStringRead_success("check end of line without trailing spaces", "Foo Bar  ", '=', 1, "", "Foo Bar");
    test_xmlSec509NameStringRead_success("check with trailing spaces", "Foo Bar  =Value", '=', 0, "=Value", "Foo Bar  ");
    test_xmlSec509NameStringRead_success("check without trailing spaces", "Foo Bar  =Value", '=', 1, "=Value", "Foo Bar");
    test_xmlSec509NameStringRead_success("check \\<char> converted to <char> ", "Fo\\o Bar=Value", '=', 0, "=Value", "Foo Bar");
    test_xmlSec509NameStringRead_success("check \\XXX converted to <char> ", "Fo\\6F Bar=Value", '=', 0, "=Value", "Foo Bar");

    /* negative tests */
    test_xmlSec509NameStringRead_failure("check bad hex char", "Foo\\6XBar", '=', 0);
    test_xmlSec509NameStringRead_failure("check output buffer too small", "FooBarFooBarFooBarFooBarFooBarFooBarFooBarFooBarFooBar=Value", '=', 0);

    /* done */
    return (testGroupFinished());
}
