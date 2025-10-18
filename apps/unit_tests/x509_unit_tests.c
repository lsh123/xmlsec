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


/*********************************** test_xmlSecX509NameRead ***********************************/
#define TEST_X509_NAME_MAX_COUNT 16

typedef struct test_X509Name {
    xmlChar names[256][TEST_X509_NAME_MAX_COUNT];
    xmlChar values[256][TEST_X509_NAME_MAX_COUNT];
    xmlSecSize valueSizes[TEST_X509_NAME_MAX_COUNT];
    int types[TEST_X509_NAME_MAX_COUNT];
    int pos;
} test_X509Name;

static int
test_xmlSecX509NameReadCallback(
    const xmlChar * name,
    const xmlChar * value,
    xmlSecSize valueSize,
    int type,
    void * context
) {
    test_X509Name * nm;

    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(value != NULL, -1);
    xmlSecAssert2(context != NULL, -1);

    nm = (test_X509Name*)context;
    xmlSecAssert2(0 <= nm->pos && nm->pos < TEST_X509_NAME_MAX_COUNT, -1);

#if defined(_MSC_VER)
    strcpy_s((char*)nm->names[nm->pos], sizeof(nm->names[nm->pos]), (const char*)name);
    strcpy_s((char*)nm->values[nm->pos], sizeof(nm->values[nm->pos]), (const char*)value);
#else  /* defined(_MSC_VER) */
    strncpy((char*)nm->names[nm->pos], (const char*)name, sizeof(nm->names[nm->pos]));
    nm->names[nm->pos][sizeof(nm->names[nm->pos]) - 1] = '\0'; /* ensure \0 terminated */

    strncpy((char*)nm->values[nm->pos], (const char*)value, sizeof(nm->values[nm->pos]));
    nm->values[nm->pos][sizeof(nm->values[nm->pos]) - 1] = '\0'; /* ensure \0 terminated */
#endif /* defined(_MSC_VER) */

    nm->valueSizes[nm->pos] = valueSize;
    nm->types[nm->pos] = type;
    nm->pos += 1;
    return(0);
}


static void
test_xmlSecX509NameRead_success(
    const char * name,
    const char * str,
    xmlSecx509NameReplacements * replacements,
    int expectedCount,
    const char * name0,
    const char * value0,
    int type0,
    const char * name1,
    const char * value1,
    int type1
) {
    test_X509Name nms;
    int ret;

    xmlSecAssert(name != NULL);
    xmlSecAssert(str != NULL);

    testStart(name);

    memset(&nms, 0, sizeof(nms));
    ret = xmlSecX509NameRead(BAD_CAST str, replacements, test_xmlSecX509NameReadCallback, &nms);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSecX509NameRead failed for '%s'\n", str);
        testFinishedFailure();
        return;
    }

    /* check results */
    if(nms.pos != expectedCount) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned type='%d' (expected: '%d')\n", nms.pos , expectedCount);
        testFinishedFailure();
        return;
    }
    if(nms.pos > 0 && xmlStrcmp(nms.names[0], BAD_CAST name0) != 0) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned nms.names[0]='%s' (expected: '%s')\n", (const char*)nms.names[0], name0);
        testFinishedFailure();
        return;
    }
    if(nms.pos > 0 && xmlStrcmp(nms.values[0], BAD_CAST value0) != 0) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned nms.value[0]='%s' (expected: '%s')\n", (const char*)nms.values[0], value0);
        testFinishedFailure();
        return;
    }
    if(nms.pos > 0 && (int)(nms.valueSizes[0]) != xmlStrlen(BAD_CAST value0)) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned nms.valueSizes[0]='%d' (expected: '%d')\n", (int)(nms.valueSizes[0]), xmlStrlen(BAD_CAST value0));
        testFinishedFailure();
        return;
    }
    if(nms.pos > 0 && nms.types[0] != type0) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned nms.types[0]='%d' (expected: '%d')\n", nms.types[0], type0);
        testFinishedFailure();
        return;
    }
    if(nms.pos > 1 && xmlStrcmp(nms.names[1], BAD_CAST name1) != 0) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned nms.names[1]='%s' (expected: '%s')\n", (const char*)nms.names[1], name1);
        testFinishedFailure();
        return;
    }
    if(nms.pos > 1 && xmlStrcmp(nms.values[1], BAD_CAST value1) != 0) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned nms.value[1]='%s' (expected: '%s')\n", (const char*)nms.values[1], value1);
        testFinishedFailure();
        return;
    }
    if(nms.pos > 1 && (int)(nms.valueSizes[1]) != xmlStrlen(BAD_CAST value1)) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned nms.valueSizes[0]='%d' (expected: '%d')\n", (int)(nms.valueSizes[1]), xmlStrlen(BAD_CAST value1));
        testFinishedFailure();
        return;
    }
    if(nms.pos > 1 && nms.types[1] != type1) {
        fprintf(stderr, "Error: xmlSecX509NameRead returned nms.types[1]='%d' (expected: '%d')\n", nms.types[1], type1);
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}

static void
test_xmlSecX509NameRead_failure(
    const char * name,
    const char * str,
    xmlSecx509NameReplacements *replacements,
    int fail_callback
) {
    test_X509Name names;
    int ret;

    xmlSecAssert(name != NULL);

    testStart(name);

    memset(&names, 0, sizeof(names));
    if (fail_callback != 0) {
        names.pos = -1;
    }
    ret = xmlSecX509NameRead(BAD_CAST str, replacements, test_xmlSecX509NameReadCallback, &names);
    if(ret >= 0) {
        fprintf(stderr, "Error: xmlSecX509NameRead expected to fail for '%s'\n", (str != NULL) ? str : "NULL");
        testFinishedFailure();
        return;
    }

    /* DONE */
    testFinishedSuccess();
}


static xmlSecx509NameReplacements test_X509NameReplacements[]  = {
    { BAD_CAST "E", BAD_CAST  "emailAddress"},
    { NULL, NULL }
};

int
test_xmlSecX509NameRead(void) {

    /* start */
    testGroupStart("xmlSecX509NameRead");

    /* positive tests */
    test_xmlSecX509NameRead_success("check empty string", "", NULL, 0, NULL, NULL, -1, NULL, NULL, -1);
    test_xmlSecX509NameRead_success("check one value", "Foo=Bar", NULL, 1, "Foo", "Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING, NULL, NULL, -1);
    test_xmlSecX509NameRead_success("check empty value", "Foo=", NULL, 1, "Foo", "", XMLSEC_X509_VALUE_TYPE_UF8_STRING, NULL, NULL, -1);
    test_xmlSecX509NameRead_success("check two values", "Foo=Bar,emailAddress=Value", NULL, 2, "Foo", "Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING, "emailAddress", "Value", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509NameRead_success("check two values with empty value", "Foo=,emailAddress=Value", NULL, 2, "Foo", "", XMLSEC_X509_VALUE_TYPE_UF8_STRING, "emailAddress", "Value", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509NameRead_success("check octet string", "Foo=Bar,emailAddress=#56616c7565", NULL, 2, "Foo", "Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING, "emailAddress", "Value", XMLSEC_X509_VALUE_TYPE_OCTET_STRING);
    test_xmlSecX509NameRead_success("check spaces", "Foo = Bar, emailAddress = Value", NULL, 2, "Foo", "Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING, "emailAddress", "Value", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509NameRead_success("check end comma", "Foo=Bar,emailAddress=Value,", NULL, 2, "Foo", "Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING, "emailAddress", "Value", XMLSEC_X509_VALUE_TYPE_UF8_STRING);
    test_xmlSecX509NameRead_success("check email address", "Foo=Bar,E=Value,", test_X509NameReplacements, 2, "Foo", "Bar", XMLSEC_X509_VALUE_TYPE_UF8_STRING, "emailAddress", "Value", XMLSEC_X509_VALUE_TYPE_UF8_STRING);

    /* negative tests */
    test_xmlSecX509NameRead_failure("check NULL", NULL, NULL, 0);
    test_xmlSecX509NameRead_failure("check missing =", "Foo", NULL, 0);
    test_xmlSecX509NameRead_failure("check bad value", "Foo=#1Q", NULL, 0);
    test_xmlSecX509NameRead_failure("check missing name value pair", "Foo=Bar,,", NULL, 0);
    test_xmlSecX509NameRead_failure("check bad callback", "Foo=Bar", NULL, 1);

    /* done */
    return (testGroupFinished());
}
