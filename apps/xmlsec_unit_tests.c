/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Unit tests
 *
 * See Copyright for the status of this software.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(_MSC_VER)
#include <libgen.h>
#endif /* defined(_MSC_VER) */

#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf
#endif /* defined(_MSC_VER) && _MSC_VER < 1900 */


#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>
#include <libxml/xpathInternals.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/extensions.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/xsltutils.h>
#include <libxslt/security.h>
#include <libexslt/exslt.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/io.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/parser.h>
#include <xmlsec/templates.h>
#include <xmlsec/errors.h>

#define XMLSEC_PRIVATE 1

#include "../src/cast_helpers.h"
#include "../src/x509_helpers.h"


static int test_xmlSec509NameStringRead(void);

#if defined(XMLSEC_WINDOWS) && defined(UNICODE) && defined(__MINGW32__)
int wmain(int argc, wchar_t* argv[]);
#endif /* defined(XMLSEC_WINDOWS) && defined(UNICODE) && defined(__MINGW32__) */


#if defined(XMLSEC_WINDOWS) && defined(UNICODE)
int wmain(int argc, wchar_t *argv[]) {
#else /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */
int main(int argc, const char **argv) {
#endif /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */
    int res = 1;

    /* check command line params */
    if((argc > 1) || (argv == NULL)) {
        fprintf(stderr, "Error: no command line parameters expected\n");
        goto done;
    }

    /* run tests */
    fprintf(stdout, "=================== Checking xmlsec-core =================================\n");

    if(test_xmlSec509NameStringRead() != 0) {
        fprintf(stderr, "Error: test_xmlSec509NameStringRead() failed\n");
        goto done;
    }

    /* sucecss! */
    fprintf(stdout, "== Checking xmlsec-core: SUCCESS\n");
    res = 0;

done:
#if defined(_MSC_VER) && defined(_CRTDBG_MAP_ALLOC)
    _CrtSetReportMode(_CRT_WARN,    _CRTDBG_MODE_FILE);
    _CrtSetReportMode(_CRT_ERROR,   _CRTDBG_MODE_FILE);
    _CrtSetReportMode(_CRT_ASSERT,  _CRTDBG_MODE_FILE);

    _CrtSetReportFile(_CRT_WARN,    _CRTDBG_FILE_STDERR);
    _CrtSetReportFile(_CRT_ERROR,   _CRTDBG_FILE_STDERR);
    _CrtSetReportFile(_CRT_ASSERT,  _CRTDBG_FILE_STDERR);
    _CrtDumpMemoryLeaks();
#endif /*  defined(_MSC_VER) && defined(_CRTDBG_MAP_ALLOC) */

    return(res);
}

static int test_xmlSec509NameStringRead_success(const char* name, const xmlChar * str, const xmlChar delim, int ingoreTrailingSpaces, const xmlChar* expectedOut, xmlSecSize expectedInSize) {
    const xmlChar *inStr;
    xmlSecSize size, inSize;
    int len;
    xmlChar out[256];
    xmlSecSize outSize;
    int ret;

    fprintf(stdout, "=== test_xmlSec509NameStringRead: test %s\n", name);
    len = xmlStrlen(str);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(-1), NULL);
    inStr = str;
    inSize = size;
    outSize = 0;

    ret = xmlSec509NameStringRead(&inStr, &inSize, out, sizeof(out) - 1, &outSize, delim, ingoreTrailingSpaces);
    if(ret < 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead failed for '%s'\n", (const char*)str);
        return (-1);
    }
    out[outSize] = '\0';

    if(xmlStrcmp(out, expectedOut) != 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead retruned out='%s' (expected: '%s')\n", (const char*)out, (const char*)expectedOut);
        return (-1);
    }

    if(inSize != expectedInSize) {
        fprintf(stderr, "Error: xmlSec509NameStringRead retruned inSize='%d' (expected: '%d')\n", (int)inSize, (int)expectedInSize);
        return (-1);
    }

    fprintf(stdout, "=== test_xmlSec509NameStringRead: test %s: '%s' -> '%s' (ingoreTrailingSpaces=%d, remaining=%d)\n", name, (const char*)str, (const char*)out, ingoreTrailingSpaces, (int)inSize);
    return(0);
}

static int test_xmlSec509NameStringRead_failure(const char* name, const xmlChar * str, const xmlChar delim, int ingoreTrailingSpaces) {
    const xmlChar *inStr;
    xmlSecSize size, inSize;
    int len;
    xmlChar out[256];
    xmlSecSize outSize;
    int ret;

    fprintf(stdout, "=== test_xmlSec509NameStringRead: negative test %s\n", name);
    len = xmlStrlen(str);
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(-1), NULL);
    inStr = str;
    inSize = size;
    outSize = 0;

    ret = xmlSec509NameStringRead(&inStr, &inSize, out, sizeof(out) - 1, &outSize, delim, ingoreTrailingSpaces);
    if(ret >= 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead expected to fail for '%s'\n", (const char*)str);
        return (-1);
    }
    if(inSize != size) {
        fprintf(stderr, "Error: xmlSec509NameStringRead retruned inSize='%d' (expected: '%d')\n", (int)inSize, (int)size);
        return (-1);
    }
    if(outSize != 0) {
        fprintf(stderr, "Error: xmlSec509NameStringRead retruned outSize='%d' (expected: '%d')\n", (int)outSize, (int)0);
        return (-1);
    }

    fprintf(stdout, "=== test_xmlSec509NameStringRead: negative test %s failed (as expected)\n", name);
    return(0);
}


static int test_xmlSec509NameStringRead(void) {
    /* start */
    fprintf(stdout, "=== START: test_xmlSec509NameStringRead()\n");

    if(test_xmlSec509NameStringRead_success("check empty string", BAD_CAST "=", '=', 0, BAD_CAST "", 1) != 0) {
        return(-1);
    }
    if(test_xmlSec509NameStringRead_success("check end of line with trailing spaces", BAD_CAST "Foo   ", '=', 0, BAD_CAST "Foo   ", 0) != 0) {
        return(-1);
    }
    if(test_xmlSec509NameStringRead_success("check end of line without trailing spaces", BAD_CAST "Foo   ", '=', 1, BAD_CAST "Foo", 0) != 0) {
        return(-1);
    }
    if(test_xmlSec509NameStringRead_success("check with trailing spaces", BAD_CAST "Foo   =", '=', 0, BAD_CAST "Foo   ", 1) != 0) {
        return(-1);
    }
    if(test_xmlSec509NameStringRead_success("check without trailing spaces", BAD_CAST "Foo   =", '=', 1, BAD_CAST "Foo", 1) != 0) {
        return(-1);
    }
    if(test_xmlSec509NameStringRead_success("check \\<char> converted to <char> ", BAD_CAST "Fo\\oBar=", '=', 0, BAD_CAST "FooBar", 1) != 0) {
        return(-1);
    }
    if(test_xmlSec509NameStringRead_success("check \\XXX converted to <char> ", BAD_CAST "Fo\\6FBar=", '=', 0, BAD_CAST "FooBar", 1) != 0) {
        return(-1);
    }


    if(test_xmlSec509NameStringRead_failure("check bad hex char", BAD_CAST "Foo\\6XBar", '=', 0) != 0) {
        return(-1);
    }

    /* success */
     fprintf(stdout, "=== SUCCESS: test_xmlSec509NameStringRead()\n");
    return(0);
}
