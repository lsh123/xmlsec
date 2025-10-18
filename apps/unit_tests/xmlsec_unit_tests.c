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

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include "../src/x509_helpers.h"

#if defined(XMLSEC_WINDOWS) && defined(UNICODE) && defined(__MINGW32__)
int wmain(int argc, wchar_t* argv[]);
#endif /* defined(XMLSEC_WINDOWS) && defined(UNICODE) && defined(__MINGW32__) */


#if defined(XMLSEC_WINDOWS) && defined(UNICODE)
int wmain(int argc, wchar_t *argv[]) {
#else /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */
int main(int argc, const char **argv) {
#endif /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */
    int success = 1;
    int res = 1;

    /* check command line params */
    if((argc > 1) || (argv == NULL)) {
        fprintf(stderr, "Error: no command line parameters expected\n");
        goto done;
    }

    /* run tests */
    fprintf(stdout, "=================== Checking xmlsec-core =================================\n");

    if (test_base64() != 1) {
        success = 0;
    }
    if (test_xmlSecX509EscapedStringRead() != 1) {
        success = 0;
    }
    if (test_xmlSecX509AttrValueStringRead() != 1) {
        success = 0;
    }
    if (test_xmlSecX509NameRead() != 1) {
        success = 0;
    }


    if(success == 1) {
        /* sucecss! */
        fprintf(stdout, "=================== Checking xmlsec-core: SUCCESS =================================\n");
        res = 0;
    } else {
        fprintf(stdout, "=================== Checking xmlsec-core: FAILURE =================================\n");
        res = 1;
    }

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


static const char * testsGroupName = NULL;
static const char * testsName = NULL;
static int testsStarted = 0;
static int testsFinishedSuccess = 0;
static int testFinishedFailed = 0;

void testGroupStart(const char * name) {
    xmlSecAssert(name != NULL);

    testsGroupName = name;
    testsStarted = 0;
    testsFinishedSuccess = 0;
    testFinishedFailed = 0;
    fprintf(stdout, "=== STARTED TESTS FOR '%s'\n", testsGroupName);
}

int testGroupFinished(void) {
    xmlSecAssert2(testsGroupName != NULL, 0);
    fprintf(stdout, "=== FINSIHED TESTS FOR '%s': TOTAL=%d, SUCCESS=%d, FAILURE=%d, NOT FIISHED=%d\n",
        testsGroupName,
        testsStarted,
        testsFinishedSuccess,
        testFinishedFailed,
        (testsStarted - (testsFinishedSuccess + testFinishedFailed))
    );
    testsGroupName = NULL;
    return testsStarted == testsFinishedSuccess ? 1 : 0;
}

void testStart(const char * name) {
    xmlSecAssert(name != NULL);

    testsName = name;
    testsStarted += 1;
    fprintf(stdout, "    %s ...\n", testsName);
}

void testFinishedSuccess(void) {
    fprintf(stdout, "    %s     OK\n", testsName);
    testsFinishedSuccess += 1;
    testsName = NULL;
}

void testFinishedFailure(void) {
    fprintf(stdout, "    %s     FAILED\n", testsName);
    testFinishedFailed += 1;
    testsName = NULL;
}
