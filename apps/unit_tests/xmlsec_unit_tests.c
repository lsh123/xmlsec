/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library unit tests main file.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#if !defined(_MSC_VER)
#include <libgen.h>
#endif /* defined(_MSC_VER) */

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include "../src/x509_helpers.h"

#if defined(_MSC_VER) && defined(_CRTDBG_MAP_ALLOC)
#include <crtdbg.h>
#endif /*defined(_MSC_VER) && defined(_CRTDBG_MAP_ALLOC) */

/* per-test log buffer (defined after main; forward-declared here for use in main) */
static char *  g_testLogBuffer;
static size_t  g_testLogBufferLen;
static size_t  g_testLogBufferCap;
static void testXmlSecErrorsCallback(const char* file, int line, const char* func,
        const char* errorObject, const char* errorSubject,
        int reason, const char* msg);

/* test group filter: if non-NULL, only the matching group runs */
static const char * g_testGroupFilter;
static int g_testGroupSkip;

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
#if defined(XMLSEC_WINDOWS) && defined(UNICODE)
    char testGroupFilterBuf[256] = { '\0' };
#endif /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */

#if defined(_MSC_VER) && defined(_CRTDBG_MAP_ALLOC)
    fprintf(stderr, "Enabling memory leaks detection\n");
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_DELAY_FREE_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif /* defined(_MSC_VER) && defined(_CRTDBG_MAP_ALLOC) */


    /* check command line params */
    if((argc > 2) || (argv == NULL)) {
        fprintf(stderr, "Error: usage: xmlsec_unit_tests [test-group-name]\n");
        goto done;
    }
    if(argc == 2) {
#if defined(XMLSEC_WINDOWS) && defined(UNICODE)
        wcstombs_s(NULL, testGroupFilterBuf, sizeof(testGroupFilterBuf), argv[1], sizeof(testGroupFilterBuf) - 1);
        g_testGroupFilter = testGroupFilterBuf;
#else /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */
        g_testGroupFilter = argv[1];
#endif /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */
    }
    xmlSecErrorsSetCallback(testXmlSecErrorsCallback);
    /* run tests */
    fprintf(stdout, "=================== Checking xmlsec-core =================================\n");

    if (test_base64() != 1) {
        success = 0;
    }
    if (test_transform_helpers() != 1) {
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
    if (test_xmltree() != 1) {
        success = 0;
    }
    if (test_templates() != 1) {
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

    xmlSecErrorsSetCallback(xmlSecErrorsDefaultCallback);
    free(g_testLogBuffer);
    g_testLogBuffer = NULL;
    g_testGroupFilter = NULL;

    return(res);
}


static void testLogReset(void) {
    g_testLogBufferLen = 0;
}

static void testLogFlush(void) {
    if (g_testLogBufferLen > 0) {
        fwrite(g_testLogBuffer, 1, g_testLogBufferLen, stdout);
        fflush(stdout);
    }
    g_testLogBufferLen = 0;
}

void testLog(const char* fmt, ...) {
    char buf[8192];
    va_list args;
    int len;
    char* newBuf;
    size_t newCap;

    if (fmt == NULL) return;

    va_start(args, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len <= 0) return;
    if ((size_t)len >= sizeof(buf)) {
        len = (int)(sizeof(buf) - 1);
    }

    if (g_testLogBufferLen + (size_t)len + 1 > g_testLogBufferCap) {
        newCap = g_testLogBufferLen + (size_t)len + 1 + 4096;
        newBuf = (char*)realloc(g_testLogBuffer, newCap);
        if (newBuf == NULL) return;
        g_testLogBuffer = newBuf;
        g_testLogBufferCap = newCap;
    }
    memcpy(g_testLogBuffer + g_testLogBufferLen, buf, (size_t)len);
    g_testLogBufferLen += (size_t)len;
    g_testLogBuffer[g_testLogBufferLen] = '\0';
}

static void testXmlSecErrorsCallback(const char* file, int line, const char* func,
        const char* errorObject, const char* errorSubject,
        int reason, const char* msg) {
    testLog("xmlsec error: func=%s:file=%s:line=%d:obj=%s:subj=%s:error=%d:%s\n",
        (func != NULL) ? func : "unknown",
        (file != NULL) ? file : "unknown",
        line,
        (errorObject != NULL) ? errorObject : "unknown",
        (errorSubject != NULL) ? errorSubject : "unknown",
        reason,
        (msg != NULL) ? msg : "");
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
    if((g_testGroupFilter != NULL) && (strcmp(g_testGroupFilter, name) != 0)) {
        g_testGroupSkip = 1;
        return;
    }
    g_testGroupSkip = 0;
    fprintf(stdout, "=== STARTED TESTS FOR '%s'\n", testsGroupName);
}

int testGroupFinished(void) {
    xmlSecAssert2(testsGroupName != NULL, 0);
    if(g_testGroupSkip) {
        g_testGroupSkip = 0;
        testsGroupName = NULL;
        return 1;
    }
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

    if(g_testGroupSkip) { return; }
    testsName = name;
    testsStarted += 1;
    testLogReset();
    testLog("    %s ...\n", testsName);
    fprintf(stdout, "    %s ...\n", testsName);
}

void testFinishedSuccess(void) {
    if(g_testGroupSkip) { return; }
    fprintf(stdout, "    %s     OK\n", testsName);
    testLogReset();
    testsFinishedSuccess += 1;
    testsName = NULL;
}

void testFinishedFailure(void) {
    if(g_testGroupSkip) { return; }
    fprintf(stdout, "    %s     FAILED\n", testsName);
    testLogFlush();
    testFinishedFailed += 1;
    testsName = NULL;
}
