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
