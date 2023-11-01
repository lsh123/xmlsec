
/**
 * XML Security Library example: Special handling for main() and wmain() on Windows.
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */

/* The real main function */
static int real_main(int argc, char** argv);

#if defined(XMLSEC_WINDOWS)

#if defined(UNICODE) && defined(__MINGW32__)
int wmain(int argc, wchar_t* argv[]);
#endif /*defined(UNICODE) && defined(__MINGW32__) */

#if defined(UNICODE)
int wmain(int argc, wchar_t* argv[]) {
#else /* defined(UNICODE) */
int main(int argc, char** argv) {
#endif /* defined(UNICODE) */
    char** utf8_argv = NULL;
    size_t utf8_argv_size;
    int ii;
    int res = 1;

    /* convert command line to UTF8 from locale or UNICODE */
    utf8_argv_size = sizeof(char*) * (size_t)argc;
    utf8_argv = (char**)xmlMalloc(utf8_argv_size);
    if (utf8_argv == NULL) {
        fprintf(stderr, "Error: can not allocate memory (" XMLSEC_SIZE_T_FMT " bytes)\n",
            utf8_argv_size);
        return(1);
    }
    memset(utf8_argv, 0, utf8_argv_size);
    for (ii = 0; ii < argc; ++ii) {
        utf8_argv[ii] = (char*)xmlSecWin32ConvertTstrToUtf8(argv[ii]);
        if (utf8_argv[ii] == NULL) {
            fprintf(stderr, "Error: can not convert command line parameter at position %d to UTF8\n", ii);
            return(1);
        }
    }

    /* call real main function */
    res = real_main(argc, utf8_argv);

    /* cleanup */
    if (utf8_argv != NULL) {
        for (ii = 0; ii < argc; ++ii) {
            if (utf8_argv[ii] != NULL) {
                xmlFree(BAD_CAST utf8_argv[ii]);
                utf8_argv[ii] = NULL;
            }
        }
        xmlFree(BAD_CAST utf8_argv);
        utf8_argv = NULL;
    }

    return(res);
}

#else /* defined(XMLSEC_WINDOWS) */
int main(int argc, char** argv) {
    return(real_main(argc, argv));
}
#endif /* defined(XMLSEC_WINDOWS) */
