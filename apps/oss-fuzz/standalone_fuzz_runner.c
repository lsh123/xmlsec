/*
 * Standalone fuzzer driver.
 *
 * Provides a main() entry point so that OSS-Fuzz harnesses that expose
 * LLVMFuzzerTestOneInput() can be compiled and run without libFuzzer.
 *
 * Usage:
 *   xmlsec_fuzzer [FILE ...]
 *
 * Each FILE is read and passed to LLVMFuzzerTestOneInput().  When no FILE
 * arguments are given the harness is exercised once with a zero-length input
 * (useful as a basic smoke test / compile check in the regular test suite).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#if defined(_WIN32) && defined(UNICODE)
#include <wchar.h>
#endif /* defined(_WIN32) && defined(UNICODE) */

/* Declared by the fuzzer harness (xmlsec_target.c / xmlsec_dsig_verify_target.c /
   xmlsec_keyload_target.c / xmlsec_keyinfo_target.c). */
extern int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#if defined(_WIN32) && defined(UNICODE)
#define FUZZER_ERROR(msg, param) \
    fwprintf(stderr, L"standalone_fuzz_runner: %hs '%ls'\n", (msg), (param))
#else /* defined(_WIN32) && defined(UNICODE) */
#define FUZZER_ERROR(msg, param) \
    fprintf(stderr, "standalone_fuzz_runner: %s '%s'\n", (msg), (param))
#endif /* defined(_WIN32) && defined(UNICODE) */

#if defined(_WIN32) && defined(UNICODE) && defined(__MINGW32__)
int wmain(int argc, wchar_t* argv[]);
#endif /* defined(_WIN32) && defined(UNICODE) && defined(__MINGW32__) */

#if defined(_MSC_VER) && defined(_WIN32)
typedef __int64 fuzzer_file_offset_t;
#define fuzzer_fseeko _fseeki64
#define fuzzer_ftello _ftelli64
#else /* defined(_MSC_VER) && defined(_WIN32) */
typedef off_t fuzzer_file_offset_t;
#define fuzzer_fseeko fseeko
#define fuzzer_ftello ftello
#endif /* defined(_MSC_VER) && defined(_WIN32) */

static void fuzzer_close_file(FILE* f) {
    if (fclose(f) != 0) {
        fprintf(stderr, "standalone_fuzz_runner: failed to close file\n");
    }
}


#if defined(_WIN32) && defined(UNICODE)
int wmain(int argc, wchar_t *argv[]) {
#else /* defined(_WIN32) && defined(UNICODE) */
int main(int argc, const char **argv) {
#endif /* defined(_WIN32) && defined(UNICODE) */
    int i;
    int ret = 0;

    if (argc < 2) {
        /* Smoke-test: run once with empty input. libFuzzer always passes a
         * valid pointer even for zero-length input, so use a dummy byte. */
        static uint8_t dummy = 0;
        return LLVMFuzzerTestOneInput(&dummy, 0);
    }

    for (i = 1; i < argc; i++) {
        FILE* f = NULL;
        fuzzer_file_offset_t len;
        uint8_t* buf;
        int inputRet;

        /* call different fopen flavors based on the environment */
#if defined(_MSC_VER) && defined(_WIN32) && defined(UNICODE)
        if (_wfopen_s(&f, argv[i], L"rb") != 0) {
            FUZZER_ERROR("cannot open", argv[i]);
            continue;
        }
#elif defined(_MSC_VER) && defined(_WIN32) && !defined(UNICODE)
        if (fopen_s(&f, argv[i], "rb") != 0) {
            FUZZER_ERROR("cannot open", argv[i]);
            continue;
        }
#elif defined(_WIN32) && defined(UNICODE)
        f = _wfopen(argv[i], L"rb");
#else /* defined(_WIN32) && defined(UNICODE) */
        f = fopen(argv[i], "rb");
#endif /* defined(_WIN32) && defined(UNICODE) */

        if (f == NULL) {
            FUZZER_ERROR("cannot open", argv[i]);
            continue;
        }

        if (fuzzer_fseeko(f, 0, SEEK_END) != 0) {
            FUZZER_ERROR("cannot seek in", argv[i]);
            fuzzer_close_file(f);
            continue;
        }
        len = fuzzer_ftello(f);
        if (len < 0) {
            FUZZER_ERROR("cannot determine the size of", argv[i]);
            fuzzer_close_file(f);
            continue;
        }
        rewind(f);

        /* Allocate at least one byte so that zero-length inputs still get a
         * valid pointer, as libFuzzer guarantees. */
        buf = (uint8_t*)malloc(((size_t)len == 0) ? 1 : (size_t)len);
        if (buf == NULL) {
            FUZZER_ERROR("out of memory reading", argv[i]);
            fuzzer_close_file(f);
            continue;
        }

        if (len > 0 && fread(buf, 1, (size_t)len, f) != (size_t)len) {
            FUZZER_ERROR("failed to read", argv[i]);
            free(buf);
            fuzzer_close_file(f);
            continue;
        }
        fuzzer_close_file(f);

        inputRet = LLVMFuzzerTestOneInput(buf, (size_t)len);
        free(buf);
        if (inputRet != 0) {
            ret = 1;
        }
    }

    return ret;
}
