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
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* Declared by the fuzzer harness (xmlsec_target.c / xmlsec_dsig_verify_target.c /
   xmlsec_keyload_target.c / xmlsec_keyinfo_target.c). */
extern int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#if defined(XMLSEC_WINDOWS) && defined(UNICODE) && defined(__MINGW32__)
int wmain(int argc, wchar_t* argv[]);
#endif /* defined(XMLSEC_WINDOWS) && defined(UNICODE) && defined(__MINGW32__) */


#if defined(XMLSEC_WINDOWS) && defined(UNICODE)
int wmain(int argc, wchar_t *argv[]) {
#else /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */
int main(int argc, const char **argv) {
#endif /* defined(XMLSEC_WINDOWS) && defined(UNICODE) */
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
        long len;
        uint8_t* buf;
        int inputRet;

#ifdef _MSC_VER
        if (fopen_s(&f, argv[i], "rb") != 0) {
            fprintf(stderr, "standalone_fuzz_runner: cannot open '%s'\n", argv[i]);
            continue;
        }
#else /* _MSC_VER */
        f = fopen(argv[i], "rb");
        if (f == NULL) {
            fprintf(stderr, "standalone_fuzz_runner: cannot open '%s'\n", argv[i]);
            continue;
        }
#endif /* _MSC_VER */
        assert(f != NULL);

        if (fseek(f, 0, SEEK_END) != 0) {
            fprintf(stderr, "standalone_fuzz_runner: cannot seek in '%s'\n", argv[i]);
            fclose(f);
            continue;
        }
        len = ftell(f);
        if (len < 0) {
            fprintf(stderr, "standalone_fuzz_runner: cannot determine the size of '%s'\n", argv[i]);
            fclose(f);
            continue;
        }
        rewind(f);

        buf = (uint8_t*)malloc((size_t)len + 1);
        if (buf == NULL) {
            fprintf(stderr, "standalone_fuzz_runner: out of memory reading '%s'\n", argv[i]);
            fclose(f);
            continue;
        }

        if (len > 0 && fread(buf, 1, (size_t)len, f) != (size_t)len) {
            fprintf(stderr, "standalone_fuzz_runner: failed to read '%s'\n", argv[i]);
            free(buf);
            fclose(f);
            continue;
        }
        fclose(f);

        inputRet = LLVMFuzzerTestOneInput(buf, (size_t)len);
        free(buf);
        if (inputRet != 0) {
            ret = 1;
        }
    }

    return ret;
}
