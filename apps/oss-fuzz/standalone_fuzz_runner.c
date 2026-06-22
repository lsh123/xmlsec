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

/* Declared by the fuzzer harness (xmlsec_target.c / xmlsec_dsig_verify_target.c). */
extern int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
    int i;

    if (argc < 2) {
        /* Smoke-test: run once with empty input. */
        return LLVMFuzzerTestOneInput(NULL, 0);
    }

    for (i = 1; i < argc; i++) {
        FILE* f = NULL;
        long len;
        uint8_t* buf;

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
            fclose(f);
            continue;
        }
        len = ftell(f);
        if (len < 0) {
            fclose(f);
            continue;
        }
        rewind(f);

        buf = (uint8_t*)malloc((size_t)len + 1);
        if (buf == NULL) {
            fclose(f);
            continue;
        }

        if (len > 0 && fread(buf, 1, (size_t)len, f) != (size_t)len) {
            free(buf);
            fclose(f);
            continue;
        }
        fclose(f);

        LLVMFuzzerTestOneInput(buf, (size_t)len);
        free(buf);
    }

    return 0;
}
