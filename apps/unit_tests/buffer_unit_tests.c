/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library buffer unit tests.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _MSC_VER
#include <process.h>
#else
#include <unistd.h>
#endif

#include <libxml/tree.h>
#include <libxml/xmlIO.h>

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include <xmlsec/buffer.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void
test_buffer_reset_default_alloc_mode(void) {
    /* restore the library-wide default so subsequent tests are unaffected */
    xmlSecBufferSetDefaultAllocMode(xmlSecAllocModeDouble, 1024);
}

#ifdef _MSC_VER
static int
test_buffer_get_env_copy(const char* name, char* out, size_t outSize) {
    char* value = NULL;
    size_t required = 0;
    errno_t err;

    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize > 0, -1);

    out[0] = '\0';
    err = _dupenv_s(&value, &required, name);
    if((err != 0) || (value == NULL) || (required == 0) || (value[0] == '\0')) {
        if(value != NULL) {
            free(value);
        }
        return(-1);
    }

    if(sprintf_s(out, outSize, "%s", value) < 0) {
        free(value);
        return(-1);
    }

    free(value);
    return(0);
}
#endif

static const char*
test_buffer_get_temp_dir(void) {
#ifdef _MSC_VER
    static char tmpPath[512];
#else
    const char* value;
#endif

    /* Prefer OS-provided temp locations; CI working directories may be read-only. */
#ifndef _MSC_VER
    value = getenv("TMPDIR");
    if((value != NULL) && (value[0] != '\0')) {
        return(value);
    }
#endif

#ifdef _MSC_VER
    if(test_buffer_get_env_copy("TMP", tmpPath, sizeof(tmpPath)) == 0) {
        return(tmpPath);
    }

    if(test_buffer_get_env_copy("TEMP", tmpPath, sizeof(tmpPath)) == 0) {
        return(tmpPath);
    }

    if(test_buffer_get_env_copy("USERPROFILE", tmpPath, sizeof(tmpPath)) == 0) {
        return(tmpPath);
    }
#else
    value = getenv("TMP");
    if((value != NULL) && (value[0] != '\0')) {
        return(value);
    }

    value = getenv("TEMP");
    if((value != NULL) && (value[0] != '\0')) {
        return(value);
    }

#ifdef P_tmpdir
    if((P_tmpdir != NULL) && (P_tmpdir[0] != '\0')) {
        return(P_tmpdir);
    }
#endif

    /* Common writable fallback on Unix-like CI runners. */
    if(access("/tmp", W_OK) == 0) {
        return("/tmp");
    }

    if(access("/var/tmp", W_OK) == 0) {
        return("/var/tmp");
    }
#endif

    return(".");
}

static int
test_buffer_make_temp_name(char* tmpName, size_t tmpNameSize, const char* suffix) {
    const char* tmpDir;
    size_t tmpDirLen;
    const char* sep;
    long now;
    unsigned int ticks;
#ifdef _MSC_VER
    int pid = _getpid();
    int ret;
#else
    int pid = getpid();
    int ret;
#endif

    xmlSecAssert2(tmpName != NULL, -1);
    xmlSecAssert2(tmpNameSize > 0, -1);
    xmlSecAssert2(suffix != NULL, -1);

    tmpDir = test_buffer_get_temp_dir();
    xmlSecAssert2(tmpDir != NULL, -1);
    tmpDirLen = strlen(tmpDir);

#ifdef _MSC_VER
    sep = ((tmpDirLen > 0) && (tmpDir[tmpDirLen - 1] != '\\') && (tmpDir[tmpDirLen - 1] != '/')) ? "\\" : "";
#else
    sep = ((tmpDirLen > 0) && (tmpDir[tmpDirLen - 1] != '/')) ? "/" : "";
#endif

    now = (long)time(NULL);
    ticks = (unsigned int)clock();
#ifdef _MSC_VER
    ret = sprintf_s(tmpName, tmpNameSize, "%s%sxmlsec_unit_tests_%ld_%d_%u_%s",
        tmpDir, sep, now, pid, ticks, suffix);
#else
    ret = snprintf(tmpName, tmpNameSize, "%s%sxmlsec_unit_tests_%ld_%d_%u_%s",
        tmpDir, sep, now, pid, ticks, suffix);
#endif
    if((ret < 0) || ((size_t)ret >= tmpNameSize)) {
        return(-1);
    }
    return(0);
}

static void
test_buffer_remove_temp_file(const char* tmpName) {
    if(remove(tmpName) != 0) {
        testLog("Error: failed to remove temp file '%s'\n", tmpName);
    }
}

/* ------------------------------------------------------------------ */
/* Individual test functions                                           */
/* ------------------------------------------------------------------ */
static void
test_buffer_default_alloc_mode(void) {
    xmlSecBufferPtr buf = NULL;
    xmlSecSize maxSize;

    testStart("xmlSecBufferSetDefaultAllocMode - exact mode");
    test_buffer_reset_default_alloc_mode();

    /* Switch to exact mode with a tiny initial size so we can observe it. */
    xmlSecBufferSetDefaultAllocMode(xmlSecAllocModeExact, 8);

    buf = xmlSecBufferCreate(1);
    if(buf == NULL) {
        testLog("Error: xmlSecBufferCreate failed\n");
        goto done;
    }

    /* With exact mode the implementation allocates size+8 (clamped to the
     * initial size of 8), so maxSize must be exactly 9; in double mode it
     * would be 2*size+32 = 34. */
    maxSize = xmlSecBufferGetMaxSize(buf);
    if(maxSize != 9) {
        testLog("Error: maxSize=" XMLSEC_SIZE_FMT " expected 9\n", maxSize);
        goto done;
    }

    xmlSecBufferDestroy(buf);
    buf = NULL;
    test_buffer_reset_default_alloc_mode();
    testFinishedSuccess();
    return;

done:
    if(buf != NULL) {
        xmlSecBufferDestroy(buf);
    }
    test_buffer_reset_default_alloc_mode();
    testFinishedFailure();
}

static void
test_buffer_create_destroy(void) {
    xmlSecBufferPtr buf = NULL;

    testStart("xmlSecBufferCreate/xmlSecBufferDestroy");
    test_buffer_reset_default_alloc_mode();

    buf = xmlSecBufferCreate(64);
    if(buf == NULL) {
        testLog("Error: xmlSecBufferCreate(64) returned NULL\n");
        goto done;
    }

    /* freshly created buffer must be empty */
    if(xmlSecBufferGetSize(buf) != 0) {
        testLog("Error: new buffer size is " XMLSEC_SIZE_FMT " expected 0\n",
            xmlSecBufferGetSize(buf));
        goto done;
    }
    if(xmlSecBufferGetMaxSize(buf) < 64) {
        testLog("Error: new buffer maxSize=" XMLSEC_SIZE_FMT " expected >= 64\n",
            xmlSecBufferGetMaxSize(buf));
        goto done;
    }
    if(!xmlSecBufferIsEmpty(buf)) {
        testLog("Error: new buffer should be empty\n");
        goto done;
    }

    xmlSecBufferDestroy(buf);
    buf = NULL;
    testFinishedSuccess();
    return;

done:
    if(buf != NULL) {
        xmlSecBufferDestroy(buf);
    }
    testFinishedFailure();
}

static void
test_buffer_create_zero_size(void) {
    xmlSecBufferPtr buf = NULL;

    testStart("xmlSecBufferCreate(0) - zero-size creation");

    buf = xmlSecBufferCreate(0);
    if(buf == NULL) {
        testLog("Error: xmlSecBufferCreate(0) returned NULL\n");
        goto done;
    }

    if(xmlSecBufferGetSize(buf) != 0) {
        testLog("Error: zero-size buffer has size=" XMLSEC_SIZE_FMT " expected 0\n",
            xmlSecBufferGetSize(buf));
        goto done;
    }
    if(!xmlSecBufferIsEmpty(buf)) {
        testLog("Error: zero-size buffer should be empty\n");
        goto done;
    }

    xmlSecBufferDestroy(buf);
    buf = NULL;
    testFinishedSuccess();
    return;

done:
    if(buf != NULL) {
        xmlSecBufferDestroy(buf);
    }
    testFinishedFailure();
}

static void
test_buffer_initialize_finalize(void) {
    xmlSecBuffer buf;
    const xmlSecByte data[] = { 0x01, 0x02, 0x03 };
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferInitialize/xmlSecBufferFinalize");

    ret = xmlSecBufferInitialize(&buf, 32);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        goto done;
    }

    if(xmlSecBufferGetSize(&buf) != 0) {
        testLog("Error: initialized buffer size=" XMLSEC_SIZE_FMT " expected 0\n",
            xmlSecBufferGetSize(&buf));
        goto done;
    }
    if(xmlSecBufferGetMaxSize(&buf) < 32) {
        testLog("Error: initialized buffer maxSize=" XMLSEC_SIZE_FMT " expected >= 32\n",
            xmlSecBufferGetMaxSize(&buf));
        goto done;
    }

    /* write some data so we can verify finalize cleans up */
    ret = xmlSecBufferSetData(&buf, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData failed\n");
        goto done;
    }

    xmlSecBufferFinalize(&buf);

    /* after finalize the struct should be fully reset */
    if((buf.data != NULL) || (buf.size != 0) || (buf.maxSize != 0)) {
        testLog("Error: xmlSecBufferFinalize did not reset all fields\n");
        goto done_after_finalize;
    }

    testFinishedSuccess();
    return;

done:
    if(xmlSecBufferGetMaxSize(&buf) > 0) {
        xmlSecBufferFinalize(&buf);
    }
done_after_finalize:
    testFinishedFailure();
}

static void
test_buffer_empty(void) {
    xmlSecBuffer buf;
    const xmlSecByte data[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    const xmlSecByte* ptr;
    xmlSecSize ii, maxSize;
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferEmpty");

    ret = xmlSecBufferInitialize(&buf, 64);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        goto done;
    }

    ret = xmlSecBufferSetData(&buf, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData failed\n");
        goto done;
    }

    /* record max size before empty */
    maxSize = xmlSecBufferGetMaxSize(&buf);
    ptr     = xmlSecBufferGetData(&buf);

    xmlSecBufferEmpty(&buf);

    /* logical size must be 0 */
    if(xmlSecBufferGetSize(&buf) != 0) {
        testLog("Error: size after Empty=" XMLSEC_SIZE_FMT " expected 0\n",
            xmlSecBufferGetSize(&buf));
        goto done;
    }
    /* allocated storage must not shrink */
    if(xmlSecBufferGetMaxSize(&buf) != maxSize) {
        testLog("Error: maxSize changed after Empty: " XMLSEC_SIZE_FMT " vs " XMLSEC_SIZE_FMT "\n",
            xmlSecBufferGetMaxSize(&buf), maxSize);
        goto done;
    }
    /* data pointer must be unchanged */
    if(xmlSecBufferGetData(&buf) != ptr) {
        testLog("Error: data pointer changed after Empty\n");
        goto done;
    }
    /* all bytes of the allocation must be zeroed */
    for(ii = 0; ii < maxSize; ++ii) {
        if(ptr[ii] != 0) {
            testLog("Error: byte at offset " XMLSEC_SIZE_FMT " is 0x%02x after Empty, expected 0x00\n",
                ii, (unsigned)ptr[ii]);
            goto done;
        }
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_is_empty(void) {
    xmlSecBuffer buf;
    const xmlSecByte data[] = { 0x01 };
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferIsEmpty");

    /* NULL pointer must be treated as empty */
    if(!xmlSecBufferIsEmpty(NULL)) {
        testLog("Error: NULL buffer should be empty\n");
        testFinishedFailure();
        return;
    }

    /* freshly initialized buffer with no data is empty */
    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }
    if(!xmlSecBufferIsEmpty(&buf)) {
        testLog("Error: zero-size buffer should be empty\n");
        goto done;
    }

    /* once data is written the buffer is non-empty */
    ret = xmlSecBufferSetData(&buf, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData failed\n");
        goto done;
    }
    if(xmlSecBufferIsEmpty(&buf)) {
        testLog("Error: buffer with data should not be empty\n");
        goto done;
    }

    /* after empty it must be empty again */
    xmlSecBufferEmpty(&buf);
    if(!xmlSecBufferIsEmpty(&buf)) {
        testLog("Error: buffer should be empty after xmlSecBufferEmpty\n");
        goto done;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_set_get_data(void) {
    xmlSecBuffer buf;
    const xmlSecByte data1[] = { 0x10, 0x20, 0x30 };
    const xmlSecByte data2[] = { 0xAA, 0xBB };
    const xmlSecByte* ptr;
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferSetData/xmlSecBufferGetData");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* set first data block */
    ret = xmlSecBufferSetData(&buf, data1, sizeof(data1));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData(data1) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(data1)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf), sizeof(data1));
        goto done;
    }
    ptr = xmlSecBufferGetData(&buf);
    if(ptr == NULL) {
        testLog("Error: GetData returned NULL after SetData\n");
        goto done;
    }
    if(memcmp(ptr, data1, sizeof(data1)) != 0) {
        testLog("Error: data mismatch after SetData(data1)\n");
        goto done;
    }

    /* overwrite with a different (shorter) data block - old data must be gone */
    ret = xmlSecBufferSetData(&buf, data2, sizeof(data2));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData(data2) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(data2)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf), sizeof(data2));
        goto done;
    }
    ptr = xmlSecBufferGetData(&buf);
    if(memcmp(ptr, data2, sizeof(data2)) != 0) {
        testLog("Error: data mismatch after SetData(data2)\n");
        goto done;
    }

    /* set empty data (size 0) */
    ret = xmlSecBufferSetData(&buf, NULL, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData(NULL, 0) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 0) {
        testLog("Error: size should be 0 after SetData(NULL, 0)\n");
        goto done;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_set_get_size(void) {
    xmlSecBuffer buf;
    const xmlSecByte data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferSetSize/xmlSecBufferGetSize");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* grow the logical + physical size */
    ret = xmlSecBufferSetSize(&buf, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetSize(" XMLSEC_SIZE_T_FMT ") failed\n", sizeof(data));
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(data)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf), sizeof(data));
        goto done;
    }
    if(xmlSecBufferGetMaxSize(&buf) < sizeof(data)) {
        testLog("Error: maxSize=" XMLSEC_SIZE_FMT " expected >= " XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetMaxSize(&buf), sizeof(data));
        goto done;
    }

    /* shrink the logical size - maxSize must not decrease and tail must be zeroed */
    {
        const xmlSecByte shrinkData[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
        xmlSecSize prevMax;
        const xmlSecByte* ptr;
        xmlSecSize ii;

        ret = xmlSecBufferSetData(&buf, shrinkData, sizeof(shrinkData));
        if(ret < 0) {
            testLog("Error: xmlSecBufferSetData(shrinkData) failed\n");
            goto done;
        }
        prevMax = xmlSecBufferGetMaxSize(&buf);
        ptr     = xmlSecBufferGetData(&buf);

        ret = xmlSecBufferSetSize(&buf, 2);
        if(ret < 0) {
            testLog("Error: xmlSecBufferSetSize(2) failed\n");
            goto done;
        }
        if(xmlSecBufferGetSize(&buf) != 2) {
            testLog("Error: shrunken size=" XMLSEC_SIZE_FMT " expected 2\n",
                xmlSecBufferGetSize(&buf));
            goto done;
        }
        if(xmlSecBufferGetMaxSize(&buf) != prevMax) {
            testLog("Error: maxSize changed on shrink: " XMLSEC_SIZE_FMT " vs " XMLSEC_SIZE_FMT "\n",
                xmlSecBufferGetMaxSize(&buf), prevMax);
            goto done;
        }
        /* bytes from new size to old size must be zeroed (ISSUE-2 fix) */
        for(ii = 2; ii < sizeof(shrinkData); ++ii) {
            if(ptr[ii] != 0) {
                testLog("Error: byte at offset " XMLSEC_SIZE_FMT " is 0x%02x after shrink, expected 0x00\n",
                    ii, (unsigned)ptr[ii]);
                goto done;
            }
        }
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_set_get_max_size(void) {
    xmlSecBuffer buf;
    xmlSecSize maxAfterGrow, maxAfterShrinkAttempt;
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferSetMaxSize/xmlSecBufferGetMaxSize");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* grow the allocated buffer */
    ret = xmlSecBufferSetMaxSize(&buf, 256);
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetMaxSize(256) failed\n");
        goto done;
    }
    maxAfterGrow = xmlSecBufferGetMaxSize(&buf);
    if(maxAfterGrow < 256) {
        testLog("Error: maxSize=" XMLSEC_SIZE_FMT " expected >= 256\n", maxAfterGrow);
        goto done;
    }

    /* requesting a smaller max must be a no-op (buffer never shrinks) */
    ret = xmlSecBufferSetMaxSize(&buf, 16);
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetMaxSize(16) failed\n");
        goto done;
    }
    maxAfterShrinkAttempt = xmlSecBufferGetMaxSize(&buf);
    if(maxAfterShrinkAttempt != maxAfterGrow) {
        testLog("Error: buffer shrank from " XMLSEC_SIZE_FMT " to " XMLSEC_SIZE_FMT " (should not shrink)\n",
            maxAfterGrow, maxAfterShrinkAttempt);
        goto done;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_swap(void) {
    xmlSecBuffer buf1, buf2;
    const xmlSecByte data1[] = { 0xAA, 0xBB, 0xCC };
    const xmlSecByte data2[] = { 0x11, 0x22 };
    int ret;

    memset(&buf1, 0, sizeof(buf1));
    memset(&buf2, 0, sizeof(buf2));

    testStart("xmlSecBufferSwap");

    ret = xmlSecBufferInitialize(&buf1, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize(buf1) failed\n");
        testFinishedFailure();
        return;
    }
    ret = xmlSecBufferInitialize(&buf2, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize(buf2) failed\n");
        xmlSecBufferFinalize(&buf1);
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferSetData(&buf1, data1, sizeof(data1));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData(buf1) failed\n");
        goto done;
    }
    ret = xmlSecBufferSetData(&buf2, data2, sizeof(data2));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData(buf2) failed\n");
        goto done;
    }

    xmlSecBufferSwap(&buf1, &buf2);

    /* buf1 must now contain data2 */
    if(xmlSecBufferGetSize(&buf1) != sizeof(data2)) {
        testLog("Error: buf1 size=" XMLSEC_SIZE_FMT " after swap, expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf1), sizeof(data2));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(&buf1), data2, sizeof(data2)) != 0) {
        testLog("Error: buf1 content mismatch after swap\n");
        goto done;
    }

    /* buf2 must now contain data1 */
    if(xmlSecBufferGetSize(&buf2) != sizeof(data1)) {
        testLog("Error: buf2 size=" XMLSEC_SIZE_FMT " after swap, expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf2), sizeof(data1));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(&buf2), data1, sizeof(data1)) != 0) {
        testLog("Error: buf2 content mismatch after swap\n");
        goto done;
    }

    xmlSecBufferFinalize(&buf1);
    xmlSecBufferFinalize(&buf2);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf1);
    xmlSecBufferFinalize(&buf2);
    testFinishedFailure();
}

static void
test_buffer_append(void) {
    xmlSecBuffer buf;
    const xmlSecByte chunk1[] = { 0x01, 0x02, 0x03 };
    const xmlSecByte chunk2[] = { 0x04, 0x05 };
    const xmlSecByte expected[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferAppend");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* append to empty buffer */
    ret = xmlSecBufferAppend(&buf, chunk1, sizeof(chunk1));
    if(ret < 0) {
        testLog("Error: xmlSecBufferAppend(chunk1) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(chunk1)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after first append, expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf), sizeof(chunk1));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(&buf), chunk1, sizeof(chunk1)) != 0) {
        testLog("Error: data mismatch after first append\n");
        goto done;
    }

    /* append second chunk */
    ret = xmlSecBufferAppend(&buf, chunk2, sizeof(chunk2));
    if(ret < 0) {
        testLog("Error: xmlSecBufferAppend(chunk2) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(expected)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after second append, expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf), sizeof(expected));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(&buf), expected, sizeof(expected)) != 0) {
        testLog("Error: data mismatch after second append\n");
        goto done;
    }

    /* appending zero bytes must be a no-op */
    ret = xmlSecBufferAppend(&buf, chunk1, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferAppend(size=0) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(expected)) {
        testLog("Error: size changed after zero-byte append\n");
        goto done;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_prepend(void) {
    xmlSecBuffer buf;
    const xmlSecByte initial[] = { 0x03, 0x04, 0x05 };
    const xmlSecByte prefix[]  = { 0x01, 0x02 };
    const xmlSecByte expected[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferPrepend");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* prepend to empty buffer */
    ret = xmlSecBufferPrepend(&buf, initial, sizeof(initial));
    if(ret < 0) {
        testLog("Error: xmlSecBufferPrepend(initial) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(initial)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after first prepend, expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf), sizeof(initial));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(&buf), initial, sizeof(initial)) != 0) {
        testLog("Error: data mismatch after first prepend\n");
        goto done;
    }

    /* prepend a prefix */
    ret = xmlSecBufferPrepend(&buf, prefix, sizeof(prefix));
    if(ret < 0) {
        testLog("Error: xmlSecBufferPrepend(prefix) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(expected)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after second prepend, expected=" XMLSEC_SIZE_T_FMT "\n",
            xmlSecBufferGetSize(&buf), sizeof(expected));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(&buf), expected, sizeof(expected)) != 0) {
        testLog("Error: data mismatch after second prepend\n");
        goto done;
    }

    /* prepending zero bytes must be a no-op */
    ret = xmlSecBufferPrepend(&buf, prefix, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferPrepend(size=0) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != sizeof(expected)) {
        testLog("Error: size changed after zero-byte prepend\n");
        goto done;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_remove_head(void) {
    xmlSecBuffer buf;
    const xmlSecByte data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferRemoveHead");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }
    ret = xmlSecBufferSetData(&buf, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData failed\n");
        goto done;
    }

    /* remove 2 bytes from head */
    ret = xmlSecBufferRemoveHead(&buf, 2);
    if(ret < 0) {
        testLog("Error: xmlSecBufferRemoveHead(2) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 3) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after RemoveHead(2), expected=3\n",
            xmlSecBufferGetSize(&buf));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(&buf), data + 2, 3) != 0) {
        testLog("Error: data mismatch after RemoveHead(2)\n");
        goto done;
    }

    /* remove zero bytes - no-op */
    ret = xmlSecBufferRemoveHead(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferRemoveHead(0) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 3) {
        testLog("Error: size changed after RemoveHead(0)\n");
        goto done;
    }

    /* remove all remaining bytes */
    ret = xmlSecBufferRemoveHead(&buf, 3);
    if(ret < 0) {
        testLog("Error: xmlSecBufferRemoveHead(3) [exact] failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 0) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after RemoveHead(all), expected=0\n",
            xmlSecBufferGetSize(&buf));
        goto done;
    }

    /* NOTE (ISSUE-1): removing more than the current size silently truncates
     * to zero instead of returning an error.  We test that the function
     * at least succeeds and leaves size == 0. */
    ret = xmlSecBufferSetData(&buf, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData (restore) failed\n");
        goto done;
    }
    ret = xmlSecBufferRemoveHead(&buf, sizeof(data) + 10);  /* more than current size */
    if(ret < 0) {
        testLog("Error: xmlSecBufferRemoveHead(over) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 0) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after over-RemoveHead, expected=0\n",
            xmlSecBufferGetSize(&buf));
        goto done;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_remove_tail(void) {
    xmlSecBuffer buf;
    const xmlSecByte data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferRemoveTail");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }
    ret = xmlSecBufferSetData(&buf, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData failed\n");
        goto done;
    }

    /* remove 2 bytes from tail */
    ret = xmlSecBufferRemoveTail(&buf, 2);
    if(ret < 0) {
        testLog("Error: xmlSecBufferRemoveTail(2) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 3) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after RemoveTail(2), expected=3\n",
            xmlSecBufferGetSize(&buf));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(&buf), data, 3) != 0) {
        testLog("Error: data mismatch after RemoveTail(2): expected first 3 bytes unchanged\n");
        goto done;
    }

    /* remove zero bytes - no-op */
    ret = xmlSecBufferRemoveTail(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferRemoveTail(0) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 3) {
        testLog("Error: size changed after RemoveTail(0)\n");
        goto done;
    }

    /* remove all remaining bytes */
    ret = xmlSecBufferRemoveTail(&buf, 3);
    if(ret < 0) {
        testLog("Error: xmlSecBufferRemoveTail(3) [exact] failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 0) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after RemoveTail(all), expected=0\n",
            xmlSecBufferGetSize(&buf));
        goto done;
    }

    /* NOTE (ISSUE-1): removing more than the current size silently truncates
     * to zero instead of returning an error. */
    ret = xmlSecBufferSetData(&buf, data, sizeof(data));
    if(ret < 0) {
        testLog("Error: xmlSecBufferSetData (restore) failed\n");
        goto done;
    }
    ret = xmlSecBufferRemoveTail(&buf, sizeof(data) + 10);
    if(ret < 0) {
        testLog("Error: xmlSecBufferRemoveTail(over) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 0) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " after over-RemoveTail, expected=0\n",
            xmlSecBufferGetSize(&buf));
        goto done;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_reverse(void) {
    xmlSecBuffer buf;
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart("xmlSecBufferReverse");

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }

    /* reverse empty buffer - must be a no-op */
    ret = xmlSecBufferReverse(&buf);
    if(ret < 0) {
        testLog("Error: xmlSecBufferReverse(empty) failed\n");
        goto done;
    }
    if(xmlSecBufferGetSize(&buf) != 0) {
        testLog("Error: size changed after reversing empty buffer\n");
        goto done;
    }

    /* single byte - must be a no-op */
    {
        const xmlSecByte single[] = { 0x42 };
        ret = xmlSecBufferSetData(&buf, single, sizeof(single));
        if(ret < 0) { testLog("Error: SetData(single) failed\n"); goto done; }
        ret = xmlSecBufferReverse(&buf);
        if(ret < 0) { testLog("Error: Reverse(single) failed\n"); goto done; }
        if(xmlSecBufferGetData(&buf)[0] != 0x42) {
            testLog("Error: single-byte reverse changed the byte\n");
            goto done;
        }
    }

    /* even number of bytes */
    {
        const xmlSecByte even[]     = { 0x01, 0x02, 0x03, 0x04 };
        const xmlSecByte expected[] = { 0x04, 0x03, 0x02, 0x01 };
        ret = xmlSecBufferSetData(&buf, even, sizeof(even));
        if(ret < 0) { testLog("Error: SetData(even) failed\n"); goto done; }
        ret = xmlSecBufferReverse(&buf);
        if(ret < 0) { testLog("Error: Reverse(even) failed\n"); goto done; }
        if(memcmp(xmlSecBufferGetData(&buf), expected, sizeof(expected)) != 0) {
            testLog("Error: data mismatch after reversing even-length buffer\n");
            goto done;
        }
    }

    /* odd number of bytes */
    {
        const xmlSecByte odd[]      = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        const xmlSecByte expected[] = { 0x05, 0x04, 0x03, 0x02, 0x01 };
        ret = xmlSecBufferSetData(&buf, odd, sizeof(odd));
        if(ret < 0) { testLog("Error: SetData(odd) failed\n"); goto done; }
        ret = xmlSecBufferReverse(&buf);
        if(ret < 0) { testLog("Error: Reverse(odd) failed\n"); goto done; }
        if(memcmp(xmlSecBufferGetData(&buf), expected, sizeof(expected)) != 0) {
            testLog("Error: data mismatch after reversing odd-length buffer\n");
            goto done;
        }
    }

    /* reversing twice must produce the original */
    {
        const xmlSecByte orig[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        ret = xmlSecBufferSetData(&buf, orig, sizeof(orig));
        if(ret < 0) { testLog("Error: SetData(double-reverse) failed\n"); goto done; }
        ret = xmlSecBufferReverse(&buf);
        if(ret < 0) { testLog("Error: first Reverse(double-reverse) failed\n"); goto done; }
        ret = xmlSecBufferReverse(&buf);
        if(ret < 0) { testLog("Error: second Reverse(double-reverse) failed\n"); goto done; }
        if(memcmp(xmlSecBufferGetData(&buf), orig, sizeof(orig)) != 0) {
            testLog("Error: double-reverse did not restore original data\n");
            goto done;
        }
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

/* ------------------------------------------------------------------ */
/* xmlSecBufferHexRead tests                                           */
/* ------------------------------------------------------------------ */

static void
test_buffer_hex_read_success(
    const char* name,
    const xmlChar* hexStr,
    const xmlSecByte* expectedBytes,
    xmlSecSize expectedLen
) {
    xmlSecBuffer buf;
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart(name);

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferHexRead(&buf, hexStr);
    if(ret < 0) {
        testLog("Error: xmlSecBufferHexRead('%s') failed unexpectedly\n", (const char*)hexStr);
        goto done;
    }

    if(xmlSecBufferGetSize(&buf) != expectedLen) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " expected=" XMLSEC_SIZE_FMT "\n",
            xmlSecBufferGetSize(&buf), expectedLen);
        goto done;
    }

    if(expectedLen > 0) {
        if(memcmp(xmlSecBufferGetData(&buf), expectedBytes, expectedLen) != 0) {
            testLog("Error: decoded bytes do not match expected\n");
            goto done;
        }
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
    return;

done:
    xmlSecBufferFinalize(&buf);
    testFinishedFailure();
}

static void
test_buffer_hex_read_failure(
    const char* name,
    const xmlChar* hexStr
) {
    xmlSecBuffer buf;
    int ret;

    memset(&buf, 0, sizeof(buf));

    testStart(name);

    ret = xmlSecBufferInitialize(&buf, 0);
    if(ret < 0) {
        testLog("Error: xmlSecBufferInitialize failed\n");
        testFinishedFailure();
        return;
    }

    ret = xmlSecBufferHexRead(&buf, hexStr);
    if(ret >= 0) {
        testLog("Error: xmlSecBufferHexRead('%s') succeeded but should have failed\n",
            (const char*)hexStr);
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    /* a failed decode must leave the buffer empty (src/buffer.c guarantees this) */
    if(!xmlSecBufferIsEmpty(&buf)) {
        testLog("Error: buffer is not empty after a failed hex read "
            "(size=" XMLSEC_SIZE_FMT ")\n", xmlSecBufferGetSize(&buf));
        xmlSecBufferFinalize(&buf);
        testFinishedFailure();
        return;
    }

    xmlSecBufferFinalize(&buf);
    testFinishedSuccess();
}

static void
test_buffer_hex_read(void) {
    /* empty string -> zero bytes */
    test_buffer_hex_read_success(
        "xmlSecBufferHexRead - empty string",
        BAD_CAST "",
        NULL, 0);

    /* single byte */
    {
        const xmlSecByte expected[] = { 0xAB };
        test_buffer_hex_read_success(
            "xmlSecBufferHexRead - single byte 'ab'",
            BAD_CAST "ab",
            expected, sizeof(expected));
    }

    /* uppercase hex */
    {
        const xmlSecByte expected[] = { 0xAB };
        test_buffer_hex_read_success(
            "xmlSecBufferHexRead - single byte 'AB' (uppercase)",
            BAD_CAST "AB",
            expected, sizeof(expected));
    }

    /* mixed case */
    {
        const xmlSecByte expected[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        test_buffer_hex_read_success(
            "xmlSecBufferHexRead - 'DeAdBeEf' mixed case",
            BAD_CAST "DeAdBeEf",
            expected, sizeof(expected));
    }

    /* longer sequence */
    {
        const xmlSecByte expected[] = { 0x00, 0x01, 0x7F, 0x80, 0xFF };
        test_buffer_hex_read_success(
            "xmlSecBufferHexRead - '00017f80ff'",
            BAD_CAST "00017f80ff",
            expected, sizeof(expected));
    }

    /* odd number of hex digits -> must fail */
    test_buffer_hex_read_failure(
        "xmlSecBufferHexRead - odd length 'abc' must fail",
        BAD_CAST "abc");

    /* invalid character -> must fail */
    test_buffer_hex_read_failure(
        "xmlSecBufferHexRead - invalid char 'GG' must fail",
        BAD_CAST "GG");

    /* invalid character in second nibble -> must fail */
    test_buffer_hex_read_failure(
        "xmlSecBufferHexRead - invalid second nibble '0Z' must fail",
        BAD_CAST "0Z");
}

/* ------------------------------------------------------------------ */
/* xmlSecBuffer grow / realloc path test                               */
/* ------------------------------------------------------------------ */

static void
test_buffer_grow_beyond_initial_allocation(void) {
    xmlSecBufferPtr buf = NULL;
    const xmlSecByte head[] = { 'A', 'B', 'C', 'D', 'E', 'F' };
    xmlSecSize headLen = sizeof(head);
    xmlSecSize bigLen = 2048;
    xmlSecByte* big = NULL;
    xmlSecSize ii;

    testStart("xmlSecBufferAppend - grow beyond initial allocation (realloc path)");
    test_buffer_reset_default_alloc_mode();

    buf = xmlSecBufferCreate(0);
    if(buf == NULL) {
        testLog("Error: xmlSecBufferCreate(0) failed\n");
        goto done;
    }

    /* first append allocates the buffer (data was NULL -> xmlMalloc path) */
    if(xmlSecBufferAppend(buf, head, headLen) < 0) {
        testLog("Error: initial xmlSecBufferAppend failed\n");
        goto done;
    }

    /* build a payload large enough to force a regrowth (xmlRealloc path) */
    big = (xmlSecByte*)malloc(bigLen);
    if(big == NULL) {
        testLog("Error: malloc for grow payload failed\n");
        goto done;
    }
    for(ii = 0; ii < bigLen; ++ii) {
        big[ii] = (xmlSecByte)(ii & 0xFF);
    }

    if(xmlSecBufferAppend(buf, big, bigLen) < 0) {
        testLog("Error: xmlSecBufferAppend (grow) failed\n");
        goto done;
    }

    /* total size must be head + big */
    if(xmlSecBufferGetSize(buf) != (headLen + bigLen)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " expected " XMLSEC_SIZE_FMT "\n",
            xmlSecBufferGetSize(buf), headLen + bigLen);
        goto done;
    }

    /* the pre-existing head bytes must be preserved across the regrowth */
    if(memcmp(xmlSecBufferGetData(buf), head, headLen) != 0) {
        testLog("Error: head bytes were not preserved after regrowth\n");
        goto done;
    }

    /* and the appended payload must be intact */
    if(memcmp(xmlSecBufferGetData(buf) + headLen, big, bigLen) != 0) {
        testLog("Error: appended payload does not match after regrowth\n");
        goto done;
    }

    free(big);
    big = NULL;
    xmlSecBufferDestroy(buf);
    buf = NULL;
    testFinishedSuccess();
    return;

done:
    if(big != NULL) {
        free(big);
    }
    if(buf != NULL) {
        xmlSecBufferDestroy(buf);
    }
    testFinishedFailure();
}

/* ------------------------------------------------------------------ */
/* xmlSecMemEqual / xmlSecMemCleanse tests                             */
/* ------------------------------------------------------------------ */

static void
test_buffer_mem_equal(void) {
    const xmlSecByte a[] = { 0x00, 0x11, 0x22, 0x33, 0xFF };
    const xmlSecByte b[] = { 0x00, 0x11, 0x22, 0x33, 0xFF };
    const xmlSecByte c[] = { 0x00, 0x11, 0x22, 0x34, 0xFF };

    testStart("xmlSecMemEqual");

    /* identical buffers -> equal */
    if(xmlSecMemEqual(a, b, sizeof(a)) != 1) {
        testLog("Error: xmlSecMemEqual should report equal buffers as equal\n");
        testFinishedFailure();
        return;
    }

    /* differing buffers -> not equal */
    if(xmlSecMemEqual(a, c, sizeof(a)) != 0) {
        testLog("Error: xmlSecMemEqual should report differing buffers as not equal\n");
        testFinishedFailure();
        return;
    }

    /* zero length -> trivially equal */
    if(xmlSecMemEqual(a, c, 0) != 1) {
        testLog("Error: xmlSecMemEqual with size 0 should return 1\n");
        testFinishedFailure();
        return;
    }

    testFinishedSuccess();
}

static void
test_buffer_mem_cleanse(void) {
    unsigned char block[16];
    size_t ii;
    int allZero;

    testStart("xmlSecMemCleanse");

    /* NULL / zero-size calls must be safe no-ops */
    xmlSecMemCleanse(NULL, 0);
    xmlSecMemCleanse(block, 0);

    /* fill with a non-zero pattern, then wipe and verify all bytes are zero */
    for(ii = 0; ii < sizeof(block); ++ii) {
        block[ii] = (unsigned char)(0xA5 + ii);
    }

    xmlSecMemCleanse(block, sizeof(block));

    allZero = 1;
    for(ii = 0; ii < sizeof(block); ++ii) {
        if(block[ii] != 0) {
            allZero = 0;
            break;
        }
    }
    if(!allZero) {
        testLog("Error: xmlSecMemCleanse did not zero the memory block\n");
        testFinishedFailure();
        return;
    }

    testFinishedSuccess();
}

/* ------------------------------------------------------------------ */
/* xmlSecBufferReadFile / xmlSecBufferDebugHexDump tests               */
/* ------------------------------------------------------------------ */

static void
test_buffer_read_file(void) {
    xmlSecBufferPtr buf = NULL;
    char tmpName[160] = { '\0' };
    const xmlSecByte payload[] = { 0x00, 0x01, 0x02, 0xAB, 0xCD, 0xEF, 0xFF };
    FILE* f = NULL;
    int fileCreated = 0;

    testStart("xmlSecBufferReadFile");
    test_buffer_reset_default_alloc_mode();

    if(test_buffer_make_temp_name(tmpName, sizeof(tmpName), "readfile_tmp.bin") < 0) {
        testLog("Error: failed to build temp file name\n");
        testFinishedFailure();
        return;
    }

    /* write a known payload to a temp file in the current directory */
#ifndef _MSC_VER
    f = fopen(tmpName, "wb");
#else
    fopen_s(&f, tmpName, "wb");
#endif
    if(f == NULL) {
        testLog("Error: failed to create temp file '%s'\n", tmpName);
        goto done;
    }
    fileCreated = 1;
    if(fwrite(payload, 1, sizeof(payload), f) != sizeof(payload)) {
        testLog("Error: failed to write temp file payload\n");
        goto done;
    }
    fclose(f);
    f = NULL;

    buf = xmlSecBufferCreate(0);
    if(buf == NULL) {
        testLog("Error: xmlSecBufferCreate(0) failed\n");
        goto done;
    }

    if(xmlSecBufferReadFile(buf, tmpName) < 0) {
        testLog("Error: xmlSecBufferReadFile failed for an existing file\n");
        goto done;
    }

    if(xmlSecBufferGetSize(buf) != sizeof(payload)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " expected " XMLSEC_SIZE_FMT "\n",
            xmlSecBufferGetSize(buf), sizeof(payload));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(buf), payload, sizeof(payload)) != 0) {
        testLog("Error: read file content does not match the written payload\n");
        goto done;
    }

    /* a missing file must be rejected */
    if(xmlSecBufferReadFile(buf, "xmlsec_unit_tests_no_such_file_xyz.bin") >= 0) {
        testLog("Error: xmlSecBufferReadFile should fail for a missing file\n");
        goto done;
    }

    xmlSecBufferDestroy(buf);
    buf = NULL;
    if(fileCreated) {
        test_buffer_remove_temp_file(tmpName);
    }
    testFinishedSuccess();
    return;

done:
    if(f != NULL) {
        fclose(f);
    }
    if(buf != NULL) {
        xmlSecBufferDestroy(buf);
    }
    if(fileCreated) {
        test_buffer_remove_temp_file(tmpName);
    }
    testFinishedFailure();
}

static void
test_buffer_debug_hex_dump(void) {
    xmlSecBufferPtr buf = NULL;
    char tmpName[160] = { '\0' };
    const xmlSecByte data[] = { 0x00, 0x01, 0x7F, 0x80, 0xFF };
    FILE* f = NULL;
    char line[64];
    int fileCreated = 0;

    testStart("xmlSecBufferDebugHexDump");
    test_buffer_reset_default_alloc_mode();

    if(test_buffer_make_temp_name(tmpName, sizeof(tmpName), "hexdump_tmp.txt") < 0) {
        testLog("Error: failed to build temp file name\n");
        testFinishedFailure();
        return;
    }

    buf = xmlSecBufferCreate(0);
    if(buf == NULL) {
        testLog("Error: xmlSecBufferCreate(0) failed\n");
        goto done;
    }
    if(xmlSecBufferAppend(buf, data, sizeof(data)) < 0) {
        testLog("Error: xmlSecBufferAppend failed\n");
        goto done;
    }

#ifndef _MSC_VER
    f = fopen(tmpName, "w");
#else
    fopen_s(&f, tmpName, "w");
#endif
    if(f == NULL) {
        testLog("Error: failed to create hex dump temp file\n");
        goto done;
    }
    fileCreated = 1;

    xmlSecBufferDebugHexDump(buf, f);
    fclose(f);
    f = NULL;

#ifndef _MSC_VER
    f = fopen(tmpName, "r");
#else
    fopen_s(&f, tmpName, "r");
#endif
    if(f == NULL) {
        testLog("Error: failed to reopen hex dump temp file\n");
        goto done;
    }
    if(fgets(line, sizeof(line), f) == NULL) {
        testLog("Error: failed to read hex dump output\n");
        goto done;
    }
    fclose(f);
    f = NULL;

    /* 5 bytes (< 32) -> a single line of lowercase hex, no trailing newline */
    if(strcmp(line, "00017f80ff") != 0) {
        testLog("Error: hex dump output '%s' expected '00017f80ff'\n", line);
        goto done;
    }

    xmlSecBufferDestroy(buf);
    buf = NULL;
    if(fileCreated) {
        test_buffer_remove_temp_file(tmpName);
    }
    testFinishedSuccess();
    return;

done:
    if(f != NULL) {
        fclose(f);
    }
    if(buf != NULL) {
        xmlSecBufferDestroy(buf);
    }
    if(fileCreated) {
        test_buffer_remove_temp_file(tmpName);
    }
    testFinishedFailure();
}

/* ------------------------------------------------------------------ */
/* xmlSecBufferCreateOutputBuffer test                                 */
/* ------------------------------------------------------------------ */

static void
test_buffer_create_output_buffer(void) {
    xmlSecBufferPtr buf = NULL;
    xmlOutputBufferPtr out = NULL;
    const char* text = "hello output buffer";

    testStart("xmlSecBufferCreateOutputBuffer");
    test_buffer_reset_default_alloc_mode();

    /* NULL input must be rejected */
    if(xmlSecBufferCreateOutputBuffer(NULL) != NULL) {
        testLog("Error: xmlSecBufferCreateOutputBuffer(NULL) should return NULL\n");
        testFinishedFailure();
        return;
    }

    buf = xmlSecBufferCreate(0);
    if(buf == NULL) {
        testLog("Error: xmlSecBufferCreate(0) failed\n");
        goto done;
    }

    out = xmlSecBufferCreateOutputBuffer(buf);
    if(out == NULL) {
        testLog("Error: xmlSecBufferCreateOutputBuffer returned NULL\n");
        goto done;
    }

    /* writing through the libxml output buffer must land in the xmlSecBuffer */
    if(xmlOutputBufferWrite(out, (int)strlen(text), text) < 0) {
        testLog("Error: xmlOutputBufferWrite failed\n");
        goto done;
    }
    xmlOutputBufferClose(out);
    out = NULL;

    if(xmlSecBufferGetSize(buf) != strlen(text)) {
        testLog("Error: size=" XMLSEC_SIZE_FMT " expected " XMLSEC_SIZE_FMT "\n",
            xmlSecBufferGetSize(buf), strlen(text));
        goto done;
    }
    if(memcmp(xmlSecBufferGetData(buf), text, strlen(text)) != 0) {
        testLog("Error: output buffer content does not match the written text\n");
        goto done;
    }

    xmlSecBufferDestroy(buf);
    buf = NULL;
    testFinishedSuccess();
    return;

done:
    if(out != NULL) {
        xmlOutputBufferClose(out);
    }
    if(buf != NULL) {
        xmlSecBufferDestroy(buf);
    }
    testFinishedFailure();
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */

/**
 * @brief Runs all buffer unit tests.
 * @return 1 on overall success, 0 on failure.
 */
int
test_buffer(void) {
    testGroupStart("buffer");

    test_buffer_default_alloc_mode();
    test_buffer_create_destroy();
    test_buffer_create_zero_size();
    test_buffer_initialize_finalize();
    test_buffer_empty();
    test_buffer_is_empty();
    test_buffer_set_get_data();
    test_buffer_set_get_size();
    test_buffer_set_get_max_size();
    test_buffer_swap();
    test_buffer_append();
    test_buffer_prepend();
    test_buffer_remove_head();
    test_buffer_remove_tail();
    test_buffer_reverse();
    test_buffer_hex_read();
    test_buffer_grow_beyond_initial_allocation();
    test_buffer_mem_equal();
    test_buffer_mem_cleanse();
    test_buffer_read_file();
    test_buffer_debug_hex_dump();
    test_buffer_create_output_buffer();

    return testGroupFinished();
}
