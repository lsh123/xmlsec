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
#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>

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

    /* With exact mode the implementation allocates size+8 but at least
     * gInitialSize (which we set to 8 above), so maxSize must be >= 8. */
    maxSize = xmlSecBufferGetMaxSize(buf);
    if(maxSize < 8) {
        testLog("Error: maxSize=" XMLSEC_SIZE_FMT " expected >= 8\n", maxSize);
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

    /* freshly initialised buffer with no data is empty */
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

    return testGroupFinished();
}
