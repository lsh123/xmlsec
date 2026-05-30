/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief XML Security Library ptr list unit tests.
 */
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include <xmlsec/list.h>

typedef struct _xmlSecListTestItem {
    int value;
} xmlSecListTestItem;

static int g_listItemDuplicateCount = 0;
static int g_listItemDestroyCount = 0;
static int g_listItemDebugDumpCount = 0;
static int g_listItemDebugXmlDumpCount = 0;

static xmlSecListTestItem* test_list_item_create                 (int value);
static xmlSecPtr          test_list_item_duplicate              (xmlSecPtr ptr);
static void               test_list_item_destroy                (xmlSecPtr ptr);
static void               test_list_item_debug_dump             (xmlSecPtr ptr,
                                                                 FILE* output);
static void               test_list_item_debug_xml_dump         (xmlSecPtr ptr,
                                                                 FILE* output);
static void               test_list_item_reset_counters         (void);
static int                test_list_output_read                 (FILE* output,
                                                                 char* buffer,
                                                                 size_t bufferSize);
static void               test_list_reset_default_alloc_mode    (void);

static void               test_ptr_list_default_alloc_mode      (void);
static void               test_ptr_list_initialize_finalize     (void);
static void               test_ptr_list_empty                   (void);
static void               test_ptr_list_insert                  (void);
static void               test_ptr_list_set                     (void);
static void               test_ptr_list_remove                  (void);
static void               test_ptr_list_remove_and_return       (void);
static void               test_ptr_list_pop_last                (void);
static void               test_ptr_list_copy_duplicate          (void);
static void               test_ptr_list_debug_dump              (void);
static void               test_string_list_klass                (void);

static xmlSecPtrListKlass g_xmlSecListTestKlass = {
    BAD_CAST "test-list",
    test_list_item_duplicate,
    test_list_item_destroy,
    test_list_item_debug_dump,
    test_list_item_debug_xml_dump,
};

static xmlSecPtrListKlass g_xmlSecListShallowKlass = {
    BAD_CAST "test-list-shallow",
    NULL,
    NULL,
    NULL,
    NULL,
};

static xmlSecListTestItem*
test_list_item_create(int value) {
    xmlSecListTestItem* item;

    item = (xmlSecListTestItem*)xmlMalloc(sizeof(xmlSecListTestItem));
    if(item == NULL) {
        return(NULL);
    }

    item->value = value;
    return(item);
}

static xmlSecPtr
test_list_item_duplicate(xmlSecPtr ptr) {
    xmlSecListTestItem* item;
    xmlSecListTestItem* copy;

    if(ptr == NULL) {
        return(NULL);
    }

    item = (xmlSecListTestItem*)ptr;
    copy = test_list_item_create(item->value);
    if(copy != NULL) {
        ++g_listItemDuplicateCount;
    }
    return(copy);
}

static void
test_list_item_destroy(xmlSecPtr ptr) {
    if(ptr == NULL) {
        return;
    }

    ++g_listItemDestroyCount;
    xmlFree(ptr);
}

static void
test_list_item_debug_dump(xmlSecPtr ptr, FILE* output) {
    xmlSecListTestItem* item;

    if((ptr == NULL) || (output == NULL)) {
        return;
    }

    item = (xmlSecListTestItem*)ptr;
    ++g_listItemDebugDumpCount;
    fprintf(output, "item=%d\n", item->value);
}

static void
test_list_item_debug_xml_dump(xmlSecPtr ptr, FILE* output) {
    xmlSecListTestItem* item;

    if((ptr == NULL) || (output == NULL)) {
        return;
    }

    item = (xmlSecListTestItem*)ptr;
    ++g_listItemDebugXmlDumpCount;
    fprintf(output, "<Item value=\"%d\"/>\n", item->value);
}

static void
test_list_item_reset_counters(void) {
    g_listItemDuplicateCount = 0;
    g_listItemDestroyCount = 0;
    g_listItemDebugDumpCount = 0;
    g_listItemDebugXmlDumpCount = 0;
}

static int
test_list_output_read(FILE* output, char* buffer, size_t bufferSize) {
    size_t readSize;

    if((output == NULL) || (buffer == NULL) || (bufferSize < 2)) {
        return(-1);
    }

    if(fflush(output) != 0) {
        return(-1);
    }
    if(fseek(output, 0, SEEK_SET) != 0) {
        return(-1);
    }

    readSize = fread(buffer, 1, bufferSize - 1, output);
    if(ferror(output)) {
        return(-1);
    }

    buffer[readSize] = '\0';
    return(0);
}

static void
test_list_reset_default_alloc_mode(void) {
    xmlSecPtrListSetDefaultAllocMode(xmlSecAllocModeDouble, 64);
}

static void
test_ptr_list_default_alloc_mode(void) {
    xmlSecPtrListPtr list = NULL;
    xmlSecListTestItem* item = NULL;

    testStart("xmlSecPtrListSetDefaultAllocMode/xmlSecPtrListCreate/xmlSecPtrListDestroy");
    test_list_item_reset_counters();
    test_list_reset_default_alloc_mode();
    xmlSecPtrListSetDefaultAllocMode(xmlSecAllocModeExact, 128);

    list = xmlSecPtrListCreate(&g_xmlSecListTestKlass);
    if(list == NULL) {
        testLog("Error: xmlSecPtrListCreate failed\n");
        goto done;
    }
    if(list->allocMode != xmlSecAllocModeExact) {
        testLog("Error: unexpected alloc mode, got=%d expected=%d\n",
            (int)list->allocMode, (int)xmlSecAllocModeExact);
        goto done;
    }
    if(xmlSecPtrListGetSize(list) != 0) {
        testLog("Error: new list is not empty\n");
        goto done;
    }

    item = test_list_item_create(10);
    if(item == NULL) {
        testLog("Error: failed to create test item\n");
        goto done;
    }
    if(xmlSecPtrListAdd(list, item) < 0) {
        testLog("Error: xmlSecPtrListAdd failed\n");
        goto done;
    }
    item = NULL;

    if(list->max < 128) {
        testLog("Error: list capacity is too small, got=" XMLSEC_SIZE_FMT "\n", list->max);
        goto done;
    }

    xmlSecPtrListDestroy(list);
    list = NULL;
    test_list_reset_default_alloc_mode();
    testFinishedSuccess();
    return;

done:
    if(item != NULL) {
        test_list_item_destroy(item);
    }
    if(list != NULL) {
        xmlSecPtrListDestroy(list);
    }
    test_list_reset_default_alloc_mode();
    testFinishedFailure();
}

static void
test_ptr_list_initialize_finalize(void) {
    xmlSecPtrList list;
    xmlSecListTestItem* item1 = NULL;
    xmlSecListTestItem* item2 = NULL;
    int ret;

    memset(&list, 0, sizeof(list));

    testStart("xmlSecPtrListInitialize/xmlSecPtrListFinalize/xmlSecPtrListAdd/xmlSecPtrListGetSize/xmlSecPtrListGetItem");
    test_list_item_reset_counters();

    ret = xmlSecPtrListInitialize(&list, &g_xmlSecListTestKlass);
    if(ret < 0) {
        testLog("Error: xmlSecPtrListInitialize failed\n");
        goto done;
    }
    if(list.id != &g_xmlSecListTestKlass) {
        testLog("Error: xmlSecPtrListInitialize set unexpected klass\n");
        goto done;
    }

    item1 = test_list_item_create(11);
    item2 = test_list_item_create(22);
    if((item1 == NULL) || (item2 == NULL)) {
        testLog("Error: failed to create test items\n");
        goto done;
    }
    if(xmlSecPtrListAdd(&list, item1) < 0) {
        testLog("Error: xmlSecPtrListAdd failed for item1\n");
        goto done;
    }
    item1 = NULL;
    if(xmlSecPtrListAdd(&list, item2) < 0) {
        testLog("Error: xmlSecPtrListAdd failed for item2\n");
        goto done;
    }
    item2 = NULL;

    if(xmlSecPtrListGetSize(&list) != 2) {
        testLog("Error: unexpected list size, got=" XMLSEC_SIZE_FMT " expected=2\n", xmlSecPtrListGetSize(&list));
        goto done;
    }
    if(((xmlSecListTestItem*)xmlSecPtrListGetItem(&list, 0))->value != 11) {
        testLog("Error: xmlSecPtrListGetItem returned unexpected first item\n");
        goto done;
    }
    if(((xmlSecListTestItem*)xmlSecPtrListGetItem(&list, 1))->value != 22) {
        testLog("Error: xmlSecPtrListGetItem returned unexpected second item\n");
        goto done;
    }

    xmlSecPtrListFinalize(&list);
    if((list.id != NULL) || (list.data != NULL) || (list.use != 0) || (list.max != 0)) {
        testLog("Error: xmlSecPtrListFinalize did not reset list state\n");
        goto done_after_finalize;
    }

    testFinishedSuccess();
    return;

done:
    if(item1 != NULL) {
        test_list_item_destroy(item1);
    }
    if(item2 != NULL) {
        test_list_item_destroy(item2);
    }
    if(xmlSecPtrListIsValid(&list)) {
        xmlSecPtrListFinalize(&list);
    }
done_after_finalize:
    testFinishedFailure();
}

static void
test_ptr_list_empty(void) {
    xmlSecPtrList list;
    xmlSecListTestItem* item1 = NULL;
    xmlSecListTestItem* item2 = NULL;

    memset(&list, 0, sizeof(list));

    testStart("xmlSecPtrListEmpty");
    test_list_item_reset_counters();

    if(xmlSecPtrListInitialize(&list, &g_xmlSecListTestKlass) < 0) {
        testLog("Error: xmlSecPtrListInitialize failed\n");
        goto done;
    }

    item1 = test_list_item_create(1);
    item2 = test_list_item_create(2);
    if((item1 == NULL) || (item2 == NULL)) {
        testLog("Error: failed to create test items\n");
        goto done;
    }
    if(xmlSecPtrListAdd(&list, item1) < 0) {
        testLog("Error: xmlSecPtrListAdd failed for item1\n");
        goto done;
    }
    item1 = NULL;
    if(xmlSecPtrListAdd(&list, item2) < 0) {
        testLog("Error: xmlSecPtrListAdd failed for item2\n");
        goto done;
    }
    item2 = NULL;

    xmlSecPtrListEmpty(&list);
    if((list.use != 0) || (list.max != 0) || (list.data != NULL)) {
        testLog("Error: xmlSecPtrListEmpty did not reset list storage\n");
        goto done;
    }
    if(g_listItemDestroyCount != 2) {
        testLog("Error: xmlSecPtrListEmpty destroyed %d items instead of 2\n", g_listItemDestroyCount);
        goto done;
    }

    xmlSecPtrListFinalize(&list);
    testFinishedSuccess();
    return;

done:
    if(item1 != NULL) {
        test_list_item_destroy(item1);
    }
    if(item2 != NULL) {
        test_list_item_destroy(item2);
    }
    if(xmlSecPtrListIsValid(&list)) {
        xmlSecPtrListFinalize(&list);
    }
    testFinishedFailure();
}

static void
test_ptr_list_insert(void) {
    xmlSecPtrList list;
    int value1 = 1;
    int value2 = 2;
    int value3 = 3;
    int value4 = 4;

    memset(&list, 0, sizeof(list));

    testStart("xmlSecPtrListInsert");

    if(xmlSecPtrListInitialize(&list, &g_xmlSecListShallowKlass) < 0) {
        testLog("Error: xmlSecPtrListInitialize failed\n");
        goto done;
    }
    if(xmlSecPtrListAdd(&list, &value1) < 0) {
        testLog("Error: xmlSecPtrListAdd failed for value1\n");
        goto done;
    }
    if(xmlSecPtrListAdd(&list, &value3) < 0) {
        testLog("Error: xmlSecPtrListAdd failed for value3\n");
        goto done;
    }
    if(xmlSecPtrListInsert(&list, &value2, 1) < 0) {
        testLog("Error: xmlSecPtrListInsert failed for middle insert\n");
        goto done;
    }
    if(xmlSecPtrListInsert(&list, &value4, 32) < 0) {
        testLog("Error: xmlSecPtrListInsert failed for append insert\n");
        goto done;
    }

    if((xmlSecPtrListGetSize(&list) != 4) ||
       (xmlSecPtrListGetItem(&list, 0) != &value1) ||
       (xmlSecPtrListGetItem(&list, 1) != &value2) ||
       (xmlSecPtrListGetItem(&list, 2) != &value3) ||
       (xmlSecPtrListGetItem(&list, 3) != &value4)) {
        testLog("Error: xmlSecPtrListInsert produced unexpected item order\n");
        goto done;
    }

    xmlSecPtrListFinalize(&list);
    testFinishedSuccess();
    return;

done:
    if(xmlSecPtrListIsValid(&list)) {
        xmlSecPtrListFinalize(&list);
    }
    testFinishedFailure();
}

static void
test_ptr_list_set(void) {
    xmlSecPtrList list;
    xmlSecListTestItem* item1 = NULL;
    xmlSecListTestItem* item2 = NULL;
    xmlSecListTestItem* item3 = NULL;

    memset(&list, 0, sizeof(list));

    testStart("xmlSecPtrListSet");
    test_list_item_reset_counters();

    if(xmlSecPtrListInitialize(&list, &g_xmlSecListTestKlass) < 0) {
        testLog("Error: xmlSecPtrListInitialize failed\n");
        goto done;
    }

    item1 = test_list_item_create(1);
    item2 = test_list_item_create(2);
    item3 = test_list_item_create(3);
    if((item1 == NULL) || (item2 == NULL) || (item3 == NULL)) {
        testLog("Error: failed to create test items\n");
        goto done;
    }
    if((xmlSecPtrListAdd(&list, item1) < 0) || (xmlSecPtrListAdd(&list, item2) < 0)) {
        testLog("Error: xmlSecPtrListAdd failed\n");
        goto done;
    }
    item1 = NULL;
    item2 = NULL;

    if(xmlSecPtrListSet(&list, item3, 1) < 0) {
        testLog("Error: xmlSecPtrListSet failed\n");
        goto done;
    }
    item3 = NULL;

    if(g_listItemDestroyCount != 1) {
        testLog("Error: xmlSecPtrListSet destroyed %d items instead of 1\n", g_listItemDestroyCount);
        goto done;
    }
    if(((xmlSecListTestItem*)xmlSecPtrListGetItem(&list, 1))->value != 3) {
        testLog("Error: xmlSecPtrListSet did not replace the target item\n");
        goto done;
    }

    xmlSecPtrListFinalize(&list);
    testFinishedSuccess();
    return;

done:
    if(item1 != NULL) {
        test_list_item_destroy(item1);
    }
    if(item2 != NULL) {
        test_list_item_destroy(item2);
    }
    if(item3 != NULL) {
        test_list_item_destroy(item3);
    }
    if(xmlSecPtrListIsValid(&list)) {
        xmlSecPtrListFinalize(&list);
    }
    testFinishedFailure();
}

static void
test_ptr_list_remove(void) {
    xmlSecPtrList list;
    xmlSecListTestItem* item1 = NULL;
    xmlSecListTestItem* item2 = NULL;
    xmlSecListTestItem* item3 = NULL;
    xmlSecListTestItem* remaining = NULL;

    memset(&list, 0, sizeof(list));

    testStart("xmlSecPtrListRemove");
    test_list_item_reset_counters();

    if(xmlSecPtrListInitialize(&list, &g_xmlSecListTestKlass) < 0) {
        testLog("Error: xmlSecPtrListInitialize failed\n");
        goto done;
    }

    item1 = test_list_item_create(1);
    item2 = test_list_item_create(2);
    item3 = test_list_item_create(3);
    if((item1 == NULL) || (item2 == NULL) || (item3 == NULL)) {
        testLog("Error: failed to create test items\n");
        goto done;
    }
    if((xmlSecPtrListAdd(&list, item1) < 0) ||
       (xmlSecPtrListAdd(&list, item2) < 0) ||
       (xmlSecPtrListAdd(&list, item3) < 0)) {
        testLog("Error: xmlSecPtrListAdd failed\n");
        goto done;
    }
    item1 = NULL;
    item2 = NULL;
    item3 = NULL;

    if(xmlSecPtrListRemove(&list, 1) < 0) {
        testLog("Error: xmlSecPtrListRemove failed for middle item\n");
        goto done;
    }
    remaining = (xmlSecListTestItem*)xmlSecPtrListGetItem(&list, 1);
    if((g_listItemDestroyCount != 1) || (xmlSecPtrListGetSize(&list) != 2) ||
       (remaining == NULL) || (remaining->value != 3)) {
        testLog("Error: xmlSecPtrListRemove did not shift remaining items as expected\n");
        goto done;
    }

    if(xmlSecPtrListRemove(&list, 1) < 0) {
        testLog("Error: xmlSecPtrListRemove failed for last item\n");
        goto done;
    }
    remaining = (xmlSecListTestItem*)xmlSecPtrListGetItem(&list, 0);
    if((g_listItemDestroyCount != 2) || (xmlSecPtrListGetSize(&list) != 1) ||
       (remaining == NULL) || (remaining->value != 1)) {
        testLog("Error: xmlSecPtrListRemove did not update trailing item state\n");
        goto done;
    }

    xmlSecPtrListFinalize(&list);
    testFinishedSuccess();
    return;

done:
    if(item1 != NULL) {
        test_list_item_destroy(item1);
    }
    if(item2 != NULL) {
        test_list_item_destroy(item2);
    }
    if(item3 != NULL) {
        test_list_item_destroy(item3);
    }
    if(xmlSecPtrListIsValid(&list)) {
        xmlSecPtrListFinalize(&list);
    }
    testFinishedFailure();
}

static void
test_ptr_list_remove_and_return(void) {
    xmlSecPtrList list;
    xmlSecListTestItem* item1 = NULL;
    xmlSecListTestItem* item2 = NULL;
    xmlSecListTestItem* item3 = NULL;
    xmlSecListTestItem* removed = NULL;
    xmlSecListTestItem* remaining = NULL;

    memset(&list, 0, sizeof(list));

    testStart("xmlSecPtrListRemoveAndReturn");
    test_list_item_reset_counters();

    if(xmlSecPtrListInitialize(&list, &g_xmlSecListTestKlass) < 0) {
        testLog("Error: xmlSecPtrListInitialize failed\n");
        goto done;
    }

    item1 = test_list_item_create(7);
    item2 = test_list_item_create(8);
    item3 = test_list_item_create(9);
    if((item1 == NULL) || (item2 == NULL) || (item3 == NULL)) {
        testLog("Error: failed to create test items\n");
        goto done;
    }
    if((xmlSecPtrListAdd(&list, item1) < 0) ||
       (xmlSecPtrListAdd(&list, item2) < 0) ||
       (xmlSecPtrListAdd(&list, item3) < 0)) {
        testLog("Error: xmlSecPtrListAdd failed\n");
        goto done;
    }
    item1 = NULL;
    item2 = NULL;
    item3 = NULL;

    removed = (xmlSecListTestItem*)xmlSecPtrListRemoveAndReturn(&list, 1);
    if((removed == NULL) || (removed->value != 8)) {
        testLog("Error: xmlSecPtrListRemoveAndReturn returned unexpected item\n");
        goto done;
    }
    remaining = (xmlSecListTestItem*)xmlSecPtrListGetItem(&list, 1);
    if((g_listItemDestroyCount != 0) || (xmlSecPtrListGetSize(&list) != 2) ||
       (remaining == NULL) || (remaining->value != 9)) {
        testLog("Error: xmlSecPtrListRemoveAndReturn changed list state unexpectedly\n");
        goto done;
    }

    test_list_item_destroy(removed);
    removed = NULL;

    xmlSecPtrListFinalize(&list);
    testFinishedSuccess();
    return;

done:
    if(item1 != NULL) {
        test_list_item_destroy(item1);
    }
    if(item2 != NULL) {
        test_list_item_destroy(item2);
    }
    if(item3 != NULL) {
        test_list_item_destroy(item3);
    }
    if(removed != NULL) {
        test_list_item_destroy(removed);
    }
    if(xmlSecPtrListIsValid(&list)) {
        xmlSecPtrListFinalize(&list);
    }
    testFinishedFailure();
}

static void
test_ptr_list_pop_last(void) {
    xmlSecPtrList list;
    xmlSecListTestItem* item1 = NULL;
    xmlSecListTestItem* item2 = NULL;
    xmlSecListTestItem* popped = NULL;

    memset(&list, 0, sizeof(list));

    testStart("xmlSecPtrListPopLast");
    test_list_item_reset_counters();

    if(xmlSecPtrListInitialize(&list, &g_xmlSecListTestKlass) < 0) {
        testLog("Error: xmlSecPtrListInitialize failed\n");
        goto done;
    }
    if(xmlSecPtrListPopLast(&list) != NULL) {
        testLog("Error: xmlSecPtrListPopLast should return NULL for an empty list\n");
        goto done;
    }

    item1 = test_list_item_create(10);
    item2 = test_list_item_create(20);
    if((item1 == NULL) || (item2 == NULL)) {
        testLog("Error: failed to create test items\n");
        goto done;
    }
    if((xmlSecPtrListAdd(&list, item1) < 0) || (xmlSecPtrListAdd(&list, item2) < 0)) {
        testLog("Error: xmlSecPtrListAdd failed\n");
        goto done;
    }
    item1 = NULL;
    item2 = NULL;

    popped = (xmlSecListTestItem*)xmlSecPtrListPopLast(&list);
    if((popped == NULL) || (popped->value != 20)) {
        testLog("Error: xmlSecPtrListPopLast returned unexpected item\n");
        goto done;
    }
    if((g_listItemDestroyCount != 0) || (xmlSecPtrListGetSize(&list) != 1)) {
        testLog("Error: xmlSecPtrListPopLast changed list state unexpectedly\n");
        goto done;
    }

    test_list_item_destroy(popped);
    popped = NULL;

    xmlSecPtrListFinalize(&list);
    testFinishedSuccess();
    return;

done:
    if(item1 != NULL) {
        test_list_item_destroy(item1);
    }
    if(item2 != NULL) {
        test_list_item_destroy(item2);
    }
    if(popped != NULL) {
        test_list_item_destroy(popped);
    }
    if(xmlSecPtrListIsValid(&list)) {
        xmlSecPtrListFinalize(&list);
    }
    testFinishedFailure();
}

static void
test_ptr_list_copy_duplicate(void) {
    xmlSecPtrList src;
    xmlSecPtrList dst;
    xmlSecPtrListPtr dup = NULL;
    xmlSecListTestItem* item1 = NULL;
    xmlSecListTestItem* item2 = NULL;
    xmlSecListTestItem* dstItem1;
    xmlSecListTestItem* dupItem1;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    testStart("xmlSecPtrListCopy/xmlSecPtrListDuplicate");
    test_list_item_reset_counters();

    if((xmlSecPtrListInitialize(&src, &g_xmlSecListTestKlass) < 0) ||
       (xmlSecPtrListInitialize(&dst, &g_xmlSecListTestKlass) < 0)) {
        testLog("Error: xmlSecPtrListInitialize failed\n");
        goto done;
    }

    item1 = test_list_item_create(100);
    item2 = test_list_item_create(200);
    if((item1 == NULL) || (item2 == NULL)) {
        testLog("Error: failed to create test items\n");
        goto done;
    }
    if((xmlSecPtrListAdd(&src, item1) < 0) || (xmlSecPtrListAdd(&src, item2) < 0)) {
        testLog("Error: xmlSecPtrListAdd failed\n");
        goto done;
    }
    item1 = NULL;
    item2 = NULL;

    if(xmlSecPtrListCopy(&dst, &src) < 0) {
        testLog("Error: xmlSecPtrListCopy failed\n");
        goto done;
    }
    if((g_listItemDuplicateCount != 2) || (xmlSecPtrListGetSize(&dst) != 2)) {
        testLog("Error: xmlSecPtrListCopy did not duplicate all source items\n");
        goto done;
    }
    dstItem1 = (xmlSecListTestItem*)xmlSecPtrListGetItem(&dst, 0);
    if((dstItem1 == NULL) || (dstItem1 == xmlSecPtrListGetItem(&src, 0)) || (dstItem1->value != 100)) {
        testLog("Error: xmlSecPtrListCopy produced unexpected destination items\n");
        goto done;
    }

    dup = xmlSecPtrListDuplicate(&src);
    if(dup == NULL) {
        testLog("Error: xmlSecPtrListDuplicate failed\n");
        goto done;
    }
    if((g_listItemDuplicateCount != 4) || (xmlSecPtrListGetSize(dup) != 2)) {
        testLog("Error: xmlSecPtrListDuplicate did not duplicate all source items\n");
        goto done;
    }
    dupItem1 = (xmlSecListTestItem*)xmlSecPtrListGetItem(dup, 0);
    if((dupItem1 == NULL) || (dupItem1 == xmlSecPtrListGetItem(&src, 0)) || (dupItem1->value != 100)) {
        testLog("Error: xmlSecPtrListDuplicate produced unexpected duplicate items\n");
        goto done;
    }

    xmlSecPtrListDestroy(dup);
    dup = NULL;
    xmlSecPtrListFinalize(&dst);
    xmlSecPtrListFinalize(&src);
    testFinishedSuccess();
    return;

done:
    if(item1 != NULL) {
        test_list_item_destroy(item1);
    }
    if(item2 != NULL) {
        test_list_item_destroy(item2);
    }
    if(dup != NULL) {
        xmlSecPtrListDestroy(dup);
    }
    if(xmlSecPtrListIsValid(&dst)) {
        xmlSecPtrListFinalize(&dst);
    }
    if(xmlSecPtrListIsValid(&src)) {
        xmlSecPtrListFinalize(&src);
    }
    testFinishedFailure();
}

static void
test_string_list_klass(void) {
    xmlSecPtrListPtr list = NULL;
    xmlSecPtrListPtr duplicate = NULL;
    xmlChar* item1 = NULL;
    xmlChar* item2 = NULL;
    xmlChar* duplicateItem1;

    testStart("xmlSecStringListGetKlass");
    test_list_reset_default_alloc_mode();

    if(xmlStrcmp(xmlSecPtrListKlassGetName(xmlSecStringListGetKlass()), BAD_CAST "strings-list") != 0) {
        testLog("Error: xmlSecStringListGetKlass returned unexpected klass name\n");
        goto done;
    }

    list = xmlSecPtrListCreate(xmlSecStringListGetKlass());
    if(list == NULL) {
        testLog("Error: xmlSecPtrListCreate failed for string list\n");
        goto done;
    }

    item1 = xmlStrdup(BAD_CAST "alpha");
    item2 = xmlStrdup(BAD_CAST "beta");
    if((item1 == NULL) || (item2 == NULL)) {
        testLog("Error: failed to allocate string list items\n");
        goto done;
    }
    if((xmlSecPtrListAdd(list, item1) < 0) || (xmlSecPtrListAdd(list, item2) < 0)) {
        testLog("Error: xmlSecPtrListAdd failed for string list\n");
        goto done;
    }
    item1 = NULL;
    item2 = NULL;

    duplicate = xmlSecPtrListDuplicate(list);
    if(duplicate == NULL) {
        testLog("Error: xmlSecPtrListDuplicate failed for string list\n");
        goto done;
    }
    if(xmlSecPtrListGetSize(duplicate) != 2) {
        testLog("Error: duplicated string list has unexpected size\n");
        goto done;
    }

    duplicateItem1 = (xmlChar*)xmlSecPtrListGetItem(duplicate, 0);
    if((duplicateItem1 == NULL) ||
       (duplicateItem1 == xmlSecPtrListGetItem(list, 0)) ||
       (xmlStrcmp(duplicateItem1, BAD_CAST "alpha") != 0)) {
        testLog("Error: duplicated string list item is invalid\n");
        goto done;
    }

    xmlSecPtrListDestroy(duplicate);
    duplicate = NULL;
    xmlSecPtrListDestroy(list);
    list = NULL;
    testFinishedSuccess();
    return;

done:
    if(item1 != NULL) {
        xmlFree(item1);
    }
    if(item2 != NULL) {
        xmlFree(item2);
    }
    if(duplicate != NULL) {
        xmlSecPtrListDestroy(duplicate);
    }
    if(list != NULL) {
        xmlSecPtrListDestroy(list);
    }
    testFinishedFailure();
}

int test_list(void) {
    testGroupStart("list");

    test_ptr_list_default_alloc_mode();
    test_ptr_list_initialize_finalize();
    test_ptr_list_empty();
    test_ptr_list_insert();
    test_ptr_list_set();
    test_ptr_list_remove();
    test_ptr_list_remove_and_return();
    test_ptr_list_pop_last();
    test_ptr_list_copy_duplicate();
    test_ptr_list_debug_dump();
    test_string_list_klass();

    return(testGroupFinished());
}