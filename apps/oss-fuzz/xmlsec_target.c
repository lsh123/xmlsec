#include <stdint.h>
#include <stddef.h>

#include <xmlsec/buffer.h>
#include <xmlsec/parser.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static void ignore(void* ctx, const char* msg, ...) {
    /* Error handler to avoid spam of error messages from libxml parser. */
    (void)ctx;
    (void)msg;
}

static int g_initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSecBufferPtr buf;
    xmlDocPtr doc;

    if (!g_initialized) {
        xmlSetGenericErrorFunc(NULL, &ignore);
        g_initialized = 1;
    }
    /* A zero-size buffer never allocates data, so xmlSecBufferGetData() would
     * return NULL; skip empty inputs like the sibling targets do. */
    if (size == 0) {
        return 0;
    }
    buf = xmlSecBufferCreate(size);
    if(buf == NULL) {
        return 0;
    }
    if(xmlSecBufferSetData(buf, data, size) < 0) {
        xmlSecBufferDestroy(buf);
        return 0;
    }
    doc = xmlSecParseMemory(xmlSecBufferGetData(buf),
            xmlSecBufferGetSize(buf), 0);

    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
    xmlSecBufferDestroy(buf);
    return 0;
}
