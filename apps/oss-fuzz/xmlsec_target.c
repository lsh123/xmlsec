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

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSetGenericErrorFunc(NULL, &ignore);
    xmlSecBufferPtr buf = xmlSecBufferCreate(size);
    xmlSecBufferSetData(buf, data, size);
    xmlDocPtr doc = xmlSecParseMemory(xmlSecBufferGetData(buf),
            xmlSecBufferGetSize(buf), 0);

    if (doc != NULL) xmlFreeDoc(doc);
    xmlSecBufferDestroy(buf);
    return 0;
}
