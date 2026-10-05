#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include <libxml/parser.h>
#include <libxml/xmlerror.h>

#include <xmlsec/buffer.h>
#include <xmlsec/parser.h>
#include <xmlsec/xmlsec.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static void ignore(void* ctx, const char* msg, ...) {
    /* Error handler to avoid spam of error messages from libxml parser. */
    (void)ctx;
    (void)msg;
}

static int g_initialized = 0;
/* Set when do_init() fails, so a failed one-time init is not retried on
 * every input. */
static int g_init_failed = 0;

static int do_init(void) {
    xmlInitParser();

    if (xmlSecInit() < 0) {
        return -1;
    }
    if (xmlSecCheckVersion() != 1) {
        xmlSecShutdown();
        return -1;
    }

    /* Silence libxml2 error spam. */
    xmlSetGenericErrorFunc(NULL, &ignore);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSecBufferPtr buf;
    xmlDocPtr doc;

    if (!g_initialized) {
        g_init_failed = (do_init() < 0);
        g_initialized = 1;
    }
    /* A zero-size buffer never allocates data, so xmlSecBufferGetData() would
     * return NULL; skip empty inputs like the sibling targets do. Also skip
     * inputs too large to fit in the int length expected by xmlSecBuffer*. */
    if (g_init_failed || size == 0 || size > (size_t)INT_MAX) {
        return 0;
    }
    buf = xmlSecBufferCreate(size);
    if (buf == NULL) {
        return 0;
    }
    if (xmlSecBufferSetData(buf, data, size) < 0) {
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
