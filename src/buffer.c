/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_core_buffer
 * @brief Binary memory buffer functions.
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>

#include "cast_helpers.h"

/******************************************************************************
 *
 * xmlSecBuffer
 *
  *****************************************************************************/
static xmlSecAllocMode gAllocMode = xmlSecAllocModeDouble;
static xmlSecSize gInitialSize = 1024;

/**
 * @brief Sets the default buffer allocation mode.
 * @details Sets new global default allocation mode and minimal intial size.
 * @param defAllocMode the new default buffer allocation mode.
 * @param defInitialSize the new default buffer minimal intial size.
 */
void
xmlSecBufferSetDefaultAllocMode(xmlSecAllocMode defAllocMode, xmlSecSize defInitialSize) {
    xmlSecAssert(defInitialSize > 0);

    gAllocMode = defAllocMode;
    gInitialSize = defInitialSize;
}

/**
 * @brief Allocates and initializes a new memory buffer.
 * @details Allocates and initializes new memory buffer with given size.
 * Caller is responsible for calling #xmlSecBufferDestroy function
 * to free the buffer.
 * @param size the intial size.
 * @return pointer to newly allocated buffer or NULL if an error occurs.
 */
xmlSecBufferPtr
xmlSecBufferCreate(xmlSecSize size) {
    xmlSecBufferPtr buf;
    int ret;

    buf = (xmlSecBufferPtr)xmlMalloc(sizeof(xmlSecBuffer));
    if(buf == NULL) {
        xmlSecMallocError(sizeof(xmlSecBuffer), NULL);
        return(NULL);
    }

    ret = xmlSecBufferInitialize(buf, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferInitialize", NULL, "size=" XMLSEC_SIZE_FMT, size);
        xmlSecBufferDestroy(buf);
        return(NULL);
    }
    return(buf);
}

/**
 * @brief Destroys a buffer object.
 * @details Destroys buffer object created with #xmlSecBufferCreate function.
 * @param buf the pointer to buffer object.
 */
void
xmlSecBufferDestroy(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);

    xmlSecBufferFinalize(buf);
    xmlFree(buf);
}

/**
 * @brief Initializes a buffer object.
 * @details Initializes buffer object @p buf. Caller is responsible for calling
 * #xmlSecBufferFinalize function to free allocated resources.
 * @param buf the pointer to buffer object.
 * @param size the initial buffer size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferInitialize(xmlSecBufferPtr buf, xmlSecSize size) {
    xmlSecAssert2(buf != NULL, -1);

    buf->data = NULL;
    buf->size = buf->maxSize = 0;
    buf->allocMode = gAllocMode;

    return(xmlSecBufferSetMaxSize(buf, size));
}

/**
 * @brief Frees resources for an initialized buffer.
 * @details Frees allocated resource for a buffer initialized with #xmlSecBufferInitialize
 * function.
 * @param buf the pointer to buffer object.
 */
void
xmlSecBufferFinalize(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);

    xmlSecBufferEmpty(buf);

    if(buf->data != 0) {
        xmlFree(buf->data);
    }
    buf->data = NULL;
    buf->size = buf->maxSize = 0;
}

/**
 * @brief Empties the buffer.
 * @param buf the pointer to buffer object.
 */
void
xmlSecBufferEmpty(xmlSecBufferPtr buf) {
    xmlSecAssert(buf != NULL);

    if(buf->data != 0) {
        xmlSecAssert(buf->maxSize > 0);
        memset(buf->data, 0, buf->maxSize);
    }
    buf->size = 0;
}

/**
 * @brief Checks if the buffer is empty.
 * @details Checks if the @p buf is empty (@p buf is null or @p buf's data is null or @p buf's size is zero).
 * @param buf the pointer to buffer object.
 * @return 1 if buffer is empty or 0 otherwise.
 */
int
xmlSecBufferIsEmpty(xmlSecBufferPtr buf) {
    return (((buf == NULL) || (buf->data == NULL) || (buf->size <= 0)) ? 1 : 0);
}

/**
 * @brief Gets pointer to buffer's data.
 * @param buf the pointer to buffer object.
 * @return pointer to buffer's data.
 */
xmlSecByte*
xmlSecBufferGetData(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, NULL);

    return(buf->data);
}

/**
 * @brief Sets the value of the buffer to @p data.
 * @param buf the pointer to buffer object.
 * @param data the data.
 * @param size the data size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferSetData(xmlSecBufferPtr buf, const xmlSecByte* data, xmlSecSize size) {
    int ret;

    xmlSecAssert2(buf != NULL, -1);

    xmlSecBufferEmpty(buf);
    if(size > 0) {
        xmlSecAssert2(data != NULL, -1);

        ret = xmlSecBufferSetMaxSize(buf, size);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, size);
            return(-1);
        }

        memcpy(buf->data, data, size);
    }

    buf->size = size;
    return(0);
}

/**
 * @brief Gets the current buffer data size.
 * @param buf the pointer to buffer object.
 * @return the current data size.
 */
xmlSecSize
xmlSecBufferGetSize(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, 0);

    return(buf->size);
}

/**
 * @brief Sets new buffer data size.
 * @details Sets new buffer data size. If necessary, buffer grows to
 * have at least @p size bytes.
 * @param buf the pointer to buffer object.
 * @param size the new data size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferSetSize(xmlSecBufferPtr buf, xmlSecSize size) {
    int ret;

    xmlSecAssert2(buf != NULL, -1);

    ret = xmlSecBufferSetMaxSize(buf, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL, "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }


    buf->size = size;
    return(0);
}

/**
 * @brief Gets the maximum (allocated) buffer size.
 * @param buf the pointer to buffer object.
 * @return the maximum (allocated) buffer size.
 */
xmlSecSize
xmlSecBufferGetMaxSize(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, 0);

    return(buf->maxSize);
}

/**
 * @brief Sets new buffer maximum size.
 * @details Sets new buffer maximum size. If necessary, buffer grows to
 * have at least @p size bytes.
 * @param buf the pointer to buffer object.
 * @param size the new maximum size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferSetMaxSize(xmlSecBufferPtr buf, xmlSecSize size) {
    xmlSecByte* newData;
    xmlSecSize newSize = 0;

    xmlSecAssert2(buf != NULL, -1);
    if(size <= buf->maxSize) {
        return(0);
    }

    switch(buf->allocMode) {
        case xmlSecAllocModeExact:
            newSize = size + 8;
            break;
        case xmlSecAllocModeDouble:
            newSize = 2 * size + 32;
            break;
    }

    if(newSize < gInitialSize) {
        newSize = gInitialSize;
    }


    if(buf->data != NULL) {
        newData = (xmlSecByte*)xmlRealloc(buf->data, newSize);
    } else {
        newData = (xmlSecByte*)xmlMalloc(newSize);
    }
    if(newData == NULL) {
        xmlSecMallocError(newSize, NULL);
        return(-1);
    }

    buf->data = newData;
    buf->maxSize = newSize;

    if(buf->size < buf->maxSize) {
        xmlSecAssert2(buf->data != NULL, -1);
        memset(buf->data + buf->size, 0, buf->maxSize - buf->size);
    }

    return(0);
}

#define SWAP(type, a, b) do { type tmp = (a); (a) = (b); (b) = tmp; } while (0)

/**
 * @brief Swaps the content of the two buffers.
 * @param buf1 the pointer to the first buffer object.
 * @param buf2 the pointer to the second buffer object.
 */
void
xmlSecBufferSwap(xmlSecBufferPtr buf1, xmlSecBufferPtr buf2) {
    xmlSecAssert(buf1 != NULL);
    xmlSecAssert(buf2 != NULL);

    SWAP(xmlSecByte*,       buf1->data, buf2->data);
    SWAP(xmlSecSize,        buf1->size, buf2->size);
    SWAP(xmlSecSize,        buf1->maxSize, buf2->maxSize);
    SWAP(xmlSecAllocMode,   buf1->allocMode, buf2->allocMode);
}

/**
 * @brief Appends data to the end of the buffer.
 * @details Appends the @p data after the current data stored in the buffer.
 * @param buf the pointer to buffer object.
 * @param data the data.
 * @param size the data size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferAppend(xmlSecBufferPtr buf, const xmlSecByte* data, xmlSecSize size) {
    int ret;

    xmlSecAssert2(buf != NULL, -1);

    if(size > 0) {
        xmlSecAssert2(data != NULL, -1);

        ret = xmlSecBufferSetMaxSize(buf, buf->size + size);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
                "size=" XMLSEC_SIZE_FMT, (buf->size + size));
            return(-1);
        }

        memcpy(buf->data + buf->size, data, size);
        buf->size += size;
    }

    return(0);
}

/**
 * @brief Prepends data to the beginning of the buffer.
 * @details Prepends the @p data before the current data stored in the buffer.
 * @param buf the pointer to buffer object.
 * @param data the data.
 * @param size the data size.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferPrepend(xmlSecBufferPtr buf, const xmlSecByte* data, xmlSecSize size) {
    int ret;

    xmlSecAssert2(buf != NULL, -1);

    if(size > 0) {
        xmlSecAssert2(data != NULL, -1);

        ret = xmlSecBufferSetMaxSize(buf, buf->size + size);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
                "size=" XMLSEC_SIZE_FMT, (buf->size + size));
            return(-1);
        }

        memmove(buf->data + size, buf->data, buf->size);
        memcpy(buf->data, data, size);
        buf->size += size;
    }

    return(0);
}

/**
 * @brief Removes bytes from the beginning of the buffer.
 * @details Removes @p size bytes from the beginning of the current buffer.
 * @param buf the pointer to buffer object.
 * @param size the number of bytes to be removed.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferRemoveHead(xmlSecBufferPtr buf, xmlSecSize size) {
    xmlSecAssert2(buf != NULL, -1);

    if(size < buf->size) {
        xmlSecAssert2(buf->data != NULL, -1);

        buf->size -= size;
        memmove(buf->data, buf->data + size, buf->size);
    } else {
        buf->size = 0;
    }
    if(buf->size < buf->maxSize) {
        xmlSecAssert2(buf->data != NULL, -1);
        memset(buf->data + buf->size, 0, buf->maxSize - buf->size);
    }
    return(0);
}

/**
 * @brief Removes bytes from the end of the buffer.
 * @details Removes @p size bytes from the end of current buffer.
 * @param buf the pointer to buffer object.
 * @param size the number of bytes to be removed.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferRemoveTail(xmlSecBufferPtr buf, xmlSecSize size) {
    xmlSecAssert2(buf != NULL, -1);

    if(size < buf->size) {
        buf->size -= size;
    } else {
        buf->size = 0;
    }
    if(buf->size < buf->maxSize) {
        xmlSecAssert2(buf->data != NULL, -1);
        memset(buf->data + buf->size, 0, buf->maxSize - buf->size);
    }
    return(0);
}

/**
 * @brief Reverses order of bytes in the buffer @p buf.
 * @param buf the pointer to buffer object.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferReverse(xmlSecBufferPtr buf) {
    xmlSecByte* pp;
    xmlSecByte* qq;
    xmlSecSize  size;
    xmlSecByte ch;

    xmlSecAssert2(buf != NULL, -1);

    /* trivial case */
    size = xmlSecBufferGetSize(buf);
    if (size <= 1) {
        return(0);
    }

    pp = xmlSecBufferGetData(buf);
    xmlSecAssert2(pp != NULL, -1);

    for (qq = pp + size - 1; pp < qq; ++pp, --qq) {
        ch = *(pp);
        *(pp) = *(qq);
        *(qq) = ch;
    }

    return(0);
}


/**
 * @brief Reads the content of a file into the buffer.
 * @details Reads the content of the file @p filename in the buffer.
 * @param buf the pointer to buffer object.
 * @param filename the filename.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferReadFile(xmlSecBufferPtr buf, const char* filename) {
    xmlSecByte buffer[1024];
    FILE* f = NULL;
    xmlSecSize size;
    size_t len;
    int ret;
    int res = -1;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

#ifndef _MSC_VER
    f = fopen(filename, "rb");
#else
    fopen_s(&f, filename, "rb");
#endif /* _MSC_VER */
    if(f == NULL) {
        xmlSecIOError("fopen", filename, NULL);
        goto done;
    }

    while(!feof(f)) {
        len = fread(buffer, 1, sizeof(buffer), f);
        if(ferror(f)) {
            xmlSecIOError("fread", filename, NULL);
            goto done;
        }

        XMLSEC_SAFE_CAST_SIZE_T_TO_SIZE(len, size, goto done, NULL);
        ret = xmlSecBufferAppend(buf, buffer, size);
        if(ret < 0) {
            xmlSecInternalError2("xmlSecBufferAppend", NULL, "size=" XMLSEC_SIZE_T_FMT, len);
            goto done;
        }
    }

    /* success */
    res = 0;

done:
    if(f != NULL) {
        fclose(f);
    }
    return(res);
}

/**
 * @brief Reads and base64-decodes a node's content into the buffer.
 * @details Reads the content of the @p node, base64 decodes it and stores the
 * result in the buffer.
 * @param buf the pointer to buffer object.
 * @param node the pointer to node.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferBase64NodeContentRead(xmlSecBufferPtr buf, xmlNodePtr node) {
    xmlChar* content = NULL;
    xmlSecSize outWritten;
    int ret;
    int res = -1;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    content = xmlSecGetNodeContentAndTrim(node);
    if(content == NULL) {
        xmlSecInvalidNodeContentError(node, NULL, "empty");
        goto done;
    }

    /* base64 decode size is less than input size */
    ret = xmlSecBufferSetMaxSize(buf, xmlSecStrlen(content));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetMaxSize", NULL);
        goto done;
    }

    ret = xmlSecBase64Decode_ex(content, xmlSecBufferGetData(buf),
        xmlSecBufferGetMaxSize(buf), &outWritten);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBase64Decode_ex", NULL);
        goto done;
    }

    ret = xmlSecBufferSetSize(buf, outWritten);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "size=" XMLSEC_SIZE_FMT, outWritten);
        goto done;
    }

    /* success */
    res = 0;

done:
    if(content != NULL) {
        xmlFree(content);
    }
    return(res);
}

/**
 * @brief Sets node content to the base64-encoded buffer data.
 * @details Sets the content of the @p node to the base64 encoded buffer data.
 * @param buf the pointer to buffer object.
 * @param node the pointer to a node.
 * @param columns the max line size for base64 encoded data.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferBase64NodeContentWrite(xmlSecBufferPtr buf, xmlNodePtr node, int columns) {
    xmlChar* content;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    content = xmlSecBase64Encode(xmlSecBufferGetData(buf), xmlSecBufferGetSize(buf), columns);
    if(content == NULL) {
        xmlSecInternalError("xmlSecBase64Encode", NULL);
        return(-1);
    }

    xmlNodeAddContent(node, content);
    xmlFree(content);

    return(0);
}


/**
 * @brief Reads hex-encoded string into the buffer.
 * @details Reads content of hex encoded @p hexStr into @p buf.
 * @param buf the pointer to buffer object.
 * @param hexStr the hex string.
 * @return 0 on success or a negative value if an error occurs.
 */
int
xmlSecBufferHexRead(xmlSecBufferPtr buf, const xmlChar* hexStr) {
    xmlSecSize hexStrSize, bufSize;
    xmlSecByte * data;
    xmlChar ch1, ch2;
    int ret;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(hexStr != NULL, -1);

    /* trivial case */
    hexStrSize = xmlSecStrlen(hexStr);
    if(hexStrSize <= 0) {
        xmlSecBufferEmpty(buf);
        return(0);
    }

    /* we expect each byte to be represented by 2 chars */
    if((hexStrSize % 2) != 0) {
        xmlSecInvalidSizeDataError("hexStrSize", hexStrSize, "even", NULL);
        return(-1);
    }
    bufSize = hexStrSize / 2;

    ret = xmlSecBufferSetSize(buf, bufSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetSize", NULL,
            "bufSize=" XMLSEC_SIZE_FMT, bufSize);
        return (-1);
    }

    data = xmlSecBufferGetData(buf);
    xmlSecAssert2(data != NULL, -1);

    for( ; (*hexStr) != '\0'; ++data) {
        ch1 = *(hexStr++);
        ch2 = *(hexStr++);
        if(!xmlSecIsHex(ch1) || !xmlSecIsHex(ch2)) {
            xmlSecInvalidDataError("Unexpected character (not hex)", NULL);
            return (-1);
        }
        (*data) = xmlSecFromHex2(ch1, ch2);
    }

    /* sucess */
    return(0);
}

/******************************************************************************
 *
 * IO buffer
 *
  *****************************************************************************/
static int      xmlSecBufferIOWrite                             (xmlSecBufferPtr buf,
                                                                 const xmlSecByte *data,
                                                                 int len);
static int      xmlSecBufferIOClose                             (xmlSecBufferPtr buf);

/**
 * @brief Creates a LibXML output buffer to store data in @p buf.
 * @details Creates new LibXML output buffer to store data in the @p buf. Caller is
 * responsible for destroying @p buf when processing is done.
 * @param buf the pointer to buffer.
 * @return pointer to newly allocated output buffer or NULL if an error
 * occurs.
 */
xmlOutputBufferPtr
xmlSecBufferCreateOutputBuffer(xmlSecBufferPtr buf) {
    return(xmlOutputBufferCreateIO((xmlOutputWriteCallback)xmlSecBufferIOWrite,
                                     (xmlOutputCloseCallback)xmlSecBufferIOClose,
                                     buf,
                                     NULL));
}

static int
xmlSecBufferIOWrite(xmlSecBufferPtr buf, const xmlSecByte *data, int len) {
    xmlSecSize size;
    int ret;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(len >= 0, -1);

    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(-1), NULL);
    ret = xmlSecBufferAppend(buf, data, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferAppend", NULL, "size=" XMLSEC_SIZE_FMT, size);
        return(-1);
    }
    /* we appended the whole input buffer */
    return(len);
}

static int
xmlSecBufferIOClose(xmlSecBufferPtr buf) {
    xmlSecAssert2(buf != NULL, -1);

    /* just do nothing */
    return(0);
}
