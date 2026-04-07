/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_MEMBUF_H__
#define __XMLSEC_MEMBUF_H__

/**
 * @defgroup xmlsec_core_membuf Memory Buffer Transform
 * @ingroup xmlsec_core
 * @brief In-memory buffer transform for capturing transform output.
 * @{
 */

#include <libxml/tree.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************************************************************
 *
 * Memory Buffer transform
 *
  *****************************************************************************/
/**
 * @brief The Memory Buffer transform klass.
 */
#define xmlSecTransformMemBufId \
        xmlSecTransformMemBufGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformMemBufGetKlass           (void);
XMLSEC_EXPORT xmlSecBufferPtr   xmlSecTransformMemBufGetBuffer          (xmlSecTransformPtr transform);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_membuf */

#endif /* __XMLSEC_MEMBUF_H__ */
