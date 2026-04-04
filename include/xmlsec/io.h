/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Input uri transform and utility functions.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_IO_H__
#define __XMLSEC_IO_H__

/**
 * @defgroup xmlsec_core_io I/O
 * @ingroup xmlsec_core
 * @brief Input/output helper functions.
 * @{
 */

#include <libxml/tree.h>
#include <libxml/xmlIO.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/transforms.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_EXPORT int       xmlSecIOInit                            (void);
XMLSEC_EXPORT void      xmlSecIOShutdown                        (void);
XMLSEC_EXPORT void      xmlSecIOCleanupCallbacks                (void);
XMLSEC_EXPORT int       xmlSecIORegisterDefaultCallbacks        (void);
XMLSEC_EXPORT int       xmlSecIORegisterCallbacks               (xmlInputMatchCallback matchFunc,
                                                                 xmlInputOpenCallback openFunc,
                                                                 xmlInputReadCallback readFunc,
                                                                 xmlInputCloseCallback closeFunc);

/******************************************************************************
 *
 * Input URI transform
 *
  *****************************************************************************/
/**
 * @brief The Input URI transform id.
 */
#define xmlSecTransformInputURIId \
        xmlSecTransformInputURIGetKlass()
XMLSEC_EXPORT xmlSecTransformId xmlSecTransformInputURIGetKlass (void);
XMLSEC_EXPORT int       xmlSecTransformInputURIOpen             (xmlSecTransformPtr transform,
                                                                 const xmlChar* uri);
XMLSEC_EXPORT int       xmlSecTransformInputURIClose            (xmlSecTransformPtr transform);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */ /** xmlsec_core_io */

#endif /* __XMLSEC_IO_H__ */
