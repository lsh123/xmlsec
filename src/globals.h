/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal header defining build-time macros.
 */

#ifndef __XMLSEC_CORE_GLOBALS_H__
#define __XMLSEC_CORE_GLOBALS_H__

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef IN_XMLSEC
#define IN_XMLSEC
#endif /* IN_XMLSEC */

#ifndef XMLSEC_PRIVATE
#define XMLSEC_PRIVATE
#endif /* XMLSEC_PRIVATE */

/* Include common error helper macros. */
#include "errors_helpers.h"

#endif /* __XMLSEC_CORE_GLOBALS_H__ */
