/*
 * XML Security Library
 *
 * globals.h: internal header only used during the compilation
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */

#ifndef __XMLSEC_GLOBALS_H__
#define __XMLSEC_GLOBALS_H__

#if defined(WIN32) && !defined(__CYGWIN__)
#include "win32config.h"
#elif defined(macintosh)
#include "config-mac.h"
#else
#include "config.h"
#endif

#endif /* ! __XMLSEC_GLOBALS_H__ */
