/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Version information
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_VERSION_H__
#define __XMLSEC_VERSION_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

/**
 * XMLSEC_VERSION:
 *
 * The library version string in the format
 * "<major-number>.<minor-number>.<sub-minor-number>".
 */
#define XMLSEC_VERSION			"1.0.4"

/**
 * XMLSEC_PACKAGE:
 *
 * The library packaqge name.
 */
#define XMLSEC_PACKAGE			"xmlsec1"

/**
 * XMLSEC_VERSION_MAJOR:
 *
 * The library major version number.
 */
#define XMLSEC_VERSION_MAJOR		1

/**
 * XMLSEC_VERSION_MINOR:
 *
 * The library minor version number.
 */
#define XMLSEC_VERSION_MINOR		0

/**
 * XMLSEC_VERSION_SUBMINOR:
 *
 * The library sub-minor version number.
 */
#define XMLSEC_VERSION_SUBMINOR		4

/**
 * XMLSEC_VERSION_INFO:
 *
 * The library version info string in the format
 * "<major-number>+<minor-number>:<sub-minor-number>:<minor-number>".
 */
#define XMLSEC_VERSION_INFO		"1:4:0"


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_VERSION_H__ */

