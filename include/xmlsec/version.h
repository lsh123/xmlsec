/** 
 * XMLSec library
 *
 * Version information
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
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
#define XMLSEC_VERSION			"0.1.0"

/**
 * XMLSEC_VERSION_MAJOR:
 *
 * The library major version number.
 */
#define XMLSEC_VERSION_MAJOR		0

/**
 * XMLSEC_VERSION_MINOR:
 *
 * The library minor version number.
 */
#define XMLSEC_VERSION_MINOR		1

/**
 * XMLSEC_VERSION_SUBMINOR:
 *
 * The library sub-minor version number.
 */
#define XMLSEC_VERSION_SUBMINOR		0

/**
 * XMLSEC_VERSION_INFO:
 *
 * The library version info string in the format
 * "<major-number>+<minor-number>:<sub-minor-number>:<minor-number>".
 */
#define XMLSEC_VERSION_INFO		"1:0:1"


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_VERSION_H__ */

