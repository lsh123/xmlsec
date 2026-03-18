/**
 * XMLSec library
 *
 * Unit tests
 *
 * See Copyright for the status of this software.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_UNIT_TESTS_H__
#define __XMLSEC_UNIT_TESTS_H__

#define XMLSEC_PRIVATE 1

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include "../src/cast_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/* helper functions */
void testGroupStart(const char * name);
int  testGroupFinished(void);

void testStart(const char * name);
void testFinishedSuccess(void);
void testFinishedFailure(void);
#ifdef __GNUC__
void testLog(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));
#else /* __GNUC__ */
void testLog(const char* fmt, ...);
#endif /* __GNUC__ */


/* tests */
int test_base64(void);
int test_transform_helpers(void);
int test_xmlSecX509EscapedStringRead(void);
int test_xmlSecX509AttrValueStringRead(void);
int test_xmlSecX509NameRead(void);
int test_xmltree(void);
int test_templates(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_UNIT_TESTS_H__ */



