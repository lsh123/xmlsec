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


/* tests */
int test_base64(void);
int test_xmlSecX509EscapedStringRead(void);
int test_xmlSecX509AttrValueStringRead(void);
int test_xmlSecX509NameRead(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_UNIT_TESTS_H__ */



