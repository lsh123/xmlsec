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

int test_xmlSec509NameStringRead(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_UNIT_TESTS_H__ */



