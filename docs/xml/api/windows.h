/**
 * @file windows.h
 * @brief Stub Windows header for doxygen documentation generation.
 *
 * This file is used when generating documentation with doxygen; the stub directory
 * is listed first in INCLUDE_PATH, so it shadows the real <windows.h> on any platform.
 * It provides minimal type stubs so the mscrypto/mscng headers and the core
 * xmltree.h header can be parsed without errors.
 */
#ifndef XMLSEC_DOXYGEN_WINDOWS_H
#define XMLSEC_DOXYGEN_WINDOWS_H

typedef void*           HCERTSTORE;
typedef void*           HCRYPTKEY;
typedef void*           HCRYPTPROV;
typedef const void*     PCCERT_CONTEXT;
typedef const void*     PCCRL_CONTEXT;
typedef void*           HCERTCHAINENGINE;
typedef void*           BCRYPT_ALG_HANDLE;
typedef void*           BCRYPT_KEY_HANDLE;
typedef void*           NCRYPT_KEY_HANDLE;
typedef void*           NCRYPT_PROV_HANDLE;
typedef char            TCHAR;
typedef TCHAR*          LPTSTR;
typedef const TCHAR*    LPCTSTR;
typedef unsigned short* LPWSTR;
typedef const unsigned short* LPCWSTR;
typedef unsigned long   DWORD;
typedef unsigned char   BYTE;
typedef unsigned char*  PBYTE;
typedef unsigned char*  PUCHAR;
typedef int             BOOL;
typedef unsigned int    UINT;
typedef unsigned long   ULONG;
typedef long            LONG;
typedef void*           HANDLE;
typedef void*           HMODULE;

#endif /* XMLSEC_DOXYGEN_WINDOWS_H */
