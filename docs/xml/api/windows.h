/**
 * @file windows.h
 * @brief Stub Windows header for doxygen documentation generation on non-Windows platforms.
 *
 * This file is only used when generating documentation with doxygen on Linux/macOS.
 * It provides minimal type stubs so the mscrypto/mscng headers can be parsed
 * without errors.
 */
#ifndef __XMLSEC_DOXYGEN_WINDOWS_H__
#define __XMLSEC_DOXYGEN_WINDOWS_H__

typedef void*           HCERTSTORE;
typedef void*           HCRYPTKEY;
typedef void*           HCRYPTPROV;
typedef void*           PCCERT_CONTEXT;
typedef void*           PCCRL_CONTEXT;
typedef void*           HCERTCHAINENGINE;
typedef void*           BCRYPT_ALG_HANDLE;
typedef void*           BCRYPT_KEY_HANDLE;
typedef void*           NCRYPT_KEY_HANDLE;
typedef unsigned long   NCRYPT_PROV_HANDLE;
typedef char*           LPTSTR;
typedef const char*     LPCTSTR;
typedef unsigned short* LPWSTR;
typedef const unsigned short* LPCWSTR;
typedef unsigned long   DWORD;
typedef unsigned char   BYTE;
typedef unsigned char*  PBYTE;
typedef int             BOOL;
typedef unsigned int    UINT;
typedef unsigned long   ULONG;
typedef long            LONG;
typedef void*           HANDLE;
typedef void*           HMODULE;

#endif /* __XMLSEC_DOXYGEN_WINDOWS_H__ */
