/* xmlsec-ltdl.h -- generic dlopen functions
   Copyright (C) 1998-2000 Free Software Foundation, Inc.
   Originally by Thomas Tanner <tanner@ffii.org>
   This file is part of GNU Libtool.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.

As a special exception to the GNU Lesser General Public License,
if you distribute this file as part of a program or library that
is built using GNU libtool, you may include it under the same
distribution terms that you use for the rest of that program.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
02111-1307  USA
*/

/* Only include this header file once. */
#ifndef LTDL_H
#define LTDL_H 1

#include <sys/types.h>		/* for size_t declaration */


/* --- MACROS FOR PORTABILITY --- */


/* LTDL_BEGIN_C_DECLS should be used at the beginning of your declarations,
   so that C++ compilers don't mangle their names.  Use LTDL_END_C_DECLS at
   the end of C declarations. */
#ifdef __cplusplus
# define LT_BEGIN_C_DECLS	extern "C" {
# define LT_END_C_DECLS		}
#else
# define LT_BEGIN_C_DECLS	/* empty */
# define LT_END_C_DECLS		/* empty */
#endif

LT_BEGIN_C_DECLS


/* LT_PARAMS is a macro used to wrap function prototypes, so that compilers
   that don't understand ANSI C prototypes still work, and ANSI C
   compilers can issue warnings about type mismatches.  */
#if defined (__STDC__) || defined (_AIX) || (defined (__mips) && defined (_SYSTYPE_SVR4)) || defined(WIN32) || defined(__cplusplus)
# define LT_PARAMS(protos)	protos
# define xmlsec_lt_ptr		void*
#else
# define LT_PARAMS(protos)	()
# define xmlsec_lt_ptr		char*
#endif

/* LT_STMT_START/END are used to create macros which expand to a
   a single compound statement in a portable way.  */
#if defined (__GNUC__) && !defined (__STRICT_ANSI__) && !defined (__cplusplus)
#  define LT_STMT_START        (void)(
#  define LT_STMT_END          )
#else
#  if (defined (sun) || defined (__sun__))
#    define LT_STMT_START      if (1)
#    define LT_STMT_END        else (void)0
#  else
#    define LT_STMT_START      do
#    define LT_STMT_END        while (0)
#  endif
#endif

/* LT_CONC creates a new concatenated symbol for the compiler
   in a portable way.  */
#if defined(__STDC__) || defined(__cplusplus) || defined(_MSC_VER)
#  define LT_CONC(s,t)	s##t
#else
#  define LT_CONC(s,t)	s/**/t
#endif




/* --- WINDOWS SUPPORT --- */


/* Canonicalise Windows and Cygwin recognition macros.  */
#ifdef __CYGWIN32__
#  ifndef __CYGWIN__
#    define __CYGWIN__ __CYGWIN32__
#  endif
#endif
#if defined(_WIN32) || defined(WIN32)
#  ifndef __WINDOWS__
#    ifdef _WIN32
#      define __WINDOWS__ _WIN32
#    else
#      ifdef WIN32
#        define __WINDOWS__ WIN32
#      endif
#    endif
#  endif
#endif

#ifdef __WINDOWS__
#  ifndef __CYGWIN__
/* LT_DIRSEP_CHAR is accepted *in addition* to '/' as a directory
   separator when it is set. */
#    define LT_DIRSEP_CHAR	'\\'
#    define LT_PATHSEP_CHAR	';'
#  endif
#endif
#ifndef LT_PATHSEP_CHAR
#  define LT_PATHSEP_CHAR	':'
#endif

/* DLL building support on win32 hosts;  mostly to workaround their
   ridiculous implementation of data symbol exporting. */
#ifndef LT_SCOPE
#  ifdef __WINDOWS__
#    ifdef DLL_EXPORT		/* defined by libtool (if required) */
#      define LT_SCOPE	__declspec(dllexport)
#    endif
#    ifdef LIBLTDL_DLL_IMPORT	/* define if linking with this dll */
#      define LT_SCOPE	extern __declspec(dllimport)
#    endif
#  endif
#  ifndef LT_SCOPE		/* static linking or !__WINDOWS__ */
#    define LT_SCOPE	extern
#  endif
#endif




/* --- DYNAMIC MODULE LOADING API --- */


typedef	struct xmlsec_lt_dlhandle_struct *xmlsec_lt_dlhandle;	/* A loaded module.  */

/* Initialisation and finalisation functions for libltdl. */
LT_SCOPE	int	    xmlsec_lt_dlinit		LT_PARAMS((void));
LT_SCOPE	int	    xmlsec_lt_dlexit		LT_PARAMS((void));

/* Module search path manipultation.  */
LT_SCOPE	int	    xmlsec_lt_dladdsearchdir	LT_PARAMS((const char *search_dir));
LT_SCOPE	int 	    xmlsec_lt_dlsetsearchpath	LT_PARAMS((const char *search_path));
LT_SCOPE	const char *xmlsec_lt_dlgetsearchpath	LT_PARAMS((void));

/* Portable libltdl versions of the system dlopen() API. */
LT_SCOPE	xmlsec_lt_dlhandle xmlsec_lt_dlopen		LT_PARAMS((const char *filename));
LT_SCOPE	xmlsec_lt_dlhandle xmlsec_lt_dlopenext	LT_PARAMS((const char *filename));
LT_SCOPE	xmlsec_lt_ptr	    xmlsec_lt_dlsym		LT_PARAMS((xmlsec_lt_dlhandle handle,
						     const char *name));
LT_SCOPE	const char *xmlsec_lt_dlerror		LT_PARAMS((void));
LT_SCOPE	int	    xmlsec_lt_dlclose		LT_PARAMS((xmlsec_lt_dlhandle handle));

/* Module residency management. */
LT_SCOPE	int	    xmlsec_lt_dlmakeresident	LT_PARAMS((xmlsec_lt_dlhandle handle));
LT_SCOPE	int	    xmlsec_lt_dlisresident	LT_PARAMS((xmlsec_lt_dlhandle handle));




/* --- MUTEX LOCKING --- */


typedef void	xmlsec_lt_dlmutex_lock		LT_PARAMS((void));
typedef void	xmlsec_lt_dlmutex_unlock	LT_PARAMS((void));
typedef void	xmlsec_lt_dlmutex_seterror	LT_PARAMS((const char *error));
typedef const char *xmlsec_lt_dlmutex_geterror	LT_PARAMS((void));

LT_SCOPE	int	xmlsec_lt_dlmutex_register	LT_PARAMS((xmlsec_lt_dlmutex_lock *lock,
					    xmlsec_lt_dlmutex_unlock *unlock,
					    xmlsec_lt_dlmutex_seterror *seterror,
					    xmlsec_lt_dlmutex_geterror *geterror));




/* --- MEMORY HANDLING --- */


/* Pointers to memory management functions to be used by libltdl. */
LT_SCOPE  xmlsec_lt_ptr   (*xmlsec_lt_dlmalloc)	LT_PARAMS((size_t size));
LT_SCOPE  void	   (*xmlsec_lt_dlfree)		LT_PARAMS((xmlsec_lt_ptr ptr));




/* --- PRELOADED MODULE SUPPORT --- */


/* A preopened symbol. Arrays of this type comprise the exported
   symbols for a dlpreopened module. */
typedef struct {
  const char *name;
  xmlsec_lt_ptr      address;
} xmlsec_lt_dlsymlist;

LT_SCOPE	int	xmlsec_lt_dlpreload	LT_PARAMS((const xmlsec_lt_dlsymlist *preloaded));
LT_SCOPE	int	xmlsec_lt_dlpreload_default
				LT_PARAMS((const xmlsec_lt_dlsymlist *preloaded));

#define LTDL_SET_PRELOADED_SYMBOLS() 		LT_STMT_START{	\
	LT_SCOPE const xmlsec_lt_dlsymlist xmlsec_lt_preloaded_symbols[];		\
	xmlsec_lt_dlpreload_default(xmlsec_lt_preloaded_symbols);			\
						}LT_STMT_END




/* --- MODULE INFORMATION --- */


/* Read only information pertaining to a loaded module. */
typedef	struct {
  char	*filename;		/* file name */
  char	*name;			/* module name */
  int	ref_count;		/* number of times xmlsec_lt_dlopened minus
				   number of times xmlsec_lt_dlclosed. */
} xmlsec_lt_dlinfo;

LT_SCOPE	const xmlsec_lt_dlinfo	*xmlsec_lt_dlgetinfo	    LT_PARAMS((xmlsec_lt_dlhandle handle));
LT_SCOPE	xmlsec_lt_dlhandle	xmlsec_lt_dlhandle_next    LT_PARAMS((xmlsec_lt_dlhandle place));
LT_SCOPE	int		xmlsec_lt_dlforeach	    LT_PARAMS((
				int (*func) (xmlsec_lt_dlhandle handle, xmlsec_lt_ptr data),
				xmlsec_lt_ptr data));

/* Associating user data with loaded modules. */
typedef unsigned xmlsec_lt_dlcaller_id;

LT_SCOPE	xmlsec_lt_dlcaller_id	xmlsec_lt_dlcaller_register  LT_PARAMS((void));
LT_SCOPE	xmlsec_lt_ptr		xmlsec_lt_dlcaller_set_data  LT_PARAMS((xmlsec_lt_dlcaller_id key,
						xmlsec_lt_dlhandle handle,
						xmlsec_lt_ptr data));
LT_SCOPE	xmlsec_lt_ptr		xmlsec_lt_dlcaller_get_data  LT_PARAMS((xmlsec_lt_dlcaller_id key,
						xmlsec_lt_dlhandle handle));



/* --- USER MODULE LOADER API --- */


typedef	struct xmlsec_lt_dlloader	xmlsec_lt_dlloader;
typedef xmlsec_lt_ptr			xmlsec_lt_user_data;
typedef xmlsec_lt_ptr			xmlsec_lt_module;

/* Function pointer types for creating user defined module loaders. */
typedef xmlsec_lt_module   xmlsec_lt_module_open	LT_PARAMS((xmlsec_lt_user_data loader_data,
					    const char *filename));
typedef int	    xmlsec_lt_module_close	LT_PARAMS((xmlsec_lt_user_data loader_data,
					    xmlsec_lt_module handle));
typedef xmlsec_lt_ptr	    xmlsec_lt_find_sym		LT_PARAMS((xmlsec_lt_user_data loader_data,
					    xmlsec_lt_module handle,
					    const char *symbol));
typedef int	    xmlsec_lt_dlloader_exit	LT_PARAMS((xmlsec_lt_user_data loader_data));

struct xmlsec_lt_user_dlloader {
  const char	       *sym_prefix;
  xmlsec_lt_module_open       *module_open;
  xmlsec_lt_module_close      *module_close;
  xmlsec_lt_find_sym	       *find_sym;
  xmlsec_lt_dlloader_exit     *dlloader_exit;
  xmlsec_lt_user_data		dlloader_data;
};

LT_SCOPE	xmlsec_lt_dlloader    *xmlsec_lt_dlloader_next    LT_PARAMS((xmlsec_lt_dlloader *place));
LT_SCOPE	xmlsec_lt_dlloader    *xmlsec_lt_dlloader_find    LT_PARAMS((
						const char *loader_name));
LT_SCOPE	const char     *xmlsec_lt_dlloader_name    LT_PARAMS((xmlsec_lt_dlloader *place));
LT_SCOPE	xmlsec_lt_user_data   *xmlsec_lt_dlloader_data    LT_PARAMS((xmlsec_lt_dlloader *place));
LT_SCOPE	int		xmlsec_lt_dlloader_add     LT_PARAMS((xmlsec_lt_dlloader *place,
						const struct xmlsec_lt_user_dlloader *dlloader,
						const char *loader_name));
LT_SCOPE	int		xmlsec_lt_dlloader_remove  LT_PARAMS((
						const char *loader_name));



/* --- ERROR MESSAGE HANDLING --- */


/* Defining error strings alongside their symbolic names in a macro in
   this way allows us to expand the macro in different contexts with
   confidence that the enumeration of symbolic names will map correctly
   onto the table of error strings.  */
#define xmlsec_lt_dlerror_table						\
    LT_ERROR(UNKNOWN,		    "unknown error")			\
    LT_ERROR(DLOPEN_NOT_SUPPORTED,  "dlopen support not available")	\
    LT_ERROR(INVALID_LOADER,	    "invalid loader")			\
    LT_ERROR(INIT_LOADER,	    "loader initialization failed")	\
    LT_ERROR(REMOVE_LOADER,	    "loader removal failed")		\
    LT_ERROR(FILE_NOT_FOUND,	    "file not found")			\
    LT_ERROR(DEPLIB_NOT_FOUND,      "dependency library not found")	\
    LT_ERROR(NO_SYMBOLS,	    "no symbols defined")		\
    LT_ERROR(CANNOT_OPEN,	    "can't open the module")		\
    LT_ERROR(CANNOT_CLOSE,	    "can't close the module")		\
    LT_ERROR(SYMBOL_NOT_FOUND,      "symbol not found")			\
    LT_ERROR(NO_MEMORY,		    "not enough memory")		\
    LT_ERROR(INVALID_HANDLE,	    "invalid module handle")		\
    LT_ERROR(BUFFER_OVERFLOW,	    "internal buffer overflow")		\
    LT_ERROR(INVALID_ERRORCODE,     "invalid errorcode")		\
    LT_ERROR(SHUTDOWN,		    "library already shutdown")		\
    LT_ERROR(CLOSE_RESIDENT_MODULE, "can't close resident module")	\
    LT_ERROR(INVALID_MUTEX_ARGS,    "invalid mutex handler registration")

/* Enumerate the symbolic error names. */
enum {
#define LT_ERROR(name, diagnostic)	LT_CONC(LT_ERROR_, name),
	xmlsec_lt_dlerror_table
#undef LT_ERROR

	LT_ERROR_MAX
};

/* These functions are only useful from inside custom module loaders. */
LT_SCOPE	int	xmlsec_lt_dladderror	LT_PARAMS((const char *diagnostic));
LT_SCOPE	int	xmlsec_lt_dlseterror	LT_PARAMS((int errorcode));




/* --- SOURCE COMPATIBILITY WITH OLD LIBLTDL --- */


#ifdef LT_NON_POSIX_NAMESPACE
#  define xmlsec_lt_ptr_t		xmlsec_lt_ptr
#  define xmlsec_lt_module_t		xmlsec_lt_module
#  define xmlsec_lt_module_open_t	xmlsec_lt_module_open
#  define xmlsec_lt_module_close_t	xmlsec_lt_module_close
#  define xmlsec_lt_find_sym_t		xmlsec_lt_find_sym
#  define xmlsec_lt_dlloader_exit_t	xmlsec_lt_dlloader_exit
#  define xmlsec_lt_dlloader_t		xmlsec_lt_dlloader
#  define xmlsec_lt_dlloader_data_t	xmlsec_lt_user_data
#endif

LT_END_C_DECLS

#endif /* !LTDL_H */
