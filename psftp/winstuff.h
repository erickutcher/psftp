/*
 * winstuff.h: Windows-specific inter-module stuff.
 */

#ifndef PUTTY_WINSTUFF_H
#define PUTTY_WINSTUFF_H

#ifndef AUTO_WINSOCK
#include <winsock2.h>
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>                     /* for FILENAME_MAX */

/* We use uintptr_t for Win32/Win64 portability, so we should in
 * principle include stdint.h, which defines it according to the C
 * standard. But older versions of Visual Studio - including the one
 * used for official PuTTY builds as of 2015-09-28 - don't provide
 * stdint.h at all, but do (non-standardly) define uintptr_t in
 * stddef.h. So here we try to make sure _some_ standard header is
 * included which defines uintptr_t. */
#include <stddef.h>
#if !defined _MSC_VER || _MSC_VER >= 1600 || defined __clang__
#include <stdint.h>
#endif

#include "defs.h"
#include "marshal.h"

#include "tree234.h"

#if defined _M_IX86 || defined _M_AMD64
#define BUILDINFO_PLATFORM "x86 Windows"
#elif defined _M_ARM || defined _M_ARM64
#define BUILDINFO_PLATFORM "Arm Windows"
#else
#define BUILDINFO_PLATFORM "Windows"
#endif

struct Filename
{
	char *path;
};

static __inline FILE *f_open( const Filename *filename, const char *mode, bool /*isprivate*/ )
{
	return fopen( filename->path, mode );
}

#ifndef __WINE__
	/* Up-to-date Windows headers warn that the unprefixed versions of
	 * these names are deprecated. */
	#define stricmp _stricmp
	#define strnicmp _strnicmp
#else
	/* Compiling with winegcc, _neither_ version of these functions
	 * exists. Use the POSIX names. */
	#define stricmp strcasecmp
	#define strnicmp strncasecmp
#endif

/*
 * Dynamically linked functions. These come in two flavours:
 *
 *  - GET_WINDOWS_FUNCTION does not expose "name" to the preprocessor,
 *    so will always dynamically link against exactly what is specified
 *    in "name". If you're not sure, use this one.
 *
 *  - GET_WINDOWS_FUNCTION_PP allows "name" to be redirected via
 *    preprocessor definitions like "#define foo bar"; this is principally
 *    intended for the ANSI/Unicode DoSomething/DoSomethingA/DoSomethingW.
 *    If your function has an argument of type "LPTSTR" or similar, this
 *    is the variant to use.
 *    (However, it can't always be used, as it trips over more complicated
 *    macro trickery such as the WspiapiGetAddrInfo wrapper for getaddrinfo.)
 *
 * (DECL_WINDOWS_FUNCTION works with both these variants.)
 */
#define DECL_WINDOWS_FUNCTION( linkage, rettype, name, params )	\
	typedef rettype ( WINAPI *t_##name ) params;				\
	linkage t_##name p_##name
#define STR1( x ) #x
#define STR( x ) STR1( x )

#define GET_WINDOWS_FUNCTION_PP( module, name )					\
		TYPECHECK( ( t_##name )NULL == name,					\
				   ( p_##name = module ?						\
				   ( t_##name )GetProcAddress( module, STR( name ) ) : NULL ) )

#define GET_WINDOWS_FUNCTION( module, name )					\
		TYPECHECK( ( t_##name )NULL == name,					\
				   ( p_##name = module ?						\
				   ( t_##name )GetProcAddress( module, #name ) : NULL ) )

#define GET_WINDOWS_FUNCTION_NO_TYPECHECK( module, name )		\
				   ( p_##name = module ?						\
				   ( t_##name )GetProcAddress( module, #name ) : NULL )

#define GETTICKCOUNT GetTickCount
#define CURSORBLINK GetCaretBlinkTime()
#define TICKSPERSEC 1000               /* GetTickCount returns milliseconds */

#define DEFAULT_CODEPAGE CP_ACP

#ifndef NO_GSSAPI
/*
 * GSS-API stuff
 */
#define GSS_CC CALLBACK
#endif

/*
 * Exports from winmisc.c.
 */
HMODULE load_system32_dll( const char *libname );

/* A few pieces of up-to-date Windows API definition needed for older
 * compilers. */
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif
#ifndef LOAD_LIBRARY_SEARCH_USER_DIRS
#define LOAD_LIBRARY_SEARCH_USER_DIRS 0x00000400
#endif
#ifndef LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR 0x00000100
#endif
#ifndef DLL_DIRECTORY_COOKIE
typedef PVOID DLL_DIRECTORY_COOKIE;
DECLSPEC_IMPORT DLL_DIRECTORY_COOKIE WINAPI AddDllDirectory ( PCWSTR NewDirectory );
#endif

#endif
