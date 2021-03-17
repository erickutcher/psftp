/*
 * winmisc.c: miscellaneous Windows-specific things
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "putty.h"

Filename *filename_from_str( const char *str )
{
	Filename *ret = snew( Filename );
	ret->path = dupstr( str );
	return ret;
}

Filename *filename_copy( const Filename *fn )
{
	return ( fn != NULL ? filename_from_str( fn->path ) : NULL );
}

const char *filename_to_str( const Filename *fn )
{
	return ( fn != NULL ? fn->path : NULL );
}

bool filename_equal( const Filename *f1, const Filename *f2 )
{
	return !strcmp( f1->path, f2->path );
}

bool filename_is_null( const Filename *fn )
{
	return !*fn->path;
}

void filename_free( Filename *fn )
{
	if ( fn != NULL )
	{
		sfree( fn->path );
		sfree( fn);
	}
}

void filename_serialise( BinarySink *bs, const Filename *f )
{
	put_asciz( bs, f->path );
}
Filename *filename_deserialise( BinarySource *src )
{
	return filename_from_str( get_asciz( src ) );
}

char filename_char_sanitise( char c )
{
	if ( strchr( "<>:\"/\\|?*", c ) )
	{
		return '.';
	}
	return c;
}

HMODULE load_system32_dll( const char *libname )
{
	/*
	* Wrapper function to load a DLL out of c:\windows\system32
	* without going through the full DLL search path. (Hence no
	* attack is possible by placing a substitute DLL earlier on that
	* path.)
	*/
	static char *sysdir = NULL;
	static size_t sysdirsize = 0;
	char *fullpath;
	HMODULE ret;

	if ( !sysdir )
	{
		size_t len;
		while ( ( len = GetSystemDirectory( sysdir, sysdirsize ) ) >= sysdirsize )
		{
			sgrowarray( char *, sysdir, sysdirsize, len );
		}
	}

	fullpath = dupcat( sysdir, "\\", libname );
	ret = LoadLibrary( fullpath );
	sfree( fullpath );
	return ret;
}
