/*
 * Header for misc.c.
 */

#ifndef PUTTY_MISC_H
#define PUTTY_MISC_H

#include "defs.h"
#include "puttymem.h"
#include "marshal.h"

#include <stdio.h>                     /* for FILE * */
#include <stdarg.h>                    /* for va_list */
#include <stdlib.h>                    /* for abort */
#include <time.h>                      /* for struct tm */
#include <limits.h>                    /* for INT_MAX/MIN */
#include <assert.h>                    /* for assert (obviously) */

unsigned long parse_blocksize( const char *bs );
char ctrlparse( char *s, char **next );

size_t host_strcspn( const char *s, const char *set );
char *host_strchr( const char *s, int c );
char *host_strrchr( const char *s, int c );
char *host_strduptrim( const char *s );

char *dupstr( const char *s );
char *dupcat_fn( const char *s1, ... );
#define dupcat( ... ) dupcat_fn( __VA_ARGS__, ( const char * )NULL )
char *dupprintf( const char *fmt, ... ) PRINTF_LIKE( 1, 2 );
char *dupvprintf( const char *fmt, va_list ap );
void burnstr( char *string );

/*
 * The visible part of a strbuf structure. There's a surrounding
 * implementation struct in misc.c, which isn't exposed to client
 * code.
 */
struct strbuf
{
	char *s;
	unsigned char *u;
	size_t len;
	BinarySink_IMPLEMENTATION;
};

/* strbuf constructors: strbuf_new_nm and strbuf_new differ in that a
 * strbuf constructed using the _nm version will resize itself by
 * alloc/copy/smemclr/free instead of realloc. Use that version for
 * data sensitive enough that it's worth costing performance to
 * avoid copies of it lingering in process memory. */
strbuf *strbuf_new( void );
strbuf *strbuf_new_nm( void );

void strbuf_free( strbuf *buf );
void *strbuf_append( strbuf *buf, size_t len );
void strbuf_shrink_to( strbuf *buf, size_t new_len );
void strbuf_shrink_by( strbuf *buf, size_t amount_to_remove );
char *strbuf_to_str( strbuf *buf ); /* does free buf, but you must free result */
void strbuf_catf( strbuf *buf, const char *fmt, ... ) PRINTF_LIKE( 2, 3 );
void strbuf_catfv( strbuf *buf, const char *fmt, va_list ap );
static __inline void strbuf_clear( strbuf *buf ) { strbuf_shrink_to( buf, 0 ); }
bool strbuf_chomp( strbuf *buf, char char_to_remove );

strbuf *strbuf_new_for_agent_query( void );
void strbuf_finalise_agent_query( strbuf *buf );

/* String-to-Unicode converters that auto-allocate the destination and
 * work around the rather deficient interface of mb_to_wc.
 *
 * These actually live in miscucs.c, not misc.c (the distinction being
 * that the former is only linked into tools that also have the main
 * Unicode support). */
wchar_t *dup_mb_to_wc_c( int codepage, int flags, const char *string, int len );
wchar_t *dup_mb_to_wc( int codepage, int flags, const char *string );

static __inline int toint( unsigned u )
{
    /*
     * Convert an unsigned to an int, without running into the
     * undefined behaviour which happens by the strict C standard if
     * the value overflows. You'd hope that sensible compilers would
     * do the sensible thing in response to a cast, but actually I
     * don't trust modern compilers not to do silly things like
     * assuming that _obviously_ you wouldn't have caused an overflow
     * and so they can elide an 'if (i < 0)' test immediately after
     * the cast.
     *
     * Sensible compilers ought of course to optimise this entire
     * function into 'just return the input value', and since it's
     * also declared inline, elide it completely in their output.
     */
    if ( u <= ( unsigned )INT_MAX )
	{
        return ( int )u;
	}
    else if ( u >= ( unsigned )INT_MIN )   /* wrap in cast _to_ unsigned is OK */
	{
        return INT_MIN + ( int )( u - ( unsigned )INT_MIN );
	}
    else
	{
        return INT_MIN; /* fallback; should never occur on binary machines */
	}
}

char *fgetline( FILE *fp );
bool read_file_into( BinarySink *bs, FILE *fp );
char *chomp( char *str );
bool strstartswith( const char *s, const char *t );
bool strendswith( const char *s, const char *t );

void base64_encode_atom( const unsigned char *data, int n, char *out );
int base64_decode_atom( const char *atom, unsigned char *out );

struct bufchain_granule;
struct bufchain_tag
{
	struct bufchain_granule *head, *tail;
	size_t buffersize;           /* current amount of buffered data */

	void ( *queue_idempotent_callback )( Ssh *ssh, IdempotentCallback *ic );
	IdempotentCallback *ic;
};

void bufchain_init( bufchain *ch );
void bufchain_clear( bufchain *ch );
size_t bufchain_size( bufchain *ch );
void bufchain_add( Ssh *ssh, bufchain *ch, const void *data, size_t len );
ptrlen bufchain_prefix( bufchain *ch );
void bufchain_consume( bufchain *ch, size_t len );
void bufchain_fetch( bufchain *ch, void *data, size_t len );
void bufchain_fetch_consume( bufchain *ch, void *data, size_t len );
bool bufchain_try_fetch_consume( bufchain *ch, void *data, size_t len );
size_t bufchain_fetch_consume_up_to( bufchain *ch, void *data, size_t len );
void bufchain_set_callback_inner( bufchain *ch, IdempotentCallback *ic, void ( *queue_idempotent_callback )( Ssh *ssh, IdempotentCallback *ic ) );
static __inline void bufchain_set_callback( bufchain *ch, IdempotentCallback *ic )
{
	extern void queue_idempotent_callback( Ssh *ssh, struct IdempotentCallback *ic );
	/* Wrapper that puts in the standard queue_idempotent_callback
	* function. Lives here rather than in utils.c so that standalone
	* programs can use the bufchain facility without this optional
	* callback feature and not need to provide a stub of
	* queue_idempotent_callback. */
	bufchain_set_callback_inner( ch, ic, queue_idempotent_callback );
}

/*
 * Special form of strcmp which can cope with NULL inputs. NULL is
 * defined to sort before even the empty string.
 */
int nullstrcmp( const char *a, const char *b );

static __inline ptrlen make_ptrlen( const void *ptr, size_t len )
{
	ptrlen pl;
	pl.ptr = ptr;
	pl.len = len;
	return pl;
}

static __inline ptrlen ptrlen_from_asciz( const char *str )
{
	return make_ptrlen( str, strlen( str ) );
}

static __inline ptrlen ptrlen_from_strbuf( strbuf *sb )
{
	return make_ptrlen( sb->u, sb->len );
}

bool ptrlen_eq_string( ptrlen pl, const char *str );
bool ptrlen_eq_ptrlen( ptrlen pl1, ptrlen pl2 );
int ptrlen_strcmp( ptrlen pl1, ptrlen pl2 );
/* ptrlen_startswith and ptrlen_endswith write through their 'tail'
 * argument if and only if it is non-NULL and they return true. Hence
 * you can write ptrlen_startswith(thing, prefix, &thing), writing
 * back to the same ptrlen it read from, to remove a prefix if present
 * and say whether it did so. */
bool ptrlen_startswith( ptrlen whole, ptrlen prefix, ptrlen *tail );
bool ptrlen_endswith( ptrlen whole, ptrlen suffix, ptrlen *tail );
ptrlen ptrlen_get_word( ptrlen *input, const char *separators );
char *mkstr( ptrlen pl );
int string_length_for_printf( size_t );
/* Derive two printf arguments from a ptrlen, suitable for "%.*s" */
#define PTRLEN_PRINTF( pl )	string_length_for_printf( ( pl ).len ), ( const char * )( pl ).ptr
/* Make a ptrlen out of a compile-time string literal. We try to
 * enforce that it _is_ a string literal by token-pasting "" on to it,
 * which should provoke a compile error if it's any other kind of
 * string. */
#define PTRLEN_LITERAL( stringlit )	TYPECHECK( "" stringlit "", make_ptrlen( stringlit, sizeof( stringlit ) - 1 ) )
/* Make a ptrlen out of a constant byte array. */
#define PTRLEN_FROM_CONST_BYTES( a )	make_ptrlen( a, sizeof( a ) )

/* Wipe sensitive data out of memory that's about to be freed. Simpler
 * than memset because we don't need the fill char parameter; also
 * attempts (by fiddly use of volatile) to inhibit the compiler from
 * over-cleverly trying to optimise the memset away because it knows
 * the variable is going out of scope. */
void smemclr( void *b, size_t len );

/* Compare two fixed-length chunks of memory for equality, without
 * data-dependent control flow (so an attacker with a very accurate
 * stopwatch can't try to guess where the first mismatching byte was).
 * Returns false for mismatch or true for equality (unlike memcmp),
 * hinted at by the 'eq' in the name. */
bool smemeq( const void *av, const void *bv, size_t len );

/*
 * A function you can put at points in the code where execution should
 * never reach in the first place. Better than assert(false), or even
 * assert(false && "some explanatory message"), because some compilers
 * don't interpret assert(false) as a declaration of unreachability,
 * so they may still warn about pointless things like some variable
 * not being initialised on the unreachable code path.
 *
 * I follow the assertion with a call to abort() just in case someone
 * compiles with -DNDEBUG, and I wrap that abort inside my own
 * function labelled NORETURN just in case some unusual kind of system
 * header wasn't foresighted enough to label abort() itself that way.
 */
//static __inline NORETURN void unreachable_internal( void ) { abort(); }
//#define unreachable( msg )	( assert( false && msg ), unreachable_internal() )

#ifndef lenof
#define lenof( x ) ( ( sizeof( ( x ) ) ) / ( sizeof( *( x ) ) ) )
#endif

#ifndef min
#define min( x, y ) ( ( x ) < ( y ) ? ( x ) : ( y ) )
#endif
#ifndef max
#define max( x, y ) ( ( x ) > ( y ) ? ( x ) : ( y ) )
#endif

static __inline uint64_t GET_64BIT_LSB_FIRST( const void *vp )
{
	const uint8_t *p = ( const uint8_t * )vp;
	return ( ( ( uint64_t )p[ 0 ]       ) | ( ( uint64_t )p[ 1 ] <<  8 ) |
			 ( ( uint64_t )p[ 2 ] << 16 ) | ( ( uint64_t )p[ 3 ] << 24 ) |
			 ( ( uint64_t )p[ 4 ] << 32 ) | ( ( uint64_t )p[ 5 ] << 40 ) |
			 ( ( uint64_t )p[ 6 ] << 48 ) | ( ( uint64_t )p[ 7 ] << 56 ) );
}

static __inline void PUT_64BIT_LSB_FIRST( void *vp, uint64_t value )
{
	uint8_t *p = ( uint8_t * )vp;
	p[ 0 ] = ( uint8_t )( value );
	p[ 1 ] = ( uint8_t )( value >> 8 );
	p[ 2 ] = ( uint8_t )( value >> 16 );
	p[ 3 ] = ( uint8_t )( value >> 24 );
	p[ 4 ] = ( uint8_t )( value >> 32 );
	p[ 5 ] = ( uint8_t )( value >> 40 );
	p[ 6 ] = ( uint8_t )( value >> 48 );
	p[ 7 ] = ( uint8_t )( value >> 56 );
}

static __inline uint32_t GET_32BIT_LSB_FIRST(const void *vp)
{
	const uint8_t *p = ( const uint8_t * )vp;
	return ( ( ( uint32_t )p[ 0 ]       ) | ( ( uint32_t )p[ 1 ] <<  8 ) |
			 ( ( uint32_t )p[ 2 ] << 16 ) | ( ( uint32_t )p[ 3 ] << 24 ) );
}

static __inline void PUT_32BIT_LSB_FIRST( void *vp, uint32_t value )
{
	uint8_t *p = ( uint8_t * )vp;
	p[ 0 ] = ( uint8_t )( value );
	p[ 1 ] = ( uint8_t )( value >> 8 );
	p[ 2 ] = ( uint8_t )( value >> 16 );
	p[ 3 ] = ( uint8_t )( value >> 24 );
}

static __inline uint16_t GET_16BIT_LSB_FIRST( const void *vp )
{
	const uint8_t *p = ( const uint8_t * )vp;
	return ( ( ( uint16_t )p[ 0 ]      ) | ( ( uint16_t )p[ 1 ] <<  8 ) );
}

static __inline void PUT_16BIT_LSB_FIRST( void *vp, uint16_t value )
{
	uint8_t *p = ( uint8_t * )vp;
	p[ 0 ] = ( uint8_t )( value );
	p[ 1 ] = ( uint8_t )( value >> 8 );
}

static __inline uint64_t GET_64BIT_MSB_FIRST( const void *vp )
{
	const uint8_t *p = ( const uint8_t * )vp;
	return ( ( ( uint64_t )p[ 7 ]       ) | ( ( uint64_t )p[ 6 ] <<  8 ) |
			 ( ( uint64_t )p[ 5 ] << 16 ) | ( ( uint64_t )p[ 4 ] << 24 ) |
			 ( ( uint64_t )p[ 3 ] << 32 ) | ( ( uint64_t )p[ 2 ] << 40 ) |
			 ( ( uint64_t )p[ 1 ] << 48 ) | ( ( uint64_t )p[ 0 ] << 56 ) );
}

static __inline void PUT_64BIT_MSB_FIRST( void *vp, uint64_t value )
{
	uint8_t *p = ( uint8_t * )vp;
	p[ 7 ] = ( uint8_t )( value );
	p[ 6 ] = ( uint8_t )( value >> 8 );
	p[ 5 ] = ( uint8_t )( value >> 16 );
	p[ 4 ] = ( uint8_t )( value >> 24 );
	p[ 3 ] = ( uint8_t )( value >> 32 );
	p[ 2 ] = ( uint8_t )( value >> 40 );
	p[ 1 ] = ( uint8_t )( value >> 48 );
	p[ 0 ] = ( uint8_t )( value >> 56 );
}

static __inline uint32_t GET_32BIT_MSB_FIRST( const void *vp )
{
	const uint8_t *p = ( const uint8_t * )vp;
	return ( ( ( uint32_t )p[ 3 ]       ) | ( ( uint32_t )p[ 2 ] <<  8) |
			 ( ( uint32_t )p[ 1 ] << 16 ) | ( ( uint32_t )p[ 0 ] << 24 ) );
}

static __inline void PUT_32BIT_MSB_FIRST( void *vp, uint32_t value )
{
	uint8_t *p = ( uint8_t * )vp;
	p[ 3 ] = ( uint8_t )( value );
	p[ 2 ] = ( uint8_t )( value >> 8 );
	p[ 1 ] = ( uint8_t )( value >> 16 );
	p[ 0 ] = ( uint8_t )( value >> 24 );
}

static __inline uint16_t GET_16BIT_MSB_FIRST(const void *vp)
{
	const uint8_t *p = ( const uint8_t * )vp;
	return ( ( ( uint16_t )p[ 1 ]      ) | ( ( uint16_t )p[ 0 ] <<  8 ) );
}

static __inline void PUT_16BIT_MSB_FIRST( void *vp, uint16_t value )
{
	uint8_t *p = ( uint8_t * )vp;
	p[ 1 ] = ( uint8_t )( value );
	p[ 0 ] = ( uint8_t )( value >> 8 );
}

#endif
