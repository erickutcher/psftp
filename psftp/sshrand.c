/*
 * sshrand.c: manage the global live PRNG instance.
 */

#include "putty.h"
#include "ssh.h"
#include <assert.h>

void random_add_noise( prng *pr, NoiseSourceId source, const void *noise, int length )
{
	prng_add_entropy( pr, source, make_ptrlen( noise, length ) );
}

void random_timer( void *ctx, unsigned long now )
{
	Ssh *ssh = ( Ssh * )ctx;

	if ( now >= ssh->timer_prng_noise.now )
	{
		noise_regular( ssh->pr );

		ssh->timer_prng_noise.now = now + NOISE_REGULAR_INTERVAL;
	}
}

prng *random_create( const ssh_hashalg *hashalg )
{
	prng *pr;

	pr = prng_new( hashalg );

	prng_seed_begin( pr );
//	noise_get_heavy( prng, random_seed_callback );

	//

	put_data( pr, &pr, sizeof( prng ) );

	HCRYPTPROV crypt_provider;
	if ( CryptAcquireContextA( &crypt_provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) )
	{
		BYTE buf[ 32 ];
		CryptGenRandom( crypt_provider, sizeof( buf ), ( BYTE * )buf );
		CryptReleaseContext( crypt_provider, 0 );

		put_data( pr, buf, sizeof( buf ) );
	}

	DWORD pid = GetCurrentProcessId();
	put_data( pr, &pid, sizeof( pid ) );

	//

	HWND w;
	DWORD z;
	POINT pt;
	MEMORYSTATUS memstat;
	FILETIME times[ 4 ];

	w = GetForegroundWindow();
	put_data( pr, &w, sizeof( w ) );
	w = GetCapture();
	put_data( pr, &w, sizeof( w ) );
	w = GetClipboardOwner();
	put_data( pr, &w, sizeof( w ) );
	z = GetQueueStatus( QS_ALLEVENTS );
	put_data( pr, &z, sizeof( z ) );

	GetCursorPos( &pt );
	put_data( pr, &pt, sizeof( pt ) );

	GlobalMemoryStatus( &memstat );
	put_data( pr, &memstat, sizeof( memstat ) );

	GetThreadTimes( GetCurrentThread(), times, times + 1, times + 2, times + 3 );
	put_data( pr, &times, sizeof( times ) );
	GetProcessTimes( GetCurrentProcess(), times, times + 1, times + 2, times + 3 );
	put_data( pr, &times, sizeof( times ) );

	//

	prng_seed_finish( pr );

	return pr;
}

void random_reseed( prng *pr, ptrlen seed )
{
	prng_seed_begin( pr );
	put_datapl( pr, seed );
	prng_seed_finish( pr );
}

void random_clear( prng *pr )
{
	prng_free( pr );
}

void random_read( prng *pr, void *buf, size_t size )
{
	prng_read( pr, buf, size );
}
