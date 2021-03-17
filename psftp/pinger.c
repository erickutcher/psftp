/*
 * pinger.c: centralised module that deals with sending SS_PING
 * keepalives, to avoid replicating this code in multiple backends.
 */

#include "putty.h"
#include "ssh.h"

void pinger_timer( void *ctx, unsigned long now )
{
	Ssh *ssh = ( Ssh * )ctx;

	if ( g_keep_alive_time > 0 )
	{
		if ( now >= ssh->timer_pinger.now )
		{
			backend_special( &ssh->backend, SS_PING, 0 );

			ssh->timer_pinger.now = now + ( g_keep_alive_time * TICKSPERSEC );
		}
	}
}
