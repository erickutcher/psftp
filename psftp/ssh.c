/*
 * SSH backend.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>

#include "putty.h"
#include "tree234.h"
#include "marshal.h"
#include "ssh.h"
#include "sshcr.h"
#include "sshbpp.h"
#include "sshppl.h"
#include "sshchan.h"
#ifndef NO_GSSAPI
#include "sshgssc.h"
#include "sshgss.h"
#define MIN_CTXT_LIFETIME	5			/* Avoid rekey with short lifetime (seconds) */
#define GSS_KEX_CAPABLE		( 1 << 0 )	/* Can do GSS KEX */
#define GSS_CRED_UPDATED	( 1 << 1 )	/* Cred updated since previous delegation */
#define GSS_CTXT_EXPIRES	( 1 << 2 )	/* Context expires before next timer */
#define GSS_CTXT_MAYFAIL	( 1 << 3 )	/* Context may expire during handshake */
#endif

void ssh_shutdown( Ssh *ssh );
void ssh_throttle_all( Ssh *ssh, bool enable, size_t bufsize );
void ssh_bpp_output_raw_data_callback( Ssh *ssh, void *vctx );

void ssh_connect_bpp( Ssh *ssh )
{
	ssh->bpp->ssh = ssh;
	ssh->bpp->in_raw = &ssh->in_raw;
	ssh->bpp->out_raw = &ssh->out_raw;
	bufchain_set_callback( ssh->bpp->out_raw, &ssh->ic_out_raw );
	ssh->bpp->remote_bugs = ssh->remote_bugs;
}

void ssh_connect_ppl( Ssh *ssh, PacketProtocolLayer *ppl )
{
	ppl->bpp = ssh->bpp;
	ppl->user_input = &ssh->user_input;
	ppl->ssh = ssh;
	ppl->remote_bugs = ssh->remote_bugs;
}

void ssh_got_ssh_version( struct ssh_version_receiver *rcv, int /*major_version*/ )
{
	Ssh *ssh = container_of( rcv, Ssh, version_receiver );
	BinaryPacketProtocol *old_bpp;
	PacketProtocolLayer *connection_layer;

	ssh->session_started = true;

	old_bpp = ssh->bpp;
	ssh->remote_bugs = ssh_verstring_get_bugs( old_bpp );

	PacketProtocolLayer *userauth_layer, *transport_child_layer;

	ssh->bpp = ssh2_bpp_new( &ssh->stats, false );
	ssh_connect_bpp( ssh );

#ifndef NO_GSSAPI
	if ( g_gss_libs == NULL )
	{
		// Creates g_gss_libs
		ssh_gss_setup();
	}

	ssh->gss_state.lib = NULL;

	if ( g_gss_libs != NULL && g_gss_libs->nlibraries > 0 )
	{
		int i, j;
		for ( i = 0; i < ngsslibs; i++ )
		{
			for ( j = 0; j < g_gss_libs->nlibraries; j++ )
			{
				if ( g_gss_libs->libraries[ j ].id == g_CONF_ssh_gsslist[ i ] )
				{
					ssh->gss_state.lib = &g_gss_libs->libraries[ j ];
					goto got_gsslib;   /* double break */
				}
			}
		}
	got_gsslib:
		/*
		* We always expect to have found something in
		* the above loop: we only came here if there
		* was at least one viable GSS library, and the
		* preference list should always mention
		* everything and only change the order.
		*/
		assert( ssh->gss_state.lib );
	}
#endif

	connection_layer = ssh2_connection_new( ssh_verstring_get_remote( old_bpp ), &ssh->cl );
	ssh_connect_ppl( ssh, connection_layer );

	if ( g_CONF_ssh_no_userauth )
	{
		userauth_layer = NULL;
		transport_child_layer = connection_layer;
	}
	else
	{
		userauth_layer = ssh2_userauth_new(
			connection_layer, ssh->fullhostname,
			ssh->keyfile,
			ssh->username,
#ifndef NO_GSSAPI
			( g_CONF_try_gssapi_auth != 0 ? true : false ),
			( g_CONF_try_gssapi_kex != 0 ? true : false ),
			g_CONF_gssapifwd,
			&ssh->gss_state
#else
			false,
			false,
			false,
			NULL
#endif
			);

		ssh_connect_ppl( ssh, userauth_layer );
		transport_child_layer = userauth_layer;
	}

	ssh->base_layer = ssh2_transport_new(
		ssh->fullhostname,
		ssh_verstring_get_local( old_bpp ),
		ssh_verstring_get_remote( old_bpp ),
#ifndef NO_GSSAPI
		&ssh->gss_state,
#else
		NULL,
#endif
		&ssh->stats, transport_child_layer );

	ssh_connect_ppl( ssh, ssh->base_layer );

	if ( userauth_layer )
	{
		ssh2_userauth_set_transport_layer( userauth_layer, ssh->base_layer );
	}

	/* Connect the base layer - whichever it is - to the BPP, and set up its selfptr. */
	ssh->base_layer->selfptr = &ssh->base_layer;
	ssh_ppl_setup_queues( ssh->base_layer, &ssh->bpp->in_pq, &ssh->bpp->out_pq );

	ssh->timer_pinger.now = GetTickCount() + ( g_keep_alive_time * TICKSPERSEC );
	ssh->timer_pinger.ctx = ssh;
	ssh->timer_pinger.fn = pinger_timer;

	queue_idempotent_callback( ssh, &ssh->bpp->ic_in_raw );
	ssh_ppl_process_queue( ssh->base_layer );

	ssh_bpp_free( old_bpp );
}

void ssh_check_frozen( Ssh *ssh )
{
	bool prev_frozen = ssh->socket_frozen;
	ssh->socket_frozen = ( ssh->logically_frozen || bufchain_size( &ssh->in_raw ) > SSH_MAX_BACKLOG );
	if ( prev_frozen && !ssh->socket_frozen && ssh->bpp )
	{
		/*
		* If we've just unfrozen, process any SSH connection data
		* that was stashed in our queue while we were frozen.
		*/
		queue_idempotent_callback( ssh, &ssh->bpp->ic_in_raw );
	}
}

void ssh_conn_processed_data( Ssh *ssh )
{
	ssh_check_frozen( ssh );
}

void ssh_bpp_output_raw_data_callback( Ssh * /*_ssh*/, void *vctx )
{
	Ssh *ssh = ( Ssh * )vctx;

	while ( bufchain_size( &ssh->out_raw ) > 0 )
	{
		size_t backlog;

		ptrlen data = bufchain_prefix( &ssh->out_raw );

		/////

		// Add the data to the buffer list on the socket.
		bufchain_add( ssh, &ssh->output_data, data.ptr, data.len );

		// Now try sending from the start of the buffer list.
		ssh_try_send( ssh, &ssh->wsabuf->buf, ssh->wsabuf->len );

		backlog = bufchain_size( &ssh->output_data );

		/////

		bufchain_consume( &ssh->out_raw, data.len );

		if ( backlog > SSH_MAX_BACKLOG )
		{
			ssh_throttle_all( ssh, true, backlog );
			return;
		}
	}

	ssh_check_frozen( ssh );

	if ( ssh->pending_close )
	{
		bufchain_clear( &ssh->output_data );
	}
}

void ssh_shutdown_internal( Ssh *ssh )
{
	expire_timer_context( &ssh->timer_pinger );

	/*
	* We only need to free the base PPL, which will free the others
	* (if any) transitively.
	*/
	if ( ssh->base_layer )
	{
		ssh_ppl_free( ssh->base_layer );
		ssh->base_layer = NULL;
	}

	ssh->cl = NULL;

	ssh->ssh_status |= SSH_STATUS_CLEANUP;
}

void ssh_shutdown( Ssh *ssh )
{
	ssh_shutdown_internal( ssh );

	if ( ssh->bpp )
	{
		ssh_bpp_free( ssh->bpp );
		ssh->bpp = NULL;
	}

	bufchain_clear( &ssh->output_data );

	bufchain_clear( &ssh->in_raw );
	bufchain_clear( &ssh->out_raw );
	bufchain_clear( &ssh->user_input );
}

void ssh_initiate_connection_close( Ssh *ssh )
{
	/* Wind up everything above the BPP. */
	ssh_shutdown_internal( ssh );

	/* Force any remaining queued SSH packets through the BPP, and
	* schedule closing the network socket after they go out. */
	ssh_bpp_handle_output( ssh->bpp );
	ssh->pending_close = true;
	queue_idempotent_callback( ssh, &ssh->ic_out_raw );

	/* Now we expect the other end to close the connection too in
	* response, so arrange that we'll receive notification of that
	* via ssh_remote_eof. */
	ssh->bpp->expect_close = true;
}

void ssh_remote_error( Ssh *ssh )
{
	if ( ssh->base_layer || !ssh->session_started )
	{
		/* Error messages sent by the remote don't count as clean exits */
		ssh->exitcode = 128;

		ssh_initiate_connection_close( ssh );
	}
}

void ssh_remote_eof( Ssh *ssh )
{
	if ( ssh->base_layer || !ssh->session_started )
	{
		/* EOF from the remote, if we were expecting it, does count as a clean exit */
		ssh->exitcode = 0;
	}

	ssh_initiate_connection_close( ssh );
}

void ssh_proto_error( Ssh *ssh )
{
	if ( ssh->base_layer || !ssh->session_started )
	{
		ssh->exitcode = 128;

		ssh_bpp_queue_disconnect( ssh->bpp, "", SSH2_DISCONNECT_PROTOCOL_ERROR );
		ssh_initiate_connection_close( ssh );
	}
}

void ssh_sw_abort( Ssh *ssh )
{
	if ( ssh->base_layer || !ssh->session_started )
	{
		ssh->exitcode = 128;

		ssh_initiate_connection_close( ssh );
	}
}

void ssh_user_close( Ssh *ssh )
{
	if ( ssh->base_layer || !ssh->session_started )
	{
		/* Closing the connection due to user action, even if the
		* action is the user aborting during authentication prompts,
		* does count as a clean exit - except that this is also how
		* we signal ordinary session termination, in which case we
		* should use the exit status already sent from the main
		* session (if any). */
		if ( ssh->exitcode < 0 )
		{
			ssh->exitcode = 0;
		}

		ssh_initiate_connection_close( ssh );
	}
}

void ssh_deferred_abort_callback( Ssh * /*_ssh*/, void *vctx )
{
	Ssh *ssh = ( Ssh * )vctx;
	ssh_sw_abort( ssh );
}

void ssh_sw_abort_deferred( Ssh *ssh )
{
	queue_toplevel_callback( ssh, ssh_deferred_abort_callback, ssh );
}

/*
 * Throttle or unthrottle the SSH connection.
 */
void ssh_throttle_conn( Ssh *ssh, int adjust )
{
	int old_count = ssh->conn_throttle_count;
	bool frozen;

	ssh->conn_throttle_count += adjust;
	assert( ssh->conn_throttle_count >= 0 );

	if ( ssh->conn_throttle_count && !old_count )
	{
		frozen = true;
	}
	else if ( !ssh->conn_throttle_count && old_count )
	{
		frozen = false;
	}
	else
	{
		return;                /* don't change current frozen state */
	}

	ssh->logically_frozen = frozen;
	ssh_check_frozen( ssh );
}

/*
 * Throttle or unthrottle _all_ local data streams (for when sends
 * on the SSH connection itself back up).
 */
void ssh_throttle_all( Ssh *ssh, bool enable, size_t bufsize )
{
	if ( enable == ssh->throttled_all )
	{
		return;
	}
	ssh->throttled_all = enable;
	ssh->overall_bufsize = bufsize;

	ssh_throttle_all_channels( ssh->cl, enable );
}

void ssh_free( Backend *be )
{
	Ssh *ssh = container_of( be, Ssh, backend );

	ssh_shutdown( ssh );

	filename_free( ssh->keyfile );
	sfree( ssh->ssh_kexlist );
	sfree( ssh->ssh_hklist );
	sfree( ssh->ssh_cipherlist );
	for ( unsigned int i = 0; i < ssh->key_info_count; ++i )
	{
		sfree( ssh->key_info[ i ].algorithm );
		sfree( ssh->key_info[ i ].fingerprint );
	}
	sfree( ssh->key_info );
	sfree( ssh->username );
	if ( ssh->password != NULL )
	{
		smemclr( ssh->password, strlen( ssh->password ) );
		sfree( ssh->password );
	}
	sfree( ssh->fullhostname );
	sfree( ssh->specials );
	sfree( ssh->key_algorithm );
	sfree( ssh->md5_key_fingerprint );
	sfree( ssh->sha256_key_fingerprint );

#ifndef NO_GSSAPI
	if ( ssh->gss_state.srv_name )
	{
		ssh->gss_state.lib->release_name( ssh->gss_state.lib, &ssh->gss_state.srv_name );
	}
	if ( ssh->gss_state.ctx != NULL )
	{
		ssh->gss_state.lib->release_cred( ssh->gss_state.lib, &ssh->gss_state.ctx );
	}
#endif

	delete_callbacks_for_context( ssh, ssh ); /* likely to catch ic_out_raw */

	expire_timer_context( &ssh->timer_prng_noise );
	random_clear( ssh->pr );

	sfree( ssh );
}

bool ssh_try_send( Ssh *ssh, CHAR **buffer, ULONG &buffer_length )
{
	if ( bufchain_size( &ssh->output_data ) > 0 )
	{
		ptrlen bufdata = bufchain_prefix( &ssh->output_data );

		*buffer = ( CHAR * )bufdata.ptr;
		buffer_length = min( bufdata.len, INT_MAX );

		ssh->ssh_status |= SSH_STATUS_WRITE;

		return true;
	}
	else
	{
		return false;
	}
}

/*
 * Called to send data down the SSH connection.
 */
size_t ssh_send( Backend *be, const char *buf, size_t len )
{
	Ssh *ssh = container_of( be, Ssh, backend );

	if ( ssh == NULL )
	{
		return 0;
	}

	bufchain_add( ssh, &ssh->user_input, buf, len );
	if ( ssh->base_layer )
	{
		ssh_ppl_got_user_input( ssh->base_layer );
	}

	return backend_sendbuffer( &ssh->backend );
}

/*
 * Called to query the current amount of buffered stdin data.
 */
size_t ssh_sendbuffer( Backend *be )
{
	Ssh *ssh = container_of( be, Ssh, backend );
	size_t backlog;

	if ( ssh == NULL || ssh->cl == NULL )
	{
		return 0;
	}

	backlog = ssh_stdin_backlog( ssh->cl );

	if ( ssh->base_layer )
	{
		backlog += ssh_ppl_queued_data_size( ssh->base_layer );
	}

	/*
	* If the SSH socket itself has backed up, add the total backup
	* size on that to any individual buffer on the stdin channel.
	*/
	if ( ssh->throttled_all )
	{
		backlog += ssh->overall_bufsize;
	}

	return backlog;
}

void ssh_add_special( void *vctx, const char *text, SessionSpecialCode code, int arg )
{
	struct ssh_add_special_ctx *ctx = ( struct ssh_add_special_ctx * )vctx;
	SessionSpecial *spec;

	sgrowarray( SessionSpecial *, ctx->specials, ctx->specials_size, ctx->nspecials );
	spec = &ctx->specials[ ctx->nspecials++ ];
	spec->name = text;
	spec->code = code;
	spec->arg = arg;
}

/*
 * Return a list of the special codes that make sense in this
 * protocol.
 */
const SessionSpecial *ssh_get_specials( Backend *be )
{
	Ssh *ssh = container_of( be, Ssh, backend );

	/*
	* Ask all our active protocol layers what specials they've got,
	* and amalgamate the list into one combined one.
	*/

	struct ssh_add_special_ctx ctx;

	ctx.specials = NULL;
	ctx.nspecials = ctx.specials_size = 0;

	if ( ssh->base_layer )
	{
		ssh_ppl_get_specials( ssh->base_layer, ssh_add_special, &ctx );
	}

	if ( ctx.specials )
	{
		/* If the list is non-empty, terminate it with a SS_EXITMENU. */
		ssh_add_special( &ctx, NULL, SS_EXITMENU, 0 );
	}

	sfree( ssh->specials );
	ssh->specials = ctx.specials;
	return ssh->specials;
}

/*
 * Send special codes.
 */
void ssh_special( Backend *be, SessionSpecialCode code, int arg )
{
	Ssh *ssh = container_of( be, Ssh, backend );

	if ( ssh->base_layer )
	{
		ssh_ppl_special_cmd( ssh->base_layer, code, arg );
	}
}

bool ssh_connected( Backend *be )
{
	Ssh *ssh = container_of( be, Ssh, backend );
	return ssh != NULL;
}

bool ssh_sendok( Backend *be )
{
	Ssh *ssh = container_of( be, Ssh, backend );
	return ssh->base_layer && ssh_ppl_want_user_input( ssh->base_layer );
}

void ssh_got_exitcode( Ssh *ssh, int exitcode )
{
	ssh->exitcode = exitcode;
}

int ssh_return_exitcode( Backend *be )
{
	Ssh *ssh = container_of( be, Ssh, backend );
	if ( ( !ssh->session_started || ssh->base_layer ) )
	{
		return -1;
	}
	else
	{
		return ( ssh->exitcode >= 0 ? ssh->exitcode : INT_MAX );
	}
}

const struct BackendVtable ssh_backend =
{
    ssh_free,
    ssh_send,
    ssh_sendbuffer,
    ssh_special,
    ssh_get_specials,
    ssh_connected,
    ssh_return_exitcode,
    ssh_sendok
};
