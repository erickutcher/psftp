/*
 * SSH main session channel handling.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "putty.h"
#include "ssh.h"
#include "sshppl.h"
#include "sshchan.h"

static void mainchan_free( Channel *chan );
static void mainchan_open_confirmation( Channel *chan );
static void mainchan_open_failure( Channel *chan );
static size_t mainchan_send( Channel *chan, bool is_stderr, const void *, size_t );
static void mainchan_send_eof( Channel *chan );
static void mainchan_set_input_wanted( Channel *chan, bool wanted );
static bool mainchan_rcvd_exit_status( Channel *chan, int status );
static bool mainchan_rcvd_exit_signal( Channel *chan, ptrlen signame, bool core_dumped, ptrlen msg );
static bool mainchan_rcvd_exit_signal_numeric( Channel *chan, int signum, bool core_dumped, ptrlen msg );
static void mainchan_request_response( Channel *chan, bool success );

static const struct ChannelVtable mainchan_channelvt =
{
	mainchan_free,
	mainchan_open_confirmation,
	mainchan_open_failure,
	mainchan_send,
	mainchan_send_eof,
	mainchan_set_input_wanted,
	chan_default_want_close,
	mainchan_rcvd_exit_status,
	mainchan_rcvd_exit_signal,
	mainchan_rcvd_exit_signal_numeric,
	mainchan_request_response,
};

typedef enum MainChanType
{
	MAINCHAN_SESSION,
	MAINCHAN_DIRECT_TCPIP
} MainChanType;

struct mainchan
{
	SshChannel *sc;
	PacketProtocolLayer *ppl;
	ConnectionLayer *cl;

	MainChanType type;

	bool req_cmd_primary, req_cmd_fallback;
	bool eof_pending, eof_sent, ready;

	Channel chan;
};

mainchan *mainchan_new( PacketProtocolLayer *ppl, ConnectionLayer *cl, SshChannel **sc_out )
{
	mainchan *mc;

	mc = snew( mainchan );
	memset( mc, 0, sizeof( mainchan ) );
	mc->ppl = ppl;
	mc->cl = cl;

	mc->sc = NULL;
	mc->chan.vt = &mainchan_channelvt;
	mc->chan.initial_fixed_window_size = 0;

	mc->sc = ssh_session_open( cl, &mc->chan );
	mc->type = MAINCHAN_SESSION;

	if ( sc_out )
	{
		*sc_out = mc->sc;
	}

	return mc;
}

static void mainchan_free( Channel *chan )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );
	sfree( mc );
}

static void mainchan_try_fallback_command( mainchan *mc );
static void mainchan_ready( mainchan *mc );

static void mainchan_open_confirmation( Channel *chan )
{
	mainchan *mc = container_of( chan, mainchan, chan );

	sshfwd_hint_channel_is_simple( mc->sc );

	if ( mc->type == MAINCHAN_SESSION )
	{
		/*
		* Send the CHANNEL_REQUESTS for the main session channel.
		*/
		char *cmd;

		bool retry_cmd_now = false;

		cmd = g_CONF_remote_cmd;
		if ( g_CONF_ssh_subsys )
		{
			retry_cmd_now = !sshfwd_start_subsystem( mc->sc, true, cmd );
		}
		else if ( *cmd )
		{
			sshfwd_start_command( mc->sc, true, cmd );
		}
		else
		{
			sshfwd_start_shell( mc->sc, true );
		}

		if ( retry_cmd_now )
		{
			mainchan_try_fallback_command( mc );
		}
		else
		{
			mc->req_cmd_primary = true;
		}
	}
	else
	{
		mainchan_ready( mc );
	}
}

static void mainchan_try_fallback_command( mainchan *mc )
{
	const char *cmd = g_CONF_remote_cmd2;
	if ( g_CONF_ssh_subsys2 )
	{
		sshfwd_start_subsystem( mc->sc, true, cmd );
	}
	else
	{
		sshfwd_start_command( mc->sc, true, cmd );
	}
	mc->req_cmd_fallback = true;
}

static void mainchan_request_response( Channel *chan, bool success )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );

	if ( mc->req_cmd_primary )
	{
		mc->req_cmd_primary = false;

		if ( success )
		{
			mainchan_ready( mc );
		}
		else if ( *g_CONF_remote_cmd2 )
		{
			mainchan_try_fallback_command( mc );
		}
		else
		{
			/*
			* If there's no remote_cmd2 configured, then we have no
			* fallback command, so we've run out of options.
			*/
			ssh_sw_abort( mc->ppl->ssh );
		}

		return;
	}

	if ( mc->req_cmd_fallback )
	{
		mc->req_cmd_fallback = false;

		if ( success )
		{
			mc->ppl->ssh->fallback_cmd = true;
			mainchan_ready( mc );
		}
		else
		{
			ssh_sw_abort( mc->ppl->ssh );
		}

		return;
	}
}

static void mainchan_ready( mainchan *mc )
{
	mc->ready = true;

	ssh_set_wants_user_input( mc->cl, true );
	ssh_ppl_got_user_input( mc->ppl ); /* in case any is already queued */

	/* If an EOF arrived before we were ready, handle it now. */
	if ( mc->eof_pending )
	{
		mc->eof_pending = false;
		mainchan_special_cmd( mc, SS_EOF, 0 );
	}

	queue_idempotent_callback( mc->ppl->ssh, &mc->ppl->ic_process_queue );
}

static void mainchan_open_failure( Channel *chan )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );

	ssh_sw_abort_deferred( mc->ppl->ssh );
}

static size_t mainchan_send( Channel *chan, bool is_stderr, const void *data, size_t length )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );

	if ( is_stderr )
	{
		return 0;
	}

	bufchain_add( mc->ppl->ssh, &mc->ppl->ssh->received_data, data, length );
	return 0;
}

static void mainchan_send_eof( Channel *chan )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );

	if ( !mc->eof_sent )
	{
		/*
		* Either seat_eof told us that the front end wants us to
		* close the outgoing side of the connection as soon as we see
		* EOF from the far end, or else we've unilaterally decided to
		* do that because we've allocated a remote pty and hence EOF
		* isn't a particularly meaningful concept.
		*/
		sshfwd_write_eof( mc->sc );
		mc->eof_sent = true;
		ssh_set_wants_user_input( mc->cl, false ); /* stop reading from stdin */
	}
}

static void mainchan_set_input_wanted( Channel *chan, bool wanted )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );

	/*
	* This is the main channel of the SSH session, i.e. the one tied
	* to the standard input (or GUI) of the primary SSH client user
	* interface. So ssh->send_ok is how we control whether we're
	* reading from that input.
	*/
	ssh_set_wants_user_input( mc->cl, wanted );
}

static bool mainchan_rcvd_exit_status( Channel *chan, int status )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );

	ssh_got_exitcode( mc->ppl->ssh, status );
	return true;
}

static bool mainchan_rcvd_exit_signal( Channel *chan, ptrlen signame, bool /*core_dumped*/, ptrlen /*msg*/ )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );
	int exitcode;

	/*
	* Translate the signal description back into a locally meaningful
	* number, or 128 if the string didn't match any we recognise.
	*/
	exitcode = 128;

	#define SIGNAL_SUB( s )							\
		if ( ptrlen_eq_string( signame, #s ) )		\
			exitcode = 128 + SIG ## s;
	#define SIGNAL_MAIN( s, text ) SIGNAL_SUB( s )
	#define SIGNALS_LOCAL_ONLY
	#include "sshsignals.h"
	#undef SIGNAL_SUB
	#undef SIGNAL_MAIN
	#undef SIGNALS_LOCAL_ONLY

	ssh_got_exitcode( mc->ppl->ssh, exitcode );

	return true;
}

static bool mainchan_rcvd_exit_signal_numeric( Channel *chan, int signum, bool /*core_dumped*/, ptrlen /*msg*/ )
{
	assert( chan->vt == &mainchan_channelvt );
	mainchan *mc = container_of( chan, mainchan, chan );

	ssh_got_exitcode( mc->ppl->ssh, 128 + signum );

	return true;
}

void mainchan_get_specials( mainchan * /*mc*/, add_special_fn_t add_special, void *ctx )
{
	/* FIXME: this _does_ depend on whether these services are supported */

	add_special( ctx, "Break", SS_BRK, 0 );

	#define SIGNAL_MAIN( name, desc )	add_special( ctx, "SIG" #name " (" desc ")", SS_SIG ## name, 0 );
	#define SIGNAL_SUB( name )
	#include "sshsignals.h"
	#undef SIGNAL_MAIN
	#undef SIGNAL_SUB

	add_special( ctx, "More signals", SS_SUBMENU, 0 );

	#define SIGNAL_MAIN( name, desc )
	#define SIGNAL_SUB( name )	add_special( ctx, "SIG" #name, SS_SIG ## name, 0 );
	#include "sshsignals.h"
	#undef SIGNAL_MAIN
	#undef SIGNAL_SUB

	add_special( ctx, NULL, SS_EXITMENU, 0 );
}

static const char *ssh_signal_lookup( SessionSpecialCode code )
{
	#define SIGNAL_SUB( name )	if ( code == SS_SIG ## name ) return #name;
	#define SIGNAL_MAIN( name, desc ) SIGNAL_SUB( name )
	#include "sshsignals.h"
	#undef SIGNAL_MAIN
	#undef SIGNAL_SUB

	/* If none of those clauses matched, fail lookup. */
	return NULL;
}

void mainchan_special_cmd( mainchan *mc, SessionSpecialCode code, int /*arg*/ )
{
	const char *signame;

	if ( code == SS_EOF )
	{
		if ( !mc->ready )
		{
			/*
			* Buffer the EOF to send as soon as the main channel is
			* fully set up.
			*/
			mc->eof_pending = true;
		}
		else if ( !mc->eof_sent )
		{
			sshfwd_write_eof( mc->sc );
			mc->eof_sent = true;
		}
	}
	else if ( code == SS_BRK )
	{
		sshfwd_send_serial_break( mc->sc, false, 0 /* default break length */ );
	}
	else if ( ( signame = ssh_signal_lookup( code ) ) != NULL )
	{
		/* It's a signal. */
		sshfwd_send_signal( mc->sc, false, signame );
	}
}
