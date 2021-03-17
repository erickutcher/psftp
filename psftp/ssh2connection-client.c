/*
 * Client-specific parts of the SSH-2 connection layer.
 */

#include <assert.h>

#include "putty.h"
#include "ssh.h"
#include "sshbpp.h"
#include "sshppl.h"
#include "sshchan.h"
#include "sshcr.h"
#include "ssh2connection.h"

SshChannel *ssh2_session_open( ConnectionLayer *cl, Channel *chan )
{
	struct ssh2_connection_state *s = container_of( cl, struct ssh2_connection_state, cl );
	struct ssh2_channel *c = snew( struct ssh2_channel );
	PktOut *pktout;

	c->connlayer = s;
	ssh2_channel_init( c );
	c->halfopen = true;
	c->chan = chan;

	pktout = ssh2_chanopen_init( c, "session" );
	pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );

	return &c->sc;
}

static void ssh2_channel_response( struct ssh2_channel *c, PktIn *pkt, void * /*ctx*/ )
{
	/* If pkt==NULL (because this handler has been called in response
	* to CHANNEL_CLOSE arriving while the request was still
	* outstanding), we treat that the same as CHANNEL_FAILURE. */
	chan_request_response( c->chan, pkt && pkt->type == SSH2_MSG_CHANNEL_SUCCESS );
}

void ssh2channel_start_shell( SshChannel *sc, bool want_reply )
{
	struct ssh2_channel *c = container_of( sc, struct ssh2_channel, sc );
	struct ssh2_connection_state *s = c->connlayer;

	PktOut *pktout = ssh2_chanreq_init( c, "shell", want_reply ? ssh2_channel_response : NULL, NULL );
	pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
}

void ssh2channel_start_command( SshChannel *sc, bool want_reply, const char *command )
{
	struct ssh2_channel *c = container_of( sc, struct ssh2_channel, sc );
	struct ssh2_connection_state *s = c->connlayer;

	PktOut *pktout = ssh2_chanreq_init( c, "exec", want_reply ? ssh2_channel_response : NULL, NULL );
	put_stringz( pktout, command );
	pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
}

bool ssh2channel_start_subsystem( SshChannel *sc, bool want_reply, const char *subsystem )
{
	struct ssh2_channel *c = container_of( sc, struct ssh2_channel, sc );
	struct ssh2_connection_state *s = c->connlayer;

	PktOut *pktout = ssh2_chanreq_init( c, "subsystem", want_reply ? ssh2_channel_response : NULL, NULL );
	put_stringz( pktout, subsystem );
	pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );

	return true;
}

bool ssh2channel_send_serial_break( SshChannel *sc, bool want_reply, int length )
{
	struct ssh2_channel *c = container_of( sc, struct ssh2_channel, sc );
	struct ssh2_connection_state *s = c->connlayer;

	PktOut *pktout = ssh2_chanreq_init( c, "break", want_reply ? ssh2_channel_response : NULL, NULL );
	put_uint32( pktout, length );
	pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );

	return true;
}

bool ssh2channel_send_signal( SshChannel *sc, bool want_reply, const char *signame )
{
	struct ssh2_channel *c = container_of( sc, struct ssh2_channel, sc );
	struct ssh2_connection_state *s = c->connlayer;

	PktOut *pktout = ssh2_chanreq_init( c, "signal", want_reply ? ssh2_channel_response : NULL, NULL );
	put_stringz( pktout, signame );
	pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );

	return true;
}
