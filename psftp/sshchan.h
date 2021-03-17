/*
 * Abstraction of the various ways to handle the local end of an SSH
 * connection-layer channel.
 */

#ifndef PUTTY_SSHCHAN_H
#define PUTTY_SSHCHAN_H

struct ChannelVtable
{
	void ( *free )( Channel * );

	/* Called for channel types that were created at the same time as
	* we sent an outgoing CHANNEL_OPEN, when the confirmation comes
	* back from the server indicating that the channel has been
	* opened, or the failure message indicating that it hasn't,
	* respectively. In the latter case, this must _not_ free the
	* Channel structure - the client will call the free method
	* separately. But it might do logging or other local cleanup. */
	void ( *open_confirmation )( Channel * );
	void ( *open_failed )( Channel * );

	size_t ( *send )( Channel *, bool is_stderr, const void *buf, size_t len );
	void ( *send_eof )( Channel * );
	void ( *set_input_wanted )( Channel *, bool wanted );

	bool ( *want_close )( Channel *, bool sent_local_eof, bool rcvd_remote_eof );

	/* A method for every channel request we know of. All of these
	* return true for success or false for failure. */
	bool ( *rcvd_exit_status )( Channel *, int status );
	bool ( *rcvd_exit_signal )( Channel *chan, ptrlen signame, bool core_dumped, ptrlen msg );
	bool ( *rcvd_exit_signal_numeric )( Channel *chan, int signum, bool core_dumped, ptrlen msg );

	/* A method for signalling success/failure responses to channel
	* requests initiated from the SshChannel vtable with want_reply
	* true. */
	void ( *request_response )( Channel *, bool success );
};

struct Channel
{
	const struct ChannelVtable *vt;
	unsigned initial_fixed_window_size;
};

static __inline void chan_free( Channel *ch )
{ ch->vt->free( ch ); }
static __inline void chan_open_confirmation( Channel *ch )
{ ch->vt->open_confirmation( ch ); }
static __inline void chan_open_failed( Channel *ch )
{ ch->vt->open_failed( ch ); }
static __inline size_t chan_send( Channel *ch, bool err, const void *buf, size_t len )
{ return ch->vt->send( ch, err, buf, len ); }
static __inline void chan_send_eof( Channel *ch )
{ ch->vt->send_eof( ch ); }
static __inline void chan_set_input_wanted( Channel *ch, bool wanted )
{ ch->vt->set_input_wanted( ch, wanted ); }
static __inline bool chan_want_close( Channel *ch, bool leof, bool reof )
{ return ch->vt->want_close( ch, leof, reof ); }
static __inline bool chan_rcvd_exit_status( Channel *ch, int status )
{ return ch->vt->rcvd_exit_status( ch, status ); }
static __inline bool chan_rcvd_exit_signal( Channel *ch, ptrlen sig, bool core, ptrlen msg )
{ return ch->vt->rcvd_exit_signal( ch, sig, core, msg ); }
static __inline bool chan_rcvd_exit_signal_numeric( Channel *ch, int sig, bool core, ptrlen msg )
{ return ch->vt->rcvd_exit_signal_numeric( ch, sig, core, msg ); }

static __inline void chan_request_response( Channel *ch, bool success )
{ ch->vt->request_response( ch, success ); }

/*
 * Reusable methods you can put in vtables to give default handling of
 * some of those functions.
 */

/* want_close for any channel that wants the default behaviour of not
 * closing until both directions have had an EOF */
bool chan_default_want_close( Channel *, bool, bool );

/* default implementations that refuse all the channel requests */
bool chan_no_exit_status( Channel *, int );
bool chan_no_exit_signal( Channel *, ptrlen, bool, ptrlen );
bool chan_no_exit_signal_numeric( Channel *, int, bool, ptrlen );

/* default implementation that never expects to receive a response */
void chan_no_request_response( Channel *, bool );

/*
 * Constructor for a trivial do-nothing implementation of
 * ChannelVtable. Used for 'zombie' channels, i.e. channels whose
 * proper local source of data has been shut down or otherwise stopped
 * existing, but the SSH side is still there and needs some kind of a
 * Channel implementation to talk to. In particular, the want_close
 * method for this channel always returns 'yes, please close this
 * channel asap', regardless of whether local and/or remote EOF have
 * been sent - indeed, even if _neither_ has.
 */
Channel *zombiechan_new( void );

/* ----------------------------------------------------------------------
 * This structure is owned by an SSH connection layer, and identifies
 * the connection layer's end of the channel, for the Channel
 * implementation to talk back to.
 */

struct SshChannelVtable
{
    size_t ( *write )( Ssh *ssh, SshChannel *c, bool is_stderr, const void *, size_t );
    void ( *write_eof )( SshChannel *c );

    /*
     * All the outgoing channel requests we support. Each one has a
     * want_reply flag, which will cause a callback to
     * chan_request_response when the result is available.
     *
     * The ones that return 'bool' use it to indicate that the SSH
     * protocol in use doesn't support this request at all.
     *
     * (It's also intentional that not all of them have a want_reply
     * flag: the ones that don't are because SSH-1 has no method for
     * signalling success or failure of that request, or because we
     * wouldn't do anything usefully different with the reply in any
     * case.)
     */
    void ( *start_shell )( SshChannel *c, bool want_reply );
    void ( *start_command )( SshChannel *c, bool want_reply, const char *command );
    bool ( *start_subsystem )( SshChannel *c, bool want_reply, const char *subsystem );
    bool ( *send_serial_break )( SshChannel *c, bool want_reply, int length ); /* length=0 for default */
    bool ( *send_signal )( SshChannel *c, bool want_reply, const char *signame );
    void ( *hint_channel_is_simple )( SshChannel *c );
};

struct SshChannel
{
	const struct SshChannelVtable *vt;
	ConnectionLayer *cl;
};

static __inline size_t sshfwd_write_ext( Ssh *ssh, SshChannel *c, bool is_stderr, const void *data, size_t len )
{ return c->vt->write( ssh, c, is_stderr, data, len ); }
static __inline size_t sshfwd_write( Ssh *ssh, SshChannel *c, const void *data, size_t len )
{ return sshfwd_write_ext( ssh, c, false, data, len ); }
static __inline void sshfwd_write_eof( SshChannel *c )
{ c->vt->write_eof( c ); }
static __inline void sshfwd_start_shell( SshChannel *c, bool want_reply )
{ c->vt->start_shell( c, want_reply ); }
static __inline void sshfwd_start_command( SshChannel *c, bool want_reply, const char *command )
{ c->vt->start_command( c, want_reply, command ); }
static __inline bool sshfwd_start_subsystem( SshChannel *c, bool want_reply, const char *subsystem )
{ return c->vt->start_subsystem( c, want_reply, subsystem ); }
static __inline bool sshfwd_send_serial_break( SshChannel *c, bool want_reply, int length )
{ return c->vt->send_serial_break( c, want_reply, length ); }
static __inline bool sshfwd_send_signal( SshChannel *c, bool want_reply, const char *signame )
{ return c->vt->send_signal( c, want_reply, signame ); }
static __inline void sshfwd_hint_channel_is_simple( SshChannel *c )
{ c->vt->hint_channel_is_simple( c ); }

/* ----------------------------------------------------------------------
 * The 'main' or primary channel of the SSH connection is special,
 * because it's the one that's connected directly to parts of the
 * frontend such as the terminal and the specials menu. So it exposes
 * a richer API.
 */

mainchan *mainchan_new( PacketProtocolLayer *ppl, ConnectionLayer *cl, SshChannel **sc_out );
void mainchan_get_specials( mainchan *mc, add_special_fn_t add_special, void *ctx );
void mainchan_special_cmd( mainchan *mc, SessionSpecialCode code, int arg );

#endif /* PUTTY_SSHCHAN_H */
