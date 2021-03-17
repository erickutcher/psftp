/*
 * Packet protocol layer for the SSH-2 connection protocol (RFC 4254).
 */

#include <assert.h>

#include "putty.h"
#include "ssh.h"
#include "sshbpp.h"
#include "sshppl.h"
#include "sshchan.h"
#include "sshcr.h"
#include "ssh2connection.h"

static void ssh2_connection_free( PacketProtocolLayer * );
static void ssh2_connection_process_queue( PacketProtocolLayer * );
static bool ssh2_connection_get_specials( PacketProtocolLayer *ppl, add_special_fn_t add_special, void *ctx );
static void ssh2_connection_special_cmd( PacketProtocolLayer *ppl, SessionSpecialCode code, int arg );
static bool ssh2_connection_want_user_input( PacketProtocolLayer *ppl );
static void ssh2_connection_got_user_input( PacketProtocolLayer *ppl );
static void ssh2_connection_reconfigure( PacketProtocolLayer *ppl );

static const struct PacketProtocolLayerVtable ssh2_connection_vtable =
{
	ssh2_connection_free,
	ssh2_connection_process_queue,
	ssh2_connection_get_specials,
	ssh2_connection_special_cmd,
	ssh2_connection_want_user_input,
	ssh2_connection_got_user_input,
	ssh2_connection_reconfigure,
	ssh_ppl_default_queued_data_size,
	"ssh-connection",
};

static size_t ssh2_stdin_backlog( ConnectionLayer *cl );
static void ssh2_throttle_all_channels( ConnectionLayer *cl, bool throttled );
static void ssh2_set_wants_user_input( ConnectionLayer *cl, bool wanted );

static const struct ConnectionLayerVtable ssh2_connlayer_vtable =
{
	ssh2_session_open,
	ssh2_stdin_backlog,
	ssh2_throttle_all_channels,
	ssh2_set_wants_user_input,
};

static size_t ssh2channel_write( Ssh *ssh, SshChannel *c, bool is_stderr, const void *buf, size_t len );
static void ssh2channel_write_eof( SshChannel *c );
static void ssh2channel_hint_channel_is_simple( SshChannel *c );

static const struct SshChannelVtable ssh2channel_vtable =
{
	ssh2channel_write,
	ssh2channel_write_eof,
	ssh2channel_start_shell,
	ssh2channel_start_command,
	ssh2channel_start_subsystem,
	ssh2channel_send_serial_break,
	ssh2channel_send_signal,
	ssh2channel_hint_channel_is_simple,
};

static void ssh2_channel_check_close( struct ssh2_channel *c );
static void ssh2_channel_try_eof( struct ssh2_channel *c );
static void ssh2_set_window( struct ssh2_channel *c, int newwin );
static size_t ssh2_try_send( struct ssh2_channel *c );
static void ssh2_try_send_and_unthrottle( struct ssh2_channel *c );
static void ssh2_channel_check_throttle( struct ssh2_channel *c );
static void ssh2_channel_close_local( struct ssh2_channel *c, const char *reason );
static void ssh2_channel_destroy( struct ssh2_channel *c );
static void ssh2_check_termination( struct ssh2_connection_state *s );

struct outstanding_global_request
{
	gr_handler_fn_t handler;
	void *ctx;
	struct outstanding_global_request *next;
};
void ssh2_queue_global_request_handler( struct ssh2_connection_state *s, gr_handler_fn_t handler, void *ctx )
{
	struct outstanding_global_request *ogr = snew( struct outstanding_global_request );
	ogr->handler = handler;
	ogr->ctx = ctx;
	if ( s->globreq_tail )
	{
		s->globreq_tail->next = ogr;
	}
	else
	{
		s->globreq_head = ogr;
	}
	s->globreq_tail = ogr;
}

static int ssh2_channelcmp( void *av, void *bv )
{
	const struct ssh2_channel *a = ( const struct ssh2_channel * )av;
	const struct ssh2_channel *b = ( const struct ssh2_channel * )bv;
	if ( a->localid < b->localid )
	{
		return -1;
	}
	if ( a->localid > b->localid )
	{
		return +1;
	}
	return 0;
}

static int ssh2_channelfind( void *av, void *bv )
{
	const unsigned *a = ( const unsigned * )av;
	const struct ssh2_channel *b = ( const struct ssh2_channel * )bv;
	if ( *a < b->localid )
	{
		return -1;
	}
	if ( *a > b->localid )
	{
		return +1;
	}
	return 0;
}

/*
 * Each channel has a queue of outstanding CHANNEL_REQUESTS and their handlers.
 */
struct outstanding_channel_request
{
	cr_handler_fn_t handler;
	void *ctx;
	struct outstanding_channel_request *next;
};

static void ssh2_channel_free( struct ssh2_channel *c )
{
	bufchain_clear( &c->outbuffer );
	bufchain_clear( &c->errbuffer );
	while ( c->chanreq_head )
	{
		struct outstanding_channel_request *chanreq = c->chanreq_head;
		c->chanreq_head = c->chanreq_head->next;
		sfree( chanreq );
	}
	if ( c->chan )
	{
		struct ssh2_connection_state *s = c->connlayer;
		if ( s->mainchan_sc == &c->sc )
		{
			s->mainchan = NULL;
			s->mainchan_sc = NULL;
		}
		chan_free( c->chan );
	}
	sfree( c );
}

PacketProtocolLayer *ssh2_connection_new( const char *peer_verstring, ConnectionLayer **cl_out )
{
	struct ssh2_connection_state *s = snew( struct ssh2_connection_state );
	memset( s, 0, sizeof( *s ) );
	s->ppl.vt = &ssh2_connection_vtable;

	s->peer_verstring = dupstr( peer_verstring );

	s->channels = newtree234( ssh2_channelcmp );

	/* Need to get the log context for s->cl now, because we won't be
	* helpfully notified when a copy is written into s->ppl by our owner. */
	s->cl.vt = &ssh2_connlayer_vtable;

	*cl_out = &s->cl;

	return &s->ppl;
}

static void ssh2_connection_free( PacketProtocolLayer *ppl )
{
	struct ssh2_connection_state *s = container_of( ppl, struct ssh2_connection_state, ppl );
	struct ssh2_channel *c;

	sfree( s->peer_verstring );

	while ( ( c = ( ssh2_channel * )delpos234( s->channels, 0 ) ) != NULL )
	{
		ssh2_channel_free( c );
	}
	freetree234( s->channels );

	delete_callbacks_for_context( s->ppl.ssh, s );

	sfree( s );
}

static bool ssh2_connection_filter_queue( struct ssh2_connection_state *s )
{
	PktIn *pktin;
	PktOut *pktout;
	ptrlen type, data;
	struct ssh2_channel *c;
	struct outstanding_channel_request *ocr;
	unsigned localid, remid, winsize, pktsize, ext_type;
	bool want_reply, reply_success, expect_halfopen;

	while ( 1 )
	{
		if ( ssh2_common_filter_queue( &s->ppl ) )
		{
			return true;
		}

		if ( ( pktin = pq_peek( s->ppl.ssh, s->ppl.in_pq ) ) == NULL )
		{
			return false;
		}

		switch ( pktin->type )
		{
			case SSH2_MSG_GLOBAL_REQUEST:
			{
				type = get_string( pktin );
				want_reply = get_bool( pktin );

				// We don't know of any global requests that an SSH client needs to honour.
				reply_success = false;

				if ( want_reply )
				{
					int type = ( reply_success ? SSH2_MSG_REQUEST_SUCCESS : SSH2_MSG_REQUEST_FAILURE );
					pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, type );
					pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
				}
				pq_pop( s->ppl.ssh, s->ppl.in_pq );
			}
			break;

			case SSH2_MSG_REQUEST_SUCCESS:
			case SSH2_MSG_REQUEST_FAILURE:
			{
				if ( !s->globreq_head )
				{
					ssh_proto_error( s->ppl.ssh );
					return true;
				}

				s->globreq_head->handler( s, pktin, s->globreq_head->ctx );
				{
					struct outstanding_global_request *tmp = s->globreq_head;
					s->globreq_head = s->globreq_head->next;
					sfree( tmp );
				}

				pq_pop( s->ppl.ssh, s->ppl.in_pq );
			}
			break;

			case SSH2_MSG_CHANNEL_OPEN:
			{
				type = get_string( pktin );
				c = snew( struct ssh2_channel );
				c->connlayer = s;
				c->chan = NULL;

				remid = get_uint32( pktin );
				winsize = get_uint32( pktin );
				pktsize = get_uint32( pktin );

				c->remoteid = remid;
				c->halfopen = false;

				pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_CHANNEL_OPEN_FAILURE );
				put_uint32( pktout, c->remoteid );
				put_uint32( pktout, SSH2_OPEN_UNKNOWN_CHANNEL_TYPE );
				put_stringz( pktout, "Unsupported channel type requested" );
				put_stringz( pktout, "en" );      /* language tag */
				pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
				sfree( c );

				pq_pop( s->ppl.ssh, s->ppl.in_pq );
			}
			break;

			case SSH2_MSG_CHANNEL_DATA:
			case SSH2_MSG_CHANNEL_EXTENDED_DATA:
			case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
			case SSH2_MSG_CHANNEL_REQUEST:
			case SSH2_MSG_CHANNEL_EOF:
			case SSH2_MSG_CHANNEL_CLOSE:
			case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
			case SSH2_MSG_CHANNEL_OPEN_FAILURE:
			case SSH2_MSG_CHANNEL_SUCCESS:
			case SSH2_MSG_CHANNEL_FAILURE:
			{
				/*
				* Common preliminary code for all the messages from the
				* server that cite one of our channel ids: look up that
				* channel id, check it exists, and if it's for a sharing
				* downstream, pass it on.
				*/
				localid = get_uint32( pktin );
				c = ( ssh2_channel * )find234( s->channels, &localid, ssh2_channelfind );

				expect_halfopen = ( pktin->type == SSH2_MSG_CHANNEL_OPEN_CONFIRMATION || pktin->type == SSH2_MSG_CHANNEL_OPEN_FAILURE );

				if ( !c || c->halfopen != expect_halfopen )
				{
					ssh_proto_error(s->ppl.ssh );
					return true;
				}

				switch ( pktin->type )
				{
					case SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
					{
						assert( c->halfopen );
						c->remoteid = get_uint32( pktin );
						c->halfopen = false;
						c->remwindow = get_uint32( pktin );
						c->remmaxpkt = get_uint32( pktin );
						if ( c->remmaxpkt > s->ppl.bpp->vt->packet_size_limit )
						{
							c->remmaxpkt = s->ppl.bpp->vt->packet_size_limit;
						}

						chan_open_confirmation( c->chan );

						/*
						* Now that the channel is fully open, it's possible
						* in principle to immediately close it. Check whether
						* it wants us to!
						*
						* This can occur if a local socket error occurred
						* between us sending out CHANNEL_OPEN and receiving
						* OPEN_CONFIRMATION. If that happens, all we can do
						* is immediately initiate close proceedings now that
						* we know the server's id to put in the close
						* message. We'll have handled that in this code by
						* having already turned c->chan into a zombie, so its
						* want_close method (which ssh2_channel_check_close
						* will consult) will already be returning true.
						*/
						ssh2_channel_check_close( c );

						if ( c->pending_eof )
						{
							ssh2_channel_try_eof( c ); /* in case we had a pending EOF */
						}
					}
					break;

					case SSH2_MSG_CHANNEL_OPEN_FAILURE:
					{
						assert( c->halfopen );

						chan_open_failed( c->chan );

						del234( s->channels, c );
						ssh2_channel_free( c );
					}
					break;

					case SSH2_MSG_CHANNEL_DATA:
					case SSH2_MSG_CHANNEL_EXTENDED_DATA:
					{
						ext_type = ( pktin->type == SSH2_MSG_CHANNEL_DATA ? 0 : get_uint32( pktin ) );
						data = get_string( pktin );
						if ( !get_err( pktin ) )
						{
							int bufsize;
							c->locwindow -= data.len;
							c->remlocwin -= data.len;
							if ( ext_type != 0 && ext_type != SSH2_EXTENDED_DATA_STDERR )
							{
								data.len = 0; /* ignore unknown extended data */
							}
							bufsize = chan_send( c->chan, ext_type == SSH2_EXTENDED_DATA_STDERR, data.ptr, data.len );

							/*
							* If it looks like the remote end hit the end of
							* its window, and we didn't want it to do that,
							* think about using a larger window.
							*/
							if ( c->remlocwin <= 0 && c->throttle_state == UNTHROTTLED && c->locmaxwin < 0x40000000 )
							{
								c->locmaxwin += OUR_V2_WINSIZE;
							}

							/*
							* If we are not buffering too much data, enlarge
							* the window again at the remote side. If we are
							* buffering too much, we may still need to adjust
							* the window if the server's sent excess data.
							*/
							if ( bufsize < c->locmaxwin )
							{
								ssh2_set_window( c, c->locmaxwin - bufsize );
							}

							/*
							* If we're either buffering way too much data, or
							* if we're buffering anything at all and we're in
							* "simple" mode, throttle the whole channel.
							*/
							if ( ( bufsize > c->locmaxwin || bufsize > 0 ) && !c->throttling_conn )
							{
								c->throttling_conn = true;
								ssh_throttle_conn( s->ppl.ssh, +1 );
							}
						}
					}
					break;

					case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
					{
						if ( !( c->closes & CLOSES_SENT_EOF ) )
						{
							c->remwindow += get_uint32( pktin );
							ssh2_try_send_and_unthrottle( c );
						}
					}
					break;

					case SSH2_MSG_CHANNEL_REQUEST:
					{
						type = get_string( pktin );
						want_reply = get_bool( pktin );

						reply_success = false;

						if ( c->closes & CLOSES_SENT_CLOSE )
						{
							/*
							* We don't reply to channel requests after we've
							* sent CHANNEL_CLOSE for the channel, because our
							* reply might cross in the network with the other
							* side's CHANNEL_CLOSE and arrive after they have
							* wound the channel up completely.
							*/
							want_reply = false;
						}

						/*
						* Try every channel request name we recognise, no
						* matter what the channel, and see if the Channel
						* instance will accept it.
						*/
						if ( ptrlen_eq_string( type, "exit-status" ) )
						{
							int exitcode = toint( get_uint32( pktin ) );
							reply_success = chan_rcvd_exit_status( c->chan, exitcode );
						}
						else if ( ptrlen_eq_string( type, "exit-signal" ) )
						{
							ptrlen signame;
							memset( &signame, 0, sizeof( ptrlen ) );
							int signum = 0;
							bool core = false;
							ptrlen errmsg;
							memset( &errmsg, 0, sizeof( ptrlen ) );
							int format;

							/*
							* ICK: older versions of OpenSSH (e.g. 3.4p1)
							* provide an `int' for the signal, despite its
							* having been a `string' in the drafts of RFC
							* 4254 since at least 2001. (Fixed in session.c
							* 1.147.) Try to infer which we can safely parse
							* it as.
							*/

							size_t startpos = BinarySource_UPCAST( pktin )->pos;

							for ( format = 0; format < 2; format++ )
							{
								BinarySource_UPCAST( pktin )->pos = startpos;
								BinarySource_UPCAST( pktin )->err = BSE_NO_ERROR;

								/* placate compiler warnings about unin */
								signame = make_ptrlen( NULL, 0 );
								signum = 0;

								if ( format == 0 ) /* standard string-based format */
								{
									signame = get_string( pktin );
								}
								else      /* nonstandard integer format */
								{
									signum = toint( get_uint32( pktin ) );
								}

								core = get_bool( pktin );
								errmsg = get_string( pktin ); /* error message */
								get_string( pktin );     /* language tag */

								if ( !get_err( pktin ) && get_avail( pktin ) == 0 )
								{
									break;             /* successful parse */
								}
							}

							switch ( format )
							{
								case 0:
								{
									reply_success = chan_rcvd_exit_signal( c->chan, signame, core, errmsg );
								}
								break;

								case 1:
								{
									reply_success = chan_rcvd_exit_signal_numeric( c->chan, signum, core, errmsg );
								}
								break;

								default:
								{
									/* Couldn't parse this message in either format */
									reply_success = false;
								}
								break;
							}
						}

						if ( want_reply )
						{
							int type = ( reply_success ? SSH2_MSG_CHANNEL_SUCCESS : SSH2_MSG_CHANNEL_FAILURE );
							pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, type );
							put_uint32( pktout, c->remoteid );
							pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
						}
					}
					break;

					case SSH2_MSG_CHANNEL_SUCCESS:
					case SSH2_MSG_CHANNEL_FAILURE:
					{
						ocr = c->chanreq_head;
						if ( !ocr )
						{
							ssh_proto_error( s->ppl.ssh );
							return true;
						}
						ocr->handler( c, pktin, ocr->ctx );
						c->chanreq_head = ocr->next;
						sfree( ocr );
						/*
						* We may now initiate channel-closing procedures, if
						* that CHANNEL_REQUEST was the last thing outstanding
						* before we send CHANNEL_CLOSE.
						*/
						ssh2_channel_check_close( c );
					}
					break;

					case SSH2_MSG_CHANNEL_EOF:
					{
						if ( !( c->closes & CLOSES_RCVD_EOF ) )
						{
							c->closes |= CLOSES_RCVD_EOF;
							chan_send_eof( c->chan );
							ssh2_channel_check_close( c );
						}
					}
					break;

					case SSH2_MSG_CHANNEL_CLOSE:
					{
						/*
						* When we receive CLOSE on a channel, we assume it
						* comes with an implied EOF if we haven't seen EOF
						* yet.
						*/
						if ( !( c->closes & CLOSES_RCVD_EOF ) )
						{
							c->closes |= CLOSES_RCVD_EOF;
							chan_send_eof( c->chan );
						}

						if ( !( s->ppl.remote_bugs & BUG_SENDS_LATE_REQUEST_REPLY ) )
						{
							/*
							* It also means we stop expecting to see replies
							* to any outstanding channel requests, so clean
							* those up too. (ssh_chanreq_init will enforce by
							* assertion that we don't subsequently put
							* anything back on this list.)
							*/
							while ( c->chanreq_head )
							{
								struct outstanding_channel_request *ocr = c->chanreq_head;
								ocr->handler( c, NULL, ocr->ctx );
								c->chanreq_head = ocr->next;
								sfree( ocr );
							}
						}

						/*
						* And we also send an outgoing EOF, if we haven't
						* already, on the assumption that CLOSE is a pretty
						* forceful announcement that the remote side is doing
						* away with the entire channel. (If it had wanted to
						* send us EOF and continue receiving data from us, it
						* would have just sent CHANNEL_EOF.)
						*/
						if ( !( c->closes & CLOSES_SENT_EOF ) )
						{
							/*
							* Abandon any buffered data we still wanted to
							* send to this channel. Receiving a CHANNEL_CLOSE
							* is an indication that the server really wants
							* to get on and _destroy_ this channel, and it
							* isn't going to send us any further
							* WINDOW_ADJUSTs to permit us to send pending
							* stuff.
							*/
							bufchain_clear( &c->outbuffer );
							bufchain_clear( &c->errbuffer );

							/*
							* Send outgoing EOF.
							*/
							sshfwd_write_eof( &c->sc );

							/*
							* Make sure we don't read any more from whatever
							* our local data source is for this channel.
							* (This will pick up on the changes made by
							* sshfwd_write_eof.)
							*/
							ssh2_channel_check_throttle( c );
						}

						/*
						* Now process the actual close.
						*/
						if ( !( c->closes & CLOSES_RCVD_CLOSE ) )
						{
							c->closes |= CLOSES_RCVD_CLOSE;
							ssh2_channel_check_close( c );
						}
					}
					break;
				}

				pq_pop( s->ppl.ssh, s->ppl.in_pq );
			}
			break;

			default:
			{
				return false;
			}
			break;
		}
	}
}

static void ssh2_handle_winadj_response( struct ssh2_channel *c, PktIn * /*pktin*/, void *ctx )
{
	unsigned *sizep = ( unsigned * )ctx;

	/*
	* Winadj responses should always be failures. However, at least
	* one server ("boks_sshd") is known to return SUCCESS for channel
	* requests it's never heard of, such as "winadj@putty". Raised
	* with foxt.com as bug 090916-090424, but for the sake of a quiet
	* life, we don't worry about what kind of response we got.
	*/

	c->remlocwin += *sizep;
	sfree( sizep );
	/*
	* winadj messages are only sent when the window is fully open, so
	* if we get an ack of one, we know any pending unthrottle is
	* complete.
	*/
	if ( c->throttle_state == UNTHROTTLING )
	{
		c->throttle_state = UNTHROTTLED;
	}
}

static void ssh2_set_window( struct ssh2_channel *c, int newwin )
{
	struct ssh2_connection_state *s = c->connlayer;

	/*
	* Never send WINDOW_ADJUST for a channel that the remote side has
	* already sent EOF on; there's no point, since it won't be
	* sending any more data anyway. Ditto if _we've_ already sent
	* CLOSE.
	*/
	if ( c->closes & ( CLOSES_RCVD_EOF | CLOSES_SENT_CLOSE ) )
	{
		return;
	}

	/*
	* If the client-side Channel is in an initial setup phase with a
	* fixed window size, e.g. for an X11 channel when we're still
	* waiting to see its initial auth and may yet hand it off to a
	* downstream, don't send any WINDOW_ADJUST either.
	*/
	if ( c->chan->initial_fixed_window_size )
	{
		return;
	}

	/*
	* If the remote end has a habit of ignoring maxpkt, limit the
	* window so that it has no choice (assuming it doesn't ignore the
	* window as well).
	*/
	if ( ( s->ppl.remote_bugs & BUG_SSH2_MAXPKT ) && newwin > OUR_V2_MAXPKT )
	{
		newwin = OUR_V2_MAXPKT;
	}

	/*
	* Only send a WINDOW_ADJUST if there's significantly more window
	* available than the other end thinks there is.  This saves us
	* sending a WINDOW_ADJUST for every character in a shell session.
	*
	* "Significant" is arbitrarily defined as half the window size.
	*/
	if ( newwin / 2 >= c->locwindow )
	{
		PktOut *pktout;
		unsigned *up;

		/*
		* In order to keep track of how much window the client
		* actually has available, we'd like it to acknowledge each
		* WINDOW_ADJUST.  We can't do that directly, so we accompany
		* it with a CHANNEL_REQUEST that has to be acknowledged.
		*
		* This is only necessary if we're opening the window wide.
		* If we're not, then throughput is being constrained by
		* something other than the maximum window size anyway.
		*/
		if ( newwin == c->locmaxwin && !( s->ppl.remote_bugs & BUG_CHOKES_ON_WINADJ ) )
		{
			up = snew( unsigned );
			*up = newwin - c->locwindow;
			pktout = ssh2_chanreq_init( c, "winadj@putty.projects.tartarus.org", ssh2_handle_winadj_response, up );
			pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );

			if ( c->throttle_state != UNTHROTTLED )
			{
				c->throttle_state = UNTHROTTLING;
			}
		}
		else
		{
			/* Pretend the WINDOW_ADJUST was acked immediately. */
			c->remlocwin = newwin;
			c->throttle_state = THROTTLED;
		}
		pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_CHANNEL_WINDOW_ADJUST );
		put_uint32( pktout, c->remoteid );
		put_uint32( pktout, newwin - c->locwindow );
		pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
		c->locwindow = newwin;
	}
}

static PktIn *ssh2_connection_pop( struct ssh2_connection_state *s )
{
	ssh2_connection_filter_queue( s );
	return pq_pop( s->ppl.ssh, s->ppl.in_pq );
}

static void ssh2_connection_process_queue( PacketProtocolLayer *ppl )
{
	struct ssh2_connection_state *s = container_of( ppl, struct ssh2_connection_state, ppl );
	PktIn *pktin;

	if ( ssh2_connection_filter_queue( s ) ) /* no matter why we were called */
	{
		return;
	}

	crBegin( s->crState );

	/*
	* Create the main session channel, if any.
	*/
	s->mainchan = mainchan_new( &s->ppl, &s->cl, &s->mainchan_sc );

	/*
	* Transfer data!
	*/

	while ( 1 )
	{
		if ( ( pktin = ssh2_connection_pop( s ) ) != NULL )
		{
			/*
			* _All_ the connection-layer packets we expect to
			* receive are now handled by the dispatch table.
			* Anything that reaches here must be bogus.
			*/

			ssh_proto_error( s->ppl.ssh );
			return;
		}
		crReturnV;
	}

	crFinishV;
}

static void ssh2_channel_check_close( struct ssh2_channel *c )
{
	struct ssh2_connection_state *s = c->connlayer;
	PktOut *pktout;

	if ( c->halfopen )
	{
		/*
		* If we've sent out our own CHANNEL_OPEN but not yet seen
		* either OPEN_CONFIRMATION or OPEN_FAILURE in response, then
		* it's too early to be sending close messages of any kind.
		*/
		return;
	}

	if ( chan_want_close( c->chan, ( c->closes & CLOSES_SENT_EOF ), ( c->closes & CLOSES_RCVD_EOF ) ) && !c->chanreq_head && !( c->closes & CLOSES_SENT_CLOSE ) )
	{
		/*
		* We have both sent and received EOF (or the channel is a
		* zombie), and we have no outstanding channel requests, which
		* means the channel is in final wind-up. But we haven't sent
		* CLOSE, so let's do so now.
		*/
		pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_CHANNEL_CLOSE );
		put_uint32( pktout, c->remoteid );
		pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
		c->closes |= CLOSES_SENT_EOF | CLOSES_SENT_CLOSE;
	}

	if ( !( ( CLOSES_SENT_CLOSE | CLOSES_RCVD_CLOSE ) & ~c->closes ) )
	{
		assert( c->chanreq_head == NULL );
		/*
		* We have both sent and received CLOSE, which means we're
		* completely done with the channel.
		*/
		ssh2_channel_destroy( c );
	}
}

static void ssh2_channel_try_eof( struct ssh2_channel *c )
{
	struct ssh2_connection_state *s = c->connlayer;
	PktOut *pktout;
	assert( c->pending_eof );          /* precondition for calling us */
	if ( c->halfopen )
	{
		return;                 /* can't close: not even opened yet */
	}
	if ( bufchain_size( &c->outbuffer ) > 0 || bufchain_size( &c->errbuffer ) > 0 )
	{
		return;              /* can't send EOF: pending outgoing data */
	}

	c->pending_eof = false;            /* we're about to send it */

	pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_CHANNEL_EOF );
	put_uint32( pktout, c->remoteid );
	pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
	c->closes |= CLOSES_SENT_EOF;
	ssh2_channel_check_close( c );
}

/*
 * Attempt to send data on an SSH-2 channel.
 */
static size_t ssh2_try_send( struct ssh2_channel *c )
{
	struct ssh2_connection_state *s = c->connlayer;
	PktOut *pktout;
	size_t bufsize;

	if ( !c->halfopen )
	{
		while ( c->remwindow > 0 && ( bufchain_size( &c->outbuffer ) > 0 || bufchain_size( &c->errbuffer ) > 0 ) )
		{
			bufchain *buf = ( bufchain_size( &c->errbuffer ) > 0 ? &c->errbuffer : &c->outbuffer );

			ptrlen data = bufchain_prefix( buf );
			if ( data.len > c->remwindow )
			{
				data.len = c->remwindow;
			}
			if ( data.len > c->remmaxpkt )
			{
				data.len = c->remmaxpkt;
			}
			if ( buf == &c->errbuffer )
			{
				pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_CHANNEL_EXTENDED_DATA );
				put_uint32( pktout, c->remoteid );
				put_uint32( pktout, SSH2_EXTENDED_DATA_STDERR );
			}
			else
			{
				pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_CHANNEL_DATA );
				put_uint32( pktout, c->remoteid );
			}
			put_stringpl( pktout, data );
			pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
			bufchain_consume( buf, data.len );
			c->remwindow -= data.len;
		}
	}

	/*
	* After having sent as much data as we can, return the amount
	* still buffered.
	*/
	bufsize = bufchain_size( &c->outbuffer ) + bufchain_size( &c->errbuffer );

	/*
	* And if there's no data pending but we need to send an EOF, send
	* it.
	*/
	if ( !bufsize && c->pending_eof )
	{
		ssh2_channel_try_eof( c );
	}

	return bufsize;
}

static void ssh2_try_send_and_unthrottle( struct ssh2_channel *c )
{
	int bufsize;
	if ( c->closes & CLOSES_SENT_EOF )
	{
		return;                   /* don't send on channels we've EOFed */
	}
	bufsize = ssh2_try_send( c );
	if ( bufsize == 0 )
	{
		c->throttled_by_backlog = false;
		ssh2_channel_check_throttle( c );
	}
}

static void ssh2_channel_check_throttle( struct ssh2_channel *c )
{
	/*
	* We don't want this channel to read further input if this
	* particular channel has a backed-up SSH window, or if the
	* outgoing side of the whole SSH connection is currently
	* throttled, or if this channel already has an outgoing EOF
	* either sent or pending.
	*/
	chan_set_input_wanted( c->chan,
						  !c->throttled_by_backlog &&
						  !c->connlayer->all_channels_throttled &&
						  !c->pending_eof &&
						  !( c->closes & CLOSES_SENT_EOF ) );
}

/*
 * Close any local socket and free any local resources associated with
 * a channel.  This converts the channel into a zombie.
 */
static void ssh2_channel_close_local( struct ssh2_channel *c, const char * /*reason*/ )
{
	chan_free( c->chan );
	c->chan = zombiechan_new();
}

static void ssh2_check_termination_callback( Ssh * /*ssh*/, void *vctx )
{
	struct ssh2_connection_state *s = ( struct ssh2_connection_state * )vctx;
	ssh2_check_termination( s );
}

static void ssh2_channel_destroy( struct ssh2_channel *c )
{
	struct ssh2_connection_state *s = c->connlayer;

	assert( c->chanreq_head == NULL );

	ssh2_channel_close_local( c, NULL );
	del234( s->channels, c );
	ssh2_channel_free( c );

	/*
	* If that was the last channel left open, we might need to
	* terminate. But we'll be a bit cautious, by doing that in a
	* toplevel callback, just in case anything on the current call
	* stack objects to this entire PPL being freed.
	*/
	queue_toplevel_callback( s->ppl.ssh, ssh2_check_termination_callback, s );
}

static void ssh2_check_termination( struct ssh2_connection_state *s )
{
	/*
	* Decide whether we should terminate the SSH connection now.
	* Called after a channel or a downstream goes away. The general
	* policy is that we terminate when none of either is left.
	*/
	if ( count234( s->channels ) == 0 )
	{
		/*
		* We used to send SSH_MSG_DISCONNECT here, because I'd
		* believed that _every_ conforming SSH-2 connection had to
		* end with a disconnect being sent by at least one side;
		* apparently I was wrong and it's perfectly OK to
		* unceremoniously slam the connection shut when you're done,
		* and indeed OpenSSH feels this is more polite than sending a
		* DISCONNECT. So now we don't.
		*/
		ssh_user_close( s->ppl.ssh );
		return;
	}
}

/*
 * Set up most of a new ssh2_channel. Nulls out sharectx, but leaves
 * chan untouched (since it will sometimes have been filled in before
 * calling this).
 */
void ssh2_channel_init( struct ssh2_channel *c )
{
	struct ssh2_connection_state *s = c->connlayer;
	c->closes = 0;
	c->pending_eof = false;
	c->throttling_conn = false;
	c->throttled_by_backlog = false;
	c->locwindow = c->locmaxwin = c->remlocwin = OUR_V2_BIGWIN;//s->ssh_is_simple ? OUR_V2_BIGWIN : OUR_V2_WINSIZE;
	c->chanreq_head = NULL;
	c->throttle_state = UNTHROTTLED;
	bufchain_init( &c->outbuffer );
	bufchain_init( &c->errbuffer );
	c->sc.vt = &ssh2channel_vtable;
	c->sc.cl = &s->cl;
	c->localid = alloc_channel_id( s->channels, struct ssh2_channel );
	add234( s->channels, c );
}

/*
 * Construct the common parts of a CHANNEL_OPEN.
 */
PktOut *ssh2_chanopen_init( struct ssh2_channel *c, const char *type )
{
	struct ssh2_connection_state *s = c->connlayer;
	PktOut *pktout;

	pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_CHANNEL_OPEN );
	put_stringz( pktout, type );
	put_uint32( pktout, c->localid );
	put_uint32( pktout, c->locwindow );     /* our window size */
	put_uint32( pktout, OUR_V2_MAXPKT );    /* our max pkt size */
	return pktout;
}

/*
 * Construct the common parts of a CHANNEL_REQUEST.  If handler is not
 * NULL then a reply will be requested and the handler will be called
 * when it arrives.  The returned packet is ready to have any
 * request-specific data added and be sent.  Note that if a handler is
 * provided, it's essential that the request actually be sent.
 *
 * The handler will usually be passed the response packet in pktin. If
 * pktin is NULL, this means that no reply will ever be forthcoming
 * (e.g. because the entire connection is being destroyed, or because
 * the server initiated channel closure before we saw the response)
 * and the handler should free any storage it's holding.
 */
PktOut *ssh2_chanreq_init( struct ssh2_channel *c, const char *type, cr_handler_fn_t handler, void *ctx )
{
	struct ssh2_connection_state *s = c->connlayer;
	PktOut *pktout;

	assert( !( c->closes & ( CLOSES_SENT_CLOSE | CLOSES_RCVD_CLOSE ) ) );
	pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_CHANNEL_REQUEST );
	put_uint32( pktout, c->remoteid );
	put_stringz( pktout, type );
	put_bool( pktout, handler != NULL );
	if ( handler != NULL )
	{
		struct outstanding_channel_request *ocr = snew( struct outstanding_channel_request );

		ocr->handler = handler;
		ocr->ctx = ctx;
		ocr->next = NULL;
		if ( !c->chanreq_head )
		{
			c->chanreq_head = ocr;
		}
		else
		{
			c->chanreq_tail->next = ocr;
		}
		c->chanreq_tail = ocr;
	}
	return pktout;
}

static void ssh2channel_write_eof( SshChannel *sc )
{
	struct ssh2_channel *c = container_of( sc, struct ssh2_channel, sc );

	if ( c->closes & CLOSES_SENT_EOF )
	{
		return;
	}

	c->pending_eof = true;
	ssh2_channel_try_eof( c );
}

static size_t ssh2channel_write( Ssh *ssh, SshChannel *sc, bool is_stderr, const void *buf, size_t len )
{
	struct ssh2_channel *c = container_of( sc, struct ssh2_channel, sc );
	assert( !( c->closes & CLOSES_SENT_EOF ) );
	bufchain_add( ssh, is_stderr ? &c->errbuffer : &c->outbuffer, buf, len );
	return ssh2_try_send( c );
}

static void ssh2channel_hint_channel_is_simple( SshChannel *sc )
{
	struct ssh2_channel *c = container_of( sc, struct ssh2_channel, sc );
	struct ssh2_connection_state *s = c->connlayer;

	PktOut *pktout = ssh2_chanreq_init( c, "simple@putty.projects.tartarus.org", NULL, NULL );
	pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
}

static bool ssh2_connection_get_specials( PacketProtocolLayer *ppl, add_special_fn_t add_special, void *ctx )
{
	struct ssh2_connection_state *s = container_of( ppl, struct ssh2_connection_state, ppl );
	bool toret = false;

	if ( s->mainchan )
	{
		mainchan_get_specials( s->mainchan, add_special, ctx );
		toret = true;
	}

	/*
	* Don't bother offering IGNORE if we've decided the remote
	* won't cope with it, since we wouldn't bother sending it if
	* asked anyway.
	*/
	if ( !( s->ppl.remote_bugs & BUG_CHOKES_ON_SSH2_IGNORE ) )
	{
		if ( toret )
		{
			add_special( ctx, NULL, SS_SEP, 0 );
		}

		add_special( ctx, "IGNORE message", SS_NOP, 0 );
		toret = true;
	}

	return toret;
}

static void ssh2_connection_special_cmd( PacketProtocolLayer *ppl, SessionSpecialCode code, int arg )
{
	struct ssh2_connection_state *s = container_of( ppl, struct ssh2_connection_state, ppl );
	PktOut *pktout;

	if ( code == SS_PING || code == SS_NOP )
	{
		if ( !( s->ppl.remote_bugs & BUG_CHOKES_ON_SSH2_IGNORE ) )
		{
			pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_IGNORE );
			put_stringz( pktout, "" );
			pq_push( s->ppl.ssh, s->ppl.out_pq, pktout );
		}
	}
	else if ( s->mainchan )
	{
		mainchan_special_cmd( s->mainchan, code, arg );
	}
}

static size_t ssh2_stdin_backlog( ConnectionLayer *cl )
{
	struct ssh2_connection_state *s = container_of( cl, struct ssh2_connection_state, cl );
	struct ssh2_channel *c;

	if ( !s->mainchan )
	{
		return 0;
	}
	c = container_of( s->mainchan_sc, struct ssh2_channel, sc );
	return s->mainchan ? bufchain_size( &c->outbuffer ) + bufchain_size( &c->errbuffer ) : 0;
}

static void ssh2_throttle_all_channels( ConnectionLayer *cl, bool throttled )
{
	struct ssh2_connection_state *s = container_of( cl, struct ssh2_connection_state, cl );
	struct ssh2_channel *c;
	int i;

	s->all_channels_throttled = throttled;

	for ( i = 0; NULL != ( c = ( ssh2_channel * )index234( s->channels, i ) ); i++ )
	{
		ssh2_channel_check_throttle( c );
	}
}

static void ssh2_set_wants_user_input( ConnectionLayer *cl, bool wanted )
{
	struct ssh2_connection_state *s = container_of( cl, struct ssh2_connection_state, cl );

	s->want_user_input = wanted;
}

static bool ssh2_connection_want_user_input( PacketProtocolLayer *ppl )
{
	struct ssh2_connection_state *s = container_of( ppl, struct ssh2_connection_state, ppl );
	return s->want_user_input;
}

static void ssh2_connection_got_user_input( PacketProtocolLayer *ppl )
{
	struct ssh2_connection_state *s = container_of( ppl, struct ssh2_connection_state, ppl );

	while ( s->mainchan && bufchain_size( s->ppl.user_input ) > 0 )
	{
		/*
		* Add user input to the main channel's buffer.
		*/
		ptrlen data = bufchain_prefix( s->ppl.user_input );
		sshfwd_write( s->ppl.ssh, s->mainchan_sc, data.ptr, data.len );
		bufchain_consume( s->ppl.user_input, data.len );
	}
}

static void ssh2_connection_reconfigure( PacketProtocolLayer * /*ppl*/ ) {}
