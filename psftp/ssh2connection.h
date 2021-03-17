#ifndef PUTTY_SSH2CONNECTION_H
#define PUTTY_SSH2CONNECTION_H

struct outstanding_channel_request;
struct outstanding_global_request;

struct ssh2_connection_state
{
	int crState;

	Ssh *ssh;

	char *peer_verstring;

	mainchan *mainchan;
	SshChannel *mainchan_sc;

	int session_attempt, session_status;
	bool want_user_input;

	tree234 *channels;                 /* indexed by local id */
	bool all_channels_throttled;

	/*
	* These store the list of global requests that we're waiting for
	* replies to. (REQUEST_FAILURE doesn't come with any indication
	* of what message caused it, so we have to keep track of the
	* queue ourselves.)
	*/
	struct outstanding_global_request *globreq_head, *globreq_tail;

	ConnectionLayer cl;
	PacketProtocolLayer ppl;
};

typedef void ( *gr_handler_fn_t )( struct ssh2_connection_state *s, PktIn *pktin, void *ctx );
void ssh2_queue_global_request_handler( struct ssh2_connection_state *s, gr_handler_fn_t handler, void *ctx );

typedef enum { THROTTLED, UNTHROTTLING, UNTHROTTLED } CHANNEL_THROTTLE_STATE;

struct ssh2_channel
{
	struct ssh2_connection_state *connlayer;

	unsigned remoteid, localid;
	int type;
	/* True if we opened this channel but server hasn't confirmed. */
	bool halfopen;

	/* Bitmap of whether we've sent/received CHANNEL_EOF and
	* CHANNEL_CLOSE. */
#define CLOSES_SENT_EOF		1
#define CLOSES_SENT_CLOSE	2
#define CLOSES_RCVD_EOF		4
#define CLOSES_RCVD_CLOSE	8
	int closes;

	/*
	* This flag indicates that an EOF is pending on the outgoing side
	* of the channel: that is, wherever we're getting the data for
	* this channel has sent us some data followed by EOF. We can't
	* actually send the EOF until we've finished sending the data, so
	* we set this flag instead to remind us to do so once our buffer
	* is clear.
	*/
	bool pending_eof;

	/*
	* True if this channel is causing the underlying connection to be
	* throttled.
	*/
	bool throttling_conn;

	/*
	* True if we currently have backed-up data on the direction of
	* this channel pointing out of the SSH connection, and therefore
	* would prefer the 'Channel' implementation not to read further
	* local input if possible.
	*/
	bool throttled_by_backlog;

	bufchain outbuffer, errbuffer;
	unsigned remwindow, remmaxpkt;
	/* locwindow is signed so we can cope with excess data. */
	int locwindow, locmaxwin;
	/*
	* remlocwin is the amount of local window that we think
	* the remote end had available to it after it sent the
	* last data packet or window adjust ack.
	*/
	int remlocwin;

	/*
	* These store the list of channel requests that we're waiting for
	* replies to. (CHANNEL_FAILURE doesn't come with any indication
	* of what message caused it, so we have to keep track of the
	* queue ourselves.)
	*/
	struct outstanding_channel_request *chanreq_head, *chanreq_tail;

	CHANNEL_THROTTLE_STATE throttle_state;

	Channel *chan;      /* handle the client side of this channel, if not */
	SshChannel sc;      /* entry point for chan to talk back to */
};

typedef void ( *cr_handler_fn_t )( struct ssh2_channel *, PktIn *, void * );

void ssh2_channel_init( struct ssh2_channel *c );
PktOut *ssh2_chanreq_init( struct ssh2_channel *c, const char *type, cr_handler_fn_t handler, void *ctx );

typedef enum ChanopenOutcome
{
	CHANOPEN_RESULT_FAILURE,
	CHANOPEN_RESULT_SUCCESS,
	CHANOPEN_RESULT_DOWNSTREAM,
} ChanopenOutcome;

typedef struct ChanopenResult
{
	ChanopenOutcome outcome;
	union
	{
		struct
		{
			char *wire_message;        /* must be freed by recipient */
			unsigned reason_code;
		} failure;

		struct
		{
			Channel *channel;
		} success;
	} u;
} ChanopenResult;

PktOut *ssh2_chanopen_init( struct ssh2_channel *c, const char *type );

SshChannel *ssh2_session_open(ConnectionLayer *cl, Channel *chan);

void ssh2channel_start_shell( SshChannel *c, bool want_reply );
void ssh2channel_start_command( SshChannel *c, bool want_reply, const char *command );
bool ssh2channel_start_subsystem( SshChannel *c, bool want_reply, const char *subsystem );
bool ssh2channel_send_serial_break( SshChannel *c, bool want_reply, int length );
bool ssh2channel_send_signal( SshChannel *c, bool want_reply, const char *signame );

#endif /* PUTTY_SSH2CONNECTION_H */
