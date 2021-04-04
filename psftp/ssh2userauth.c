/*
 * Packet protocol layer for the client side of the SSH-2 userauth
 * protocol (RFC 4252).
 */

#include <assert.h>

#include "putty.h"
#include "ssh.h"
#include "sshbpp.h"
#include "sshppl.h"
#include "sshcr.h"

#ifndef NO_GSSAPI
#include "sshgssc.h"
#include "sshgss.h"
#endif

#define BANNER_LIMIT	131072

typedef struct agent_key
{
	strbuf *blob, *comment;
	ptrlen algorithm;
} agent_key;

typedef enum
{
	AUTH_TYPE_NONE,
	AUTH_TYPE_PUBLICKEY,
	AUTH_TYPE_PUBLICKEY_OFFER_LOUD,
	AUTH_TYPE_PUBLICKEY_OFFER_QUIET,
	AUTH_TYPE_PASSWORD,
	AUTH_TYPE_GSSAPI,      /* always QUIET */
	AUTH_TYPE_KEYBOARD_INTERACTIVE,
	AUTH_TYPE_KEYBOARD_INTERACTIVE_QUIET
} USER_AUTH_STATE_TYPE;

struct ssh2_userauth_state
{
	int crState;

	PacketProtocolLayer *transport_layer, *successor_layer;
	Filename *keyfile;
	char *fullhostname;
	char *default_username;
	bool try_gssapi_auth, try_gssapi_kex_auth, gssapi_fwd;

	ptrlen session_id;
	USER_AUTH_STATE_TYPE type;
	bool can_pubkey, can_passwd;
	bool tried_pubkey_config;
	struct ssh_connection_shared_gss_state *shgss;
#ifndef NO_GSSAPI
	bool can_gssapi;
	bool can_gssapi_keyex_auth;
	bool tried_gssapi;
	bool tried_gssapi_keyex_auth;
	time_t gss_cred_expiry;
	Ssh_gss_buf gss_buf;
	Ssh_gss_buf gss_rcvtok, gss_sndtok;
	Ssh_gss_stat gss_stat;
#endif
	bool suppress_wait_for_response_packet;
	const char *username;
	char *password;
	bool got_username;
	strbuf *publickey_blob;
	bool privatekey_available, privatekey_encrypted;
	char *publickey_algorithm;
	char *publickey_comment;
	int len;
	PktOut *pktout;

	PacketProtocolLayer ppl;
};

static void ssh2_userauth_free( PacketProtocolLayer * );
static void ssh2_userauth_process_queue( PacketProtocolLayer * );
static bool ssh2_userauth_get_specials( PacketProtocolLayer *ppl, add_special_fn_t add_special, void *ctx );
static void ssh2_userauth_special_cmd( PacketProtocolLayer *ppl, SessionSpecialCode code, int arg );
static bool ssh2_userauth_want_user_input( PacketProtocolLayer *ppl );
static void ssh2_userauth_got_user_input( PacketProtocolLayer *ppl );
static void ssh2_userauth_reconfigure( PacketProtocolLayer *ppl );

static void ssh2_userauth_add_sigblob( struct ssh2_userauth_state *s, PktOut *pkt, ptrlen pkblob, ptrlen sigblob );
static void ssh2_userauth_add_session_id( struct ssh2_userauth_state *s, strbuf *sigdata );
#ifndef NO_GSSAPI
static PktOut *ssh2_userauth_gss_packet( struct ssh2_userauth_state *s, const char *authtype );
#endif

static const struct PacketProtocolLayerVtable ssh2_userauth_vtable =
{
	ssh2_userauth_free,
	ssh2_userauth_process_queue,
	ssh2_userauth_get_specials,
	ssh2_userauth_special_cmd,
	ssh2_userauth_want_user_input,
	ssh2_userauth_got_user_input,
	ssh2_userauth_reconfigure,
	ssh_ppl_default_queued_data_size,
	"ssh-userauth",
};

PacketProtocolLayer *ssh2_userauth_new(
	PacketProtocolLayer *successor_layer,
	const char *fullhostname,
	Filename *keyfile,
	const char *default_username,
	bool try_gssapi_auth, bool try_gssapi_kex_auth,
	bool gssapi_fwd, struct ssh_connection_shared_gss_state *shgss )
{
	struct ssh2_userauth_state *s = snew( struct ssh2_userauth_state );
	memset( s, 0, sizeof( *s ) );
	s->ppl.vt = &ssh2_userauth_vtable;

	s->successor_layer = successor_layer;
	s->fullhostname = dupstr( fullhostname );
	s->keyfile = filename_copy( keyfile );
	s->default_username = dupstr( default_username );
	s->try_gssapi_auth = try_gssapi_auth;
	s->try_gssapi_kex_auth = try_gssapi_kex_auth;
	s->gssapi_fwd = gssapi_fwd;
	s->shgss = shgss;

	return &s->ppl;
}

void ssh2_userauth_set_transport_layer( PacketProtocolLayer *userauth, PacketProtocolLayer *transport )
{
	struct ssh2_userauth_state *s = container_of( userauth, struct ssh2_userauth_state, ppl );
	s->transport_layer = transport;
}

static void ssh2_userauth_free( PacketProtocolLayer *ppl )
{
	struct ssh2_userauth_state *s = container_of( ppl, struct ssh2_userauth_state, ppl );

	if ( s->successor_layer )
	{
		ssh_ppl_free( s->successor_layer );
	}

	filename_free( s->keyfile );
	sfree( s->default_username );
	sfree( s->fullhostname );
	sfree( s->publickey_comment );
	sfree( s->publickey_algorithm );
	if ( s->publickey_blob )
	{
		strbuf_free( s->publickey_blob );
	}

	sfree( s );
}

static void ssh2_userauth_filter_queue( struct ssh2_userauth_state *s )
{
	PktIn *pktin;

	while ( ( pktin = pq_peek( s->ppl.ssh, s->ppl.in_pq ) ) != NULL )
	{
		switch ( pktin->type )
		{
			case SSH2_MSG_USERAUTH_BANNER:
			{
				pq_pop( s->ppl.ssh, s->ppl.in_pq );
			}
			break;

			default:
			{
				return;
			}
			break;
		}
	}
}

static PktIn *ssh2_userauth_pop( struct ssh2_userauth_state *s )
{
	ssh2_userauth_filter_queue( s );
	return pq_pop( s->ppl.ssh, s->ppl.in_pq );
}

static void ssh2_userauth_process_queue( PacketProtocolLayer *ppl )
{
	struct ssh2_userauth_state *s = container_of( ppl, struct ssh2_userauth_state, ppl );
	PktIn *pktin;

	ssh2_userauth_filter_queue( s );     /* no matter why we were called */

	s->ppl.ssh->ssh_status |= SSH_STATUS_AUTHENTICATE;

	crBegin( s->crState );

#ifndef NO_GSSAPI
	s->tried_gssapi = false;
	s->tried_gssapi_keyex_auth = false;
#endif

	/*
	* Misc one-time setup for authentication.
	*/
	s->session_id = ssh2_transport_get_session_id( s->transport_layer );

	s->publickey_blob = NULL;

	/*
	* Load the public half of any configured public key file for later use.
	*/
	if ( s->keyfile != NULL )
	{
		int keytype;
		keytype = key_type( s->keyfile );
		if ( keytype == SSH_KEYTYPE_SSH2 || keytype == SSH_KEYTYPE_SSH2_PUBLIC_RFC4716 || keytype == SSH_KEYTYPE_SSH2_PUBLIC_OPENSSH )
		{
			const char *error;
			s->publickey_blob = strbuf_new();
			if ( ssh2_userkey_loadpub( s->keyfile, &s->publickey_algorithm, BinarySink_UPCAST( s->publickey_blob ), &s->publickey_comment, &error ) )
			{
				s->privatekey_available = ( keytype == SSH_KEYTYPE_SSH2 );

				s->privatekey_encrypted = ssh2_userkey_encrypted( s->keyfile, NULL );
			}
			else
			{
				strbuf_free( s->publickey_blob );
				s->publickey_blob = NULL;
			}
		}
		else
		{
			s->publickey_blob = NULL;
		}
	}

	/*
	* We repeat this whole loop, including the username prompt,
	* until we manage a successful authentication. If the user
	* types the wrong _password_, they can be sent back to the
	* beginning to try another username, if this is configured on.
	* (If they specify a username in the config, they are never
	* asked, even if they do give a wrong password.)
	*
	* I think this best serves the needs of
	*
	*  - the people who have no configuration, no keys, and just
	*    want to try repeated (username,password) pairs until they
	*    type both correctly
	*
	*  - people who have keys and configuration but occasionally
	*    need to fall back to passwords
	*
	*  - people with a key held in Pageant, who might not have
	*    logged in to a particular machine before; so they want to
	*    type a username, and then _either_ their key will be
	*    accepted, _or_ they will type a password. If they mistype
	*    the username they will want to be able to get back and
	*    retype it!
	*/
	s->got_username = false;
	while ( 1 )
	{
		/*
		* Get a username.
		*/
		if ( s->got_username )
		{
			/*
			* We got a username last time round this loop, and
			* with change_username turned off we don't try to get
			* it again.
			*/
		}
		else if ( ( s->username = s->default_username ) == NULL )
		{
			// No username supplied.
			ssh_user_close( s->ppl.ssh );
			return;
		}

		s->got_username = true;

		/*
		* Send an authentication request using method "none": (a)
		* just in case it succeeds, and (b) so that we know what
		* authentication methods we can usefully try next.
		*/
//		s->ppl.bpp->pls->actx = SSH2_PKTCTX_NOAUTH;

		s->pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_USERAUTH_REQUEST );
		put_stringz( s->pktout, s->username );
		put_stringz( s->pktout, s->successor_layer->vt->name );
		put_stringz( s->pktout, "none" );    /* method */
		pq_push( s->ppl.ssh, s->ppl.out_pq, s->pktout );
		s->type = AUTH_TYPE_NONE;

		s->tried_pubkey_config = false;

		while ( 1 )
		{
			/*
			* Wait for the result of the last authentication request,
			* unless the request terminated for some reason on our
			* own side.
			*/
			if ( s->suppress_wait_for_response_packet )
			{
				pktin = NULL;
				s->suppress_wait_for_response_packet = false;
			}
			else
			{
				crMaybeWaitUntilV( ( pktin = ssh2_userauth_pop( s ) ) != NULL );
			}

			if ( pktin && pktin->type == SSH2_MSG_USERAUTH_SUCCESS )
			{
				goto userauth_success;
			}

			if ( pktin && pktin->type != SSH2_MSG_USERAUTH_FAILURE && s->type != AUTH_TYPE_GSSAPI )
			{
				ssh_proto_error( s->ppl.ssh );
				return;
			}

			/*
			* OK, we're now sitting on a USERAUTH_FAILURE message, so
			* we can look at the string in it and know what we can
			* helpfully try next.
			*/
			if ( pktin && pktin->type == SSH2_MSG_USERAUTH_FAILURE )
			{
				ptrlen methods = get_string( pktin );

				/*
				* Scan it for method identifiers we know about.
				*/
				bool srv_pubkey = false, srv_passwd = false;
				bool srv_keyb_inter = false;
				#ifndef NO_GSSAPI
				bool srv_gssapi = false, srv_gssapi_keyex_auth = false;
				#endif

				for ( ptrlen method; get_commasep_word( &methods, &method ); )
				{
					if ( ptrlen_eq_string( method, "publickey" ) )
					{
						srv_pubkey = true;
					}
					else if ( ptrlen_eq_string( method, "password" ) )
					{
						srv_passwd = true;
					}
					else if ( ptrlen_eq_string( method, "keyboard-interactive" ) )
					{
						srv_keyb_inter = true;
					}
#ifndef NO_GSSAPI
					else if ( ptrlen_eq_string( method, "gssapi-with-mic" ) )
					{
						srv_gssapi = true;
					}
					else if ( ptrlen_eq_string( method, "gssapi-keyex" ) )
					{
						srv_gssapi_keyex_auth = true;
					}
#endif
				}

				/*
				* And combine those flags with our own configuration
				* and context to set the main can_foo variables.
				*/
				s->can_pubkey = srv_pubkey;
				s->can_passwd = srv_passwd;
#ifndef NO_GSSAPI
				s->can_gssapi = s->try_gssapi_auth && srv_gssapi && s->shgss != NULL && s->shgss->lib != NULL/*g_gss_libs != NULL && g_gss_libs->nlibraries > 0*/;
				s->can_gssapi_keyex_auth = s->try_gssapi_kex_auth && srv_gssapi_keyex_auth && s->shgss != NULL && s->shgss->lib != NULL/*g_gss_libs != NULL && g_gss_libs->nlibraries > 0*/ && s->shgss->ctx;
#endif
			}

//			s->ppl.bpp->pls->actx = SSH2_PKTCTX_NOAUTH;

#ifndef NO_GSSAPI
			if ( s->can_gssapi_keyex_auth && !s->tried_gssapi_keyex_auth )
			{
				/* gssapi-keyex authentication */

				s->type = AUTH_TYPE_GSSAPI;
				s->tried_gssapi_keyex_auth = true;
//				s->ppl.bpp->pls->actx = SSH2_PKTCTX_GSSAPI;

				s->pktout = ssh2_userauth_gss_packet( s, "gssapi-keyex" );
				pq_push( s->ppl.ssh, s->ppl.out_pq, s->pktout );
				s->shgss->lib->release_cred( s->shgss->lib, &s->shgss->ctx );
				s->shgss->ctx = NULL;

				continue;
			}
			else
#endif /* NO_GSSAPI */
				if ( s->can_pubkey && s->publickey_blob && s->privatekey_available && !s->tried_pubkey_config )
			{
				ssh2_userkey *key;   /* not live over crReturn */
				char *passphrase;           /* not live over crReturn */

//				s->ppl.bpp->pls->actx = SSH2_PKTCTX_PUBLICKEY;

				s->tried_pubkey_config = true;

				/*
				* Try the public key supplied in the configuration.
				*
				* First, offer the public blob to see if the server is willing to accept it.
				*/
				s->pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_USERAUTH_REQUEST );
				put_stringz( s->pktout, s->username );
				put_stringz( s->pktout, s->successor_layer->vt->name );
				put_stringz( s->pktout, "publickey" );    /* method */
				put_bool( s->pktout, false);
				/* no signature included */
				put_stringz( s->pktout, s->publickey_algorithm );
				put_string( s->pktout, s->publickey_blob->s, s->publickey_blob->len );
				pq_push( s->ppl.ssh, s->ppl.out_pq, s->pktout );

				crMaybeWaitUntilV( ( pktin = ssh2_userauth_pop( s ) ) != NULL );
				if ( pktin->type != SSH2_MSG_USERAUTH_PK_OK )
				{
					/* Key refused. Give up. */
					pq_push_front( s->ppl.ssh, s->ppl.in_pq, pktin );
					s->type = AUTH_TYPE_PUBLICKEY_OFFER_LOUD;
					continue; /* process this new message */
				}

				/*
				* Actually attempt a serious authentication using the key.
				*/

				key = NULL;
				while ( !key )
				{
					const char *error;  /* not live over crReturn */
					if ( s->privatekey_encrypted )
					{
						if ( s->ppl.ssh->password == NULL )
						{
							ssh_bpp_queue_disconnect( s->ppl.bpp, "Unable to authenticate", SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER );
							ssh_user_close( s->ppl.ssh );
							return;
						}

						passphrase = dupstr( s->ppl.ssh->password );
					}
					else
					{
						passphrase = NULL; /* no passphrase needed */
					}

					/*
					* Try decrypting the key.
					*/
					key = ssh2_load_userkey( s->keyfile, passphrase, &error );
					if ( passphrase )
					{
						/* burn the evidence */
						smemclr( passphrase, strlen( passphrase ) );
						sfree( passphrase );
					}
					if ( key == SSH2_WRONG_PASSPHRASE || key == NULL )
					{
						key = NULL;
						s->suppress_wait_for_response_packet = true;
						break; /* try something else */
					}
					else
					{
						/* FIXME: if we ever support variable signature
						* flags, this is somewhere they'll need to be put */
						char *invalid = ssh_key_invalid( key->key, 0 );
						if ( invalid )
						{
							ssh_key_free( key->key );
							sfree( key->comment );
							sfree( key );
							sfree( invalid );
							key = NULL;
							s->suppress_wait_for_response_packet = true;
							break; /* try something else */
						}
					}
				}

				if ( key )
				{
					strbuf *pkblob, *sigdata, *sigblob;

					/*
					* We have loaded the private key and the server
					* has announced that it's willing to accept it.
					* Hallelujah. Generate a signature and send it.
					*/
					s->pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_USERAUTH_REQUEST );
					put_stringz( s->pktout, s->username );
					put_stringz( s->pktout, s->successor_layer->vt->name );
					put_stringz( s->pktout, "publickey" ); /* method */
					put_bool( s->pktout, true ); /* signature follows */
					put_stringz( s->pktout, ssh_key_ssh_id( key->key ) );
					pkblob = strbuf_new();
					ssh_key_public_blob( key->key, BinarySink_UPCAST( pkblob ) );
					put_string( s->pktout, pkblob->s, pkblob->len );

					/*
					* The data to be signed is:
					*
					*   string  session-id
					*
					* followed by everything so far placed in the outgoing packet.
					*/
					sigdata = strbuf_new();
					ssh2_userauth_add_session_id( s, sigdata );
					put_data( sigdata, s->pktout->data + 5, s->pktout->length - 5 );
					sigblob = strbuf_new();
					ssh_key_sign( key->key, ptrlen_from_strbuf( sigdata ), 0, BinarySink_UPCAST( sigblob ) );
					strbuf_free( sigdata );
					ssh2_userauth_add_sigblob( s, s->pktout, ptrlen_from_strbuf( pkblob ), ptrlen_from_strbuf( sigblob ) );
					strbuf_free( pkblob );
					strbuf_free( sigblob );

					pq_push( s->ppl.ssh, s->ppl.out_pq, s->pktout );
					s->type = AUTH_TYPE_PUBLICKEY;
					ssh_key_free( key->key );
					sfree( key->comment );
					sfree( key );
				}
			}
#ifndef NO_GSSAPI
			else if ( s->can_gssapi && !s->tried_gssapi )
			{
				/* gssapi-with-mic authentication */

				ptrlen data;

				s->type = AUTH_TYPE_GSSAPI;
				s->tried_gssapi = true;
//				s->ppl.bpp->pls->actx = SSH2_PKTCTX_GSSAPI;

				/* Sending USERAUTH_REQUEST with "gssapi-with-mic" method */
				s->pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_USERAUTH_REQUEST );
				put_stringz( s->pktout, s->username );
				put_stringz( s->pktout, s->successor_layer->vt->name );
				put_stringz( s->pktout, "gssapi-with-mic" );

				/* add mechanism info */
				s->shgss->lib->indicate_mech( s->shgss->lib, &s->gss_buf );

				/* number of GSSAPI mechanisms */
				put_uint32( s->pktout, 1 );

				/* length of OID + 2 */
				put_uint32( s->pktout, s->gss_buf.length + 2 );
				put_byte( s->pktout, SSH2_GSS_OIDTYPE );

				/* length of OID */
				put_byte( s->pktout, s->gss_buf.length );

				put_data( s->pktout, s->gss_buf.value, s->gss_buf.length );
				pq_push( s->ppl.ssh, s->ppl.out_pq, s->pktout );
				crMaybeWaitUntilV( ( pktin = ssh2_userauth_pop( s ) ) != NULL );
				if ( pktin->type != SSH2_MSG_USERAUTH_GSSAPI_RESPONSE )
				{
					pq_push_front( s->ppl.ssh, s->ppl.in_pq, pktin );
					continue;
				}

				/* check returned packet ... */

				data = get_string( pktin );
				s->gss_rcvtok.value = ( char * )data.ptr;
				s->gss_rcvtok.length = data.len;
				if ( s->gss_rcvtok.length != s->gss_buf.length + 2 ||
					( ( char * )s->gss_rcvtok.value )[ 0 ] != SSH2_GSS_OIDTYPE ||
					( ( char * )s->gss_rcvtok.value )[ 1 ] != s->gss_buf.length ||
					memcmp( ( char * )s->gss_rcvtok.value + 2, s->gss_buf.value,s->gss_buf.length ) )
				{
					continue;
				}

				/* Import server name if not cached from KEX */
				if ( s->shgss->srv_name == GSS_C_NO_NAME )
				{
					s->gss_stat = s->shgss->lib->import_name( s->shgss->lib, s->fullhostname, &s->shgss->srv_name );
					if ( s->gss_stat != SSH_GSS_OK )
					{
						continue;
					}
				}

				/* Allocate our gss_ctx */
				s->gss_stat = s->shgss->lib->acquire_cred( s->shgss->lib, &s->shgss->ctx, NULL );
				if ( s->gss_stat != SSH_GSS_OK )
				{
					/* The failure was on our side, so the server
					* won't be sending a response packet indicating
					* failure. Avoid waiting for it next time round
					* the loop. */
					s->suppress_wait_for_response_packet = true;
					continue;
				}

				/* initial tokens are empty */
				SSH_GSS_CLEAR_BUF( &s->gss_rcvtok );
				SSH_GSS_CLEAR_BUF( &s->gss_sndtok );

				/* now enter the loop */
				do
				{
					/*
					* When acquire_cred yields no useful expiration, go with the service ticket expiration.
					*/
					s->gss_stat = s->shgss->lib->init_sec_context(
						s->shgss->lib,
						&s->shgss->ctx,
						s->shgss->srv_name,
						s->gssapi_fwd,
						&s->gss_rcvtok,
						&s->gss_sndtok,
						NULL,
						NULL );

					if ( s->gss_stat != SSH_GSS_S_COMPLETE && s->gss_stat != SSH_GSS_S_CONTINUE_NEEDED )
					{
						if ( s->shgss->lib->display_status( s->shgss->lib, s->shgss->ctx, &s->gss_buf ) == SSH_GSS_OK )
						{
							sfree( s->gss_buf.value );
						}

						pq_push_front( s->ppl.ssh, s->ppl.in_pq, pktin );
						break;
					}

					/*
					* Client and server now exchange tokens until GSSAPI no longer says CONTINUE_NEEDED
					*/
					if ( s->gss_sndtok.length != 0 )
					{
						s->pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_USERAUTH_GSSAPI_TOKEN );
						put_string( s->pktout, s->gss_sndtok.value, s->gss_sndtok.length );
						pq_push( s->ppl.ssh, s->ppl.out_pq, s->pktout );
						s->shgss->lib->free_tok( s->shgss->lib, &s->gss_sndtok );
					}

					if ( s->gss_stat == SSH_GSS_S_CONTINUE_NEEDED )
					{
						crMaybeWaitUntilV( ( pktin = ssh2_userauth_pop( s ) ) != NULL );

						if ( pktin->type == SSH2_MSG_USERAUTH_GSSAPI_ERRTOK )
						{
							/*
							* Per RFC 4462 section 3.9, this packet
							* type MUST immediately precede an
							* ordinary USERAUTH_FAILURE.
							*
							* We currently don't know how to do
							* anything with the GSSAPI error token
							* contained in this packet, so we ignore
							* it and just wait for the following
							* FAILURE.
							*/
							crMaybeWaitUntilV( ( pktin = ssh2_userauth_pop( s ) ) != NULL );
							if ( pktin->type != SSH2_MSG_USERAUTH_FAILURE )
							{
								ssh_proto_error( s->ppl.ssh );
								return;
							}
						}

						if ( pktin->type == SSH2_MSG_USERAUTH_FAILURE )
						{
							s->gss_stat = SSH_GSS_FAILURE;
							pq_push_front( s->ppl.ssh, s->ppl.in_pq, pktin );
							break;
						}
						else if ( pktin->type != SSH2_MSG_USERAUTH_GSSAPI_TOKEN )
						{
							s->gss_stat = SSH_GSS_FAILURE;
							break;
						}
						data = get_string( pktin );
						s->gss_rcvtok.value = ( char * )data.ptr;
						s->gss_rcvtok.length = data.len;
					}
				}
				while ( s->gss_stat == SSH_GSS_S_CONTINUE_NEEDED );

				if ( s->gss_stat != SSH_GSS_OK )
				{
					s->shgss->lib->release_cred( s->shgss->lib, &s->shgss->ctx );
					continue;
				}

				/* Now send the MIC */

				s->pktout = ssh2_userauth_gss_packet( s, "gssapi-with-mic" );
				pq_push( s->ppl.ssh, s->ppl.out_pq, s->pktout );

				s->shgss->lib->release_cred( s->shgss->lib, &s->shgss->ctx );
				continue;
			}
#endif
			else if ( s->can_passwd )
			{
				/*
				* Plain old password authentication.
				*/
				bool changereq_first_time; /* not live over crReturn */

//				s->ppl.bpp->pls->actx = SSH2_PKTCTX_PASSWORD;

				if ( s->ppl.ssh->password == NULL )
				{
					ssh_bpp_queue_disconnect( s->ppl.bpp, "Unable to authenticate", SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER );
					ssh_user_close( s->ppl.ssh );
					return;
				}

				/*
				* Squirrel away the password. (We may need it later if asked to change it.)
				*/
				s->password = dupstr( s->ppl.ssh->password );

				/*
				* Send the password packet.
				*
				* We pad out the password packet to 256 bytes to make
				* it harder for an attacker to find the length of the
				* user's password.
				*
				* Anyone using a password longer than 256 bytes
				* probably doesn't have much to worry about from
				* people who find out how long their password is!
				*/
				s->pktout = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_USERAUTH_REQUEST );
				put_stringz( s->pktout, s->username );
				put_stringz( s->pktout, s->successor_layer->vt->name );
				put_stringz( s->pktout, "password" );
				put_bool( s->pktout, false );
				put_stringz( s->pktout, s->password );
				s->pktout->minlen = 256;
				pq_push( s->ppl.ssh, s->ppl.out_pq, s->pktout );
				s->type = AUTH_TYPE_PASSWORD;

				/*
				* Wait for next packet, in case it's a password change request.
				*/
				crMaybeWaitUntilV( ( pktin = ssh2_userauth_pop( s ) ) != NULL );
				changereq_first_time = true;

				/*
				* We need to reexamine the current pktin at the top
				* of the loop. Either:
				*  - we weren't asked to change password at all, in
				*    which case it's a SUCCESS or FAILURE with the
				*    usual meaning
				*  - we sent a new password, and the server was
				*    either OK with it (SUCCESS or FAILURE w/partial
				*    success) or unhappy with the _old_ password
				*    (FAILURE w/o partial success)
				* In any of these cases, we go back to the top of
				* the loop and start again.
				*/
				pq_push_front( s->ppl.ssh, s->ppl.in_pq, pktin );

				/*
				* We don't need the old password any more, in any case. Burn the evidence.
				*/
				smemclr( s->password, strlen( s->password ) );
				sfree( s->password );
			}
			else
			{
				ssh_bpp_queue_disconnect( s->ppl.bpp, "No supported authentication methods available", SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE );
				ssh_sw_abort( s->ppl.ssh );
				return;
			}
		}
	}

userauth_success:

	s->ppl.ssh->ssh_status &= ~SSH_STATUS_AUTHENTICATE;

	/*
	* We've just received USERAUTH_SUCCESS, and we haven't sent
	* any packets since. Signal the transport layer to consider
	* doing an immediate rekey, if it has any reason to want to.
	*/
	ssh2_transport_notify_auth_done( s->transport_layer );

	/*
	* Finally, hand over to our successor layer, and return
	* immediately without reaching the crFinishV: ssh_ppl_replace
	* will have freed us, so crFinishV's zeroing-out of crState would
	* be a use-after-free bug.
	*/
	{
		PacketProtocolLayer *successor = s->successor_layer;
		s->successor_layer = NULL;     /* avoid freeing it ourself */
		ssh_ppl_replace( &s->ppl, successor );
		return;   /* we've just freed s, so avoid even touching s->crState */
	}

	crFinishV;
}

static void ssh2_userauth_add_session_id( struct ssh2_userauth_state *s, strbuf *sigdata )
{
	if ( s->ppl.remote_bugs & BUG_SSH2_PK_SESSIONID )
	{
		put_datapl( sigdata, s->session_id );
	}
	else
	{
		put_stringpl( sigdata, s->session_id );
	}
}

/*
 * Helper function to add an SSH-2 signature blob to a packet. Expects
 * to be shown the public key blob as well as the signature blob.
 * Normally just appends the sig blob unmodified as a string, except
 * that it optionally breaks it open and fiddle with it to work around
 * BUG_SSH2_RSA_PADDING.
 */
static void ssh2_userauth_add_sigblob( struct ssh2_userauth_state *s, PktOut *pkt, ptrlen pkblob, ptrlen sigblob )
{
	BinarySource pk[ 1 ], sig[ 1 ];
	BinarySource_BARE_INIT_PL( pk, pkblob );
	BinarySource_BARE_INIT_PL( sig, sigblob );

	/*
	* See if this is in fact an ssh-rsa signature and a buggy
	* server; otherwise we can just do this the easy way.
	*/
	if ( ( s->ppl.remote_bugs & BUG_SSH2_RSA_PADDING ) &&
		ptrlen_eq_string( get_string( pk ), "ssh-rsa" ) &&
		ptrlen_eq_string( get_string( sig ), "ssh-rsa" ) )
	{
		ptrlen mod_mp, sig_mp;
		size_t sig_prefix_len;

		/*
		* Find the modulus and signature integers.
		*/
		get_string( pk );                /* skip over exponent */
		mod_mp = get_string( pk );       /* remember modulus */
		sig_prefix_len = sig->pos;
		sig_mp = get_string( sig );
		if ( get_err( pk ) || get_err( sig ) )
		{
			goto give_up;
		}

		/*
		* Find the byte length of the modulus, not counting leading zeroes.
		*/
		while ( mod_mp.len > 0 && *( const char * )mod_mp.ptr == 0 )
		{
			mod_mp.len--;
			mod_mp.ptr = ( const char * )mod_mp.ptr + 1;
		}

		if ( mod_mp.len > sig_mp.len )
		{
			strbuf *substr = strbuf_new();
			put_data( substr, sigblob.ptr, sig_prefix_len );
			put_uint32( substr, mod_mp.len );
			put_padding( substr, mod_mp.len - sig_mp.len, 0 );
			put_datapl( substr, sig_mp );
			put_stringsb( pkt, substr );
			return;
		}

		/* Otherwise fall through and do it the easy way. We also come
		* here as a fallback if we discover above that the key blob
		* is misformatted in some way. */
give_up:;
	}

	put_stringpl( pkt, sigblob );
}

#ifndef NO_GSSAPI
static PktOut *ssh2_userauth_gss_packet( struct ssh2_userauth_state *s, const char *authtype )
{
	strbuf *sb;
	PktOut *p;
	Ssh_gss_buf buf;
	Ssh_gss_buf mic;

	/*
	* The mic is computed over the session id + intended USERAUTH_REQUEST packet.
	*/
	sb = strbuf_new();
	put_stringpl( sb, s->session_id );
	put_byte( sb, SSH2_MSG_USERAUTH_REQUEST );
	put_stringz( sb, s->username );
	put_stringz( sb, s->successor_layer->vt->name );
	put_stringz( sb, authtype );

	/* Compute the mic */
	buf.value = sb->s;
	buf.length = sb->len;
	s->shgss->lib->get_mic( s->shgss->lib, s->shgss->ctx, &buf, &mic );
	strbuf_free( sb );

	/* Now we can build the real packet */
	if ( strcmp( authtype, "gssapi-with-mic" ) == 0 )
	{
		p = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_USERAUTH_GSSAPI_MIC );
	}
	else
	{
		p = ssh_bpp_new_pktout( s->ppl.ssh, s->ppl.bpp, SSH2_MSG_USERAUTH_REQUEST );
		put_stringz( p, s->username );
		put_stringz( p, s->successor_layer->vt->name );
		put_stringz( p, authtype );
	}
	put_string( p, mic.value, mic.length );

	return p;
}
#endif

static bool ssh2_userauth_get_specials( PacketProtocolLayer * /*ppl*/, add_special_fn_t /*add_special*/, void * /*ctx*/ )
{
	/* No specials provided by this layer. */
	return false;
}

static void ssh2_userauth_special_cmd( PacketProtocolLayer * /*ppl*/, SessionSpecialCode /*code*/, int /*arg*/ )
{
	/* No specials provided by this layer. */
}

static bool ssh2_userauth_want_user_input( PacketProtocolLayer * /*ppl*/ )
{
	return false;
}

static void ssh2_userauth_got_user_input( PacketProtocolLayer * /*ppl*/ ) {}

static void ssh2_userauth_reconfigure( PacketProtocolLayer *ppl )
{
	struct ssh2_userauth_state *s = container_of( ppl, struct ssh2_userauth_state, ppl );
	ssh_ppl_reconfigure( s->successor_layer );
}
