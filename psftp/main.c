/*
	psftp DLL based on PuTTY's SFTP client.
	Copyright (C) 2021 Eric Kutcher

	PuTTY is copyright 1997-2020 Simon Tatham.

	Portions copyright Robert de Bath, Joris van Rantwijk, Delian
	Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas Barry,
	Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus
	Kuhn, Colin Watson, Christopher Staite, Lorenz Diener, Christian
	Brabandt, Jeff Smith, Pavel Kryukov, Maxim Kuznetsov, Svyatoslav
	Kuzmich, Nico Williams, Viktor Dukhovni, and CORE SDI S.A.

	Permission is hereby granted, free of charge, to any person
	obtaining a copy of this software and associated documentation files
	(the "Software"), to deal in the Software without restriction,
	including without limitation the rights to use, copy, modify, merge,
	publish, distribute, sublicense, and/or sell copies of the Software,
	and to permit persons to whom the Software is furnished to do so,
	subject to the following conditions:

	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE
	FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
	CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "putty.h"
#include "ssh.h"
#include "sftp.h"

volatile int g_keep_alive_time = 0;
volatile int g_rekey_time = 60;
volatile int g_gss_rekey_time = 2;
volatile unsigned long g_rekey_data_limit = 1073741824;

volatile int g_CONF_compression = 0;

int g_CONF_ssh_gsslist[ GSS_LIB_MAX ] = { GSS_LIB_GSSAPI32, GSS_LIB_SSPI };

bool g_CONF_ssh_prefer_known_hostkeys = true;
bool g_CONF_ssh_no_userauth = false;

volatile int g_CONF_try_gssapi_auth = 1;
volatile int g_CONF_try_gssapi_kex = 1;
bool g_CONF_gssapifwd = false;

char *g_CONF_remote_cmd = "sftp";
bool g_CONF_ssh_subsys = true;
char *g_CONF_remote_cmd2 = "test -x /usr/lib/sftp-server && " \
						   "exec /usr/lib/sftp-server\n" \
						   "test -x /usr/local/lib/sftp-server && " \
						   "exec /usr/local/lib/sftp-server\n" \
						   "exec sftp-server";
bool g_CONF_ssh_subsys2 = false;

int g_CONF_sshbug_ignore1 = AUTO;
int g_CONF_sshbug_plainpw1 = AUTO;
int g_CONF_sshbug_rsa1 = AUTO;
int g_CONF_sshbug_hmac2 = AUTO;
int g_CONF_sshbug_derivekey2 = AUTO;
int g_CONF_sshbug_rsapad2 = AUTO;
int g_CONF_sshbug_pksessid2 = AUTO;
int g_CONF_sshbug_rekey2 = AUTO;
int g_CONF_sshbug_maxpkt2 = AUTO;
int g_CONF_sshbug_ignore2 = AUTO;
int g_CONF_sshbug_oldgex2 = AUTO;
int g_CONF_sshbug_winadj = AUTO;
int g_CONF_sshbug_chanreq = AUTO;

//

bool g_gss_loaded = false;
CRITICAL_SECTION gss_library_cs;
CRITICAL_SECTION algorithm_priorities_cs;
CRITICAL_SECTION ssh2kex_cs;

// *_MAX value terminates the array.
//int g_priority_kex_algorithm[ KEX_MAX ] = { KEX_ECDH, KEX_DHGEX, KEX_DHGROUP14, KEX_RSA, KEX_DHGROUP1, KEX_MAX };
//int g_priority_host_key[ HK_MAX ] = { HK_ED25519, HK_ECDSA, HK_RSA, HK_DSA, HK_MAX };
//int g_priority_encryption_cipher[ CIPHER_MAX ] = { CIPHER_AES, CIPHER_CHACHA20, CIPHER_3DES, CIPHER_DES, CIPHER_BLOWFISH, CIPHER_ARCFOUR, CIPHER_MAX };

int g_priority_kex_algorithm[ KEX_MAX ] = { KEX_ECDH, KEX_DHGEX, KEX_DHGROUP14, KEX_RSA, KEX_MAX, KEX_MAX };
int g_priority_host_key[ HK_MAX ] = { HK_ED25519, HK_ECDSA, HK_RSA, HK_DSA, HK_MAX };
int g_priority_encryption_cipher[ CIPHER_MAX ] = { CIPHER_AES, CIPHER_CHACHA20, CIPHER_3DES, CIPHER_MAX, CIPHER_MAX, CIPHER_MAX, CIPHER_MAX };

struct FILE_ATTRIBUTES
{
	unsigned long long size;
	unsigned long mtime;
};

extern "C" __declspec ( dllexport )
VOID SFTP_InitGSSAPI()
{
	if ( g_gss_libs == NULL )
	{
		// Creates g_gss_libs
		ssh_gss_setup();
	}
}

extern "C" __declspec ( dllexport )
VOID SFTP_UninitGSSAPI()
{
	if ( g_gss_libs != NULL )
	{
		ssh_gss_cleanup( g_gss_libs );
	}
}

extern "C" __declspec ( dllexport )
VOID SFTP_SetConfigInfo( unsigned char info, unsigned long value )
{
	switch ( info )
	{
		case 0: { InterlockedExchange( ( volatile LONG * )&g_CONF_compression, value ); } break;
		case 1: { InterlockedExchange( ( volatile LONG * )&g_CONF_try_gssapi_auth, value ); } break;
		case 2: { InterlockedExchange( ( volatile LONG * )&g_CONF_try_gssapi_kex, value ); } break;

		case 3: { InterlockedExchange( ( volatile LONG * )&g_keep_alive_time, value ); } break;
		case 4: { InterlockedExchange( ( volatile LONG * )&g_rekey_time, value ); } break;
		case 5: { InterlockedExchange( ( volatile LONG * )&g_gss_rekey_time, value ); } break;
		case 6: { InterlockedExchange( ( volatile LONG * )&g_rekey_data_limit, value ); } break;
	}
}

extern "C" __declspec ( dllexport )
VOID SFTP_SetAlgorithmPriorities( unsigned char algorithm, unsigned char priority_list[], unsigned char priority_list_length )
{
	EnterCriticalSection( &algorithm_priorities_cs );

	int *p_priority_list = NULL;
	int max_value = 0;

	unsigned char j = 0;

	switch ( algorithm )
	{
		case 0: { p_priority_list = g_priority_kex_algorithm; max_value = KEX_MAX; } break;
		case 1: { p_priority_list = g_priority_host_key; max_value = HK_MAX; } break;
		case 2: { p_priority_list = g_priority_encryption_cipher; max_value = CIPHER_MAX; } break;
	}

	if ( p_priority_list != NULL )
	{
		for ( unsigned char i = 0; i < priority_list_length; ++i )
		{
			// See if the entry is enabled.
			if ( priority_list[ i ] & 0x40 )
			{
				p_priority_list[ j++ ] = priority_list[ i ] & 0x3F;
			}
		}

		for ( ; j < priority_list_length; ++j )
		{
			p_priority_list[ j ] = max_value;
		}
	}

	LeaveCriticalSection( &algorithm_priorities_cs );
}

extern "C" __declspec ( dllexport )
PVOID SFTP_CreateSSHHandle( wchar_t *canonname,
							char *username, char *password,
							char *key_info,
							char *private_key_file_path,
							WSABUF *wsabuf )
{
	Ssh *ssh;

	ssh = snew( Ssh );
	memset( ssh, 0, sizeof( Ssh ) );

	if ( private_key_file_path != NULL )
	{
		ssh->keyfile = filename_from_str( private_key_file_path );
	}

	EnterCriticalSection( &algorithm_priorities_cs );

	int i;
	ssh->ssh_kexlist = snewn( KEX_MAX, int );
	for ( i = 0; i < KEX_MAX; ++i )
	{
		ssh->ssh_kexlist[ i ] = g_priority_kex_algorithm[ i ];
	}

	ssh->ssh_hklist = snewn( HK_MAX, int );
	for ( i = 0; i < HK_MAX; ++i )
	{
		ssh->ssh_hklist[ i ] = g_priority_host_key[ i ];
	}

	ssh->ssh_cipherlist = snewn( CIPHER_MAX, int );
	for ( i = 0; i < CIPHER_MAX; ++i )
	{
		ssh->ssh_cipherlist[ i ] = g_priority_encryption_cipher[ i ];
	}

	LeaveCriticalSection( &algorithm_priorities_cs );

	if ( key_info != NULL )
	{
		unsigned int key_info_count = 0;
		memcpy_s( &key_info_count, sizeof( unsigned int ), key_info, sizeof( unsigned int ) );

		KEY_INFO *ki = snewn( key_info_count, KEY_INFO );
		memset( ki, 0, sizeof( KEY_INFO ) * key_info_count );

		key_info_count = 0;

		char *ptr = key_info + sizeof( unsigned int );
		while ( ptr != NULL && *ptr != NULL )
		{
			char *algorithm = NULL;
			char *fingerprint = NULL;

			char *end = strchr( ptr, '\n' );
			if ( end != NULL )
			{
				*end = 0;
				++end;

				algorithm = ptr;
			}
			else
			{
				break;
			}

			ptr = end;

			end = strchr( ptr, '\n' );
			if ( end != NULL )
			{
				*end = 0;
				++end;
			}

			fingerprint = ptr;

			ki[ key_info_count ].algorithm = dupstr( algorithm );
			ki[ key_info_count ].fingerprint = dupstr( fingerprint );

			ptr = end;

			++key_info_count;
		}

		ssh->key_info = ki;
		ssh->key_info_count = key_info_count;
	}

	ssh->username = dupstr( username );
	ssh->password = dupstr( password );

	if ( canonname != NULL )
	{
		wchar_t *canonname_end = wcschr( canonname, L':' );
		int canonname_length = ( canonname_end != NULL ? ( int )( canonname_end - canonname ) + 1 : -1 );	// Ignore any port that's added.

		int val_length = WideCharToMultiByte( CP_UTF8, 0, canonname, canonname_length, NULL, 0, NULL, NULL );
		ssh->fullhostname = snewn( sizeof( char ) * val_length, char ); // Size includes the null character.
		val_length = WideCharToMultiByte( CP_UTF8, 0, canonname, canonname_length, ssh->fullhostname, val_length, NULL, NULL );
		ssh->fullhostname[ val_length - 1 ] = 0;	// Sanity.
		//ssh->fullhostname = dupstr( canonname );	// save in case of GSSAPI
	}

	ssh->exitcode = -1;
//	ssh->pls.kctx = SSH2_PKTCTX_NOKEX;
//	ssh->pls.actx = SSH2_PKTCTX_NOAUTH;
	bufchain_init( &ssh->in_raw );
	bufchain_init( &ssh->out_raw );
	bufchain_init( &ssh->user_input );
	ssh->ic_out_raw.fn = ssh_bpp_output_raw_data_callback;
	ssh->ic_out_raw.ctx = ssh;

	bufchain_init( &ssh->output_data );

	ssh->backend.vt = &ssh_backend;

	//

	ssh->pktin_freeq_head.next = &ssh->pktin_freeq_head;
	ssh->pktin_freeq_head.prev = &ssh->pktin_freeq_head;
	ssh->pktin_freeq_head.formal_size = 1;
	ssh->pktin_freeq_head.on_free_queue = false;

	//

	ssh->pr = random_create( &ssh_sha256 );
	ssh->timer_prng_noise.now = GetTickCount() + NOISE_REGULAR_INTERVAL;
	ssh->timer_prng_noise.ctx = ssh;
	ssh->timer_prng_noise.fn = random_timer;

	//

	/*
	* Set up the initial BPP that will do the version string
	* exchange, and get it started so that it can send the outgoing
	* version string early if it wants to.
	*/
	ssh->version_receiver.got_ssh_version = ssh_got_ssh_version;
	ssh->bpp = ssh_verstring_new( "2.0", &ssh->version_receiver, false, "PuTTY" );
	ssh_connect_bpp( ssh );
	queue_idempotent_callback( ssh, &ssh->bpp->ic_in_raw );

	//

	ssh->wsabuf = wsabuf;	// Used to write encrypted data.

	return ssh;
}

extern "C" __declspec ( dllexport )
VOID SFTP_FreeSSHHandle( Ssh *ssh )
{
	if ( ssh != NULL )
	{
		ssh->sftp_info.sent_eof = true;

		sftp_cleanup_request( &ssh->sftp_info.reqs );

		backend_free( &ssh->backend );
	}
}

extern "C" __declspec ( dllexport )
BOOL SFTP_CheckCallbacks( Ssh *ssh )
{
	bool ret = toplevel_callback_pending( ssh );

	run_timers( ssh );

	return ( ret ? TRUE : FALSE );
}

extern "C" __declspec ( dllexport )
BOOL SFTP_RunCallbacks( Ssh *ssh )
{
	return ( run_toplevel_callbacks( ssh ) ? TRUE : FALSE );
}

extern "C" __declspec ( dllexport )
INT SFTP_GetKeyInfo( Ssh *ssh, char **algorithm, int *key_size, char **md5_fingerprint, char **sha256_fingerprint )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		*algorithm = ssh->key_algorithm;
		*md5_fingerprint = ssh->md5_key_fingerprint;
		*sha256_fingerprint = ssh->sha256_key_fingerprint;
		*key_size = ssh->key_size;

		status = 0;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_ProcessWriteRequest( Ssh *ssh, DWORD io_size )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		int bufsize_before, bufsize_after;

		noise_ultralight( ssh->pr, NOISE_SOURCE_IOLEN, io_size );

		bufsize_before = bufchain_size( &ssh->output_data );

		bufchain_consume( &ssh->output_data, io_size );

		bufsize_after = bufchain_size( &ssh->output_data );

		ssh->wsabuf->buf = NULL;
		ssh->wsabuf->len = 0;

		ssh->ssh_status &= ~SSH_STATUS_WRITE;

		status = ( ssh_try_send( ssh, &ssh->wsabuf->buf, ssh->wsabuf->len ) ? 1 : 0 );

		if ( bufsize_after < bufsize_before &&
			 bufsize_after < SSH_MAX_BACKLOG )
		{
			ssh_throttle_all( ssh, false, bufsize_after );
			queue_idempotent_callback( ssh, &ssh->ic_out_raw );
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
BOOL SFTP_CheckInitStatus( Ssh *ssh )
{
	if ( ssh != NULL )
	{
		return ( backend_sendok( &ssh->backend ) ? TRUE : FALSE );
	}

	return FALSE;
}

extern "C" __declspec ( dllexport )
VOID SFTP_InitSendVersion( Ssh *ssh )
{
	if ( ssh != NULL )
	{
		struct sftp_packet *pktout;

		pktout = sftp_pkt_init( SSH_FXP_INIT );
		put_uint32( pktout, SFTP_PROTO_VERSION );
		sftp_send( &ssh->backend, pktout );
	}
}

extern "C" __declspec ( dllexport )
VOID SFTP_ProcessGetRequestBuffer( Ssh *ssh, char *buffer, DWORD io_size )
{
	if ( ssh != NULL )
	{
		noise_ultralight( ssh->pr, NOISE_SOURCE_IOLEN, io_size );

		bufchain_add( ssh, &ssh->in_raw, buffer, io_size );
		if ( !ssh->logically_frozen && ssh->bpp )
		{
			queue_idempotent_callback( ssh, &ssh->bpp->ic_in_raw );
		}

		ssh_check_frozen( ssh );
	}
}

extern "C" __declspec ( dllexport )
INT SFTP_GetStatus( Ssh *ssh )
{
	if ( ssh != NULL )
	{
		return ssh->ssh_status;
	}
	else
	{
		return 0;
	}
}

extern "C" __declspec ( dllexport )
VOID SFTP_SetStatus( Ssh *ssh, int status )
{
	if ( ssh != NULL )
	{
		ssh->ssh_status = status;
	}
}

extern "C" __declspec ( dllexport )
INT SFTP_CheckCallbackStatus( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		status = 0;

		if ( bufchain_size( &ssh->received_data ) == 0 )
		{
			status = 1;
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_GetRequestPacket( Ssh *ssh, char type )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		if ( bufchain_size( &ssh->received_data ) != 0 )
		{
			char **buf = NULL;
			size_t *len = NULL;

			if ( type == 0 )
			{
				buf = &ssh->sftp_info.buf1;
				len = &ssh->sftp_info.buf1_len;
			}
			else if ( type == 1 )
			{
				buf = &ssh->sftp_info.buf2;
				len = &ssh->sftp_info.buf2_len;
			}

			size_t got = bufchain_fetch_consume_up_to( &ssh->received_data, *buf, *len );
			*buf += got;
			*len -= got;

			if ( *len > 0 )
			{
				status = 1;	// Read more.
			}
			else
			{
				status = 0;
			}
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_GetPacketInfo( Ssh *ssh, char type, char **data, size_t *length )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		if ( type == 0 )
		{
			*data = ssh->sftp_info.buf1;
			*length = ssh->sftp_info.buf1_len;

			return 0;
		}
		else if ( type == 1 )
		{
			*data = ssh->sftp_info.buf2;
			*length = ssh->sftp_info.buf2_len;

			return 0;
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_ResetPacketInfo( Ssh *ssh, char type )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		if ( type == 0 )
		{
			ssh->sftp_info.buf1 = ssh->sftp_info.tbuf1;
			ssh->sftp_info.buf1_len = 4;

			return 0;
		}
		else if ( type == 1 )
		{
			ssh->sftp_info.buf2 = ssh->sftp_info.pkt->data;
			ssh->sftp_info.buf2_len = ssh->sftp_info.pkt->length;

			return 0;
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_PrepareRequestPacket( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		ssh->sftp_info.pkt = sftp_recv_prepare( GET_32BIT_MSB_FIRST( ssh->sftp_info.tbuf1 ) );

		status = 0;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_GetRequestPacketType( Ssh *ssh, int *packet_type )
{
	INT status = -1;

	*packet_type = -1;

	if ( ssh != NULL && ssh->sftp_info.pkt != NULL )
	{
		if ( sftp_recv_finish( ssh->sftp_info.pkt ) )
		{
			*packet_type = ssh->sftp_info.pkt->type;

			status = 0;
		}
		else
		{
			*packet_type = 0;

			status = 1;
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_ProcessVersion( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL && ssh->sftp_info.pkt != NULL )
	{
		unsigned long remotever = get_uint32( ssh->sftp_info.pkt );
		if ( !get_err( ssh->sftp_info.pkt ) && remotever <= SFTP_PROTO_VERSION  )
		{
			status = 0;
		}

		// In principle, this packet might also contain extension-string pairs.
		// We should work through them and look for any we recognise.
		// In practice we don't currently do so because we know we don't recognise _any_.
		sftp_pkt_free( ssh->sftp_info.pkt );
		ssh->sftp_info.pkt = NULL;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_GetAttributes( Ssh *ssh, char *fname )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		ssh->sftp_info.req = fxp_stat_send( &ssh->backend, &ssh->sftp_info.reqs, fname );
		sftp_register( ssh->sftp_info.req );

		status = 0;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_ProcessAttributes( Ssh *ssh, FILE_ATTRIBUTES *file_attributes )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		// Removes ssh->sftp_info.req from ssh->sftp_info.sftp_requests.
		struct sftp_request *rreq = sftp_find_request( ssh->sftp_info.reqs, ssh->sftp_info.pkt );
		if ( rreq == ssh->sftp_info.req )
		{
			ssh->sftp_info.req = NULL;
		}

		if ( ssh->sftp_info.pkt != NULL )
		{
			// pkt and rreq are freed here.
			struct fxp_attrs attrs;
			memset( &attrs, 0, sizeof( struct fxp_attrs ) );
			/*bool result =*/ fxp_stat_recv( ssh->sftp_info.pkt, rreq, &attrs );

			if ( file_attributes != NULL )
			{
				file_attributes->mtime = attrs.mtime;
				file_attributes->size = attrs.size;
			}

			status = 0;
		}
		else if ( rreq != NULL )
		{
			sfree( rreq );
		}

		ssh->sftp_info.pkt = NULL;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_GetHandle( Ssh *ssh, char *path )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		ssh->sftp_info.req = fxp_open_send( &ssh->backend, &ssh->sftp_info.reqs, path, SSH_FXF_READ, NULL );

		sftp_register( ssh->sftp_info.req );

		status = 0;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_ProcessDownloadHandle( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		// Removes ssh->sftp_info.req from ssh->sftp_info.reqs.
		struct sftp_request *rreq = sftp_find_request( ssh->sftp_info.reqs, ssh->sftp_info.pkt );
		if ( rreq == ssh->sftp_info.req )
		{
			ssh->sftp_info.req = NULL;
		}

		if ( ssh->sftp_info.pkt != NULL )
		{
			// pkt and req are freed here.
			ssh->sftp_info.fh = fxp_open_recv( ssh->sftp_info.pkt, rreq );
			if ( ssh->sftp_info.fh != NULL )
			{
				status = 0;
			}
		}
		else if ( rreq != NULL )
		{
			sfree( rreq );
		}

		ssh->sftp_info.pkt = NULL;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_DownloadInit( Ssh *ssh, unsigned long long offset = 0, unsigned long long filesize = UINT64_MAX )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		ssh->sftp_info.xfer = xfer_download_init( &ssh->backend, &ssh->sftp_info.reqs, ssh->sftp_info.fh, offset, filesize );

		status = 0;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_DownloadPrepareData( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL && ssh->sftp_info.xfer != NULL && ssh->sftp_info.pkt != NULL )
	{
		int retd;
		retd = xfer_download_gotpkt( ssh->sftp_info.reqs, ssh->sftp_info.xfer, ssh->sftp_info.pkt );
		if ( retd > 0 )
		{
			status = 0;	// Get more data.
		}
		else
		{
			if ( retd == INT_MIN )
			{
				sfree( ssh->sftp_info.pkt );
			}
		}

		ssh->sftp_info.pkt = NULL;
	}

	return status;
}

extern "C" __declspec ( dllexport )
BOOL SFTP_DownloadData( Ssh *ssh, char **buffer, DWORD *io_size )
{
	return ( xfer_download_data( ssh->sftp_info.xfer, ( void ** )buffer, ( int * )io_size ) ? TRUE : FALSE );
}

extern "C" __declspec ( dllexport )
VOID SFTP_FreeDownloadData( char *buffer )
{
	sfree( buffer );
}

extern "C" __declspec ( dllexport )
INT SFTP_IsDownloadDone( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL && ssh->sftp_info.xfer != NULL )
	{
		if ( !xfer_done( ssh->sftp_info.xfer ) )
		{
			status = 0;
		}
		else
		{
			status = 1;
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_DownloadQueue( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL && ssh->sftp_info.xfer != NULL )
	{
		xfer_download_queue( &ssh->backend, &ssh->sftp_info.reqs, ssh->sftp_info.xfer );

		status = 0;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_DownloadClose( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL && ssh->sftp_info.fh != NULL )
	{
		// Close the transfer.
		ssh->sftp_info.req = fxp_close_send( &ssh->backend, &ssh->sftp_info.reqs, ssh->sftp_info.fh );
		ssh->sftp_info.fh = NULL;
		sftp_register( ssh->sftp_info.req );

		status = 0;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_DownloadCleanupPacket( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		// Removes ssh->sftp_info.req from ssh->sftp_info.reqs.
		struct sftp_request *rreq = sftp_find_request( ssh->sftp_info.reqs, ssh->sftp_info.pkt );
		if ( rreq == ssh->sftp_info.req )
		{
			ssh->sftp_info.req = NULL;
		}

		if ( ssh->sftp_info.pkt != NULL )
		{
			// pkt and req are freed here.
			fxp_close_recv( ssh->sftp_info.pkt, rreq );

			if ( !ssh->sftp_info.sent_eof )
			{
				if ( backend_connected( &ssh->backend ) )
				{
					ssh->sftp_info.sent_eof = true;

					backend_special( &ssh->backend, SS_EOF, 0 );
				}
			}

			status = 0;
		}
		else if ( rreq != NULL )
		{
			sfree( rreq );
		}

		ssh->sftp_info.pkt = NULL;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_DownloadCleanupTransfer( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL && ssh->sftp_info.xfer != NULL )
	{
		xfer_cleanup( ssh->sftp_info.xfer );
		ssh->sftp_info.xfer = NULL;
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_CheckBackendStatus( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		status = 0;

		if ( backend_exitcode( &ssh->backend ) < 0 )
		{
			status = 1;
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
INT SFTP_BackendClose( Ssh *ssh )
{
	INT status = -1;

	if ( ssh != NULL )
	{
		if ( backend_connected( &ssh->backend ) )
		{
			ssh->sftp_info.sent_eof = true;

			backend_special( &ssh->backend, SS_EOF, 0 );

			status = 0;
		}
	}

	return status;
}

extern "C" __declspec ( dllexport )
VOID SFTP_BackendFree( Ssh *ssh )
{
	if ( ssh != NULL )
	{
		ssh->sftp_info.sent_eof = true;

		sftp_cleanup_request( &ssh->sftp_info.reqs );

		backend_free( &ssh->backend );
	}
}

extern "C" BOOL WINAPI DllMain( HINSTANCE const instance, DWORD const reason, LPVOID const reserved )
{
	switch ( reason )
	{
		case DLL_PROCESS_ATTACH:
		{
			InitializeCriticalSection( &gss_library_cs );
			InitializeCriticalSection( &algorithm_priorities_cs );
			InitializeCriticalSection( &ssh2kex_cs );

			ec_p256();
			ec_p384();
			ec_p521();
			ec_curve25519();
			ec_ed25519();
		}
		break;

		//case DLL_THREAD_ATTACH: break;
		//case DLL_THREAD_DETACH: break;

		case DLL_PROCESS_DETACH:
		{
			DeleteCriticalSection( &ssh2kex_cs );
			DeleteCriticalSection( &algorithm_priorities_cs );
			DeleteCriticalSection( &gss_library_cs );
		}
		break;
	}

	return TRUE;
}
