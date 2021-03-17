#ifndef _SSH_H_
#define _SSH_H_

#include <stdio.h>
#include <string.h>

#include "putty.h"
#include "puttymem.h"
#include "tree234.h"
#include "misc.h"


struct ssh_channel;

/*
 * Buffer management constants. There are several of these for
 * various different purposes:
 *
 *  - SSH1_BUFFER_LIMIT is the amount of backlog that must build up
 *    on a local data stream before we throttle the whole SSH
 *    connection (in SSH-1 only). Throttling the whole connection is
 *    pretty drastic so we set this high in the hope it won't
 *    happen very often.
 *
 *  - SSH_MAX_BACKLOG is the amount of backlog that must build up
 *    on the SSH connection itself before we defensively throttle
 *    _all_ local data streams. This is pretty drastic too (though
 *    thankfully unlikely in SSH-2 since the window mechanism should
 *    ensure that the server never has any need to throttle its end
 *    of the connection), so we set this high as well.
 *
 *  - OUR_V2_WINSIZE is the default window size we present on SSH-2
 *    channels.
 *
 *  - OUR_V2_BIGWIN is the window size we advertise for the only
 *    channel in a simple connection.  It must be <= INT_MAX.
 *
 *  - OUR_V2_MAXPKT is the official "maximum packet size" we send
 *    to the remote side. This actually has nothing to do with the
 *    size of the _packet_, but is instead a limit on the amount
 *    of data we're willing to receive in a single SSH2 channel
 *    data message.
 *
 *  - OUR_V2_PACKETLIMIT is actually the maximum size of SSH
 *    _packet_ we're prepared to cope with.  It must be a multiple
 *    of the cipher block size, and must be at least 35000.
 */

#define SSH1_BUFFER_LIMIT	32768
#define SSH_MAX_BACKLOG		32768
#define OUR_V2_WINSIZE		16384
//#define OUR_V2_WINSIZE	65536
#define OUR_V2_BIGWIN		0x7fffffff
#define OUR_V2_MAXPKT		0x4000UL
#define OUR_V2_PACKETLIMIT	0x9000UL

typedef struct PacketQueueNode PacketQueueNode;
struct PacketQueueNode
{
	PacketQueueNode *next, *prev;
	size_t formal_size;		/* contribution to PacketQueueBase's total_size */
	bool on_free_queue;		/* is this packet scheduled for freeing? */
};

typedef struct PktIn
{
	int type;
	unsigned long sequence;	/* SSH-2 incoming sequence number */
	PacketQueueNode qnode;	/* for linking this packet on to a queue */
	BinarySource_IMPLEMENTATION;
} PktIn;

typedef struct PktOut
{
	size_t prefix;          /* bytes up to and including type field */
	size_t length;          /* total bytes, including prefix */
	int type;
	size_t minlen;          /* SSH-2: ensure wire length is at least this */
	unsigned char *data;    /* allocated storage */
	size_t maxlen;          /* amount of storage allocated for `data' */

	/* Extra metadata used in SSH packet logging mode, allowing us to
	* log in the packet header line that the packet came from a
	* connection-sharing downstream and what if anything unusual was
	* done to it. The additional_log_text field is expected to be a
	* static string - it will not be freed. */
	unsigned downstream_id;
	const char *additional_log_text;

	PacketQueueNode qnode;  /* for linking this packet on to a queue */
	BinarySink_IMPLEMENTATION;
} PktOut;

typedef struct PacketQueueBase
{
	PacketQueueNode end;
	size_t total_size;    /* sum of all formal_size fields on the queue */
	struct IdempotentCallback *ic;
} PacketQueueBase;

typedef struct PktInQueue
{
	PacketQueueBase pqb;
	PktIn *( *after )( Ssh *ssh, PacketQueueBase *, PacketQueueNode *prev, bool pop );
} PktInQueue;

typedef struct PktOutQueue
{
	PacketQueueBase pqb;
	PktOut *( *after )( Ssh *ssh, PacketQueueBase *, PacketQueueNode *prev, bool pop );
} PktOutQueue;

void pq_base_push( Ssh *ssh, PacketQueueBase *pqb, PacketQueueNode *node );
void pq_base_push_front( Ssh *ssh, PacketQueueBase *pqb, PacketQueueNode *node );
void pq_base_concatenate( Ssh *ssh, PacketQueueBase *dest, PacketQueueBase *q1, PacketQueueBase *q2 );

void pq_in_init( PktInQueue *pq );
void pq_out_init( PktOutQueue *pq );
void pq_in_clear( Ssh *ssh, PktInQueue *pq );
void pq_out_clear( Ssh *ssh, PktOutQueue *pq );

#define pq_push( ssh, pq, pkt )			TYPECHECK( ( pq )->after( ssh, &( pq )->pqb, NULL, false ) == pkt, pq_base_push( ssh, &( pq )->pqb, &( pkt )->qnode ) )
#define pq_push_front( ssh, pq, pkt )	TYPECHECK( ( pq )->after( ssh, &( pq )->pqb, NULL, false ) == pkt, pq_base_push_front( ssh, &( pq )->pqb, &( pkt )->qnode ) )
#define pq_peek( ssh, pq )				( ( pq )->after( ssh, &( pq )->pqb, &( pq )->pqb.end, false ) )
#define pq_pop( ssh, pq )				( ( pq )->after( ssh, &( pq )->pqb, &( pq )->pqb.end, true ) )
#define pq_concatenate( ssh, dst, q1, q2 )													\
		TYPECHECK( ( q1 )->after( ssh, &( q1 )->pqb, NULL, false ) ==						\
				   ( dst )->after( ssh, &( dst )->pqb, NULL, false ) &&						\
				   ( q2 )->after( ssh, &( q2 )->pqb, NULL, false ) ==						\
				   ( dst )->after( ssh, &( dst )->pqb, NULL, false ),						\
				   pq_base_concatenate( ssh, &( dst )->pqb, &( q1 )->pqb, &( q2 )->pqb ) )

#define pq_first( ssh, pq )				pq_peek( ssh, pq )
#define pq_next( ssh, pq, pkt )			( ( pq )->after( ssh, &( pq )->pqb, &( pkt )->qnode, false ) )

/*
 * Packet type contexts, so that ssh2_pkt_type can correctly decode
 * the ambiguous type numbers back into the correct type strings.
 */
typedef enum
{
	SSH2_PKTCTX_NOKEX,
	SSH2_PKTCTX_DHGROUP,
	SSH2_PKTCTX_DHGEX,
	SSH2_PKTCTX_ECDHKEX,
	SSH2_PKTCTX_GSSKEX,
	SSH2_PKTCTX_RSAKEX
} Pkt_KCtx;

typedef enum
{
	SSH2_PKTCTX_NOAUTH,
	SSH2_PKTCTX_PUBLICKEY,
	SSH2_PKTCTX_PASSWORD,
	SSH2_PKTCTX_GSSAPI,
	SSH2_PKTCTX_KBDINTER
} Pkt_ACtx;

PktOut *ssh_new_packet( void );
void ssh_free_pktout( PktOut *pkt );

struct ConnectionLayerVtable
{
	/* Initiate opening of a 'session'-type channel */
	SshChannel *( *session_open )( ConnectionLayer *cl, Channel *chan );

	/* Query the size of the backlog on standard _input_ */
	size_t ( *stdin_backlog )( ConnectionLayer *cl );

	/* Tell the connection layer that the SSH connection itself has
	* backed up, so it should tell all currently open channels to
	* cease reading from their local input sources if they can. (Or
	* tell it that that state of affairs has gone away again.) */
	void ( *throttle_all_channels )( ConnectionLayer *cl, bool throttled );

	/* Communicate to the connection layer whether the main session channel currently wants user input. */
	void ( *set_wants_user_input )( ConnectionLayer *cl, bool wanted );
};

struct ConnectionLayer
{
	const struct ConnectionLayerVtable *vt;
};

static __inline SshChannel *ssh_session_open( ConnectionLayer *cl, Channel *chan )
{ return cl->vt->session_open( cl, chan ); }
static __inline size_t ssh_stdin_backlog( ConnectionLayer *cl )
{ return cl->vt->stdin_backlog( cl ); }
static __inline void ssh_throttle_all_channels( ConnectionLayer *cl, bool thr )
{ cl->vt->throttle_all_channels( cl, thr ); }
static __inline void ssh_set_wants_user_input( ConnectionLayer *cl, bool wanted )
{ cl->vt->set_wants_user_input( cl, wanted ); }

//////////////////////////////////////////////////////////

#include "sshgss.h"
#include "sshbpp.h"

#define SSH_STATUS_NONE						0x00000000
#define SSH_STATUS_CLEANUP					0x00000001
#define SSH_STATUS_WRITE					0x00000002
#define SSH_STATUS_AUTHENTICATE				0x00000004
#define SSH_STATUS_KEY_NOT_FOUND			0x00000008
#define SSH_STATUS_KEY_MISMATCH				0x00000010
#define SSH_STATUS_INITIALIZED				0x00000020
#define SSH_STATUS_INITIALIZED_FILE_HANDLE	0x00000040
#define SSH_STATUS_USER_CLEANUP				0x00000080
#define SSH_STATUS_BACKEND_CLOSED			0x00000100

struct SFTP_INFO
{
	tree234 *reqs;

    struct req *rr;
    struct sftp_request *req;

    struct sftp_packet *pkt;

    struct fxp_handle *fh;
    struct fxp_xfer *xfer;

	char tbuf1[ 4 ];
	char *buf1;
	size_t buf1_len;

	char *buf2;
	size_t buf2_len;

    bool sent_eof;
};

struct KEY_INFO
{
	char *algorithm;
	char *fingerprint;
};

struct Ssh
{
	char *username;
	char *password;

	struct ssh_version_receiver version_receiver;
	int remote_bugs;

	Backend backend;

	bufchain received_data;
	bufchain output_data;
	SFTP_INFO sftp_info;
	WSABUF *wsabuf;

	// CONF values //
	Filename *keyfile;
	int *ssh_kexlist;
	int *ssh_hklist;
	int *ssh_cipherlist;
	KEY_INFO *key_info;
	unsigned int key_info_count;
	/////////////////

	char *key_algorithm;
	char *md5_key_fingerprint;
	char *sha256_key_fingerprint;
	int key_size;

	int ssh_status;

	PacketQueueNode pktin_freeq_head;

	struct callback *cbcurr;
	struct callback *cbhead;
	struct callback *cbtail;

	prng *pr;
	unsigned long next_noise_collection;

	// TIMER INFO //
	TIMER_INFO timer_prng_noise;
	TIMER_INFO timer_transport_rekey;
	TIMER_INFO timer_pinger;
	////////////////

	/* The last list returned from get_specials. */
	SessionSpecial *specials;

#ifndef NO_GSSAPI
	struct ssh_connection_shared_gss_state gss_state;
#endif

	char *fullhostname;

	bool fallback_cmd;
	int exitcode;

	int conn_throttle_count;
	size_t overall_bufsize;
	bool throttled_all;

	/*
	* logically_frozen is true if we're not currently _processing_
	* data from the SSH socket (e.g. because a higher layer has asked
	* us not to due to ssh_throttle_conn). socket_frozen is true if
	* we're not even _reading_ data from the socket (i.e. it should
	* always match the value we last passed to sk_set_frozen).
	*
	* The two differ in that socket_frozen can also become
	* temporarily true because of a large backlog in the in_raw
	* bufchain, to force no further plug_receive events until the BPP
	* input function has had a chance to run. (Some front ends, like
	* GTK, can persistently call the network and never get round to
	* the toplevel callbacks.) If we've stopped reading from the
	* socket for that reason, we absolutely _do_ want to carry on
	* processing our input bufchain, because that's the only way
	* it'll ever get cleared!
	*
	* ssh_check_frozen() resets socket_frozen, and should be called
	* whenever either of logically_frozen and the bufchain size
	* changes.
	*/
	bool logically_frozen, socket_frozen;

	bufchain in_raw, out_raw, user_input;
	bool pending_close;
	IdempotentCallback ic_out_raw;

	struct DataTransferStats stats;

	BinaryPacketProtocol *bpp;

	/*
	* base_layer identifies the bottommost packet protocol layer, the
	* one connected directly to the BPP's packet queues. Any
	* operation that needs to talk to all layers (e.g. free, or
	* get_specials) will do it by talking to this, which will
	* recursively propagate it if necessary.
	*/
	PacketProtocolLayer *base_layer;

	/*
	* The ConnectionLayer vtable from our connection layer.
	*/
	ConnectionLayer *cl;

	/*
	* session_started is false until we initialise the main protocol
	* layers. So it distinguishes between base_layer==NULL meaning
	* that the SSH protocol hasn't been set up _yet_, and
	* base_layer==NULL meaning the SSH protocol has run and finished.
	* It's also used to mark the point where we stop counting proxy
	* command diagnostics as pre-session-startup.
	*/
	bool session_started;
};

void ssh_shutdown( Ssh *ssh );
void ssh_throttle_all( Ssh *ssh, bool enable, size_t bufsize );
void ssh_bpp_output_raw_data_callback( Ssh *ssh, void *vctx );
void ssh_connect_bpp( Ssh *ssh );
void ssh_connect_ppl( Ssh *ssh, PacketProtocolLayer *ppl );
void ssh_got_ssh_version( struct ssh_version_receiver *rcv, int major_version );
void ssh_check_frozen( Ssh *ssh );
void ssh_conn_processed_data( Ssh *ssh );
void ssh_bpp_output_raw_data_callback( void *vctx );
void ssh_shutdown_internal( Ssh *ssh );
void ssh_shutdown( Ssh *ssh );
void ssh_initiate_connection_close( Ssh *ssh );
void ssh_remote_error( Ssh *ssh );
void ssh_remote_eof( Ssh *ssh );
void ssh_proto_error( Ssh *ssh );
void ssh_sw_abort( Ssh *ssh );
void ssh_user_close( Ssh *ssh );
void ssh_deferred_abort_callback( void *vctx );
void ssh_sw_abort_deferred( Ssh *ssh );

/*
 * Throttle or unthrottle the SSH connection.
 */
void ssh_throttle_conn( Ssh *ssh, int adjust );
/*
 * Throttle or unthrottle _all_ local data streams (for when sends
 * on the SSH connection itself back up).
 */
void ssh_throttle_all( Ssh *ssh, bool enable, size_t bufsize );
void ssh_cache_conf_values( Ssh *ssh );

void ssh_free( Backend *be );
/*
 * Reconfigure the SSH backend.
 */
void ssh_reconfig( Backend *be );

bool ssh_try_send( Ssh *ssh, CHAR **buffer, ULONG &buffer_length );
/*
 * Called to send data down the SSH connection.
 */
size_t ssh_send( Backend *be, const char *buf, size_t len );
/*
 * Called to query the current amount of buffered stdin data.
 */
size_t ssh_sendbuffer( Backend *be );

struct ssh_add_special_ctx
{
	SessionSpecial *specials;
	size_t nspecials, specials_size;
};

void ssh_add_special( void *vctx, const char *text, SessionSpecialCode code, int arg );
/*
 * Return a list of the special codes that make sense in this
 * protocol.
 */
const SessionSpecial *ssh_get_specials( Backend *be );
/*
 * Send special codes.
 */
void ssh_special( Backend *be, SessionSpecialCode code, int arg );
bool ssh_connected( Backend *be );
bool ssh_sendok( Backend *be );
void ssh_got_exitcode( Ssh *ssh, int exitcode );
int ssh_return_exitcode( Backend *be );

//////////////////////////////////////////////////////////

struct ssh_key
{
	const ssh_keyalg *vt;
};

struct RSAKey
{
	int bits;
	int bytes;
	mp_int *modulus;
	mp_int *exponent;
	mp_int *private_exponent;
	mp_int *p;
	mp_int *q;
	mp_int *iqmp;
	char *comment;
	ssh_key sshk;
};

struct dss_key
{
	mp_int *p, *q, *g, *y, *x;
	ssh_key sshk;
};

struct ec_curve;

/* Weierstrass form curve */
struct ec_wcurve
{
	WeierstrassCurve *wc;
	WeierstrassPoint *G;
	mp_int *G_order;
};

/* Montgomery form curve */
struct ec_mcurve
{
	MontgomeryCurve *mc;
	MontgomeryPoint *G;
	unsigned log2_cofactor;
};

/* Edwards form curve */
struct ec_ecurve
{
	EdwardsCurve *ec;
	EdwardsPoint *G;
	mp_int *G_order;
};

typedef enum EllipticCurveType
{
	EC_WEIERSTRASS, EC_MONTGOMERY, EC_EDWARDS
} EllipticCurveType;

struct ec_curve
{
	EllipticCurveType type;
	/* 'name' is the identifier of the curve when it has to appear in
	* wire protocol encodings, as it does in e.g. the public key and
	* signature formats for NIST curves. Curves which do not format
	* their keys or signatures in this way just have name==NULL.
	*
	* 'textname' is non-NULL for all curves, and is a human-readable
	* identification suitable for putting in log messages. */
	const char *name, *textname;
	size_t fieldBits, fieldBytes;
	mp_int *p;
	union
	{
		struct ec_wcurve w;
		struct ec_mcurve m;
		struct ec_ecurve e;
	};
};

const ssh_keyalg *ec_alg_by_oid( int len, const void *oid, const struct ec_curve **curve );
const unsigned char *ec_alg_oid( const ssh_keyalg *alg, int *oidlen );
extern const int ec_nist_curve_lengths[], n_ec_nist_curve_lengths;
bool ec_nist_alg_and_curve_by_bits( int bits, const struct ec_curve **curve, const ssh_keyalg **alg );
bool ec_ed_alg_and_curve_by_bits( int bits, const struct ec_curve **curve, const ssh_keyalg **alg );

struct ecdsa_key
{
	const struct ec_curve *curve;
	WeierstrassPoint *publicKey;
	mp_int *privateKey;
	ssh_key sshk;
};

struct eddsa_key
{
	const struct ec_curve *curve;
	EdwardsPoint *publicKey;
	mp_int *privateKey;
	ssh_key sshk;
};

WeierstrassPoint *ecdsa_public( mp_int *private_key, const ssh_keyalg *alg );
EdwardsPoint *eddsa_public( mp_int *private_key, const ssh_keyalg *alg );

char *rsastr_fmt( RSAKey *key );
bool rsa_verify( RSAKey *key );
void freersapriv( RSAKey *key );
void freersakey( RSAKey *key );

/*
 * SSH2 RSA key exchange functions
 */
struct ssh_rsa_kex_extra
{
	int minklen;
};
RSAKey *ssh_rsakex_newkey( ptrlen data );
void ssh_rsakex_freekey( RSAKey *key );
int ssh_rsakex_klen( RSAKey *key );
strbuf *ssh_rsakex_encrypt( prng *pr, RSAKey *key, const ssh_hashalg *h, ptrlen plaintext );
mp_int *ssh_rsakex_decrypt( RSAKey *key, const ssh_hashalg *h, ptrlen ciphertext );

/*
 * SSH2 ECDH key exchange functions
 */
const char *ssh_ecdhkex_curve_textname( const ssh_kex *kex );
ecdh_key *ssh_ecdhkex_newkey( prng *pr, const ssh_kex *kex );
void ssh_ecdhkex_freekey( ecdh_key *key );
void ssh_ecdhkex_getpublic( ecdh_key *key, BinarySink *bs );
mp_int *ssh_ecdhkex_getkey( ecdh_key *key, ptrlen remoteKey );

/*
 * Helper function for k generation in DSA, reused in ECDSA
 */
mp_int *dss_gen_k( const char *id_string, mp_int *modulus, mp_int *private_key, unsigned char *digest, int digest_len );

struct ssh_cipher
{
	const ssh_cipheralg *vt;
};

struct ssh_cipheralg
{
	ssh_cipher *( *_new )( const ssh_cipheralg *alg );
	void ( *free )( ssh_cipher * );
	void ( *setiv )( ssh_cipher *, const void *iv );
	void ( *setkey )( ssh_cipher *, const void *key );
	void ( *encrypt )( ssh_cipher *, void *blk, int len );
	void ( *decrypt )( ssh_cipher *, void *blk, int len );
	/* Ignored unless SSH_CIPHER_SEPARATE_LENGTH flag set */
	void ( *encrypt_length )( ssh_cipher *, void *blk, int len, unsigned long seq );
	void ( *decrypt_length )( ssh_cipher *, void *blk, int len, unsigned long seq );
	const char *ssh2_id;
	int blksize;
	/* real_keybits is the number of bits of entropy genuinely used by
	* the cipher scheme; it's used for deciding how big a
	* Diffie-Hellman group is needed to exchange a key for the
	* cipher. */
	int real_keybits;
	/* padded_keybytes is the number of bytes of key data expected as
	* input to the setkey function; it's used for deciding how much
	* data needs to be generated from the post-kex generation of key
	* material. In a sensible cipher which uses all its key bytes for
	* real work, this will just be real_keybits/8, but in DES-type
	* ciphers which ignore one bit in each byte, it'll be slightly
	* different. */
	int padded_keybytes;
	unsigned int flags;
#define SSH_CIPHER_IS_CBC				1
#define SSH_CIPHER_SEPARATE_LENGTH      2
	const char *text_name;
	/* If set, this takes priority over other MAC. */
	const ssh2_macalg *required_mac;

	/* Pointer to any extra data used by a particular implementation. */
	const void *extra;
};

static __inline ssh_cipher *ssh_cipher_new( const ssh_cipheralg *alg )
{ return alg->_new( alg ); }
static __inline void ssh_cipher_free( ssh_cipher *c )
{ c->vt->free( c ); }
static __inline void ssh_cipher_setiv( ssh_cipher *c, const void *iv )
{ c->vt->setiv( c, iv ); }
static __inline void ssh_cipher_setkey( ssh_cipher *c, const void *key )
{ c->vt->setkey( c, key ); }
static __inline void ssh_cipher_encrypt( ssh_cipher *c, void *blk, int len )
{ c->vt->encrypt( c, blk, len ); }
static __inline void ssh_cipher_decrypt( ssh_cipher *c, void *blk, int len )
{ c->vt->decrypt( c, blk, len ); }
static __inline void ssh_cipher_encrypt_length( ssh_cipher *c, void *blk, int len, unsigned long seq )
{ c->vt->encrypt_length( c, blk, len, seq ); }
static __inline void ssh_cipher_decrypt_length( ssh_cipher *c, void *blk, int len, unsigned long seq )
{ c->vt->decrypt_length( c, blk, len, seq ); }
static __inline const struct ssh_cipheralg *ssh_cipher_alg( ssh_cipher *c )
{ return c->vt; }

struct ssh2_ciphers
{
	int nciphers;
	const ssh_cipheralg *const *list;
};

struct ssh2_mac
{
	const ssh2_macalg *vt;
	BinarySink_DELEGATE_IMPLEMENTATION;
};

struct ssh2_macalg
{
	/* Passes in the cipher context */
	ssh2_mac *( *_new )( const ssh2_macalg *alg, ssh_cipher *cipher );
	void ( *free )( ssh2_mac * );
	void ( *setkey )( ssh2_mac *, ptrlen key );
	void ( *start )( ssh2_mac * );
	void ( *genresult )( ssh2_mac *, unsigned char * );
	const char *( *text_name )( ssh2_mac * );
	const char *name, *etm_name;
	int len, keylen;

	/* Pointer to any extra data used by a particular implementation. */
	const void *extra;
};

static __inline ssh2_mac *ssh2_mac_new( const ssh2_macalg *alg, ssh_cipher *cipher )
{ return alg->_new( alg, cipher ); }
static __inline void ssh2_mac_free( ssh2_mac *m )
{ m->vt->free( m ); }
static __inline void ssh2_mac_setkey( ssh2_mac *m, ptrlen key )
{ m->vt->setkey( m, key ); }
static __inline void ssh2_mac_start( ssh2_mac *m )
{ m->vt->start( m ); }
static __inline void ssh2_mac_genresult( ssh2_mac *m, unsigned char *out )
{ m->vt->genresult( m, out ); }
static __inline const char *ssh2_mac_text_name( ssh2_mac *m )
{ return m->vt->text_name( m ); }
static __inline const ssh2_macalg *ssh2_mac_alg( ssh2_mac *m )
{ return m->vt; }

/* Centralised 'methods' for ssh2_mac, defined in sshmac.c. These run
 * the MAC in a specifically SSH-2 style, i.e. taking account of a
 * packet sequence number as well as the data to be authenticated. */
bool ssh2_mac_verresult( ssh2_mac *, const void * );
void ssh2_mac_generate( ssh2_mac *, void *, int, unsigned long seq );
bool ssh2_mac_verify( ssh2_mac *, const void *, int, unsigned long seq );

/* Use a MAC in its raw form, outside SSH-2 context, to MAC a given
 * string with a given key in the most obvious way. */
void mac_simple( const ssh2_macalg *alg, ptrlen key, ptrlen data, void *output );

struct ssh_hash
{
	const ssh_hashalg *vt;
	BinarySink_DELEGATE_IMPLEMENTATION;
};

struct ssh_hashalg
{
	ssh_hash *( *_new )( const ssh_hashalg *alg );
	ssh_hash *( *copy )( ssh_hash * );
	void ( *final )( ssh_hash *, unsigned char * ); /* ALSO FREES THE ssh_hash! */
	void ( *free )( ssh_hash * );
	int hlen; /* output length in bytes */
	int blocklen; /* length of the hash's input block, or 0 for N/A */
	const char *text_basename;     /* the semantic name of the hash */
	const char *annotation;   /* extra info, e.g. which of multiple impls */
	const char *text_name;    /* both combined, e.g. "SHA-n (unaccelerated)" */
};

static __inline ssh_hash *ssh_hash_new( const ssh_hashalg *alg )
{ return alg->_new( alg ); }
static __inline ssh_hash *ssh_hash_copy( ssh_hash *h )
{ return h->vt->copy( h ); }
static __inline void ssh_hash_final( ssh_hash *h, unsigned char *out )
{ h->vt->final( h, out ); }
static __inline void ssh_hash_free( ssh_hash *h )
{ h->vt->free( h ); }
static __inline const ssh_hashalg *ssh_hash_alg( ssh_hash *h )
{ return h->vt; }

/* Handy macros for defining all those text-name fields at once */
#define HASHALG_NAMES_BARE( base )					base, NULL, base
#define HASHALG_NAMES_ANNOTATED( base, annotation )	base, annotation, base " (" annotation ")"

void hash_simple( const ssh_hashalg *alg, ptrlen data, void *output );

typedef enum { KEXTYPE_DH, KEXTYPE_RSA, KEXTYPE_ECDH, KEXTYPE_GSS } KEX_TYPE;

struct ssh_kex
{
	const char *name, *groupname;
	KEX_TYPE main_type;
	const ssh_hashalg *hash;
	const void *extra;                 /* private to the kex methods */
};

struct ssh_kexes
{
	int nkexes;
	const ssh_kex *const *list;
};

/* Indices of the negotiation strings in the KEXINIT packet */
enum kexlist
{
	KEXLIST_KEX,
	KEXLIST_HOSTKEY,
	KEXLIST_CSCIPHER,
	KEXLIST_SCCIPHER,
	KEXLIST_CSMAC,
	KEXLIST_SCMAC,
	KEXLIST_CSCOMP,
	KEXLIST_SCCOMP,
	NKEXLIST
};

struct ssh_keyalg
{
	/* Constructors that create an ssh_key */
	ssh_key *( *new_pub )( const ssh_keyalg *self, ptrlen pub );
	ssh_key *( *new_priv )( const ssh_keyalg *self, ptrlen pub, ptrlen priv );
	ssh_key *( *new_priv_openssh)( const ssh_keyalg *self, BinarySource * );

	/* Methods that operate on an existing ssh_key */
	void ( *freekey )( ssh_key *key );
	char *( *invalid )( ssh_key *key, unsigned flags );
	void ( *sign )( ssh_key *key, ptrlen data, unsigned flags, BinarySink * );
	bool ( *verify )( ssh_key *key, ptrlen sig, ptrlen data );
	void ( *public_blob )( ssh_key *key, BinarySink * );
	void ( *private_blob )( ssh_key *key, BinarySink * );
	void ( *openssh_blob )( ssh_key *key, BinarySink * );
	char *( *cache_str )( ssh_key *key );

	/* 'Class methods' that don't deal with an ssh_key at all */
	int ( *pubkey_bits )( const ssh_keyalg *self, ptrlen blob );

	/* Constant data fields giving information about the key type */
	const char *ssh_id;    /* string identifier in the SSH protocol */
	const char *cache_id;  /* identifier used in PuTTY's host key cache */
	const void *extra;     /* private to the public key methods */
	const unsigned supported_flags;    /* signature-type flags we understand */
};

static __inline ssh_key *ssh_key_new_pub( const ssh_keyalg *self, ptrlen pub )
{ return self->new_pub( self, pub ); }
static __inline ssh_key *ssh_key_new_priv( const ssh_keyalg *self, ptrlen pub, ptrlen priv )
{ return self->new_priv( self, pub, priv ); }
static __inline ssh_key *ssh_key_new_priv_openssh( const ssh_keyalg *self, BinarySource *src )
{ return self->new_priv_openssh( self, src ); }
static __inline void ssh_key_free( ssh_key *key )
{ key->vt->freekey( key ); }
static __inline char *ssh_key_invalid( ssh_key *key, unsigned flags )
{ return key->vt->invalid( key, flags ); }
static __inline void ssh_key_sign( ssh_key *key, ptrlen data, unsigned flags, BinarySink *bs )
{ key->vt->sign( key, data, flags, bs ); }
static __inline bool ssh_key_verify( ssh_key *key, ptrlen sig, ptrlen data )
{ return key->vt->verify( key, sig, data ); }
static __inline void ssh_key_public_blob( ssh_key *key, BinarySink *bs )
{ key->vt->public_blob( key, bs ); }
static __inline void ssh_key_private_blob( ssh_key *key, BinarySink *bs )
{ key->vt->private_blob( key, bs ); }
static __inline void ssh_key_openssh_blob( ssh_key *key, BinarySink *bs )
{ key->vt->openssh_blob( key, bs ); }
static __inline char *ssh_key_cache_str( ssh_key *key )
{ return key->vt->cache_str( key ); }
static __inline int ssh_key_public_bits( const ssh_keyalg *self, ptrlen blob )
{ return self->pubkey_bits( self, blob ); }
static __inline const ssh_keyalg *ssh_key_alg( ssh_key *key )
{ return key->vt; }
static __inline const char *ssh_key_ssh_id( ssh_key *key )
{ return key->vt->ssh_id; }
static __inline const char *ssh_key_cache_id( ssh_key *key )
{ return key->vt->cache_id; }

/*
 * Enumeration of signature flags from draft-miller-ssh-agent-02
 */
#define SSH_AGENT_RSA_SHA2_256 2
#define SSH_AGENT_RSA_SHA2_512 4

struct ssh_compressor
{
	const ssh_compression_alg *vt;
};
struct ssh_decompressor
{
	const ssh_compression_alg *vt;
};

struct ssh_compression_alg
{
	const char *name;
	/* For zlib@openssh.com: if non-NULL, this name will be considered once userauth has completed successfully. */
	const char *delayed_name;
	ssh_compressor *( *compress_new )( void );
	void ( *compress_free )( ssh_compressor * );
	void ( *compress )( ssh_compressor *, const unsigned char *block, int len, unsigned char **outblock, int *outlen, int minlen );
	ssh_decompressor *( *decompress_new )( void );
	void ( *decompress_free )( ssh_decompressor * );
	bool ( *decompress )( ssh_decompressor *, const unsigned char *block, int len, unsigned char **outblock, int *outlen );
	const char *text_name;
};

static __inline ssh_compressor *ssh_compressor_new( const ssh_compression_alg *alg )
{ return alg->compress_new(); }
static __inline ssh_decompressor *ssh_decompressor_new( const ssh_compression_alg *alg )
{ return alg->decompress_new(); }
static __inline void ssh_compressor_free( ssh_compressor *c )
{ c->vt->compress_free( c ); }
static __inline void ssh_decompressor_free( ssh_decompressor *d )
{ d->vt->decompress_free( d ); }
static __inline void ssh_compressor_compress( ssh_compressor *c, const unsigned char *block, int len, unsigned char **outblock, int *outlen, int minlen )
{ c->vt->compress( c, block, len, outblock, outlen, minlen ); }
static __inline bool ssh_decompressor_decompress( ssh_decompressor *d, const unsigned char *block, int len, unsigned char **outblock, int *outlen )
{ return d->vt->decompress( d, block, len, outblock, outlen ); }
static __inline const ssh_compression_alg *ssh_compressor_alg( ssh_compressor *c )
{ return c->vt; }
static __inline const ssh_compression_alg *ssh_decompressor_alg( ssh_decompressor *d )
{ return d->vt; }

struct ssh2_userkey
{
	ssh_key *key;                      /* the key itself */
	char *comment;                     /* the key comment */
};

/* The maximum length of any hash algorithm. (bytes) */
#define MAX_HASH_LEN ( 64 )              /* longest is SHA-512 */

extern const ssh_cipheralg ssh_3des_ssh1;
extern const ssh_cipheralg ssh_blowfish_ssh1;
extern const ssh_cipheralg ssh_3des_ssh2_ctr;
extern const ssh_cipheralg ssh_3des_ssh2;
extern const ssh_cipheralg ssh_des;
extern const ssh_cipheralg ssh_des_sshcom_ssh2;
extern const ssh_cipheralg ssh_aes256_sdctr;
extern const ssh_cipheralg ssh_aes256_sdctr_hw;
extern const ssh_cipheralg ssh_aes256_sdctr_sw;
extern const ssh_cipheralg ssh_aes256_cbc;
extern const ssh_cipheralg ssh_aes256_cbc_hw;
extern const ssh_cipheralg ssh_aes256_cbc_sw;
extern const ssh_cipheralg ssh_aes192_sdctr;
extern const ssh_cipheralg ssh_aes192_sdctr_hw;
extern const ssh_cipheralg ssh_aes192_sdctr_sw;
extern const ssh_cipheralg ssh_aes192_cbc;
extern const ssh_cipheralg ssh_aes192_cbc_hw;
extern const ssh_cipheralg ssh_aes192_cbc_sw;
extern const ssh_cipheralg ssh_aes128_sdctr;
extern const ssh_cipheralg ssh_aes128_sdctr_hw;
extern const ssh_cipheralg ssh_aes128_sdctr_sw;
extern const ssh_cipheralg ssh_aes128_cbc;
extern const ssh_cipheralg ssh_aes128_cbc_hw;
extern const ssh_cipheralg ssh_aes128_cbc_sw;
extern const ssh_cipheralg ssh_blowfish_ssh2_ctr;
extern const ssh_cipheralg ssh_blowfish_ssh2;
extern const ssh_cipheralg ssh_arcfour256_ssh2;
extern const ssh_cipheralg ssh_arcfour128_ssh2;
extern const ssh_cipheralg ssh2_chacha20_poly1305;
extern const ssh2_ciphers ssh2_3des;
extern const ssh2_ciphers ssh2_des;
extern const ssh2_ciphers ssh2_aes;
extern const ssh2_ciphers ssh2_blowfish;
extern const ssh2_ciphers ssh2_arcfour;
extern const ssh2_ciphers ssh2_ccp;
extern const ssh_hashalg ssh_md5;
extern const ssh_hashalg ssh_sha1;
extern const ssh_hashalg ssh_sha1_hw;
extern const ssh_hashalg ssh_sha1_sw;
extern const ssh_hashalg ssh_sha256;
extern const ssh_hashalg ssh_sha256_hw;
extern const ssh_hashalg ssh_sha256_sw;
extern const ssh_hashalg ssh_sha384;
extern const ssh_hashalg ssh_sha512;
extern const ssh_kexes ssh_diffiehellman_group1;
extern const ssh_kexes ssh_diffiehellman_group14;
extern const ssh_kexes ssh_diffiehellman_gex;
extern const ssh_kexes ssh_gssk5_sha1_kex;
extern const ssh_kexes ssh_rsa_kex;
extern const ssh_kex ssh_ec_kex_curve25519;
extern const ssh_kex ssh_ec_kex_nistp256;
extern const ssh_kex ssh_ec_kex_nistp384;
extern const ssh_kex ssh_ec_kex_nistp521;
extern const ssh_kexes ssh_ecdh_kex;
extern const ssh_keyalg ssh_dss;
extern const ssh_keyalg ssh_rsa;
extern const ssh_keyalg ssh_ecdsa_ed25519;
extern const ssh_keyalg ssh_ecdsa_nistp256;
extern const ssh_keyalg ssh_ecdsa_nistp384;
extern const ssh_keyalg ssh_ecdsa_nistp521;
extern const ssh2_macalg ssh_hmac_md5;
extern const ssh2_macalg ssh_hmac_sha1;
extern const ssh2_macalg ssh_hmac_sha1_buggy;
extern const ssh2_macalg ssh_hmac_sha1_96;
extern const ssh2_macalg ssh_hmac_sha1_96_buggy;
extern const ssh2_macalg ssh_hmac_sha256;
extern const ssh2_macalg ssh2_poly1305;
extern const ssh_compression_alg ssh_zlib;

/*
 * On some systems, you have to detect hardware crypto acceleration by
 * asking the local OS API rather than OS-agnostically asking the CPU
 * itself. If so, then this function should be implemented in each
 * platform subdirectory.
 */
bool platform_aes_hw_available( void );
bool platform_sha256_hw_available( void );
bool platform_sha1_hw_available( void );

/*
 * The PRNG type, defined in sshprng.c. Visible data fields are
 * 'savesize', which suggests how many random bytes you should request
 * from a particular PRNG instance to write to putty.rnd, and a
 * BinarySink implementation which you can use to write seed data in
 * between calling prng_seed_{begin,finish}.
 */
struct prng
{
	size_t savesize;
	BinarySink_IMPLEMENTATION;
	/* (also there's a surrounding implementation struct in sshprng.c) */
};

prng *prng_new( const ssh_hashalg *hashalg );
void prng_free( prng *p );
void prng_seed_begin( prng *p );
void prng_seed_finish( prng *p );
void prng_read( prng *p, void *vout, size_t size );
void prng_add_entropy( prng *p, unsigned source_id, ptrlen data );

/* This function must be implemented by the platform, and returns a
 * timer in milliseconds that the PRNG can use to know whether it's
 * been reseeded too recently to do it again.
 *
 * The PRNG system has its own special timing function not because its
 * timing needs are unusual in the real applications, but simply so
 * that testcrypt can mock it to keep the tests deterministic. */
uint64_t prng_reseed_time_ms( void );

bool dh_is_gex( const ssh_kex *kex );
dh_ctx *dh_setup_group( const ssh_kex *kex );
dh_ctx *dh_setup_gex( mp_int *pval, mp_int *gval );
int dh_modulus_bit_size( const dh_ctx *ctx );
void dh_cleanup( dh_ctx * );
mp_int *dh_create_e( prng *pr, dh_ctx *, int nbits );
const char *dh_validate_f( dh_ctx *, mp_int *f );
mp_int *dh_find_K( dh_ctx *, mp_int *f );

extern int base64_decode_atom( const char *atom, unsigned char *out );
extern int base64_lines( int datalen );
extern void base64_encode_atom( const unsigned char *data, int n, char *out );
extern void base64_encode( FILE *fp, const unsigned char *data, int datalen, int cpl );

/* ssh2_load_userkey can return this as an error */
extern ssh2_userkey ssh2_wrong_passphrase;
#define SSH2_WRONG_PASSPHRASE ( &ssh2_wrong_passphrase )

bool ssh2_userkey_encrypted( const Filename *filename, char **comment );
ssh2_userkey *ssh2_load_userkey( const Filename *filename, const char *passphrase, const char **errorstr );
bool ssh2_userkey_loadpub( const Filename *filename, char **algorithm, BinarySink *bs, char **commentptr, const char **errorstr );
const ssh_keyalg *find_pubkey_alg( const char *name );
const ssh_keyalg *find_pubkey_alg_len( ptrlen name );

enum
{
	SSH_KEYTYPE_UNOPENABLE,
	SSH_KEYTYPE_UNKNOWN,
	SSH_KEYTYPE_SSH1, SSH_KEYTYPE_SSH2,
	/*
	* The OpenSSH key types deserve a little explanation. OpenSSH has
	* two physical formats for private key storage: an old PEM-based
	* one largely dictated by their use of OpenSSL and full of ASN.1,
	* and a new one using the same private key formats used over the
	* wire for talking to ssh-agent. The old format can only support
	* a subset of the key types, because it needs redesign for each
	* key type, and after a while they decided to move to the new
	* format so as not to have to do that.
	*
	* On input, key files are identified as either
	* SSH_KEYTYPE_OPENSSH_PEM or SSH_KEYTYPE_OPENSSH_NEW, describing
	* accurately which actual format the keys are stored in.
	*
	* On output, however, we default to following OpenSSH's own
	* policy of writing out PEM-style keys for maximum backwards
	* compatibility if the key type supports it, and otherwise
	* switching to the new format. So the formats you can select for
	* output are SSH_KEYTYPE_OPENSSH_NEW (forcing the new format for
	* any key type), and SSH_KEYTYPE_OPENSSH_AUTO to use the oldest
	* format supported by whatever key type you're writing out.
	*
	* So we have three type codes, but only two of them usable in any
	* given circumstance. An input key file will never be identified
	* as AUTO, only PEM or NEW; key export UIs should not be able to
	* select PEM, only AUTO or NEW.
	*/
	SSH_KEYTYPE_OPENSSH_AUTO,
	SSH_KEYTYPE_OPENSSH_PEM,
	SSH_KEYTYPE_OPENSSH_NEW,
	SSH_KEYTYPE_SSHCOM,
	/*
	* Public-key-only formats, which we still want to be able to read
	* for various purposes.
	*/
	SSH_KEYTYPE_SSH1_PUBLIC,
	SSH_KEYTYPE_SSH2_PUBLIC_RFC4716,
	SSH_KEYTYPE_SSH2_PUBLIC_OPENSSH
};

//char *ssh2_pubkey_openssh_str( ssh2_userkey *key );
void get_key_info( ssh_key *data, char **algorithm_str, int *key_size, char **md5_fingerprint_str, char **sha256_fingerprint_str );
int key_type( const Filename *filename );
const char *key_type_to_str( int type );

void des3_decrypt_pubkey( const void *key, void *blk, int len );
void des3_encrypt_pubkey( const void *key, void *blk, int len );
void des3_decrypt_pubkey_ossh( const void *key, const void *iv, void *blk, int len );
void des3_encrypt_pubkey_ossh( const void *key, const void *iv, void *blk, int len );
void aes256_encrypt_pubkey( const void *key, void *blk, int len );
void aes256_decrypt_pubkey( const void *key, void *blk, int len );

void des_encrypt_xdmauth( const void *key, void *blk, int len );
void des_decrypt_xdmauth( const void *key, void *blk, int len );

/*
 * List macro defining SSH-2 message type codes. Some of these depend
 * on particular contexts (i.e. a previously negotiated kex or auth
 * method)
 */
#define SSH2_MESSAGE_TYPES( X, K, A, y )									\
    X( y, SSH2_MSG_DISCONNECT, 1 )											\
    X( y, SSH2_MSG_IGNORE, 2 )												\
    X( y, SSH2_MSG_UNIMPLEMENTED, 3 )										\
    X( y, SSH2_MSG_DEBUG, 4 )												\
    X( y, SSH2_MSG_SERVICE_REQUEST, 5 )										\
    X( y, SSH2_MSG_SERVICE_ACCEPT, 6 )										\
    X( y, SSH2_MSG_KEXINIT, 20 )											\
    X( y, SSH2_MSG_NEWKEYS, 21 )											\
    K( y, SSH2_MSG_KEXDH_INIT, 30, SSH2_PKTCTX_DHGROUP )					\
    K( y, SSH2_MSG_KEXDH_REPLY, 31, SSH2_PKTCTX_DHGROUP )					\
    K( y, SSH2_MSG_KEX_DH_GEX_REQUEST_OLD, 30, SSH2_PKTCTX_DHGEX )			\
    K( y, SSH2_MSG_KEX_DH_GEX_REQUEST, 34, SSH2_PKTCTX_DHGEX )				\
    K( y, SSH2_MSG_KEX_DH_GEX_GROUP, 31, SSH2_PKTCTX_DHGEX )				\
    K( y, SSH2_MSG_KEX_DH_GEX_INIT, 32, SSH2_PKTCTX_DHGEX )					\
    K( y, SSH2_MSG_KEX_DH_GEX_REPLY, 33, SSH2_PKTCTX_DHGEX )				\
    K( y, SSH2_MSG_KEXGSS_INIT, 30, SSH2_PKTCTX_GSSKEX )					\
    K( y, SSH2_MSG_KEXGSS_CONTINUE, 31, SSH2_PKTCTX_GSSKEX )				\
    K( y, SSH2_MSG_KEXGSS_COMPLETE, 32, SSH2_PKTCTX_GSSKEX )				\
    K( y, SSH2_MSG_KEXGSS_HOSTKEY, 33, SSH2_PKTCTX_GSSKEX )					\
    K( y, SSH2_MSG_KEXGSS_ERROR, 34, SSH2_PKTCTX_GSSKEX )					\
    K( y, SSH2_MSG_KEXGSS_GROUPREQ, 40, SSH2_PKTCTX_GSSKEX )				\
    K( y, SSH2_MSG_KEXGSS_GROUP, 41, SSH2_PKTCTX_GSSKEX )					\
    K( y, SSH2_MSG_KEXRSA_PUBKEY, 30, SSH2_PKTCTX_RSAKEX )					\
    K( y, SSH2_MSG_KEXRSA_SECRET, 31, SSH2_PKTCTX_RSAKEX )					\
    K( y, SSH2_MSG_KEXRSA_DONE, 32, SSH2_PKTCTX_RSAKEX )					\
    K( y, SSH2_MSG_KEX_ECDH_INIT, 30, SSH2_PKTCTX_ECDHKEX )					\
    K( y, SSH2_MSG_KEX_ECDH_REPLY, 31, SSH2_PKTCTX_ECDHKEX )				\
    X( y, SSH2_MSG_USERAUTH_REQUEST, 50 )									\
    X( y, SSH2_MSG_USERAUTH_FAILURE, 51 )									\
    X( y, SSH2_MSG_USERAUTH_SUCCESS, 52 )									\
    X( y, SSH2_MSG_USERAUTH_BANNER, 53 )									\
    A( y, SSH2_MSG_USERAUTH_PK_OK, 60, SSH2_PKTCTX_PUBLICKEY )				\
    A( y, SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ, 60, SSH2_PKTCTX_PASSWORD )	\
    A( y, SSH2_MSG_USERAUTH_INFO_REQUEST, 60, SSH2_PKTCTX_KBDINTER )		\
    A( y, SSH2_MSG_USERAUTH_INFO_RESPONSE, 61, SSH2_PKTCTX_KBDINTER )		\
    A( y, SSH2_MSG_USERAUTH_GSSAPI_RESPONSE, 60, SSH2_PKTCTX_GSSAPI )		\
    A( y, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, 61, SSH2_PKTCTX_GSSAPI )			\
    A( y, SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, 63, SSH2_PKTCTX_GSSAPI )	\
    A( y, SSH2_MSG_USERAUTH_GSSAPI_ERROR, 64, SSH2_PKTCTX_GSSAPI )			\
    A( y, SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, 65, SSH2_PKTCTX_GSSAPI )			\
    A( y, SSH2_MSG_USERAUTH_GSSAPI_MIC, 66, SSH2_PKTCTX_GSSAPI )			\
    X( y, SSH2_MSG_GLOBAL_REQUEST, 80 )										\
    X( y, SSH2_MSG_REQUEST_SUCCESS, 81 )									\
    X( y, SSH2_MSG_REQUEST_FAILURE, 82 )									\
    X( y, SSH2_MSG_CHANNEL_OPEN, 90 )										\
    X( y, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, 91 )							\
    X( y, SSH2_MSG_CHANNEL_OPEN_FAILURE, 92 )								\
    X( y, SSH2_MSG_CHANNEL_WINDOW_ADJUST, 93 )								\
    X( y, SSH2_MSG_CHANNEL_DATA, 94 )										\
    X( y, SSH2_MSG_CHANNEL_EXTENDED_DATA, 95 )								\
    X( y, SSH2_MSG_CHANNEL_EOF, 96 )										\
    X( y, SSH2_MSG_CHANNEL_CLOSE, 97 )										\
    X( y, SSH2_MSG_CHANNEL_REQUEST, 98 )									\
    X( y, SSH2_MSG_CHANNEL_SUCCESS, 99 )									\
    X( y, SSH2_MSG_CHANNEL_FAILURE, 100 )									\
    /* end of list */

#define DEF_ENUM_UNIVERSAL( y, name, value ) name = value,
#define DEF_ENUM_CONTEXTUAL( y, name, value, context ) name = value,
enum
{
	SSH2_MESSAGE_TYPES( DEF_ENUM_UNIVERSAL, DEF_ENUM_CONTEXTUAL, DEF_ENUM_CONTEXTUAL, y )
	/* Virtual packet type, for packets too short to even have a type */
	SSH_MSG_NO_TYPE_CODE = 256
};
#undef DEF_ENUM_UNIVERSAL
#undef DEF_ENUM_CONTEXTUAL

/*
 * Messages common to SSH-1 and OpenSSH's SSH-2.
 */
#define SSH_AGENT_FAILURE					5
#define SSH_AGENT_SUCCESS					6

/*
 * OpenSSH's SSH-2 agent messages.
 */
#define SSH2_AGENTC_REQUEST_IDENTITIES			11
#define SSH2_AGENT_IDENTITIES_ANSWER			12
#define SSH2_AGENTC_SIGN_REQUEST				13
#define SSH2_AGENT_SIGN_RESPONSE				14
#define SSH2_AGENTC_ADD_IDENTITY				17
#define SSH2_AGENTC_REMOVE_IDENTITY				18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES		19

/*
 * Assorted other SSH-related enumerations.
 */
#define SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT		1	/* 0x1 */
#define SSH2_DISCONNECT_PROTOCOL_ERROR					2	/* 0x2 */
#define SSH2_DISCONNECT_KEY_EXCHANGE_FAILED				3	/* 0x3 */
#define SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED		4	/* 0x4 */
#define SSH2_DISCONNECT_MAC_ERROR						5	/* 0x5 */
#define SSH2_DISCONNECT_COMPRESSION_ERROR				6	/* 0x6 */
#define SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE			7	/* 0x7 */
#define SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED	8	/* 0x8 */
#define SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE			9	/* 0x9 */
#define SSH2_DISCONNECT_CONNECTION_LOST					10	/* 0xa */
#define SSH2_DISCONNECT_BY_APPLICATION					11	/* 0xb */
#define SSH2_DISCONNECT_TOO_MANY_CONNECTIONS			12	/* 0xc */
#define SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER			13	/* 0xd */
#define SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE	14	/* 0xe */
#define SSH2_DISCONNECT_ILLEGAL_USER_NAME				15	/* 0xf */

#define SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED			1	/* 0x1 */
#define SSH2_OPEN_CONNECT_FAILED						2	/* 0x2 */
#define SSH2_OPEN_UNKNOWN_CHANNEL_TYPE					3	/* 0x3 */
#define SSH2_OPEN_RESOURCE_SHORTAGE						4	/* 0x4 */

#define SSH2_EXTENDED_DATA_STDERR						1	/* 0x1 */

enum
{
	/* TTY modes with opcodes defined consistently in the SSH specs. */
	#define TTYMODE_CHAR( name, val, index ) SSH_TTYMODE_##name = val,
	#define TTYMODE_FLAG( name, val, field, mask ) SSH_TTYMODE_##name = val,
	#include "sshttymodes.h"
	#undef TTYMODE_CHAR
	#undef TTYMODE_FLAG

	/* Modes encoded differently between SSH-1 and SSH-2, for which we
	* make up our own dummy opcodes to avoid confusion. */
	TTYMODE_dummy = 255,
	TTYMODE_ISPEED, TTYMODE_OSPEED,

	/* Limiting value that we can use as an array bound below */
	TTYMODE_LIMIT,

	/* The real opcodes for terminal speeds. */
	TTYMODE_ISPEED_SSH1 = 192,
	TTYMODE_OSPEED_SSH1 = 193,
	TTYMODE_ISPEED_SSH2 = 128,
	TTYMODE_OSPEED_SSH2 = 129,

	/* And the opcode that ends a list. */
	TTYMODE_END_OF_LIST = 0
};

struct ssh_ttymodes
{
	/* A boolean per mode, indicating whether it's set. */
	bool have_mode[ TTYMODE_LIMIT ];

	/* The actual value for each mode. */
	unsigned mode_val[ TTYMODE_LIMIT ];
};

struct ssh_ttymodes read_ttymodes_from_packet( BinarySource *bs, int ssh_version );

/*
 * Flags indicating implementation bugs that we know how to mitigate
 * if we think the other end has them.
 */
#define SSH_IMPL_BUG_LIST( X )					\
    X( BUG_CHOKES_ON_SSH1_IGNORE )				\
    X( BUG_SSH2_HMAC )							\
    X( BUG_NEEDS_SSH1_PLAIN_PASSWORD )			\
    X( BUG_CHOKES_ON_RSA )						\
    X( BUG_SSH2_RSA_PADDING )					\
    X( BUG_SSH2_DERIVEKEY )						\
    X( BUG_SSH2_REKEY )							\
    X( BUG_SSH2_PK_SESSIONID )					\
    X( BUG_SSH2_MAXPKT )						\
    X( BUG_CHOKES_ON_SSH2_IGNORE )				\
    X( BUG_CHOKES_ON_WINADJ )					\
    X( BUG_SENDS_LATE_REQUEST_REPLY )			\
    X( BUG_SSH2_OLDGEX )						\
    /* end of list */
#define TMP_DECLARE_LOG2_ENUM( thing ) log2_##thing,
enum { SSH_IMPL_BUG_LIST( TMP_DECLARE_LOG2_ENUM ) };
#undef TMP_DECLARE_LOG2_ENUM
#define TMP_DECLARE_REAL_ENUM( thing ) thing = 1 << log2_##thing,
enum { SSH_IMPL_BUG_LIST( TMP_DECLARE_REAL_ENUM ) };
#undef TMP_DECLARE_REAL_ENUM

/* Shared system for allocating local SSH channel ids. Expects to be
 * passed a tree full of structs that have a field called 'localid' of
 * type unsigned, and will check that! */
unsigned alloc_channel_id_general( tree234 *channels, size_t localid_offset );
#define alloc_channel_id( tree, type )	TYPECHECK( &( ( type * )0 )->localid == ( unsigned * )0, alloc_channel_id_general( tree, offsetof( type, localid ) ) )

void add_to_commasep( strbuf *buf, const char *data );
bool get_commasep_word( ptrlen *list, ptrlen *word );

typedef struct ssh_transient_hostkey_cache ssh_transient_hostkey_cache;
ssh_transient_hostkey_cache *ssh_transient_hostkey_cache_new( void );
void ssh_transient_hostkey_cache_free( ssh_transient_hostkey_cache *thc );
void ssh_transient_hostkey_cache_add( ssh_transient_hostkey_cache *thc, ssh_key *key );
bool ssh_transient_hostkey_cache_verify( ssh_transient_hostkey_cache *thc, ssh_key *key );
bool ssh_transient_hostkey_cache_has( ssh_transient_hostkey_cache *thc, const ssh_keyalg *alg );
bool ssh_transient_hostkey_cache_non_empty( ssh_transient_hostkey_cache *thc );

#endif
