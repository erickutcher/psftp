#ifndef PUTTY_PUTTY_H
#define PUTTY_PUTTY_H

#include <stddef.h>                    /* for wchar_t */
#include <limits.h>                    /* for INT_MAX */

#include "defs.h"
#include "winstuff.h"
#include "misc.h"
#include "marshal.h"

/* Collect environmental noise every 5 minutes */
#define NOISE_REGULAR_INTERVAL ( 5 * 60 * TICKSPERSEC )

/*
 * We express various time intervals in unsigned long minutes, but may need to
 * clip some values so that the resulting number of ticks does not overflow an
 * integer value.
 */
#define MAX_TICK_MINS	( INT_MAX / ( 60 * TICKSPERSEC ) )

/*
 * Enumeration of 'special commands' that can be sent during a
 * session, separately from the byte stream of ordinary session data.
 */
typedef enum
{
	/*
	* Commands that are generally useful in multiple backends.
	*/
	SS_BRK,    /* serial-line break */
	SS_EOF,    /* end-of-file on session input */
	SS_NOP,    /* transmit data with no effect */
	SS_PING,   /* try to keep the session alive (probably, but not necessarily, implemented as SS_NOP) */

	/*
	* Commands specific to Telnet.
	*/
	SS_AYT,    /* Are You There */
	SS_SYNCH,  /* Synch */
	SS_EC,     /* Erase Character */
	SS_EL,     /* Erase Line */
	SS_GA,     /* Go Ahead */
	SS_ABORT,  /* Abort Process */
	SS_AO,     /* Abort Output */
	SS_IP,     /* Interrupt Process */
	SS_SUSP,   /* Suspend Process */
	SS_EOR,    /* End Of Record */
	SS_EOL,    /* Telnet end-of-line sequence (CRLF, as opposed to CR NUL that escapes a literal CR) */

	/*
	* Commands specific to SSH.
	*/
	SS_REKEY,  /* trigger an immediate repeat key exchange */
	SS_XCERT,  /* cross-certify another host key ('arg' indicates which) */

	/*
	* Send a POSIX-style signal. (Useful in SSH and also pterm.)
	*
	* We use the master list in sshsignals.h to define these enum
	* values, which will come out looking like names of the form
	* SS_SIGABRT, SS_SIGINT etc.
	*/
	#define SIGNAL_MAIN( name, text ) SS_SIG ## name,
	#define SIGNAL_SUB( name ) SS_SIG ## name,
	#include "sshsignals.h"
	#undef SIGNAL_MAIN
	#undef SIGNAL_SUB

	/*
	* These aren't really special commands, but they appear in the
	* enumeration because the list returned from
	* backend_get_specials() will use them to specify the structure
	* of the GUI specials menu.
	*/
	SS_SEP,         /* Separator */
	SS_SUBMENU,     /* Start a new submenu with specified name */
	SS_EXITMENU,    /* Exit current submenu, or end of entire specials list */
} SessionSpecialCode;

/*
 * The structure type returned from backend_get_specials.
 */
struct SessionSpecial
{
	const char *name;
	SessionSpecialCode code;
	int arg;
};

/* Needed by both sshchan.h and sshppl.h */
typedef void ( *add_special_fn_t )( void *ctx, const char *text, SessionSpecialCode code, int arg );

enum
{
	/*
	* SSH-2 key exchange algorithms
	*/
	KEX_WARN,
	KEX_DHGROUP1,
	KEX_DHGROUP14,
	KEX_DHGEX,
	KEX_RSA,
	KEX_ECDH,
	KEX_MAX
};

enum
{
	/*
	* SSH-2 host key algorithms
	*/
	HK_WARN,
	HK_RSA,
	HK_DSA,
	HK_ECDSA,
	HK_ED25519,
	HK_MAX
};

enum
{
	/*
	* SSH ciphers (both SSH-1 and SSH-2)
	*/
	CIPHER_WARN,                       /* pseudo 'cipher' */
	CIPHER_3DES,
	CIPHER_BLOWFISH,
	CIPHER_AES,                        /* (SSH-2 only) */
	CIPHER_DES,
	CIPHER_ARCFOUR,
	CIPHER_CHACHA20,
	CIPHER_MAX                         /* no. ciphers (inc warn) */
};

enum
{
	/*
	* GSS Libraries
	*/
	GSS_LIB_GSSAPI32,
	GSS_LIB_SSPI,
	GSS_LIB_MAX
};

enum TriState
{
	/*
	* Several different bits of the PuTTY configuration seem to be
	* three-way settings whose values are `always yes', `always
	* no', and `decide by some more complex automated means'. This
	* is true of line discipline options (local echo and line
	* editing), proxy DNS, proxy terminal logging, Close On Exit, and
	* SSH server bug workarounds. Accordingly I supply a single enum
	* here to deal with them all.
	*/
	FORCE_ON, FORCE_OFF, AUTO
};

enum
{
	/* Protocol back ends. (CONF_protocol) */
	PROT_RAW, PROT_TELNET, PROT_RLOGIN, PROT_SSH,
	/* PROT_SERIAL is supported on a subset of platforms, but it doesn't
	* hurt to define it globally. */
	PROT_SERIAL
};

/*
 * Tables of string <-> enum value mappings used in settings.c.
 * Defined here so that backends can export their GSS library tables
 * to the cross-platform settings code.
 */
struct keyvalwhere
{
	/*
	* Two fields which define a string and enum value to be
	* equivalent to each other.
	*/
	const char *s;
	int v;

	/*
	* The next pair of fields are used by gprefs() in settings.c to
	* arrange that when it reads a list of strings representing a
	* preference list and translates it into the corresponding list
	* of integers, strings not appearing in the list are entered in a
	* configurable position rather than uniformly at the end.
	*/

	/*
	* 'vrel' indicates which other value in the list to place this
	* element relative to. It should be a value that has occurred in
	* a 'v' field of some other element of the array, or -1 to
	* indicate that we simply place relative to one or other end of
	* the list.
	*
	* gprefs will try to process the elements in an order which makes
	* this field work (i.e. so that the element referenced has been
	* added before processing this one).
	*/
	int vrel;

	/*
	* 'where' indicates whether to place the new value before or
	* after the one referred to by vrel. -1 means before; +1 means
	* after.
	*
	* When vrel is -1, this also implicitly indicates which end of
	* the array to use. So vrel=-1, where=-1 means to place _before_
	* some end of the list (hence, at the last element); vrel=-1,
	* where=+1 means to place _after_ an end (hence, at the first).
	*/
	int where;
};

#ifndef NO_GSSAPI
extern const int ngsslibs;
#endif


struct Backend
{
	const BackendVtable *vt;
};
struct BackendVtable
{
	void ( *free )( Backend *be );
	/* send() returns the current amount of buffered data. */
	size_t ( *send )( Backend *be, const char *buf, size_t len );
	/* sendbuffer() does the same thing but without attempting a send */
	size_t ( *sendbuffer )( Backend *be );
	void ( *special )( Backend *be, SessionSpecialCode code, int arg );
	const SessionSpecial *( *get_specials )( Backend *be );
	bool ( *connected )( Backend *be );
	int ( *exitcode )( Backend *be );
	/* If back->sendok() returns false, the backend doesn't currently
	* want input data, so the frontend should avoid acquiring any if
	* possible (passing back-pressure on to its sender). */
	bool ( *sendok )( Backend *be );
};

static __inline void backend_free( Backend *be )
{ be->vt->free( be ); }
static __inline size_t backend_send( Backend *be, const char *buf, size_t len )
{ return be->vt->send( be, buf, len ); }
static __inline size_t backend_sendbuffer( Backend *be )
{ return be->vt->sendbuffer( be ); }
static __inline void backend_special( Backend *be, SessionSpecialCode code, int arg )
{ be->vt->special( be, code, arg ); }
static __inline const SessionSpecial *backend_get_specials( Backend *be )
{ return be->vt->get_specials( be ); }
static __inline bool backend_connected( Backend *be )
{ return be->vt->connected( be ); }
static __inline int backend_exitcode( Backend *be )
{ return be->vt->exitcode( be ); }
static __inline bool backend_sendok( Backend *be )
{ return be->vt->sendok( be ); }

/*
 * Exports from noise.c.
 */
typedef enum NoiseSourceId
{
	NOISE_SOURCE_TIME,
	NOISE_SOURCE_IOID,
	NOISE_SOURCE_IOLEN,
	NOISE_SOURCE_KEY,
	NOISE_SOURCE_MOUSEBUTTON,
	NOISE_SOURCE_MOUSEPOS,
	NOISE_SOURCE_MEMINFO,
	NOISE_SOURCE_STAT,
	NOISE_SOURCE_RUSAGE,
	NOISE_SOURCE_FGWINDOW,
	NOISE_SOURCE_CAPTURE,
	NOISE_SOURCE_CLIPBOARD,
	NOISE_SOURCE_QUEUE,
	NOISE_SOURCE_CURSORPOS,
	NOISE_SOURCE_THREADTIME,
	NOISE_SOURCE_PROCTIME,
	NOISE_SOURCE_PERFCOUNT,
	NOISE_MAX_SOURCES
} NoiseSourceId;
void noise_get_heavy( prng *pr, void ( *func ) ( prng *, void *, int ) );
void noise_get_light(void ( *func ) ( void *, int ) );
void noise_regular( prng *pr );
void noise_ultralight( prng *pr, NoiseSourceId id, unsigned long data );
void random_save_seed( prng *pr );
void random_destroy_seed( void );

/*
 * Exports from ssh.c.
 */
extern const struct BackendVtable ssh_backend;

/*
 * Exports from sshrand.c.
 */

void random_add_noise( prng *pr, NoiseSourceId source, const void *noise, int length );
void random_read( prng *pr, void *buf, size_t size );
/* The random number subsystem is activated if at least one other entity
 * within the program expresses an interest in it. So each SSH session
 * calls random_ref on startup and random_unref on shutdown. */
prng *random_create( const ssh_hashalg *hashalg );
/* random_clear is equivalent to calling random_unref as many times as
 * necessary to shut down the global PRNG instance completely. It's
 * not needed in normal applications, but the command-line PuTTYgen
 * test finds it useful to clean up after each invocation of the
 * logical main() no matter whether it needed random numbers or
 * not. */
void random_clear( prng *pr );
/* Manually drop a random seed into the random number generator, e.g.
 * just before generating a key. */
void random_reseed( prng *pr, ptrlen seed );
void random_timer( void *ctx, unsigned long now );

/*
 * Exports from pinger.c.
 */
void pinger_timer( void *ctx, unsigned long now );

/*
 * Exports from wildcard.c
 */
const char *wc_error( int value );
int wc_match_pl( const char *wildcard, ptrlen target );
int wc_match( const char *wildcard, const char *target );
bool wc_unescape( char *output, const char *wildcard );

/*
 * have_ssh_host_key() just returns true if a key of that type is
 * already cached and false otherwise.
 */
bool have_ssh_host_key( Ssh *ssh, const char *algorithm );

/*
 * Miscellaneous exports from the platform-specific code.
 *
 * filename_serialise and filename_deserialise have the same semantics
 * as fontspec_serialise and fontspec_deserialise above.
 */
Filename *filename_from_str( const char *string );
const char *filename_to_str( const Filename *fn );
bool filename_equal( const Filename *f1, const Filename *f2 );
bool filename_is_null( const Filename *fn );
Filename *filename_copy( const Filename *fn );
void filename_free( Filename *fn );
void filename_serialise( BinarySink *bs, const Filename *f );
Filename *filename_deserialise( BinarySource *src );
char *get_username( void );              /* return value needs freeing */
char *get_random_data( int bytes, const char *device ); /* used in cmdgen.c */
char filename_char_sanitise( char c );   /* rewrite special pathname chars */
bool open_for_write_would_lose_data( const Filename *fn );

/*
 * Exports and imports from timing.c.
 *
 * schedule_timer() asks the front end to schedule a callback to a
 * timer function in a given number of ticks. The returned value is
 * the time (in ticks since an arbitrary offset) at which the
 * callback can be expected. This value will also be passed as the
 * `now' parameter to the callback function. Hence, you can (for
 * example) schedule an event at a particular time by calling
 * schedule_timer() and storing the return value in your context
 * structure as the time when that event is due. The first time a
 * callback function gives you that value or more as `now', you do
 * the thing.
 *
 * expire_timer_context() drops all current timers associated with
 * a given value of ctx (for when you're about to free ctx).
 *
 * run_timers() is called from the front end when it has reason to
 * think some timers have reached their moment, or when it simply
 * needs to know how long to wait next. We pass it the time we
 * think it is. It returns true and places the time when the next
 * timer needs to go off in `next', or alternatively it returns
 * false if there are no timers at all pending.
 *
 * timer_change_notify() must be supplied by the front end; it
 * notifies the front end that a new timer has been added to the
 * list which is sooner than any existing ones. It provides the
 * time when that timer needs to go off.
 *
 * *** FRONT END IMPLEMENTORS NOTE:
 *
 * There's an important subtlety in the front-end implementation of
 * the timer interface. When a front end is given a `next' value,
 * either returned from run_timers() or via timer_change_notify(),
 * it should ensure that it really passes _that value_ as the `now'
 * parameter to its next run_timers call. It should _not_ simply
 * call GETTICKCOUNT() to get the `now' parameter when invoking
 * run_timers().
 *
 * The reason for this is that an OS's system clock might not agree
 * exactly with the timing mechanisms it supplies to wait for a
 * given interval. I'll illustrate this by the simple example of
 * Unix Plink, which uses timeouts to poll() in a way which for
 * these purposes can simply be considered to be a wait() function.
 * Suppose, for the sake of argument, that this wait() function
 * tends to return early by 1%. Then a possible sequence of actions
 * is:
 *
 *  - run_timers() tells the front end that the next timer firing
 *    is 10000ms from now.
 *  - Front end calls wait(10000ms), but according to
 *    GETTICKCOUNT() it has only waited for 9900ms.
 *  - Front end calls run_timers() again, passing time T-100ms as
 *    `now'.
 *  - run_timers() does nothing, and says the next timer firing is
 *    still 100ms from now.
 *  - Front end calls wait(100ms), which only waits for 99ms.
 *  - Front end calls run_timers() yet again, passing time T-1ms.
 *  - run_timers() says there's still 1ms to wait.
 *  - Front end calls wait(1ms).
 *
 * If you're _lucky_ at this point, wait(1ms) will actually wait
 * for 1ms and you'll only have woken the program up three times.
 * If you're unlucky, wait(1ms) might do nothing at all due to
 * being below some minimum threshold, and you might find your
 * program spends the whole of the last millisecond tight-looping
 * between wait() and run_timers().
 *
 * Instead, what you should do is to _save_ the precise `next'
 * value provided by run_timers() or via timer_change_notify(), and
 * use that precise value as the input to the next run_timers()
 * call. So:
 *
 *  - run_timers() tells the front end that the next timer firing
 *    is at time T, 10000ms from now.
 *  - Front end calls wait(10000ms).
 *  - Front end then immediately calls run_timers() and passes it
 *    time T, without stopping to check GETTICKCOUNT() at all.
 *
 * This guarantees that the program wakes up only as many times as
 * there are actual timer actions to be taken, and that the timing
 * mechanism will never send it into a tight loop.
 *
 * (It does also mean that the timer action in the above example
 * will occur 100ms early, but this is not generally critical. And
 * the hypothetical 1% error in wait() will be partially corrected
 * for anyway when, _after_ run_timers() returns, you call
 * GETTICKCOUNT() and compare the result with the returned `next'
 * value to find out how long you have to make your next wait().)
 */
typedef void ( *TIMER_FN_T )( void *ctx, unsigned long now );
struct TIMER_INFO
{
    TIMER_FN_T fn;
    void *ctx;
    unsigned long now;
};

typedef void ( *timer_fn_t )( void *ctx, unsigned long now );
unsigned long schedule_timer( Ssh *ssh, int ticks, timer_fn_t fn, void *ctx );
void expire_timer_context( TIMER_INFO *timer_info );
bool run_timers( unsigned long now, unsigned long *next );
void run_timers( Ssh *ssh );
void timer_change_notify( unsigned long next );
unsigned long timing_last_clock( void );

/*
 * Exports from callback.c.
 *
 * This provides a method of queuing function calls to be run at the
 * earliest convenience from the top-level event loop. Use it if
 * you're deep in a nested chain of calls and want to trigger an
 * action which will probably lead to your function being re-entered
 * recursively if you just call the initiating function the normal
 * way.
 *
 * Most front ends run the queued callbacks by simply calling
 * run_toplevel_callbacks() after handling each event in their
 * top-level event loop. However, if a front end doesn't have control
 * over its own event loop (e.g. because it's using GTK) then it can
 * instead request notifications when a callback is available, so that
 * it knows to ask its delegate event loop to do the same thing. Also,
 * if a front end needs to know whether a callback is pending without
 * actually running it (e.g. so as to put a zero timeout on a poll()
 * call) then it can call toplevel_callback_pending(), which will
 * return true if at least one callback is in the queue.
 *
 * run_toplevel_callbacks() returns true if it ran any actual code.
 * This can be used as a means of speculatively terminating a poll
 * loop, as in PSFTP, for example - if a callback has run then perhaps
 * it might have done whatever the loop's caller was waiting for.
 */
typedef void ( *toplevel_callback_fn_t )( Ssh *ssh, void *ctx );
void queue_toplevel_callback( Ssh *ssh, toplevel_callback_fn_t fn, void *ctx );
bool run_toplevel_callbacks( Ssh *ssh );
bool toplevel_callback_pending( Ssh *ssh );
void delete_callbacks_for_context( Ssh *ssh, void *ctx );

/*
 * Another facility in callback.c deals with 'idempotent' callbacks,
 * defined as those which never need to be scheduled again if they are
 * already scheduled and have not yet run. (An example would be one
 * which, when called, empties a queue of data completely: when data
 * is added to the queue, you must ensure a run of the queue-consuming
 * function has been scheduled, but if one is already pending, you
 * don't need to schedule a second one.)
 */
struct IdempotentCallback
{
	toplevel_callback_fn_t fn;
	void *ctx;
	bool queued;
};
void queue_idempotent_callback( Ssh *ssh, struct IdempotentCallback *ic );

////////////////////////////////////////

struct ec_curve *ec_p256( void );
struct ec_curve *ec_p384( void );
struct ec_curve *ec_p521( void );
struct ec_curve *ec_curve25519( void );
struct ec_curve *ec_ed25519( void );

extern bool g_gss_loaded;
extern CRITICAL_SECTION gss_library_cs;
extern CRITICAL_SECTION algorithm_priorities_cs;
extern CRITICAL_SECTION ssh2kex_cs;

extern volatile int g_keep_alive_time;
extern volatile int g_rekey_time;
extern volatile int g_gss_rekey_time;
extern volatile unsigned long g_rekey_data_limit;

extern volatile int g_CONF_compression;

extern int g_CONF_ssh_gsslist[ GSS_LIB_MAX ];

extern bool g_CONF_ssh_prefer_known_hostkeys;
extern bool g_CONF_ssh_no_userauth;

extern volatile int g_CONF_try_gssapi_auth;
extern volatile int g_CONF_try_gssapi_kex;
extern bool g_CONF_gssapifwd;

extern char *g_CONF_remote_cmd;
extern bool g_CONF_ssh_subsys;
extern char *g_CONF_remote_cmd2;
extern bool g_CONF_ssh_subsys2;

extern int g_CONF_sshbug_ignore1;
extern int g_CONF_sshbug_plainpw1;
extern int g_CONF_sshbug_rsa1;
extern int g_CONF_sshbug_hmac2;
extern int g_CONF_sshbug_derivekey2;
extern int g_CONF_sshbug_rsapad2;
extern int g_CONF_sshbug_pksessid2;
extern int g_CONF_sshbug_rekey2;
extern int g_CONF_sshbug_maxpkt2;
extern int g_CONF_sshbug_ignore2;
extern int g_CONF_sshbug_oldgex2;
extern int g_CONF_sshbug_winadj;
extern int g_CONF_sshbug_chanreq;

#endif
