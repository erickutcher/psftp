/*
 * sftp.h: definitions for SFTP and the sftp.c routines.
 */

#include "defs.h"
#include "tree234.h"

#define SSH_FXP_INIT                              1     /* 0x1 */
#define SSH_FXP_VERSION                           2     /* 0x2 */
#define SSH_FXP_OPEN                              3     /* 0x3 */
#define SSH_FXP_CLOSE                             4     /* 0x4 */
#define SSH_FXP_READ                              5     /* 0x5 */
#define SSH_FXP_WRITE                             6     /* 0x6 */
#define SSH_FXP_LSTAT                             7     /* 0x7 */
#define SSH_FXP_FSTAT                             8     /* 0x8 */
#define SSH_FXP_SETSTAT                           9     /* 0x9 */
#define SSH_FXP_FSETSTAT                          10    /* 0xa */
#define SSH_FXP_OPENDIR                           11    /* 0xb */
#define SSH_FXP_READDIR                           12    /* 0xc */
#define SSH_FXP_REMOVE                            13    /* 0xd */
#define SSH_FXP_MKDIR                             14    /* 0xe */
#define SSH_FXP_RMDIR                             15    /* 0xf */
#define SSH_FXP_REALPATH                          16    /* 0x10 */
#define SSH_FXP_STAT                              17    /* 0x11 */
#define SSH_FXP_RENAME                            18    /* 0x12 */
#define SSH_FXP_STATUS                            101   /* 0x65 */
#define SSH_FXP_HANDLE                            102   /* 0x66 */
#define SSH_FXP_DATA                              103   /* 0x67 */
#define SSH_FXP_NAME                              104   /* 0x68 */
#define SSH_FXP_ATTRS                             105   /* 0x69 */
#define SSH_FXP_EXTENDED                          200   /* 0xc8 */
#define SSH_FXP_EXTENDED_REPLY                    201   /* 0xc9 */

#define SSH_FX_OK                                 0
#define SSH_FX_EOF                                1
#define SSH_FX_NO_SUCH_FILE                       2
#define SSH_FX_PERMISSION_DENIED                  3
#define SSH_FX_FAILURE                            4
#define SSH_FX_BAD_MESSAGE                        5
#define SSH_FX_NO_CONNECTION                      6
#define SSH_FX_CONNECTION_LOST                    7
#define SSH_FX_OP_UNSUPPORTED                     8

#define SSH_FILEXFER_ATTR_SIZE                    0x00000001
#define SSH_FILEXFER_ATTR_UIDGID                  0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS             0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME               0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED                0x80000000

#define SSH_FXF_READ                              0x00000001
#define SSH_FXF_WRITE                             0x00000002
#define SSH_FXF_APPEND                            0x00000004
#define SSH_FXF_CREAT                             0x00000008
#define SSH_FXF_TRUNC                             0x00000010
#define SSH_FXF_EXCL                              0x00000020

#define SFTP_PROTO_VERSION 3

#define PERMS_DIRECTORY   040000

/*
 * External references. The sftp client module sftp.c expects to be
 * able to get at these functions.
 *
 * sftp_recvdata must never return less than len. It either blocks
 * until len is available and then returns true, or it returns false
 * for failure.
 *
 * sftp_senddata returns true on success, false on failure.
 *
 * sftp_sendbuffer returns the size of the backlog of data in the
 * transmit queue.
 */
bool sftp_senddata( const char *data, size_t len );
size_t sftp_sendbuffer( void );
bool sftp_recvdata( char *data, size_t len );

struct fxp_attrs
{
	unsigned long flags;
	uint64_t size;
	unsigned long uid;
	unsigned long gid;
	unsigned long permissions;
	unsigned long atime;
	unsigned long mtime;
};
extern const struct fxp_attrs no_attrs;

/*
 * Copy between the possibly-unused permissions field in an fxp_attrs
 * and a possibly-negative integer containing the same permissions.
 */
#define PUT_PERMISSIONS( attrs, perms )						\
	( ( perms ) >= 0 ?										\
	( ( attrs ).flags |= SSH_FILEXFER_ATTR_PERMISSIONS,		\
	  ( attrs ).permissions = ( perms ) ) :					\
	( ( attrs ).flags &= ~SSH_FILEXFER_ATTR_PERMISSIONS ) )
#define GET_PERMISSIONS( attrs, defaultperms )				\
	( ( attrs ).flags & SSH_FILEXFER_ATTR_PERMISSIONS ?		\
	  ( attrs ).permissions : defaultperms )

struct fxp_handle
{
	char *hstring;
	int hlen;
};

struct fxp_name
{
	char *filename, *longname;
	struct fxp_attrs attrs;
};

struct fxp_names
{
	int nnames;
	struct fxp_name *names;
};

struct sftp_request;

/*
 * Packet-manipulation functions.
 */

struct sftp_packet
{
	char *data;
	size_t length, maxlen, savedpos;
	int type;
	BinarySink_IMPLEMENTATION;
	BinarySource_IMPLEMENTATION;
};

/* When sending a packet, create it with sftp_pkt_init, then add
 * things to it by treating it as a BinarySink. When it's done, call
 * sftp_send_prepare, and then pkt->data and pkt->length describe its
 * wire format. */
struct sftp_packet *sftp_pkt_init( int pkt_type );
void sftp_send_prepare( struct sftp_packet *pkt );

/* When receiving a packet, create it with sftp_recv_prepare once you
 * decode its length from the first 4 bytes of wire data. Then write
 * that many bytes into pkt->data, and call sftp_recv_finish to set up
 * the type code and BinarySource. */
struct sftp_packet *sftp_recv_prepare( unsigned length );
bool sftp_recv_finish( struct sftp_packet *pkt );

/* Either kind of packet can be freed afterwards with sftp_pkt_free. */
void sftp_pkt_free( struct sftp_packet *pkt );

void BinarySink_put_fxp_attrs( BinarySink *bs, struct fxp_attrs attrs );
bool BinarySource_get_fxp_attrs( BinarySource *src, struct fxp_attrs *attrs );
#define put_fxp_attrs( bs, attrs )	BinarySink_put_fxp_attrs( BinarySink_UPCAST( bs ), attrs )
#define get_fxp_attrs( bs, attrs )	BinarySource_get_fxp_attrs( BinarySource_UPCAST( bs ), attrs )

/*
 * Close a file/dir. Returns true on success, false on error.
 */
struct sftp_request *fxp_close_send( Backend *be, tree234 **reqs, struct fxp_handle *handle );
bool fxp_close_recv( struct sftp_packet *pktin, struct sftp_request *req );

/*
 * Error handling.
 */
int fxp_error_type( void );

/*
 * Store user data in an sftp_request structure.
 */
void fxp_set_userdata( struct sftp_request *req, void *data );
void *fxp_get_userdata( struct sftp_request *req );

/*
 * Open a file. 'attrs' contains attributes to be applied to the file
 * if it's being created.
 */
struct sftp_request *fxp_open_send( Backend *be, tree234 **reqs, const char *path, int type, const struct fxp_attrs *attrs );
struct fxp_handle *fxp_open_recv( struct sftp_packet *pktin, struct sftp_request *req );

/*
 * Read from a file.
 */
struct sftp_request *fxp_read_send( Backend *be, tree234 **reqs, struct fxp_handle *handle, uint64_t offset, int len );
int fxp_read_recv( struct sftp_packet *pktin, struct sftp_request *req, char *buffer, int len );

/*
 * Return file attributes.
 */
struct sftp_request *fxp_stat_send( Backend *be, tree234 **reqs, const char *fname );
bool fxp_stat_recv( struct sftp_packet *pktin, struct sftp_request *req, struct fxp_attrs *attrs );

void sftp_register( struct sftp_request *req );
bool sftp_send( struct Backend *backend, struct sftp_packet *pkt );
struct sftp_request *sftp_find_request( tree234 *reqs, struct sftp_packet *pktin );
void sftp_cleanup_request( tree234 **reqs );

struct fxp_xfer *xfer_download_init( Backend *be, tree234 **reqs, struct fxp_handle *fh, uint64_t offset, uint64_t filesize = UINT64_MAX );
void xfer_download_queue( Backend *be, tree234 **reqs, struct fxp_xfer *xfer );
bool xfer_download_data( struct fxp_xfer *xfer, void **buf, int *len );
int xfer_download_gotpkt( tree234 *reqs, struct fxp_xfer *xfer, struct sftp_packet *pktin );

bool xfer_done( struct fxp_xfer *xfer );
void xfer_set_error( struct fxp_xfer *xfer );
void xfer_cleanup( struct fxp_xfer *xfer );
