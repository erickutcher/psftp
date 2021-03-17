/*
 * sftp.c: SFTP generic client code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#include "putty.h"
#include "sftp.h"

static const char *fxp_error_message;
static int fxp_errtype;

static void fxp_internal_error( const char *msg );

/* ----------------------------------------------------------------------
 * Request ID allocation and temporary dispatch routines.
 */

#define REQUEST_ID_OFFSET 256

struct sftp_request
{
	unsigned id;
	bool registered;
	void *userdata;
};

void sftp_register( struct sftp_request *req )
{
	req->registered = true;
}

int sftp_reqcmp( void *av, void *bv )
{
	struct sftp_request *a = ( struct sftp_request * )av;
	struct sftp_request *b = ( struct sftp_request * )bv;

	if ( a->id < b->id )
	{
		return -1;
	}

	if ( a->id > b->id )
	{
		return +1;
	}

	return 0;
}

int sftp_reqfind( void *av, void *bv )
{
	unsigned *a = ( unsigned * ) av;
	struct sftp_request *b = ( struct sftp_request * )bv;

	if ( *a < b->id )
	{
		return -1;
	}

	if ( *a > b->id )
	{
		return +1;
	}

	return 0;
}

struct sftp_request *sftp_alloc_request( tree234 **sftp_requests )
{
	unsigned low, high, mid;
	int tsize;
	struct sftp_request *r;

	if ( *sftp_requests == NULL )
	{
		*sftp_requests = newtree234( sftp_reqcmp );
	}

	/*
	* First-fit allocation of request IDs: always pick the lowest
	* unused one. To do this, binary-search using the counted
	* B-tree to find the largest ID which is in a contiguous
	* sequence from the beginning. (Precisely everything in that
	* sequence must have ID equal to its tree index plus
	* REQUEST_ID_OFFSET.)
	*/
	tsize = count234( *sftp_requests );

	low = -1;
	high = tsize;
	while ( high - low > 1 )
	{
		mid = (high + low) / 2;
		r = ( sftp_request * )index234( *sftp_requests, mid );
		if ( r->id == mid + REQUEST_ID_OFFSET )
		{
			low = mid;		       /* this one is fine */
		}
		else
		{
			high = mid;		       /* this one is past it */
		}
	}
	/*
	* Now low points to either -1, or the tree index of the
	* largest ID in the initial sequence.
	*/
	{
		unsigned i = low + 1 + REQUEST_ID_OFFSET;
		assert( NULL == find234( *sftp_requests, &i, sftp_reqfind ) );
	}

	/*
	* So the request ID we need to create is
	* low + 1 + REQUEST_ID_OFFSET.
	*/
	r = snew( struct sftp_request );
	r->id = low + 1 + REQUEST_ID_OFFSET;
	r->registered = false;
	r->userdata = NULL;
	add234( *sftp_requests, r );

	return r;
}

struct sftp_request *sftp_find_request( tree234 *reqs, struct sftp_packet *pktin )
{
	unsigned id;
	struct sftp_request *req;

	if ( !pktin )
	{
		return NULL;
	}

	id = get_uint32( pktin );
	if ( get_err( pktin ) )
	{
		return NULL;
	}

	req = ( sftp_request * )find234( reqs, &id, sftp_reqfind );
	if ( !req || !req->registered )
	{
		return NULL;
	}

	del234( reqs, req );

	return req;
}

bool sftp_senddata( struct Backend *backend, const char *buf, size_t len )
{
	backend_send( backend, buf, len );
	return true;
}

bool sftp_send( struct Backend *backend, struct sftp_packet *pkt )
{
	bool ret;
	sftp_send_prepare( pkt );
	ret = sftp_senddata( backend, pkt->data, pkt->length );
	sftp_pkt_free( pkt );
	return ret;
}

void sftp_cleanup_request( tree234 **reqs )
{
	if ( *reqs != NULL )
	{
		int tsize = count234( *reqs );
		for ( int i = 0; i < tsize; ++i )
		{
			sftp_request *rreq = ( sftp_request * )index234( *reqs, i );

//			struct req *rr = ( struct req * )fxp_get_userdata( rreq );

			sfree( rreq );
		}

		freetree234( *reqs );
		*reqs = NULL;
	}
}

/* ----------------------------------------------------------------------
 * SFTP primitives.
 */

/*
 * Deal with (and free) an FXP_STATUS packet. Return 1 if
 * SSH_FX_OK, 0 if SSH_FX_EOF, and -1 for anything else (error).
 * Also place the status into fxp_errtype.
 */
static int fxp_got_status( struct sftp_packet *pktin )
{
	static const char *const messages[] =
	{
		/* SSH_FX_OK. The only time we will display a _message_ for this
		* is if we were expecting something other than FXP_STATUS on
		* success, so this is actually an error message! */
		"unexpected OK response",
		"end of file",
		"no such file or directory",
		"permission denied",
		"failure",
		"bad message",
		"no connection",
		"connection lost",
		"operation unsupported",
	};

	if ( pktin->type != SSH_FXP_STATUS )
	{
		fxp_error_message = "expected FXP_STATUS packet";
		fxp_errtype = -1;
	}
	else
	{
		fxp_errtype = get_uint32( pktin );
		if ( get_err( pktin ) )
		{
			fxp_error_message = "malformed FXP_STATUS packet";
			fxp_errtype = -1;
		}
		else
		{
			if ( fxp_errtype < 0 || fxp_errtype >= lenof( messages ) )
			{
				fxp_error_message = "unknown error code";
			}
			else
			{
				fxp_error_message = messages[ fxp_errtype ];
			}
		}
	}

	if ( fxp_errtype == SSH_FX_OK )
	{
		return 1;
	}
	else if ( fxp_errtype == SSH_FX_EOF )
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

static void fxp_internal_error( const char *msg )
{
	fxp_error_message = msg;
	fxp_errtype = -1;
}

const char *fxp_error( void )
{
	return fxp_error_message;
}

int fxp_error_type( void )
{
	return fxp_errtype;
}

static struct fxp_handle *fxp_got_handle( struct sftp_packet *pktin )
{
	ptrlen id;
	struct fxp_handle *handle;

	id = get_string( pktin );
	if ( get_err( pktin ) )
	{
		fxp_internal_error( "received malformed FXP_HANDLE" );
		sftp_pkt_free( pktin );
		return NULL;
	}
	handle = snew( struct fxp_handle );
	handle->hstring = mkstr( id );
	handle->hlen = id.len;
	sftp_pkt_free( pktin );
	return handle;
}

struct sftp_request *fxp_open_send( Backend *be, tree234 **reqs, const char *path, int type, const struct fxp_attrs *attrs )
{
	struct sftp_request *req = sftp_alloc_request( reqs );
	struct sftp_packet *pktout;

	pktout = sftp_pkt_init( SSH_FXP_OPEN );
	put_uint32( pktout, req->id );
	put_stringz( pktout, path );
	put_uint32( pktout, type );
	put_fxp_attrs( pktout, attrs ? *attrs : no_attrs );
	sftp_send( be, pktout );

	return req;
}

struct fxp_handle *fxp_open_recv( struct sftp_packet *pktin, struct sftp_request *req )
{
	sfree( req );

	if ( pktin->type == SSH_FXP_HANDLE )
	{
		return fxp_got_handle( pktin );
	}
	else
	{
		fxp_got_status( pktin );
		sftp_pkt_free( pktin );
		return NULL;
	}
}

struct sftp_request *fxp_close_send( Backend *be, tree234 **reqs, struct fxp_handle *handle )
{
	struct sftp_request *req = sftp_alloc_request( reqs );
	struct sftp_packet *pktout;

	pktout = sftp_pkt_init( SSH_FXP_CLOSE );
	put_uint32( pktout, req->id );
	put_string( pktout, handle->hstring, handle->hlen );
	sftp_send( be, pktout );

	sfree( handle->hstring );
	sfree( handle );

	return req;
}

bool fxp_close_recv( struct sftp_packet *pktin, struct sftp_request *req )
{
	sfree( req );
	fxp_got_status( pktin );
	sftp_pkt_free( pktin );
	return fxp_errtype == SSH_FX_OK;
}

static bool fxp_got_attrs( struct sftp_packet *pktin, struct fxp_attrs *attrs )
{
	get_fxp_attrs( pktin, attrs );
	if ( get_err( pktin ) )
	{
		fxp_internal_error( "malformed SSH_FXP_ATTRS packet" );
		sftp_pkt_free( pktin );
		return false;
	}
	sftp_pkt_free( pktin );
	return true;
}

struct sftp_request *fxp_stat_send( Backend *be, tree234 **reqs, const char *fname )
{
	struct sftp_request *req = sftp_alloc_request( reqs );
	struct sftp_packet *pktout;

	pktout = sftp_pkt_init( SSH_FXP_STAT );
	put_uint32( pktout, req->id );
	put_stringz( pktout, fname );
	sftp_send( be, pktout );

	return req;
}

bool fxp_stat_recv( struct sftp_packet *pktin, struct sftp_request *req, struct fxp_attrs *attrs )
{
	sfree( req );
	if ( pktin->type == SSH_FXP_ATTRS )
	{
		return fxp_got_attrs( pktin, attrs );
	}
	else
	{
		fxp_got_status( pktin );
		sftp_pkt_free( pktin );
		return false;
	}
}

struct sftp_request *fxp_read_send( Backend *be, tree234 **reqs, struct fxp_handle *handle, uint64_t offset, int len )
{
	struct sftp_request *req = sftp_alloc_request( reqs );
	struct sftp_packet *pktout;

	pktout = sftp_pkt_init( SSH_FXP_READ );
	put_uint32( pktout, req->id );
	put_string( pktout, handle->hstring, handle->hlen );
	put_uint64( pktout, offset );
	put_uint32( pktout, len);
	sftp_send( be, pktout );

	return req;
}

int fxp_read_recv( struct sftp_packet *pktin, struct sftp_request *req, char *buffer, int len )
{
	sfree( req );
	if ( pktin->type == SSH_FXP_DATA )
	{
		ptrlen data;

		data = get_string( pktin );
		if ( get_err( pktin ) )
		{
			fxp_internal_error( "READ returned malformed SSH_FXP_DATA packet" );
			sftp_pkt_free( pktin );
			return -1;
		}

		if ( data.len > len )
		{
			fxp_internal_error( "READ returned more bytes than requested" );
			sftp_pkt_free( pktin );
			return -1;
		}

		memcpy( buffer, data.ptr, data.len );
		sftp_pkt_free( pktin );
		return data.len;
	}
	else
	{
		fxp_got_status( pktin );
		sftp_pkt_free( pktin );
		return -1;
	}
}

/*
 * Store user data in an sftp_request structure.
 */
void *fxp_get_userdata( struct sftp_request *req )
{
	return req->userdata;
}

void fxp_set_userdata( struct sftp_request *req, void *data )
{
	req->userdata = data;
}

/*
 * A wrapper to go round fxp_read_* and fxp_write_*, which manages
 * the queueing of multiple read/write requests.
 */

struct req
{
	char *buffer;
	int len, retlen, complete;
	uint64_t offset;
	struct req *next, *prev;
};

struct fxp_xfer
{
	uint64_t offset, furthestdata, filesize;
	int req_totalsize, req_maxsize;
	bool eof, err;
	struct fxp_handle *fh;
	struct req *head, *tail;
};

struct fxp_xfer *xfer_download_init( Backend *be, tree234 **reqs, struct fxp_handle *fh, uint64_t offset, uint64_t filesize )
{
	struct fxp_xfer *xfer = snew( struct fxp_xfer );

	xfer->fh = fh;
	xfer->offset = offset;
	xfer->head = xfer->tail = NULL;
	xfer->req_totalsize = 0;
	xfer->req_maxsize = 1048576;
	xfer->err = false;
	xfer->filesize = filesize;
	xfer->furthestdata = 0;

	xfer->eof = false;
	xfer_download_queue( be, reqs, xfer );

	return xfer;
}

bool xfer_done( struct fxp_xfer *xfer )
{
	/*
	* We're finished if we've seen EOF _and_ there are no
	* outstanding requests.
	*/
	return ( xfer->eof || xfer->err ) && !xfer->head;
}

void xfer_set_error( struct fxp_xfer *xfer )
{
	xfer->err = true;
}

void xfer_download_queue( Backend *be, tree234 **reqs, struct fxp_xfer *xfer )
{
	while ( xfer->req_totalsize < xfer->req_maxsize && !xfer->eof && !xfer->err )
	{
		/*
		* Queue a new read request.
		*/
		struct req *rr;
		struct sftp_request *req;

		rr = snew( struct req );
		rr->offset = xfer->offset;
		rr->complete = 0;
		if ( xfer->tail )
		{
			xfer->tail->next = rr;
			rr->prev = xfer->tail;
		}
		else
		{
			xfer->head = rr;
			rr->prev = NULL;
		}
		xfer->tail = rr;
		rr->next = NULL;

		rr->len = 32768;
		rr->buffer = snewn( rr->len, char );
		sftp_register( req = fxp_read_send( be, reqs, xfer->fh, rr->offset, rr->len ) );
		fxp_set_userdata( req, rr );

		xfer->offset += rr->len;
		xfer->req_totalsize += rr->len;
	}
}

bool xfer_download_data( struct fxp_xfer *xfer, void **buf, int *len )
{
	void *retbuf = NULL;
	int retlen = 0;

	/*
	* Discard anything at the head of the rr queue with complete <
	* 0; return the first thing with complete > 0.
	*/
	while ( xfer->head && xfer->head->complete && !retbuf )
	{
		struct req *rr = xfer->head;

		if ( rr->complete > 0 )
		{
			retbuf = rr->buffer;
			retlen = rr->retlen;
		}

		xfer->head = xfer->head->next;
		if ( xfer->head )
		{
			xfer->head->prev = NULL;
		}
		else
		{
			xfer->tail = NULL;
		}
		xfer->req_totalsize -= rr->len;
		sfree( rr );
	}

	if ( retbuf )
	{
		*buf = retbuf;
		*len = retlen;
		return true;
	}
	else
	{
		return false;
	}
}

int xfer_download_gotpkt( tree234 *reqs, struct fxp_xfer *xfer, struct sftp_packet *pktin )
{
	struct sftp_request *rreq;
	struct req *rr;

	rreq = sftp_find_request( reqs, pktin );

	if ( !rreq )
	{
		return INT_MIN;            /* this packet doesn't even make sense */
	}

	rr = ( struct req * )fxp_get_userdata( rreq );
	if ( !rr )
	{
		return INT_MIN;		       /* this packet isn't ours */
	}

	rr->retlen = fxp_read_recv( pktin, rreq, rr->buffer, rr->len );

	if ( ( rr->retlen < 0 && fxp_error_type() == SSH_FX_EOF ) || rr->retlen == 0 )
	{
		xfer->eof = true;
		rr->retlen = 0;
		//rr->complete = -1;
	}
	else if ( rr->retlen < 0 )
	{
		/* some error other than EOF; signal it back to caller */
		xfer_set_error( xfer );
		rr->complete = -1;
		return -1;
	}

	rr->complete = 1;

	/*
	* Special case: if we have received fewer bytes than we
	* actually read, we should do something. For the moment I'll
	* just throw an ersatz FXP error to signal this; the SFTP
	* draft I've got says that it can't happen except on special
	* files, in which case seeking probably has very little
	* meaning and so queueing an additional read request to fill
	* up the gap sounds like the wrong answer. I'm not sure what I
	* should be doing here - if it _was_ a special file, I suspect
	* I simply shouldn't have been queueing multiple requests in
	* the first place...
	*/
	if ( rr->retlen > 0 && xfer->furthestdata < rr->offset )
	{
		xfer->furthestdata = rr->offset;
	}

	if ( rr->retlen < rr->len )
	{
		uint64_t filesize = rr->offset + (rr->retlen < 0 ? 0 : rr->retlen );

		if ( xfer->filesize > filesize )
		{
			xfer->filesize = filesize;    
		}
	}

	if ( xfer->furthestdata > xfer->filesize )
	{
		//fxp_errtype = -1;
		//xfer_set_error(xfer);
		//return -1;

		xfer->eof = true;
		rr->retlen = 0;
	}

	return 1;
}

void xfer_cleanup( struct fxp_xfer *xfer )
{
	struct req *rr;
	while ( xfer->head )
	{
		rr = xfer->head;

		xfer->head = xfer->head->next;
		sfree( rr->buffer );
		sfree( rr );
	}
	sfree( xfer );
}
