/*
 * Supporting routines used in common by all the various components of
 * the SSH system.
 */

#include <assert.h>
#include <stdlib.h>

#include "putty.h"
#include "mpint.h"
#include "ssh.h"
#include "sshbpp.h"
#include "sshppl.h"
#include "sshchan.h"

/* ----------------------------------------------------------------------
 * Implementation of PacketQueue.
 */

static void pq_ensure_unlinked( PacketQueueNode *node )
{
	if ( node->on_free_queue )
	{
		node->next->prev = node->prev;
		node->prev->next = node->next;
	}
	else
	{
		assert( !node->next );
		assert( !node->prev );
	}
}

void pq_base_push( Ssh *ssh, PacketQueueBase *pqb, PacketQueueNode *node )
{
	pq_ensure_unlinked( node );
	node->next = &pqb->end;
	node->prev = pqb->end.prev;
	node->next->prev = node;
	node->prev->next = node;
	pqb->total_size += node->formal_size;

	if ( pqb->ic )
	{
		queue_idempotent_callback( ssh, pqb->ic );
	}
}

void pq_base_push_front( Ssh *ssh, PacketQueueBase *pqb, PacketQueueNode *node )
{
	pq_ensure_unlinked( node );
	node->prev = &pqb->end;
	node->next = pqb->end.next;
	node->next->prev = node;
	node->prev->next = node;
	pqb->total_size += node->formal_size;

	if ( pqb->ic )
	{
		queue_idempotent_callback( ssh, pqb->ic );
	}
}

static void pktin_free_queue_callback( Ssh *ssh, void * /*vctx*/ )
{
	while ( ssh->pktin_freeq_head.next != &ssh->pktin_freeq_head )
	{
		PacketQueueNode *node = ssh->pktin_freeq_head.next;
		PktIn *pktin = container_of( node, PktIn, qnode );
		ssh->pktin_freeq_head.next = node->next;
		sfree( pktin );
	}

	ssh->pktin_freeq_head.prev = &ssh->pktin_freeq_head;
}

static IdempotentCallback ic_pktin_free =
{
	pktin_free_queue_callback, NULL, false
};

static __inline void pq_unlink_common( PacketQueueBase *pqb, PacketQueueNode *node )
{
	node->next->prev = node->prev;
	node->prev->next = node->next;

	/* Check total_size doesn't drift out of sync downwards, by
	* ensuring it doesn't underflow when we do this subtraction */
	assert( pqb->total_size >= node->formal_size );
	pqb->total_size -= node->formal_size;

	/* Check total_size doesn't drift out of sync upwards, by checking
	* that it's returned to exactly zero whenever a queue is
	* emptied */
	assert( pqb->end.next != &pqb->end || pqb->total_size == 0 );
}

static PktIn *pq_in_after( Ssh *ssh, PacketQueueBase *pqb, PacketQueueNode *prev, bool pop )
{
	PacketQueueNode *node = prev->next;
	if ( node == &pqb->end )
	{
		return NULL;
	}

	if ( pop )
	{
		pq_unlink_common( pqb, node );

		node->prev = ssh->pktin_freeq_head.prev;
		node->next = &ssh->pktin_freeq_head;
		node->next->prev = node;
		node->prev->next = node;
		node->on_free_queue = true;

		queue_idempotent_callback( ssh, &ic_pktin_free );
	}

	return container_of( node, PktIn, qnode );
}

static PktOut *pq_out_after( Ssh * /*ssh*/, PacketQueueBase *pqb, PacketQueueNode *prev, bool pop )
{
	PacketQueueNode *node = prev->next;
	if ( node == &pqb->end )
	{
		return NULL;
	}

	if ( pop )
	{
		pq_unlink_common( pqb, node );

		node->prev = node->next = NULL;
	}

	return container_of( node, PktOut, qnode );
}

void pq_in_init( PktInQueue *pq )
{
	pq->pqb.ic = NULL;
	pq->pqb.end.next = pq->pqb.end.prev = &pq->pqb.end;
	pq->after = pq_in_after;
	pq->pqb.total_size = 0;
}

void pq_out_init( PktOutQueue *pq )
{
	pq->pqb.ic = NULL;
	pq->pqb.end.next = pq->pqb.end.prev = &pq->pqb.end;
	pq->after = pq_out_after;
	pq->pqb.total_size = 0;
}

void pq_in_clear( Ssh *ssh, PktInQueue *pq )
{
	PktIn *pkt;
	pq->pqb.ic = NULL;
	while ( ( pkt = pq_pop( ssh, pq ) ) != NULL )
	{
		/* No need to actually free these packets: pq_pop on a
		* PktInQueue will automatically move them to the free
		* queue. */
	}
}

void pq_out_clear( Ssh *ssh, PktOutQueue *pq )
{
	PktOut *pkt;
	pq->pqb.ic = NULL;
	while ( ( pkt = pq_pop( ssh, pq ) ) != NULL )
	{
		ssh_free_pktout( pkt );
	}
}

/*
 * Concatenate the contents of the two queues q1 and q2, and leave the
 * result in qdest. qdest must be either empty, or one of the input
 * queues.
 */
void pq_base_concatenate( Ssh *ssh, PacketQueueBase *qdest, PacketQueueBase *q1, PacketQueueBase *q2 )
{
	struct PacketQueueNode *head1, *tail1, *head2, *tail2;

	size_t total_size = q1->total_size + q2->total_size;

	/*
	* Extract the contents from both input queues, and empty them.
	*/

	head1 = ( q1->end.next == &q1->end ? NULL : q1->end.next );
	tail1 = ( q1->end.prev == &q1->end ? NULL : q1->end.prev );
	head2 = ( q2->end.next == &q2->end ? NULL : q2->end.next );
	tail2 = ( q2->end.prev == &q2->end ? NULL : q2->end.prev );

	q1->end.next = q1->end.prev = &q1->end;
	q2->end.next = q2->end.prev = &q2->end;
	q1->total_size = q2->total_size = 0;

	/*
	* Link the two lists together, handling the case where one or
	* both is empty.
	*/

	if ( tail1 )
	{
		tail1->next = head2;
	}
	else
	{
		head1 = head2;
	}

	if ( head2 )
	{
		head2->prev = tail1;
	}
	else
	{
		tail2 = tail1;
	}

	/*
	* Check the destination queue is currently empty. (If it was one
	* of the input queues, then it will be, because we emptied both
	* of those just a moment ago.)
	*/

	assert( qdest->end.next == &qdest->end );
	assert( qdest->end.prev == &qdest->end );

	/*
	* If our concatenated list has anything in it, then put it in
	* dest.
	*/

	if ( !head1 )
	{
		assert( !tail2 );
	}
	else
	{
		assert( tail2 );
		qdest->end.next = head1;
		qdest->end.prev = tail2;
		head1->prev = &qdest->end;
		tail2->next = &qdest->end;

		if ( qdest->ic )
		{
			queue_idempotent_callback( ssh, qdest->ic );
		}
	}

	qdest->total_size = total_size;
}

/* ----------------------------------------------------------------------
 * Low-level functions for the packet structures themselves.
 */

static void ssh_pkt_BinarySink_write( BinarySink *bs, const void *data, size_t len );

PktOut *ssh_new_packet( void )
{
	PktOut *pkt = snew( PktOut );

	BinarySink_INIT( pkt, ssh_pkt_BinarySink_write );
	pkt->data = NULL;
	pkt->length = 0;
	pkt->maxlen = 0;
	pkt->downstream_id = 0;
	pkt->additional_log_text = NULL;
	pkt->qnode.next = pkt->qnode.prev = NULL;
	pkt->qnode.on_free_queue = false;

	return pkt;
}

static void ssh_pkt_adddata( PktOut *pkt, const void *data, int len )
{
	sgrowarrayn_nm( unsigned char *, pkt->data, pkt->maxlen, pkt->length, len );
	memcpy( pkt->data + pkt->length, data, len );
	pkt->length += len;
	pkt->qnode.formal_size = pkt->length;
}

static void ssh_pkt_BinarySink_write( BinarySink *bs, const void *data, size_t len )
{
	PktOut *pkt = BinarySink_DOWNCAST( bs, PktOut );
	ssh_pkt_adddata( pkt, data, len );
}

void ssh_free_pktout( PktOut *pkt )
{
	sfree( pkt->data );
	sfree( pkt );
}

/* ----------------------------------------------------------------------
 * Implement zombiechan_new() and its trivial vtable.
 */

static void zombiechan_free( Channel *chan );
static size_t zombiechan_send( Channel *chan, bool is_stderr, const void *, size_t );
static void zombiechan_set_input_wanted( Channel *chan, bool wanted );
static void zombiechan_do_nothing( Channel *chan );
static void zombiechan_open_failure( Channel *chan );
static bool zombiechan_want_close( Channel *chan, bool sent_eof, bool rcvd_eof );

static const struct ChannelVtable zombiechan_channelvt =
{
	zombiechan_free,
	zombiechan_do_nothing,             /* open_confirmation */
	zombiechan_open_failure,
	zombiechan_send,
	zombiechan_do_nothing,             /* send_eof */
	zombiechan_set_input_wanted,
	zombiechan_want_close,
	chan_no_exit_status,
	chan_no_exit_signal,
	chan_no_exit_signal_numeric,
	chan_no_request_response,
};

Channel *zombiechan_new( void )
{
	Channel *chan = snew( Channel );
	chan->vt = &zombiechan_channelvt;
	chan->initial_fixed_window_size = 0;
	return chan;
}

static void zombiechan_free( Channel *chan )
{
	assert( chan->vt == &zombiechan_channelvt );
	sfree( chan );
}

static void zombiechan_do_nothing( Channel *chan )
{
	assert( chan->vt == &zombiechan_channelvt );
}

static void zombiechan_open_failure( Channel *chan )
{
	assert( chan->vt == &zombiechan_channelvt );
}

static size_t zombiechan_send( Channel *chan, bool /*is_stderr*/, const void * /*data*/, size_t /*length*/ )
{
	assert( chan->vt == &zombiechan_channelvt );
	return 0;
}

static void zombiechan_set_input_wanted( Channel *chan, bool /*enable*/ )
{
	assert( chan->vt == &zombiechan_channelvt );
}

static bool zombiechan_want_close( Channel * /*chan*/, bool /*sent_eof*/, bool /*rcvd_eof*/ )
{
	return true;
}

/* ----------------------------------------------------------------------
 * Centralised standard methods for other channel implementations to borrow.
 */

bool chan_default_want_close( Channel * /*chan*/, bool sent_local_eof, bool rcvd_remote_eof )
{
	/*
	* Default close policy: we start initiating the CHANNEL_CLOSE
	* procedure as soon as both sides of the channel have seen EOF.
	*/
	return sent_local_eof && rcvd_remote_eof;
}

bool chan_no_exit_status( Channel * /*chan*/, int /*status*/ )
{
	return false;
}

bool chan_no_exit_signal( Channel * /*chan*/, ptrlen /*signame*/, bool /*core_dumped*/, ptrlen /*msg*/ )
{
	return false;
}

bool chan_no_exit_signal_numeric( Channel * /*chan*/, int /*signum*/, bool /*core_dumped*/, ptrlen /*msg*/ )
{
	return false;
}

void chan_no_request_response( Channel * /*chan*/, bool /*success*/ )
{
//	unreachable( "this channel type should never send a want-reply request" );
}

/* ----------------------------------------------------------------------
 * Routine for allocating a new channel ID, given a means of finding
 * the index field in a given channel structure.
 */

unsigned alloc_channel_id_general( tree234 *channels, size_t localid_offset )
{
	const unsigned CHANNEL_NUMBER_OFFSET = 256;
	search234_state ss;

	/*
	* First-fit allocation of channel numbers: we always pick the
	* lowest unused one.
	*
	* Every channel before that, and no channel after it, has an ID
	* exactly equal to its tree index plus CHANNEL_NUMBER_OFFSET. So
	* we can use the search234 system to identify the length of that
	* initial sequence, in a single log-time pass down the channels
	* tree.
	*/
	search234_start( &ss, channels );
	while ( ss.element )
	{
		unsigned localid = *( unsigned * )( ( char * )ss.element + localid_offset );
		if ( localid == ss.index + CHANNEL_NUMBER_OFFSET )
		{
			search234_step( &ss, +1 );
		}
		else
		{
			search234_step( &ss, -1 );
		}
	}

	/*
	* Now ss.index gives exactly the number of channels in that
	* initial sequence. So adding CHANNEL_NUMBER_OFFSET to it must
	* give precisely the lowest unused channel number.
	*/
	return ss.index + CHANNEL_NUMBER_OFFSET;
}

/* ----------------------------------------------------------------------
 * Functions for handling the comma-separated strings used to store
 * lists of protocol identifiers in SSH-2.
 */

void add_to_commasep( strbuf *buf, const char *data )
{
	if ( buf->len > 0 )
	{
		put_byte( buf, ',' );
	}
	put_data( buf, data, strlen( data ) );
}

bool get_commasep_word( ptrlen *list, ptrlen *word )
{
	const char *comma;

	/*
	* Discard empty list elements, should there be any, because we
	* never want to return one as if it was a real string. (This
	* introduces a mild tolerance of badly formatted data in lists we
	* receive, but I think that's acceptable.)
	*/
	while ( list->len > 0 && *( const char * )list->ptr == ',' )
	{
		list->ptr = ( const char * )list->ptr + 1;
		list->len--;
	}

	if ( !list->len )
	{
		return false;
	}

	comma = ( const char * )memchr( list->ptr, ',', list->len );
	if ( !comma )
	{
		*word = *list;
		list->len = 0;
	}
	else
	{
		size_t wordlen = comma - ( const char * )list->ptr;
		word->ptr = list->ptr;
		word->len = wordlen;
		list->ptr = ( const char * )list->ptr + wordlen + 1;
		list->len -= wordlen + 1;
	}
	return true;
}

/* ----------------------------------------------------------------------
 * Common helper function for clients and implementations of PacketProtocolLayer.
 */

void ssh_ppl_replace( PacketProtocolLayer *old, PacketProtocolLayer *_new )
{
	_new->bpp = old->bpp;
	ssh_ppl_setup_queues( _new, old->in_pq, old->out_pq );
	_new->selfptr = old->selfptr;
	_new->user_input = old->user_input;
	_new->ssh = old->ssh;

	*_new->selfptr = _new;
	ssh_ppl_free( old );

	/* The new layer might need to be the first one that sends a
	* packet, so trigger a call to its main coroutine immediately. If
	* it doesn't need to go first, the worst that will do is return
	* straight away. */
	queue_idempotent_callback( _new->ssh, &_new->ic_process_queue );
}

void ssh_ppl_free( PacketProtocolLayer *ppl )
{
	delete_callbacks_for_context( ppl->ssh, ppl );
	ppl->vt->free( ppl );
}

static void ssh_ppl_ic_process_queue_callback( Ssh * /*ssh*/, void *context )
{
	PacketProtocolLayer *ppl = ( PacketProtocolLayer * )context;
	ssh_ppl_process_queue( ppl );
}

void ssh_ppl_setup_queues( PacketProtocolLayer *ppl, PktInQueue *inq, PktOutQueue *outq )
{
	ppl->in_pq = inq;
	ppl->out_pq = outq;
	ppl->in_pq->pqb.ic = &ppl->ic_process_queue;
	ppl->ic_process_queue.fn = ssh_ppl_ic_process_queue_callback;
	ppl->ic_process_queue.ctx = ppl;

	/* If there's already something on the input queue, it will want handling immediately. */
	if ( pq_peek( ppl->ssh, ppl->in_pq ) )
	{
		queue_idempotent_callback( ppl->ssh, &ppl->ic_process_queue );
	}
}

size_t ssh_ppl_default_queued_data_size( PacketProtocolLayer *ppl )
{
	return ppl->out_pq->pqb.total_size;
}

/* ----------------------------------------------------------------------
 * Common helper functions for clients and implementations of BinaryPacketProtocol.
 */

static void ssh_bpp_input_raw_data_callback( Ssh * /*_ssh*/, void *context )
{
	BinaryPacketProtocol *bpp = ( BinaryPacketProtocol * )context;
	Ssh *ssh = bpp->ssh;               /* in case bpp is about to get freed */
	ssh_bpp_handle_input( bpp );
	/* If we've now cleared enough backlog on the input connection, we may need to unfreeze it. */
	ssh_conn_processed_data( ssh );
}

static void ssh_bpp_output_packet_callback( Ssh * /*ssh*/, void *context )
{
	BinaryPacketProtocol *bpp = ( BinaryPacketProtocol * )context;
	ssh_bpp_handle_output( bpp );
}

void ssh_bpp_common_setup( BinaryPacketProtocol *bpp )
{
	pq_in_init( &bpp->in_pq );
	pq_out_init( &bpp->out_pq );
	bpp->input_eof = false;
	bpp->ic_in_raw.fn = ssh_bpp_input_raw_data_callback;
	bpp->ic_in_raw.ctx = bpp;
	bpp->ic_out_pq.fn = ssh_bpp_output_packet_callback;
	bpp->ic_out_pq.ctx = bpp;
	bpp->out_pq.pqb.ic = &bpp->ic_out_pq;
}

void ssh_bpp_free( BinaryPacketProtocol *bpp )
{
	delete_callbacks_for_context( bpp->ssh, bpp );
	bpp->vt->free( bpp );
}

void ssh2_bpp_queue_disconnect( BinaryPacketProtocol *bpp, const char *msg, int category )
{
	PktOut *pkt = ssh_bpp_new_pktout( bpp->ssh, bpp, SSH2_MSG_DISCONNECT );
	put_uint32( pkt, category );
	put_stringz( pkt, msg );
	put_stringz( pkt, "en" );            /* language tag */
	pq_push( bpp->ssh, &bpp->out_pq, pkt );
}

#define BITMAP_UNIVERSAL( y, name, value )			| ( value >= y && value < y + 32 ? 1UL << ( value - y ) : 0 )
#define BITMAP_CONDITIONAL( y, name, value, ctx )		BITMAP_UNIVERSAL( y, name, value )
#define SSH2_BITMAP_WORD( y )							( 0 SSH2_MESSAGE_TYPES( BITMAP_UNIVERSAL, BITMAP_CONDITIONAL, BITMAP_CONDITIONAL, ( 32 * y ) ) )

bool ssh2_bpp_check_unimplemented( BinaryPacketProtocol *bpp, PktIn *pktin )
{
	#pragma warning( push )
	#pragma warning( disable : 4293 )	// Warning about shifting out of bounds.
	static const unsigned valid_bitmap[] =
	{
		SSH2_BITMAP_WORD( 0 ),
		SSH2_BITMAP_WORD( 1 ),
		SSH2_BITMAP_WORD( 2 ),
		SSH2_BITMAP_WORD( 3 ),
		SSH2_BITMAP_WORD( 4 ),
		SSH2_BITMAP_WORD( 5 ),
		SSH2_BITMAP_WORD( 6 ),
		SSH2_BITMAP_WORD( 7 ),
	};
	#pragma warning( pop )

	if ( pktin->type < 0x100 && !( ( valid_bitmap[ pktin->type >> 5 ] >> ( pktin->type & 0x1F ) ) & 1 ) )
	{
		PktOut *pkt = ssh_bpp_new_pktout( bpp->ssh, bpp, SSH2_MSG_UNIMPLEMENTED );
		put_uint32( pkt, pktin->sequence );
		pq_push( bpp->ssh, &bpp->out_pq, pkt );
		return true;
	}

	return false;
}

#undef BITMAP_UNIVERSAL
#undef BITMAP_CONDITIONAL
