/*
 * Facility for queueing callback functions to be run from the
 * top-level event loop after the current top-level activity finishes.
 */

#include <stddef.h>

#include "putty.h"
#include "ssh.h"

struct callback
{
	struct callback *next;

	toplevel_callback_fn_t fn;
	void *ctx;
};

static void run_idempotent_callback( Ssh *ssh, void *ctx )
{
	struct IdempotentCallback *ic = ( struct IdempotentCallback * )ctx;
	ic->queued = false;
	ic->fn( ssh, ic->ctx );
}

void queue_idempotent_callback( Ssh *ssh, struct IdempotentCallback *ic )
{
	if ( ssh == NULL || ic->queued )
	{
		return;
	}

	ic->queued = true;
	queue_toplevel_callback( ssh, run_idempotent_callback, ic );
}

void delete_callbacks_for_context( Ssh *ssh, void *ctx )
{
	struct callback *newhead, *newtail;

	if ( ssh == NULL )
	{
		return;
	}

	newhead = newtail = NULL;
	while ( ssh->cbhead )
	{
		struct callback *cb = ssh->cbhead;
		ssh->cbhead = ssh->cbhead->next;
		if ( cb->ctx == ctx || ( cb->fn == run_idempotent_callback && ( ( struct IdempotentCallback * )cb->ctx )->ctx == ctx ) )
		{
			sfree( cb );
		}
		else
		{
			if ( !newhead )
			{
				newhead = cb;
			}
			else
			{
				newtail->next = cb;
			}

			newtail = cb;
		}
	}

	ssh->cbhead = newhead;
	ssh->cbtail = newtail;
	if ( newtail )
	{
		newtail->next = NULL;
	}
}

void queue_toplevel_callback( Ssh *ssh, toplevel_callback_fn_t fn, void *ctx )
{
	struct callback *cb;

	if ( ssh == NULL )
	{
		return;
	}

	cb = snew( struct callback );
	cb->fn = fn;
	cb->ctx = ctx;

	if ( ssh->cbtail )
	{
		ssh->cbtail->next = cb;
	}
	else
	{
		ssh->cbhead = cb;
	}
	ssh->cbtail = cb;
	cb->next = NULL;
}

bool run_toplevel_callbacks( Ssh *ssh )
{
	bool done_something = false;

	if ( ssh == NULL )
	{
		return false;
	}

	if ( ssh->cbhead )
	{
		/*
		* Transfer the head callback into cbcurr to indicate that
		* it's being executed. Then operations which transform the
		* queue, like delete_callbacks_for_context, can proceed as if
		* it's not there.
		*/
		ssh->cbcurr = ssh->cbhead;
		ssh->cbhead = ssh->cbhead->next;
		if ( !ssh->cbhead )
		{
			ssh->cbtail = NULL;
		}

		/*
		* Now run the callback, and then clear it out of cbcurr.
		*/
		ssh->cbcurr->fn( ssh, ssh->cbcurr->ctx );
		sfree( ssh->cbcurr );
		ssh->cbcurr = NULL;

		done_something = true;
	}

	return done_something;
}

bool toplevel_callback_pending( Ssh *ssh )
{
	if ( ssh == NULL )
	{
		return false;
	}

	return ssh->cbcurr != NULL || ssh->cbhead != NULL;
}
