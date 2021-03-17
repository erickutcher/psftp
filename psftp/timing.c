/*
 * timing.c
 *
 * This module tracks any timers set up by schedule_timer(). It
 * keeps all the currently active timers in a list; it informs the
 * front end of when the next timer is due to go off if that
 * changes; and, very importantly, it tracks the context pointers
 * passed to schedule_timer(), so that if a context is freed all
 * the timers associated with it can be immediately annulled.
 *
 *
 * The problem is that computer clocks aren't perfectly accurate.
 * The GETTICKCOUNT function returns a 32bit number that normally
 * increases by about 1000 every second. On windows this uses the PC's
 * interrupt timer and so is only accurate to around 20ppm.  On unix it's
 * a value that's calculated from the current UTC time and so is in theory
 * accurate in the long term but may jitter and jump in the short term.
 *
 * What PuTTY needs from these timers is simply a way of delaying the
 * calling of a function for a little while, if it's occasionally called a
 * little early or late that's not a problem. So to protect against clock
 * jumps schedule_timer records the time that it was called in the timer
 * structure. With this information the run_timers function can see when
 * the current GETTICKCOUNT value is after the time the event should be
 * fired OR before the time it was set. In the latter case the clock must
 * have jumped, the former is (probably) just the normal passage of time.
 *
 */

#include <stdio.h>

#include "putty.h"
#include "ssh.h"

void run_timers( Ssh *ssh )
{
	if ( ssh != NULL )
	{
		unsigned long now = GetTickCount();

		if ( ssh->timer_prng_noise.fn != NULL && now >= ssh->timer_prng_noise.now )
		{
			ssh->timer_prng_noise.fn( ssh->timer_prng_noise.ctx, ssh->timer_prng_noise.now );
		}

		if ( ssh->timer_transport_rekey.fn != NULL && now >= ssh->timer_transport_rekey.now )
		{
			ssh->timer_transport_rekey.fn( ssh->timer_transport_rekey.ctx, ssh->timer_transport_rekey.now );
		}

		if ( ssh->timer_pinger.fn != NULL && now >= ssh->timer_pinger.now )
		{
			ssh->timer_pinger.fn( ssh->timer_pinger.ctx, ssh->timer_pinger.now );
		}
	}
}

void expire_timer_context( TIMER_INFO *timer_info )
{
	if ( timer_info != NULL )
	{
		memset( timer_info, 0, sizeof( TIMER_INFO ) );
	}
}
