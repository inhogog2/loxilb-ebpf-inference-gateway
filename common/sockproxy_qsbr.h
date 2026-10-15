/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_QSBR_H__
#define __SOCKPROXY_QSBR_H__

/*
 * Grace periods for memory the notify workers read without a lock.
 *
 * A notify worker is a reader between two quiescent points: the return of
 * its epoll_wait and the next call to it. While it waits it is offline and
 * reads nothing. Memory a writer has unlinked (under the proxy lock) may
 * still be in use by a worker that found it earlier in its current loop
 * iteration; it is freed only once every worker has been offline, or has
 * come round its loop, since the unlink. That is the grace period.
 *
 * The rule a worker keeps: it never carries a pointer to such memory across
 * its quiescent point unless it holds a reference counted by the memory's
 * owner (sockproxy_pool.h for the pools).
 *
 * Only notify workers are readers. Any other thread reaches the same memory
 * under the proxy lock, which the work run after a grace period takes when
 * it needs to exclude such a thread.
 */

#include <stdint.h>

/* One slot per notify thread: the relay shards and the listener shard. */
#define SP_QSBR_MAX_THREADS 64

typedef struct sp_qsbr_work {
  struct sp_qsbr_work *next;
  uint64_t epoch;                      /* the grace period this work waits for */
  void (*fn)(struct sp_qsbr_work *w);
} sp_qsbr_work_t;

/* Reader side, called by a notify worker on its own thread. A thread that
 * never registers, or has unregistered, is offline: it holds back no grace
 * period. */
void sp_qsbr_register(int slot);
void sp_qsbr_unregister(void);
void sp_qsbr_offline(void);
void sp_qsbr_online(void);

/* Run fn(w) on the reclaimer thread, with no lock held, after a grace period
 * that starts now. Never blocks and never runs fn inline, so it may be called
 * under any lock and on any thread. w is the caller's and must stay valid
 * until fn runs. */
void sp_qsbr_defer(sp_qsbr_work_t *w, void (*fn)(sp_qsbr_work_t *w));

/* Run the deferred work whose grace period is over, in the order it was
 * deferred. Returns how many items are still waiting. The reclaimer calls
 * it; a test may call it directly instead of starting the reclaimer. */
int sp_qsbr_run_ready(void);

/* The reclaimer thread: started once with the notify workers. */
int sp_qsbr_start(void);

/* Items deferred and not yet run. */
uint64_t sp_qsbr_pending(void);

#endif
