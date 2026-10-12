/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause)
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_abandon.h — streams that end before their terminator, and the
 * stalled-client policy.
 *
 * A streamed inference ends in one of two ways: the engine's terminator
 * ("data: [DONE]" or the chunked end) reaches the client, or the connection
 * is torn down with the stream still open. The second case is where GPU
 * time is at stake:
 *
 *   client_gone   the client closed or reset mid-stream. The teardown shuts
 *                 the backend leg in the same pass, the engine sees EOF and
 *                 aborts the request (vLLM, SGLang and TensorRT-LLM all do),
 *                 so the waste is bounded by that propagation — which this
 *                 module makes visible rather than assumed.
 *   backend_died  the engine leg ended first; the client is answered with an
 *                 error or a synthesized terminator by the paths that count
 *                 it (pd_decode_ep_died, the reaper). Recorded here so the
 *                 three reasons add up to every unfinished stream.
 *   stall_abort   the client is alive but not reading: its relay cache sat
 *                 at the high-water mark for LLB_SSE_STALL_ABORT_SEC, so the
 *                 gateway ended the stream itself. Default off (0). While a
 *                 client stalls, backpressure pauses the backend reads, the
 *                 engine's own send buffer fills and the engine keeps
 *                 generating into memory until max_tokens: the stream's
 *                 remaining tokens are GPU work nobody will read. The abort
 *                 bounds that at the knob's value.
 *
 * Per reason: a counter and a histogram of the stream's age at the end
 * (seconds since the stream was activated), so an operator sees both how
 * often streams are abandoned and how deep into generation it happens.
 *
 * Pure header: integers and the stats block in, integers out, no proxy
 * object graph, so test_abandon.c runs it without a link library. The
 * recorder is the same cumulative-le-bucket shape as record_latency_sample.
 */
#ifndef __SOCKPROXY_ABANDON_H__
#define __SOCKPROXY_ABANDON_H__

#include <stdint.h>
#include <stdatomic.h>
#include <sys/socket.h>

enum abandon_reason {
  ABANDON_CLIENT_GONE = 0,
  ABANDON_BACKEND_DIED,
  ABANDON_STALL_ABORT,
  ABANDON_REASONS
};

#define ABANDON_N_BUCKETS 12

/* Age-at-end bucket upper bounds in SECONDS (must match kvAbandonAgeBounds in
 * api/prometheus/stream_abandon_metrics.go). */
static const uint64_t abandon_age_bounds_s[ABANDON_N_BUCKETS] = {
  1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 1800, 3600
};

typedef struct abandon_stats {
  _Atomic uint64_t total[ABANDON_REASONS];
  _Atomic uint64_t age_bucket[ABANDON_REASONS][ABANDON_N_BUCKETS];
  _Atomic uint64_t age_sum_s[ABANDON_REASONS];
  _Atomic uint64_t age_count[ABANDON_REASONS];
} abandon_stats_t;

/* Record one unfinished stream: its reason and its age in seconds. An
 * out-of-range reason is a no-op; a negative age (clock went backwards)
 * records as 0 so the count still matches the total. */
static inline void
abandon_record(abandon_stats_t *st, int reason, long age_s)
{
  uint64_t age;

  if (!st || reason < 0 || reason >= ABANDON_REASONS) {
    return;
  }
  age = age_s < 0 ? 0 : (uint64_t)age_s;
  atomic_fetch_add(&st->total[reason], 1);
  for (int i = 0; i < ABANDON_N_BUCKETS; i++) {
    if (age <= abandon_age_bounds_s[i]) {
      atomic_fetch_add(&st->age_bucket[reason][i], 1);
    }
  }
  atomic_fetch_add(&st->age_sum_s[reason], age);
  atomic_fetch_add(&st->age_count[reason], 1);
}

/* The stalled-client decision, taken once per health tick for a stream that
 * is active and not yet ended. `backpressure` is the connection's relay-cache
 * flag (set when the cache reached the high-water mark and the client has
 * not drained it since), `bp_since` the tick the stall was first seen (0 =
 * not stalled), `now` the current tick, `stall_sec` the knob (0 = off).
 * Returns the new bp_since and sets *abort when the stall has lasted the
 * knob's value. A stall is measured from the first tick that saw it, so the
 * abort lands between stall_sec and stall_sec+1 seconds in. */
static inline long
abandon_stall_tick(int backpressure, long bp_since, long now, long stall_sec, int *abort)
{
  *abort = 0;
  if (!backpressure) {
    return 0;                 /* draining again (or never stalled): disarm */
  }
  if (bp_since == 0) {
    return now;               /* first sight: arm */
  }
  if (stall_sec > 0 && now - bp_since >= stall_sec) {
    *abort = 1;
  }
  return bp_since;
}

/* Whether a backend leg being let go must be reset rather than closed in
 * order. A leg whose reads were paused when its client's teardown releases
 * it still holds response bytes that now have no reader, and the engine has
 * more queued behind the zero window those bytes left. The orderly close
 * that follows reads them out and sends only a FIN: the window is not
 * reopened on a socket whose read side is shut, so the engine can neither
 * send nor learn that its peer is gone, and it generates to the end of the
 * request. `releaser_odir` is the direction of the entry doing the release
 * (0 = a client), `leg_odir` the leg's (1 = a backend), `leg_read_paused`
 * the leg's flag as it stands BEFORE the release clears it. */
static inline int
abandon_leg_wants_reset(int releaser_odir, int leg_odir, int leg_read_paused)
{
  return releaser_odir == 0 && leg_odir == 1 && leg_read_paused != 0;
}

/* Make the eventual close of `fd` a reset, whatever is read from it or shut
 * on it in between. The owner's ordinary teardown still does the close. */
static inline int
abandon_leg_arm_reset(int fd)
{
  struct linger lg = { .l_onoff = 1, .l_linger = 0 };

  if (fd <= 0) {
    return -1;
  }
  return setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
}

#endif /* __SOCKPROXY_ABANDON_H__ */
