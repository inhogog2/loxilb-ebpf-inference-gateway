/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_hdr_deadline.h — the listener header-completion deadline.
 *
 * Every L7 listener bounds how long a client may take to finish sending
 * request headers (the slowloris guard). The rule field timeout_tcp_inspect_ms
 * sets that bound; a rule that sets nothing, or sets 0, gets the product
 * default. There is NO value that disables the deadline: 0 is "default",
 * not "off", and the swagger description says so. This header holds the one
 * resolution rule so the proxy and its unit agree on it, and so a comment
 * elsewhere cannot quietly promise a disable switch the code never had.
 *
 * Deliberately free of project includes so a unit can exercise it without the
 * proxy object graph.
 */
#ifndef __SOCKPROXY_HDR_DEADLINE_H__
#define __SOCKPROXY_HDR_DEADLINE_H__

#include <stdint.h>

/* Header-completion deadline (ms) for every listener whose rule sets no
 * timeout_tcp_inspect_ms. 10 s mirrors a conservative HAProxy `timeout
 * http-request`: long enough not to trip legitimate slow clients, short
 * enough to bound a slowloris hold. */
#ifndef L7_TCP_INSPECT_DEFAULT_MS
#define L7_TCP_INSPECT_DEFAULT_MS 10000
#endif

/* The deadline a listener enforces, from the value its rule configured.
 * 0 (unset) resolves to the default; any positive value is used as given. */
static inline uint32_t
sp_hdr_deadline_resolve_ms(uint32_t configured_ms)
{
  return configured_ms > 0 ? configured_ms : L7_TCP_INSPECT_DEFAULT_MS;
}

/* One connection's header-completion clock. It is armed when a request's
 * header block begins and disarmed when the block completes, so it measures
 * header blocks only: never a connection's age, a request in flight or the
 * idle time between requests.
 *
 * The connection's worker arms and disarms it; the 1 Hz health pass reads it
 * from another thread, and a connection shell is reused by the next
 * connection on the same fd. So a start is published, not just written: the
 * start and the connection generation it belongs to are stored first, the
 * armed flag last with release; the reader takes the flag with acquire
 * before it reads them. A reader that sees the flag sees the start that
 * goes with it, never the previous block's or the previous connection's;
 * the generation is likewise released after the start and acquired before
 * it, so a flag left by an earlier arm cannot pair a new generation with an
 * old start.
 * And the reader charges a start only to the generation that wrote it,
 * read before and after: a shell that changed hands meanwhile is skipped. */
typedef struct sp_hdr_clock {
  int64_t start;   /* time() the block began; meaningful only while armed */
  uint64_t gen;    /* the connection generation that armed it */
  int32_t stream;  /* HTTP/2: the stream whose header block armed it */
  uint8_t armed;
} sp_hdr_clock_t;

/* Test seams: a unit runs the reader between the writer's stores, runs a
 * whole new arm between the reader's two data loads, or changes the
 * generation between the reader's two generation reads. Empty otherwise. */
#ifndef SP_HDR_PUBLISH_HOOK
#define SP_HDR_PUBLISH_HOOK(c) do { } while (0)
#endif
#ifndef SP_HDR_READ_HOOK
#define SP_HDR_READ_HOOK(c) do { } while (0)
#endif
#ifndef SP_HDR_PAIR_HOOK
#define SP_HDR_PAIR_HOOK(c) do { } while (0)
#endif

static inline void
sp_hdr_arm(sp_hdr_clock_t *c, int64_t now, uint64_t gen, int32_t stream)
{
  __atomic_store_n(&c->start, now, __ATOMIC_RELAXED);
  __atomic_store_n(&c->stream, stream, __ATOMIC_RELAXED);
  /* The generation is released after the start it vouches for, so a
   * reader that acquires it reads that start or a later one. */
  __atomic_store_n(&c->gen, gen, __ATOMIC_RELEASE);
  SP_HDR_PUBLISH_HOOK(c);
  __atomic_store_n(&c->armed, 1, __ATOMIC_RELEASE);
}

static inline void
sp_hdr_disarm(sp_hdr_clock_t *c)
{
  __atomic_store_n(&c->armed, 0, __ATOMIC_RELEASE);
}

static inline int
sp_hdr_armed(const sp_hdr_clock_t *c)
{
  return __atomic_load_n(&c->armed, __ATOMIC_ACQUIRE);
}

/* Seconds the armed header block has been open on the connection whose
 * generation is *conn_gen, or -1 when none is armed or the clock is not that
 * connection's (armed by an earlier one, or the shell changed hands while
 * it was read). */
static inline int64_t
sp_hdr_age(const sp_hdr_clock_t *c, const uint64_t *conn_gen, int64_t now)
{
  uint64_t g0, g1, armed_gen;
  int64_t start;

  g0 = __atomic_load_n(conn_gen, __ATOMIC_ACQUIRE);
  if (!__atomic_load_n(&c->armed, __ATOMIC_ACQUIRE))
    return -1;
  /* The generation before the start: a flag seen from an earlier arm can
   * then only pair with that arm's generation (no match) or with a start no
   * older than the generation read. */
  armed_gen = __atomic_load_n(&c->gen, __ATOMIC_ACQUIRE);
  SP_HDR_PAIR_HOOK(c);
  start = __atomic_load_n(&c->start, __ATOMIC_RELAXED);
  SP_HDR_READ_HOOK(c);
  __atomic_thread_fence(__ATOMIC_ACQUIRE);
  g1 = __atomic_load_n(conn_gen, __ATOMIC_RELAXED);
  if (g1 != g0 || armed_gen != g0)
    return -1;
  return now > start ? now - start : 0;
}

/* True once the armed block has been open longer than deadline_ms, which is
 * rounded up to whole seconds, the resolution of the clock. *age is the
 * block's age, or -1 when nothing of this connection's is armed. */
static inline int
sp_hdr_expired(const sp_hdr_clock_t *c, const uint64_t *conn_gen, int64_t now,
               uint32_t deadline_ms, int64_t *age)
{
  int64_t a = sp_hdr_age(c, conn_gen, now);

  if (age)
    *age = a;
  return deadline_ms > 0 && a >= 0 && a > (int64_t)((deadline_ms + 999) / 1000);
}

#endif /* __SOCKPROXY_HDR_DEADLINE_H__ */
