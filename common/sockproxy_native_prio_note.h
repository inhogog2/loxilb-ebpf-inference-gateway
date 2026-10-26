/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * The operator's view of a neutralised client-supplied engine priority
 * (sockproxy_native_prio.h): one info line per service, rate-limited, so the
 * clients that send one are seen without a line per request. The includer
 * provides log_info, get_timestamp_ns and fc_state_t (sockproxy_fc.h); the
 * proxy's two request paths include it, no unit does.
 */
#ifndef __SOCKPROXY_NATIVE_PRIO_NOTE_H__
#define __SOCKPROXY_NATIVE_PRIO_NOTE_H__

#include <stdatomic.h>
#include <stdint.h>

#define SP_NATIVE_PRIO_NOTE_NS 10000000000ULL   /* one line per service per 10 s */

/* `fc` is the pool's admission state, where the limiter lives; NULL logs
 * nothing. Two threads past the window: one writes the stamp and logs. */
static inline void
sp_native_prio_note(fc_state_t *fc, const char *svc, int in_header, int in_body)
{
  uint64_t now, last;

  if (!fc || (!in_header && !in_body))
    return;
  now = get_timestamp_ns();
  last = atomic_load_explicit(&fc->native_prio_note_ns, memory_order_relaxed);
  if (last && now - last < SP_NATIVE_PRIO_NOTE_NS)
    return;
  if (!atomic_compare_exchange_strong_explicit(&fc->native_prio_note_ns, &last,
                                               now, memory_order_relaxed,
                                               memory_order_relaxed))
    return;
  log_info("[AIGateway] %s: a client-supplied engine priority (%s) was "
           "neutralised; the tenant band decides the order (one line per "
           "service per %llu s)",
           svc ? svc : "?",
           in_header && in_body ? "X-Vllm-Priority header and body priority" :
           in_header ? "X-Vllm-Priority header" : "body priority",
           (unsigned long long)(SP_NATIVE_PRIO_NOTE_NS / 1000000000ULL));
}

#endif /* __SOCKPROXY_NATIVE_PRIO_NOTE_H__ */
