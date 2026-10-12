/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_CACHE_MARK_H__
#define __SOCKPROXY_CACHE_MARK_H__

#include <stddef.h>

/*
 * sockproxy_cache_mark.h - which backpressure mark a relay cache runs under.
 *
 * Two facts about the proxy meet here:
 *
 *   1. The chunked flag (is_chunked_response) is written on the leg whose
 *      headers carried "Transfer-Encoding: chunked" -- the BACKEND leg, by
 *      the P7 design, so that header rewriting skips chunked bodies and the
 *      request path is never affected.
 *   2. The relay cache for a response lives on the PEER that receives the
 *      bytes -- the CLIENT leg (proxy_add_xmitcache(rfd_ent, ...)).
 *
 * A mark selected from the cached entry's own flag therefore never sees the
 * chunked case on the response path: the client's flag is never written, and
 * every SSE / chunked response has been running under the 12 MiB binary mark
 * instead of the 768 KiB one the comment next to the thresholds promises.
 * The stalled-client guard (LLB_SSE_STALL_ABORT_SEC) arms on that mark, so
 * it could not arm below 12 MiB of unread stream.
 *
 * Resolve the mark over the entry AND its legs. The flag itself stays where
 * P7 put it; only the lookup changes.
 *
 * Requires proxy_fd_ent_t (fields is_chunked_response, rfd_ent[], n_rfd) and
 * MAX_PROXY_EP to be in scope before inclusion -- the production struct from
 * sockproxy.h, or a test's mirror of those fields.
 */

/*
 * ADAPTIVE BACKPRESSURE: Different thresholds for chunked vs non-chunked.
 * Chunked encoding (text/JS/CSS/SSE): lower threshold to prevent SSL timeout
 * and to bound what a non-reading client can pin per connection.
 * Binary transfers (images/videos): higher threshold for performance.
 */
#define PROXY_CACHE_HIGH_WATER_CHUNKED (768 * 1024)       /* 768KB for chunked */
#define PROXY_CACHE_LOW_WATER_CHUNKED  (384 * 1024)       /* 384KB resume */
#define PROXY_CACHE_HIGH_WATER         (12 * 1024 * 1024) /* 12MB binary */
#define PROXY_CACHE_LOW_WATER          (4 * 1024 * 1024)  /* 4MB resume */

/* 1 if the entry, or any leg it relays with, carries a chunked response.
 * The leg pointers are read with an acquire load, as the health pass does
 * (sp_reap_client_chunked): a leg may be unlinked by a teardown on another
 * worker while this entry is still caching. */
static inline int
proxy_cache_chunked(proxy_fd_ent_t *ent)
{
  int i, n;

  if (ent->is_chunked_response) {
    return 1;
  }
  n = ent->n_rfd;
  if (n > MAX_PROXY_EP) {
    n = MAX_PROXY_EP;
  }
  for (i = 0; i < n; i++) {
    proxy_fd_ent_t *leg = __atomic_load_n(&ent->rfd_ent[i], __ATOMIC_ACQUIRE);
    if (leg && leg->is_chunked_response) {
      return 1;
    }
  }
  return 0;
}

/* The marks the entry runs under; returns the chunked verdict so the caller
 * can log it. Either output may be NULL. Both cache sites use this, so a
 * cache that armed at the chunked mark also releases at the chunked mark. */
static inline int
proxy_cache_marks(proxy_fd_ent_t *ent, size_t *high, size_t *low)
{
  int chunked = proxy_cache_chunked(ent);

  if (high) {
    *high = chunked ? (size_t)PROXY_CACHE_HIGH_WATER_CHUNKED
                    : (size_t)PROXY_CACHE_HIGH_WATER;
  }
  if (low) {
    *low = chunked ? (size_t)PROXY_CACHE_LOW_WATER_CHUNKED
                   : (size_t)PROXY_CACHE_LOW_WATER;
  }
  return chunked;
}

#endif /* __SOCKPROXY_CACHE_MARK_H__ */
