/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * sockproxy_pool.c - the lifetime of a pool and the index the notify workers
 * read a listener's pools through (sockproxy_pool.h).
 */
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uthash.h"             /* MUST precede sockproxy.h */
#include "log.h"
#include "sockproxy.h"
#include "sockproxy_pool.h"

typedef struct sp_pool_hdr {
  _Atomic uint32_t refs;
  uint8_t uncounted;                   /* the L7 scratch pool */
  _Atomic uint8_t queued;              /* work is waiting on the reclaimer */
  uint64_t born_ms;
  sp_qsbr_work_t work;
} __attribute__((aligned(64))) sp_pool_hdr_t;

_Static_assert(sizeof(sp_pool_hdr_t) % 64 == 0, "the pool body keeps 64-byte alignment");

static _Atomic uint64_t pools_live;
static _Atomic uint64_t pools_freed;
static void (*pool_finalizer)(proxy_epval_t *p);

static inline sp_pool_hdr_t *
pool_hdr(const proxy_epval_t *p)
{
  return (sp_pool_hdr_t *)((char *)p - sizeof(sp_pool_hdr_t));
}

static inline proxy_epval_t *
pool_body(sp_pool_hdr_t *h)
{
  return (proxy_epval_t *)((char *)h + sizeof(sp_pool_hdr_t));
}

static uint64_t
pool_now_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static proxy_epval_t *
pool_alloc(int uncounted)
{
  size_t sz = sizeof(sp_pool_hdr_t) + sizeof(proxy_epval_t);
  sp_pool_hdr_t *h;

  sz = (sz + 63) & ~(size_t)63;
  h = aligned_alloc(64, sz);
  if (!h)
    return NULL;
  memset(h, 0, sz);
  h->uncounted = (uint8_t)uncounted;
  h->born_ms = pool_now_ms();
  atomic_init(&h->refs, uncounted ? 0 : 1);
  if (!uncounted)
    atomic_fetch_add_explicit(&pools_live, 1, memory_order_relaxed);
  return pool_body(h);
}

proxy_epval_t *
sp_pool_alloc(void)
{
  return pool_alloc(0);
}

proxy_epval_t *
sp_pool_alloc_uncounted(void)
{
  return pool_alloc(1);
}

void
sp_pool_free_uncounted(proxy_epval_t *p)
{
  if (p && pool_hdr(p)->uncounted)
    free(pool_hdr(p));
}

/* A capacity permit points into its pool (&pool->fc): it holds the pool. */
static proxy_epval_t *
pool_of_fc(fc_state_t *fc)
{
  return (proxy_epval_t *)((char *)fc - offsetof(proxy_epval_t, fc));
}

void
sp_pool_fc_hold(fc_state_t *fc)
{
  sp_pool_get(pool_of_fc(fc));
}

void
sp_pool_fc_drop(fc_state_t *fc)
{
  sp_pool_put(pool_of_fc(fc));
}

void
sp_pool_init(void (*fn)(proxy_epval_t *p))
{
  pool_finalizer = fn;
}

void
sp_pool_discard(proxy_epval_t *p)
{
  if (!p || pool_hdr(p)->uncounted)
    return;
  free(pool_hdr(p));
  atomic_fetch_sub_explicit(&pools_live, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&pools_freed, 1, memory_order_relaxed);
}

static void
pool_final_free(sp_qsbr_work_t *w)
{
  sp_pool_hdr_t *h = (sp_pool_hdr_t *)((char *)w - offsetof(sp_pool_hdr_t, work));
  proxy_epval_t *p = pool_body(h);

  atomic_store_explicit(&h->queued, 0, memory_order_relaxed);
  if (atomic_load_explicit(&h->refs, memory_order_acquire) != 0) {
    /* A count back above zero is a get on a pool nobody could reach: a
     * holder that took its reference without one. Keep the memory. */
    log_error("[POOL] %s: reference taken after the last release (refs=%u): not freed",
              p->ephash_key, atomic_load_explicit(&h->refs, memory_order_relaxed));
    return;
  }
  if (pool_finalizer)
    pool_finalizer(p);
  log_info("[POOL] freed %s after %llu ms", p->ephash_key,
           (unsigned long long)(pool_now_ms() - h->born_ms));
  free(h);
  atomic_fetch_sub_explicit(&pools_live, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&pools_freed, 1, memory_order_relaxed);
}

static void
pool_queue(sp_pool_hdr_t *h, void (*fn)(sp_qsbr_work_t *w))
{
  if (atomic_exchange_explicit(&h->queued, 1, memory_order_acq_rel)) {
    log_error("[POOL] %s queued twice: refused", pool_body(h)->ephash_key);
    return;
  }
  sp_qsbr_defer(&h->work, fn);
}

void
sp_pool_get(proxy_epval_t *p)
{
  if (!p || pool_hdr(p)->uncounted)
    return;
  atomic_fetch_add_explicit(&pool_hdr(p)->refs, 1, memory_order_relaxed);
}

void
sp_pool_put(proxy_epval_t *p)
{
  sp_pool_hdr_t *h;
  uint32_t was;

  if (!p)
    return;
  h = pool_hdr(p);
  if (h->uncounted)
    return;
  was = atomic_fetch_sub_explicit(&h->refs, 1, memory_order_acq_rel);
  if (was == 1) {
    pool_queue(h, pool_final_free);
  } else if (was == 0) {
    atomic_fetch_add_explicit(&h->refs, 1, memory_order_relaxed);
    log_error("[POOL] %s: release without a reference: ignored", p->ephash_key);
  }
}

void
sp_pool_hold(void **holder, proxy_epval_t *p)
{
  proxy_epval_t *old = *holder;

  if (old == p)
    return;
  sp_pool_get(p);
  *holder = p;
  sp_pool_put(old);
}

void
sp_pool_release_conn(proxy_fd_ent_t *pfe)
{
  sp_pool_hold(&pfe->epv, NULL);
  sp_pool_hold(&pfe->learn_epv, NULL);
  fc_permit_unbind(&pfe->fc);
}

static void
pool_table_drop(sp_qsbr_work_t *w)
{
  sp_pool_hdr_t *h = (sp_pool_hdr_t *)((char *)w - offsetof(sp_pool_hdr_t, work));

  atomic_store_explicit(&h->queued, 0, memory_order_relaxed);
  sp_pool_put(pool_body(h));
}

void
sp_pool_unlinked(proxy_epval_t *p)
{
  if (!p || pool_hdr(p)->uncounted)
    return;
  pool_queue(pool_hdr(p), pool_table_drop);
}

uint32_t
sp_pool_refs(const proxy_epval_t *p)
{
  if (!p)
    return 0;
  return atomic_load_explicit(&pool_hdr(p)->refs, memory_order_relaxed);
}

void
sp_pool_counts(uint64_t *live, uint64_t *freed)
{
  if (live)
    *live = atomic_load_explicit(&pools_live, memory_order_relaxed);
  if (freed)
    *freed = atomic_load_explicit(&pools_freed, memory_order_relaxed);
}

/* FNV-1a. */
static uint32_t
index_hash(const char *s)
{
  uint32_t h = 2166136261u;

  while (*s) {
    h ^= (uint8_t)*s++;
    h *= 16777619u;
  }
  return h;
}

static void
index_free(sp_qsbr_work_t *w)
{
  free((char *)w - offsetof(sp_pool_index_t, work));
}

int
sp_pool_index_publish(proxy_map_ent_t *ent)
{
  sp_pool_index_t *ix = NULL, *old;
  proxy_epval_t *p;
  uint32_t n = 0, cap = 4;

  for (p = ent->val.ephash; p; p = p->hh.next)
    n++;
  if (n) {
    while (cap < 2 * n)
      cap <<= 1;
    ix = calloc(1, sizeof(*ix) + n * sizeof(*ix->order) + cap * sizeof(*ix->slot));
    if (!ix) {
      log_error("[POOL] index of %u pools: out of memory, the old index stays", n);
      return -1;
    }
    ix->order = (proxy_epval_t **)(ix + 1);
    ix->slot = (struct sp_pool_index_slot *)(ix->order + n);
    ix->mask = cap - 1;
    for (p = ent->val.ephash; p; p = p->hh.next) {
      uint32_t h = index_hash(p->ephash_key);
      uint32_t i = h & ix->mask;

      while (ix->slot[i].ep)
        i = (i + 1) & ix->mask;
      ix->slot[i].h = h;
      ix->slot[i].ep = p;
      ix->order[ix->n++] = p;
    }
    ix->first = ix->order[0];
  }
  old = atomic_exchange_explicit(&ent->val.pools, ix, memory_order_acq_rel);
  if (old)
    sp_qsbr_defer(&old->work, index_free);
  return 0;
}

const sp_pool_index_t *
sp_pool_index(const proxy_map_ent_t *ent)
{
  if (!ent)
    return NULL;
  return atomic_load_explicit(&((proxy_map_ent_t *)ent)->val.pools, memory_order_acquire);
}

proxy_epval_t *
sp_pool_index_find(const sp_pool_index_t *ix, const char *key)
{
  uint32_t h, i;

  if (!ix || !key)
    return NULL;
  h = index_hash(key);
  for (i = h & ix->mask; ix->slot[i].ep; i = (i + 1) & ix->mask) {
    if (ix->slot[i].h == h && strcmp(ix->slot[i].ep->ephash_key, key) == 0)
      return ix->slot[i].ep;
  }
  return NULL;
}

proxy_epval_t *
sp_pool_first(const proxy_map_ent_t *ent)
{
  const sp_pool_index_t *ix = sp_pool_index(ent);

  return ix ? ix->first : NULL;
}

proxy_epval_t *
sp_pool_find(const proxy_map_ent_t *ent, const char *key)
{
  return sp_pool_index_find(sp_pool_index(ent), key);
}
