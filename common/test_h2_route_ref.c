/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_route_ref.c - an HTTP/2 stream holds the pool it was routed to
 * (stream->route_epv) until the stream is freed.
 *
 * pfe->epv of an HTTP/2 connection moves to the pool of its latest stream,
 * while the settle of an earlier stream still reads that stream's own pool
 * when it ends. So the stream keeps a reference of its own, and the stream
 * free gives it back. This drives the REAL free, out of sockproxy_h2.c,
 * through proxy_h2_cleanup_session: a deleted pool held only by a stream
 * stays allocated, and the session teardown frees it (the mutation twin in
 * wp8/twins-wp8.sh removes the release and must turn this red).
 *
 * Build: make test_h2rref (ASan + UBSan).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_h2.h"
#include "sockproxy_pool.h"
#include "sockproxy_qsbr.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("  (%s:%d)\n", __FILE__, __LINE__);                     \
    }                                                                \
  } while (0)

/* Reached only from a backend session's load release, which this test never
 * creates; sockproxy_lb.c is not linked. */
void
chwbl_dec_runtime(proxy_epval_t *epv, int ep_idx)
{
  (void)epv;
  (void)ep_idx;
}

static void
no_final(proxy_epval_t *p)
{
  (void)p;
}

static uint64_t
live(void)
{
  uint64_t l;

  sp_pool_counts(&l, NULL);
  return l;
}

static void
drain(void)
{
  for (int i = 0; i < 16 && sp_qsbr_pending(); i++)
    sp_qsbr_run_ready();
}

int
main(void)
{
  proxy_map_ent_t ent = { 0 };
  proxy_fd_ent_t *pfe = calloc(1, sizeof(*pfe));
  proxy_h2_session_t *sess = calloc(1, sizeof(*sess));
  proxy_h2_stream_t *st = calloc(1, sizeof(*st));
  proxy_epval_t *a, *b;
  uint64_t base;

  setvbuf(stdout, NULL, _IONBF, 0);
  assert(pfe && sess && st);
  sp_pool_init(no_final);
  fc_set_owner_hooks(sp_pool_fc_hold, sp_pool_fc_drop);
  base = live();

  /* Two pools on one listener, the product's add. */
  a = sp_pool_alloc();
  b = sp_pool_alloc();
  assert(a && b);
  snprintf(a->ephash_key, sizeof(a->ephash_key), "a.example");
  snprintf(b->ephash_key, sizeof(b->ephash_key), "b.example");
  HASH_ADD_KEYPTR(hh, ent.val.ephash, a->ephash_key, strlen(a->ephash_key), a);
  HASH_ADD_KEYPTR(hh, ent.val.ephash, b->ephash_key, strlen(b->ephash_key), b);
  assert(sp_pool_index_publish(&ent) == 0);

  /* Stream 1 routed to A, then stream 3 to B: the connection's epv moves
   * to B, as the routing step does it (sockproxy_h2.c, the forward). */
  pfe->h2_session = sess;
  pfe->protocol_version = 2;
  st->stream_id = 1;
  sp_pool_hold(&pfe->epv, a);
  sp_pool_hold(&st->route_epv, a);
  HASH_ADD_INT(sess->streams, stream_id, st);
  sess->active_stream_count = 1;
  sp_pool_hold(&pfe->epv, b);

  /* A's rule is deleted. */
  HASH_DEL(ent.val.ephash, a);
  assert(sp_pool_index_publish(&ent) == 0);
  sp_pool_unlinked(a);
  drain();
  CHECK(live() == base + 2, "a deleted pool held only by a stream stays allocated");
  CHECK(sp_pool_refs(a) == 1, "the stream is its only holder (%u)", sp_pool_refs(a));

  /* The session ends: every stream goes through the real stream free. */
  proxy_h2_cleanup_session(pfe);
  drain();
  CHECK(live() == base + 1, "the stream free gives its pool back and the pool is freed");

  sp_pool_release_conn(pfe);
  HASH_DEL(ent.val.ephash, b);
  assert(sp_pool_index_publish(&ent) == 0);
  sp_pool_unlinked(b);
  drain();
  CHECK(live() == base, "and the connection's own pool goes with the connection");
  free(pfe);

  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
