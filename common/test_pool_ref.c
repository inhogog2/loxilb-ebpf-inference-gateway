/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_pool_ref.c - the lifetime of a pool (sockproxy_pool.h) and the grace
 * period it is freed after (sockproxy_qsbr.h).
 *
 *   - a deleted pool with no holder is freed, once, after a grace period;
 *   - every holder kind keeps a deleted pool until it lets go, and each of
 *     its releases is needed for the pool to be freed (the mutation twins in
 *     wp8/twins-wp8.sh remove them one at a time and must turn this red);
 *   - a holder overwritten, a permit rebound, give the old pool back; the
 *     same pool twice changes nothing;
 *   - two threads that unbind one permit at the same instant (the queue
 *     drain and the owner's teardown) drop its reference once;
 *   - the L7 scratch pool is never counted, and copying a pool's body into it
 *     touches no count;
 *   - the index answers what the table holds after every publish;
 *   - a worker that found a pool before its delete may still take its
 *     reference in the same loop iteration: the count never reads zero in
 *     that window and the pool is not freed under it (ASan);
 *   - a worker idle in its wait, a worker whose wait returns at once, and a
 *     worker that has exited hold back no grace period: a delete is freed
 *     within a bound.
 *
 * Build: make test_poolref (ASan + UBSan, then the same under TSan).
 */
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "uthash.h"
#include "sockproxy.h"
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

static _Atomic int finalized;

static void
count_final(proxy_epval_t *p)
{
  (void)p;
  atomic_fetch_add(&finalized, 1);
}

static uint64_t
live(void)
{
  uint64_t l;

  sp_pool_counts(&l, NULL);
  return l;
}

/* Run the deferred work on this thread: no reader is registered in the
 * single-threaded tests, so every grace period is already over. */
static void
drain(void)
{
  for (int i = 0; i < 16 && sp_qsbr_pending(); i++)
    sp_qsbr_run_ready();
}

static uint64_t
now_ms(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Wait until the live count is back at base; the time it took, or -1. */
static long
wait_live(uint64_t base, long bound_ms)
{
  uint64_t t0 = now_ms();

  while ((long)(now_ms() - t0) <= bound_ms) {
    if (live() == base)
      return (long)(now_ms() - t0);
    usleep(1000);
  }
  return -1;
}

/* The product's add and delete, as far as the pool's lifetime goes. */
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

static proxy_epval_t *
add_pool(proxy_map_ent_t *ent, const char *key)
{
  proxy_epval_t *p = sp_pool_alloc();

  assert(p);
  snprintf(p->ephash_key, sizeof(p->ephash_key), "%s", key);
  pthread_mutex_lock(&table_lock);
  HASH_ADD_KEYPTR(hh, ent->val.ephash, p->ephash_key, strlen(p->ephash_key), p);
  assert(sp_pool_index_publish(ent) == 0);
  pthread_mutex_unlock(&table_lock);
  return p;
}

static void
del_pool(proxy_map_ent_t *ent, proxy_epval_t *p)
{
  pthread_mutex_lock(&table_lock);
  HASH_DEL(ent->val.ephash, p);
  assert(sp_pool_index_publish(ent) == 0);
  sp_pool_unlinked(p);
  pthread_mutex_unlock(&table_lock);
}

static void
test_delete_without_holders(void)
{
  proxy_map_ent_t ent = { 0 };
  uint64_t base = live();
  int f0 = atomic_load(&finalized);
  proxy_epval_t *p = add_pool(&ent, "a.example");

  CHECK(live() == base + 1, "a new pool is live");
  CHECK(sp_pool_refs(p) == 1, "the table holds the one reference");
  del_pool(&ent, p);
  CHECK(sp_pool_refs(p) == 1, "the table's reference outlives the unlink until a grace period");
  CHECK(sp_pool_find(&ent, "a.example") == NULL, "a deleted pool is no longer found");
  drain();
  CHECK(live() == base, "a deleted pool with no holder is freed");
  CHECK(atomic_load(&finalized) == f0 + 1, "its teardown ran once");
}

static void
test_connection_holds_across_delete(void)
{
  proxy_map_ent_t ent = { 0 };
  proxy_fd_ent_t *pfe = calloc(1, sizeof(*pfe));
  uint64_t base = live();
  proxy_epval_t *p = add_pool(&ent, "b.example");

  assert(pfe);
  sp_pool_hold(&pfe->epv, p);
  sp_pool_hold(&pfe->learn_epv, p);
  fc_bypass(&p->fc, &pfe->fc);
  CHECK(sp_pool_refs(p) == 4, "epv, learn_epv and the permit each hold the pool (4 = 3 + table)");
  del_pool(&ent, p);
  drain();
  CHECK(live() == base + 1, "a deleted pool its connection holds is kept");
  CHECK(sp_pool_refs(p) == 3, "only the table's reference went");
  sp_pool_release_conn(pfe);
  CHECK(pfe->epv == NULL && pfe->learn_epv == NULL && pfe->fc.fc == NULL,
        "the recycle clears the three holders");
  drain();
  CHECK(live() == base, "the recycle of the last holder frees the pool");
  free(pfe);
}

static void
test_each_holder_alone(void)
{
  /* One holder at a time: a release missing from any one of them keeps
   * its pool. */
  for (int kind = 0; kind < 3; kind++) {
    proxy_map_ent_t ent = { 0 };
    proxy_fd_ent_t *pfe = calloc(1, sizeof(*pfe));
    uint64_t base = live();
    proxy_epval_t *p = add_pool(&ent, "c.example");
    static const char *name[] = { "epv", "learn_epv", "permit" };

    assert(pfe);
    if (kind == 0)
      sp_pool_hold(&pfe->epv, p);
    else if (kind == 1)
      sp_pool_hold(&pfe->learn_epv, p);
    else
      fc_bypass(&p->fc, &pfe->fc);
    del_pool(&ent, p);
    drain();
    CHECK(live() == base + 1, "%s alone keeps a deleted pool", name[kind]);
    sp_pool_release_conn(pfe);
    drain();
    CHECK(live() == base, "%s's release frees it", name[kind]);
    free(pfe);
  }
}

static void
test_overwrite_and_rebind(void)
{
  proxy_map_ent_t ent = { 0 };
  void *slot = NULL;
  fc_permit_t permit;
  uint64_t base = live();
  proxy_epval_t *p1 = add_pool(&ent, "d1.example");
  proxy_epval_t *p2 = add_pool(&ent, "d2.example");

  memset(&permit, 0, sizeof(permit));
  sp_pool_hold(&slot, p1);
  sp_pool_hold(&slot, p2);
  CHECK(sp_pool_refs(p1) == 1 && sp_pool_refs(p2) == 2,
        "a holder overwritten gives the old pool back");
  sp_pool_hold(&slot, p2);
  CHECK(sp_pool_refs(p2) == 2, "the same pool twice changes nothing");
  sp_pool_hold(&slot, NULL);
  CHECK(sp_pool_refs(p2) == 1 && slot == NULL, "a holder cleared gives its pool back");

  fc_bypass(&p1->fc, &permit);
  fc_bypass(&p2->fc, &permit);
  CHECK(sp_pool_refs(p1) == 1 && sp_pool_refs(p2) == 2,
        "a permit rebound gives the old pool back");
  fc_bypass(&p2->fc, &permit);
  CHECK(sp_pool_refs(p2) == 2, "a permit rebound to its own pool keeps one reference");
  fc_permit_release(&permit);
  CHECK(sp_pool_refs(p2) == 2, "a released permit still holds: it is read after its release");
  fc_permit_init(&permit);
  CHECK(sp_pool_refs(p2) == 1 && permit.fc == NULL, "a permit reset gives its pool back");
  fc_permit_unbind(&permit);
  CHECK(sp_pool_refs(p2) == 1, "an unbound permit unbinds nothing more");

  del_pool(&ent, p1);
  del_pool(&ent, p2);
  drain();
  CHECK(live() == base, "both pools freed");
}

/* Two threads unbind one permit at the same instant. */
static fc_permit_t race_permit;
static _Atomic int race_go;

static void *
race_unbind(void *arg)
{
  (void)arg;
  while (!atomic_load_explicit(&race_go, memory_order_acquire))
    ;
  fc_permit_unbind(&race_permit);
  return NULL;
}

static void
test_unbind_once_across_threads(void)
{
  proxy_map_ent_t ent = { 0 };
  uint64_t base = live();
  proxy_epval_t *p = add_pool(&ent, "u.example");
  int i, n = 20000, bad = -1;

  for (i = 0; i < n; i++) {
    pthread_t a, b;

    memset(&race_permit, 0, sizeof(race_permit));
    fc_bypass(&p->fc, &race_permit);
    atomic_store(&race_go, 0);
    pthread_create(&a, NULL, race_unbind, NULL);
    pthread_create(&b, NULL, race_unbind, NULL);
    atomic_store_explicit(&race_go, 1, memory_order_release);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    if (sp_pool_refs(p) != 1) {
      bad = i;
      break;
    }
  }
  CHECK(bad < 0, "two unbinds of one permit drop one reference (%d rounds%s)",
        bad < 0 ? n : bad, bad < 0 ? "" : ", the count fell below its holders");
  if (bad >= 0)
    return;   /* the pool is already queued for its free: leave it */
  del_pool(&ent, p);
  drain();
  CHECK(live() == base, "and the pool is freed once");
}

/* The drain checker reads a connection's holder slot from its own thread
 * while the owner re-holds it. Under TSan a plain store into the slot is a
 * reported race: this test fails the TSan build when sp_pool_hold or the
 * reader stops using atomic accesses. */
static void *peek_slot;
static _Atomic int peek_stop;
static proxy_epval_t *peek_pools[2];

static void *
peek_reader(void *arg)
{
  long *odd = arg;

  while (!atomic_load_explicit(&peek_stop, memory_order_acquire)) {
    proxy_epval_t *seen = sp_pool_holder_peek(&peek_slot);

    if (seen && seen != peek_pools[0] && seen != peek_pools[1])
      (*odd)++;
  }
  return NULL;
}

static void
test_peek_across_threads(void)
{
  proxy_map_ent_t ent = { 0 };
  uint64_t base = live();
  pthread_t r;
  long odd = 0;
  int i;

  peek_pools[0] = add_pool(&ent, "k0.example");
  peek_pools[1] = add_pool(&ent, "k1.example");
  atomic_store(&peek_stop, 0);
  pthread_create(&r, NULL, peek_reader, &odd);
  for (i = 0; i < 200000; i++)
    sp_pool_hold(&peek_slot, i % 3 == 2 ? NULL : peek_pools[i & 1]);
  atomic_store_explicit(&peek_stop, 1, memory_order_release);
  pthread_join(r, NULL);
  CHECK(odd == 0, "a peek of a slot being re-held sees one of its pools or nothing (%ld odd)", odd);
  sp_pool_hold(&peek_slot, NULL);
  del_pool(&ent, peek_pools[0]);
  del_pool(&ent, peek_pools[1]);
  drain();
  CHECK(live() == base, "both pools freed after the peeks");
}

static void
test_scratch_is_not_counted(void)
{
  proxy_map_ent_t ent = { 0 };
  void *slot = NULL;
  fc_permit_t permit;
  uint64_t base = live();
  proxy_epval_t *p = add_pool(&ent, "e.example");
  proxy_epval_t *s = sp_pool_alloc_uncounted();

  assert(s);
  memset(&permit, 0, sizeof(permit));
  CHECK(live() == base + 1, "the scratch pool is not a live pool");
  sp_pool_hold(&slot, p);
  memcpy(s, p, sizeof(*s));   /* what l7_resolve_pool does on every FORWARD */
  CHECK(sp_pool_refs(p) == 2 && sp_pool_refs(s) == 0,
        "copying a pool's body into the scratch copies no count");
  sp_pool_hold(&slot, s);
  CHECK(sp_pool_refs(p) == 1 && sp_pool_refs(s) == 0, "the scratch as a holder's pool is not counted");
  fc_bypass(&s->fc, &permit);
  CHECK(sp_pool_refs(s) == 0, "a permit on the scratch counts nothing");
  fc_permit_init(&permit);
  sp_pool_hold(&slot, NULL);
  sp_pool_put(s);
  CHECK(sp_pool_refs(s) == 0, "a release of the scratch is ignored");
  sp_pool_free_uncounted(s);
  del_pool(&ent, p);
  drain();
  CHECK(live() == base, "the counted pool is freed; the scratch never was a live pool");
}

static void
test_index(void)
{
  proxy_map_ent_t ent = { 0 };
  uint64_t base = live();
  proxy_epval_t *a = add_pool(&ent, "f.example|/a");
  proxy_epval_t *b = add_pool(&ent, "f.example|/b");
  proxy_epval_t *c = add_pool(&ent, "f.example||model");
  const sp_pool_index_t *ix = sp_pool_index(&ent);

  CHECK(ix && ix->n == 3 && ix->order[0] == a && ix->order[2] == c,
        "the index holds the table's pools in insertion order");
  CHECK(sp_pool_first(&ent) == a, "the first pool is the table's head");
  CHECK(sp_pool_find(&ent, "f.example|/a") == a && sp_pool_find(&ent, "f.example|/b") == b &&
        sp_pool_find(&ent, "f.example||model") == c, "every key is found");
  CHECK(sp_pool_find(&ent, "f.example") == NULL && sp_pool_find(&ent, "") == NULL,
        "a key that is not there is not found");
  del_pool(&ent, b);
  CHECK(sp_pool_find(&ent, "f.example|/b") == NULL && sp_pool_find(&ent, "f.example||model") == c,
        "a deleted key goes, the others stay");
  del_pool(&ent, a);
  CHECK(sp_pool_first(&ent) == c, "deleting the head moves the first pool on");
  del_pool(&ent, c);
  CHECK(sp_pool_index(&ent) == NULL && sp_pool_first(&ent) == NULL, "no pool, no index");
  drain();
  CHECK(live() == base, "all freed");
}

/* ---- threads ------------------------------------------------------------ */

static proxy_map_ent_t thr_ent;
static _Atomic int stop_workers;

/* A worker that goes into its wait and stays there. */
static int idle_pipe[2];

static void *
idle_worker(void *arg)
{
  char c;

  sp_qsbr_register((int)(intptr_t)arg);
  sp_qsbr_offline();
  (void)read(idle_pipe[0], &c, 1);   /* the epoll_wait that never returns */
  sp_qsbr_online();
  sp_qsbr_unregister();
  return NULL;
}

/* A worker that keeps going round its loop. */
static void *
busy_worker(void *arg)
{
  sp_qsbr_register((int)(intptr_t)arg);
  while (!atomic_load(&stop_workers)) {
    sp_qsbr_offline();
    usleep(500);
    sp_qsbr_online();
  }
  sp_qsbr_unregister();
  return NULL;
}

/* A worker under load: its wait returns at once, so it is offline for
 * almost no time and the grace period must end on what it last saw. */
static void *
loaded_worker(void *arg)
{
  sp_qsbr_register((int)(intptr_t)arg);
  while (!atomic_load(&stop_workers)) {
    sp_qsbr_offline();
    sp_qsbr_online();
    usleep(500);                     /* the events it handles, online */
  }
  sp_qsbr_unregister();
  return NULL;
}

static void *
exiting_worker(void *arg)
{
  sp_qsbr_register((int)(intptr_t)arg);
  sp_qsbr_unregister();
  return NULL;
}

static void
test_idle_worker_does_not_hold_back_a_free(void)
{
  pthread_t idle, busy;
  uint64_t base = live();
  long took;

  assert(pipe(idle_pipe) == 0);
  atomic_store(&stop_workers, 0);
  pthread_create(&idle, NULL, idle_worker, (void *)(intptr_t)0);
  pthread_create(&busy, NULL, busy_worker, (void *)(intptr_t)1);
  usleep(20000);

  proxy_epval_t *p = add_pool(&thr_ent, "g.example");
  del_pool(&thr_ent, p);
  took = wait_live(base, 1000);
  CHECK(took >= 0 && took <= 200,
        "one worker idle in its wait, one going round: the deleted pool is freed in %ld ms (bound 200)",
        took);

  atomic_store(&stop_workers, 1);
  (void)write(idle_pipe[1], "x", 1);
  pthread_join(idle, NULL);
  pthread_join(busy, NULL);
  close(idle_pipe[0]);
  close(idle_pipe[1]);
}

static void
test_loaded_worker_does_not_hold_back_a_free(void)
{
  pthread_t w;
  uint64_t base = live();
  long took;

  atomic_store(&stop_workers, 0);
  pthread_create(&w, NULL, loaded_worker, (void *)(intptr_t)4);
  usleep(20000);
  proxy_epval_t *p = add_pool(&thr_ent, "j.example");
  del_pool(&thr_ent, p);
  took = wait_live(base, 1000);
  CHECK(took >= 0 && took <= 200,
        "a worker whose wait returns at once: the deleted pool is freed in %ld ms (bound 200)", took);
  atomic_store(&stop_workers, 1);
  pthread_join(w, NULL);
}

static void
test_exited_worker_does_not_hold_back_a_free(void)
{
  pthread_t gone;
  uint64_t base = live();
  long took;

  pthread_create(&gone, NULL, exiting_worker, (void *)(intptr_t)2);
  pthread_join(gone, NULL);
  proxy_epval_t *p = add_pool(&thr_ent, "h.example");
  del_pool(&thr_ent, p);
  took = wait_live(base, 1000);
  CHECK(took >= 0 && took <= 200, "an exited worker holds back nothing: freed in %ld ms", took);
}

/* The find window: a worker reads the index, the pool is deleted, the
 * worker takes its reference later in the same iteration. */
static _Atomic int fw_step;
static _Atomic uint32_t fw_refs_in_window;
static void *fw_holder;

static void *
window_worker(void *arg)
{
  proxy_epval_t *p;

  sp_qsbr_register((int)(intptr_t)arg);
  /* One loop iteration: online from here to the offline below. */
  p = sp_pool_find(&thr_ent, "i.example");
  atomic_store(&fw_step, 1);                     /* found, no reference yet */
  while (atomic_load(&fw_step) != 2)             /* the delete runs meanwhile */
    usleep(1000);
  atomic_store(&fw_refs_in_window, sp_pool_refs(p));
  sp_pool_hold(&fw_holder, p);                   /* store it in a holder */
  (void)strlen(p->ephash_key);                   /* and use it */
  atomic_store(&fw_step, 3);
  sp_qsbr_offline();                             /* the iteration ends */
  while (atomic_load(&fw_step) != 4)
    usleep(1000);
  sp_qsbr_online();
  sp_pool_hold(&fw_holder, NULL);                /* the connection ends */
  sp_qsbr_offline();
  sp_qsbr_unregister();
  return NULL;
}

static void
test_find_window(void)
{
  pthread_t w;
  uint64_t base = live();
  long took;

  atomic_store(&fw_step, 0);
  proxy_epval_t *p = add_pool(&thr_ent, "i.example");
  pthread_create(&w, NULL, window_worker, (void *)(intptr_t)3);
  while (atomic_load(&fw_step) != 1)
    usleep(1000);
  del_pool(&thr_ent, p);
  usleep(50000);
  CHECK(live() == base + 1, "a pool deleted inside a worker's iteration is not freed under it");
  atomic_store(&fw_step, 2);
  while (atomic_load(&fw_step) != 3)
    usleep(1000);
  CHECK(atomic_load(&fw_refs_in_window) >= 1,
        "the count the worker takes from is not zero (%u): the table's reference waits for it",
        atomic_load(&fw_refs_in_window));
  usleep(50000);
  CHECK(live() == base + 1, "the worker's holder keeps the deleted pool");
  atomic_store(&fw_step, 4);
  took = wait_live(base, 1000);
  CHECK(took >= 0, "the holder's release frees the pool (%ld ms)", took);
  pthread_join(w, NULL);
}

int
main(void)
{
  /* Unbuffered: a sanitizer that ends the run must not swallow the checks. */
  setvbuf(stdout, NULL, _IONBF, 0);
  sp_pool_init(count_final);
  fc_set_owner_hooks(sp_pool_fc_hold, sp_pool_fc_drop);

  test_delete_without_holders();
  test_connection_holds_across_delete();
  test_each_holder_alone();
  test_overwrite_and_rebind();
  test_unbind_once_across_threads();
  test_peek_across_threads();
  test_scratch_is_not_counted();
  test_index();

  /* From here the reclaimer runs the deferred work. */
  assert(sp_qsbr_start() == 0);
  test_idle_worker_does_not_hold_back_a_free();
  test_loaded_worker_does_not_hold_back_a_free();
  test_exited_worker_does_not_hold_back_a_free();
  test_find_window();

  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
