/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The strict band order and the shed of the capacity gate, driven alone:
 * the one conversion between a triple's positions and the band index; a
 * sheddable request that may not wait is shed (FC_BAND_SHED) at whichever
 * ceiling it meets; under strict a newcomer waits only behind its own band
 * or a higher one, and a wake takes the highest band first, oldest first
 * inside it; with every request standard both are today's FIFO; an
 * arrival above sheddable at a full queue evicts the youngest sheddable
 * waiter (fc_shed_queue), whose answer is owed until claimed once, and
 * comes by the second 1 Hz pass however many are evicted in a second; the
 * per-band outcome counters split five decisions exactly, standard derived.
 *
 * Build: make test_fc_band_shed (also run by `make test_fc`).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)
#define C FC_BAND_CRITICAL
#define S FC_BAND_STANDARD
#define B FC_BAND_SHEDDABLE

static void
pool_with(fc_state_t *fc, uint32_t max_out, uint32_t depth, uint8_t wake,
          uint8_t shed_queue, uint8_t share_pct)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = max_out;
  cfg.max_queue_depth = depth;
  cfg.max_queue_wait_ms = depth ? 5000 : 0;
  cfg.wake_policy = wake;
  cfg.shed_queue = shed_queue;
  cfg.tenant_share_pct = share_pct;
  if (wake == FC_WAKE_WEIGHTED) {
    cfg.band_weight[FC_BAND_CRITICAL] = 8;
    cfg.band_weight[FC_BAND_STANDARD] = 3;
    cfg.band_weight[FC_BAND_SHEDDABLE] = 1;
  }
  fc_state_apply(fc, &cfg);
}

static int woken_fd[64];
static int woken_n;
static int wake_refuse;

static int
record_wake(int fd, uint64_t gen)
{
  (void)gen;
  if (wake_refuse)
    return -1;
  assert(woken_n < 64);
  woken_fd[woken_n++] = fd;
  return 0;
}

static fc_verdict_t
admit(fc_state_t *fc, fc_permit_t *p, uint8_t band, int woken, uint64_t tkey)
{
  fc_verdict_t v = fc_service_acquire_h1_band(fc, p, woken, tkey, band);

  if (v == FC_ADMIT && p->state == FC_P_EXECUTING)
    assert(fc_ep_acquire(fc, p, 0, FC_ROLE_NORMAL) == FC_ADMIT);
  return v;
}

static void
park(fc_state_t *fc, fc_permit_t *p, uint8_t band, int fd, uint64_t now)
{
  assert(admit(fc, p, band, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(fc_queue_push(fc, p, fd, 1, now, 0) == 0);
}

static uint64_t
dec(const fc_state_t *fc, enum fc_reason r)
{
  return atomic_load(&fc->decisions[r]);
}

static uint64_t
bo(fc_state_t *fc, uint8_t band, int o)
{
  return fc_band_outcome(fc, band, o);
}

/* Every outcome: the three bands sum to the decision it splits. */
static void
assert_split(fc_state_t *fc)
{
  static const enum fc_reason of[FC_BO_COUNT] = {
    FC_R_ADMITTED, FC_R_QUEUED, FC_R_SHED, FC_R_QUEUE_TIMEOUT, FC_R_CANCELLED,
  };

  for (int o = 0; o < FC_BO_COUNT; o++)
    assert(bo(fc, C, o) + bo(fc, S, o) + bo(fc, B, o) == dec(fc, of[o]));
  /* The standard row is never written. */
  for (int o = 0; o < FC_BO_COUNT; o++)
    assert(atomic_load(&fc->band_outcome[S][o]) == 0);
}

static void
test_order_round_trip(void)
{
  uint32_t idx[FC_BANDS];
  char out[32];

  /* Positions are ranks, highest band first; rank is the inverse. */
  assert(fc_band_at_rank(0) == C && fc_band_at_rank(1) == S &&
         fc_band_at_rank(2) == B);
  for (int r = 0; r < FC_BANDS; r++)
    assert(fc_band_rank(fc_band_at_rank(r)) == r);
  for (int b = 0; b < FC_BANDS; b++)
    assert(fc_band_at_rank(fc_band_rank((uint8_t)b)) == b);
  /* Out of range is standard, both ways. */
  assert(fc_band_at_rank(-1) == S && fc_band_at_rank(3) == S);
  assert(fc_band_rank(9) == fc_band_rank(S));

  /* A band-indexed triple prints as operators write it. */
  idx[S] = 3;
  idx[C] = 8;
  idx[B] = 1;
  assert(fc_band_triple_fmt(out, sizeof(out), idx) == 5);
  assert(strcmp(out, "8:3:1") == 0);
  idx[S] = 5000;
  idx[C] = 0;
  idx[B] = 500;
  fc_band_triple_fmt(out, sizeof(out), idx);
  assert(strcmp(out, "0:5000:500") == 0);
  printf("  ok order round trip\n");
}

static void
test_sheddable_is_shed_unless_it_may_wait(void)
{
  fc_state_t fc;
  fc_permit_t a, p;

  /* No queue: a sheddable request at the ceiling is shed, the others meet
   * the plain capacity refusal. */
  pool_with(&fc, 1, 0, FC_WAKE_STRICT, 0, 0);
  fc_permit_init(&a);
  fc_permit_init(&p);
  assert(admit(&fc, &a, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(fc_service_acquire_band(&fc, &p, fc_tenant_key(NULL), B) == FC_BAND_SHED);
  assert(p.state == FC_P_NONE);
  assert(fc_service_acquire_band(&fc, &p, fc_tenant_key(NULL), S) == FC_SHED);
  assert(fc_service_acquire_band(&fc, &p, fc_tenant_key(NULL), C) == FC_SHED);
  fc_permit_release(&a);
  /* Below the ceiling everyone is admitted at once, sheddable too. */
  assert(admit(&fc, &a, B, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release(&a);
  fc_state_destroy(&fc);

  /* A queue, fc_shed_queue off: a sheddable request never waits. */
  pool_with(&fc, 1, 4, FC_WAKE_STRICT, 0, 0);
  fc_permit_init(&a);
  fc_permit_init(&p);
  assert(admit(&fc, &a, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &p, B, 0, fc_tenant_key(NULL)) == FC_BAND_SHED);
  assert(admit(&fc, &p, S, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  /* An endpoint ceiling's FC_SHED is shed too for it, and only for it. */
  p.band = B;
  assert(fc_band_verdict(&fc, &p, FC_SHED) == FC_BAND_SHED);
  assert(fc_band_verdict(&fc, &p, FC_QUEUE) == FC_BAND_SHED);
  assert(fc_band_verdict(&fc, &p, FC_NO_CAPACITY) == FC_NO_CAPACITY);
  assert(fc_band_verdict(&fc, &p, FC_TENANT_SHARE) == FC_TENANT_SHARE);
  assert(fc_band_verdict(&fc, &p, FC_DRAINING) == FC_DRAINING);
  p.band = S;
  assert(fc_band_verdict(&fc, &p, FC_SHED) == FC_SHED);
  fc_permit_release(&a);
  fc_state_destroy(&fc);

  /* fc_shed_queue on: it waits in its band. */
  pool_with(&fc, 1, 4, FC_WAKE_STRICT, 1, 0);
  fc_permit_init(&a);
  fc_permit_init(&p);
  assert(admit(&fc, &a, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &p, B, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  fc_permit_release(&a);
  fc_state_destroy(&fc);

  /* Observe mode decides nothing. */
  pool_with(&fc, 1, 0, FC_WAKE_STRICT, 0, 0);
  fc.cfg.mode = FC_MODE_OBSERVE;
  fc_permit_init(&a);
  fc_permit_init(&p);
  assert(admit(&fc, &a, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &p, B, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release(&a);
  fc_permit_release(&p);
  fc_state_destroy(&fc);

  /* A tenant at its share: a sheddable request that may not wait takes the
   * share's refusal, not a shed (the pool is not at its ceiling). */
  pool_with(&fc, 4, 4, FC_WAKE_STRICT, 0, 25);
  fc_permit_init(&a);
  fc_permit_init(&p);
  assert(admit(&fc, &a, B, 0, fc_tenant_key("t1")) == FC_ADMIT);
  assert(admit(&fc, &p, B, 0, fc_tenant_key("t1")) == FC_TENANT_SHARE);
  assert(admit(&fc, &p, S, 0, fc_tenant_key("t1")) == FC_QUEUE);
  fc_permit_release(&a);
  fc_state_destroy(&fc);
  printf("  ok sheddable shed unless it may wait\n");
}

static void
test_strict_newcomer_rule(void)
{
  fc_state_t fc;
  fc_permit_t run, w, n;

  /* Ceiling 2, one held, a standard waiter (it waits behind nobody now:
   * pushed by hand, as a request that lost its unit). A critical newcomer
   * takes the free unit; a standard one waits behind its own band. */
  pool_with(&fc, 2, 4, FC_WAKE_STRICT, 0, 0);
  fc_permit_init(&run);
  fc_permit_init(&w);
  fc_permit_init(&n);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  w.band = S;
  assert(fc_queue_push(&fc, &w, 10, 1, MS(1), 0) == 0);
  assert(admit(&fc, &n, S, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(admit(&fc, &n, B, 0, fc_tenant_key(NULL)) == FC_BAND_SHED);
  assert(admit(&fc, &n, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release_nowake(&n);
  /* A critical waiter is ahead of a critical newcomer. */
  fc_permit_init(&n);
  n.band = C;
  assert(fc_queue_push(&fc, &n, 11, 1, MS(2), 0) == 0);
  {
    fc_permit_t m;
    fc_permit_init(&m);
    assert(admit(&fc, &m, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  }
  fc_permit_release(&n);
  fc_permit_release(&w);
  fc_permit_release(&run);
  fc_state_destroy(&fc);

  /* Weighted: behind anybody. */
  pool_with(&fc, 2, 4, FC_WAKE_WEIGHTED, 0, 0);
  fc_permit_init(&run);
  fc_permit_init(&w);
  fc_permit_init(&n);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  w.band = S;
  assert(fc_queue_push(&fc, &w, 10, 1, MS(1), 0) == 0);
  assert(admit(&fc, &n, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  fc_permit_release(&w);
  fc_permit_release(&run);
  fc_state_destroy(&fc);

  /* With a share: the same rule, read under the lock. A sheddable waiter
   * of another tenant is no reason for a standard newcomer to wait, a
   * standard waiter that can run is. */
  pool_with(&fc, 4, 8, FC_WAKE_STRICT, 1, 50);
  fc_permit_init(&run);
  fc_permit_init(&w);
  fc_permit_init(&n);
  assert(admit(&fc, &run, S, 0, fc_tenant_key("t1")) == FC_ADMIT);
  w.band = B;
  w.tkey = fc_tenant_key("t2");
  assert(fc_queue_push(&fc, &w, 10, 1, MS(1), 0) == 0);
  assert(admit(&fc, &n, S, 0, fc_tenant_key("t3")) == FC_ADMIT);
  fc_permit_release_nowake(&n);
  fc_permit_init(&n);
  {
    fc_permit_t w2;
    fc_permit_init(&w2);
    w2.band = S;
    w2.tkey = fc_tenant_key("t4");
    assert(fc_queue_push(&fc, &w2, 12, 1, MS(2), 0) == 0);
    assert(admit(&fc, &n, S, 0, fc_tenant_key("t3")) == FC_QUEUE);
    assert(admit(&fc, &n, C, 0, fc_tenant_key("t3")) == FC_ADMIT);
    fc_permit_release_nowake(&n);
    fc_permit_release(&w2);
  }
  fc_permit_release(&w);
  fc_permit_release(&run);
  fc_state_destroy(&fc);
  printf("  ok strict newcomer rule\n");
}

/* Fill a pool of ceiling 1, park the given bands in order (fds 100, 101,
 * ...), then release the unit one turn at a time and record whom each turn
 * woke. */
static void
wake_order(uint8_t wake, const uint8_t *bands, int n, int *order, int share)
{
  fc_state_t fc;
  fc_permit_t run, q[8];

  pool_with(&fc, 1, 8, wake, 1, share ? 50 : 0);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  fc_permit_init(&run);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  for (int i = 0; i < n; i++) {
    fc_permit_init(&q[i]);
    q[i].band = bands[i];
    q[i].tkey = fc_tenant_key(share ? (i & 1 ? "ta" : "tb") : NULL);
    assert(fc_queue_push(&fc, &q[i], 100 + i, 1, MS(10 + i), 0) == 0);
  }
  fc_permit_release(&run);
  for (int i = 0; i < n; i++) {
    int fd;
    int k;

    assert(woken_n == i + 1);
    fd = woken_fd[i];
    k = fd - 100;
    order[i] = k;
    /* The woken one takes its unit, then hands it back: the next turn. */
    fc_queue_resumed(&fc, &q[k], MS(100));
    assert(admit(&fc, &q[k], q[k].band, 1, q[k].tkey) == FC_ADMIT);
    fc_permit_release(&q[k]);
  }
  assert(fc_queued(&fc) == 0);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
}

static void
test_strict_pick(void)
{
  int order[8];

  /* Highest band first, oldest first inside a band. */
  {
    const uint8_t b[] = { S, B, C, S, C, B };
    const int want[] = { 2, 4, 0, 3, 1, 5 };
    wake_order(FC_WAKE_STRICT, b, 6, order, 0);
    for (int i = 0; i < 6; i++)
      assert(order[i] == want[i]);
    wake_order(FC_WAKE_STRICT, b, 6, order, 1);
    for (int i = 0; i < 6; i++)
      assert(order[i] == want[i]);
  }
  /* Every waiter standard: arrival order, today's FIFO. */
  {
    const uint8_t b[] = { S, S, S, S };
    wake_order(FC_WAKE_STRICT, b, 4, order, 0);
    for (int i = 0; i < 4; i++)
      assert(order[i] == i);
  }
  /* Weighted 8:3:1: a fresh round serves the highest band with credit
   * first, then the next: critical, standard, sheddable. */
  {
    const uint8_t b[] = { S, B, C };
    const int want[] = { 2, 0, 1 };
    wake_order(FC_WAKE_WEIGHTED, b, 3, order, 0);
    for (int i = 0; i < 3; i++)
      assert(order[i] == want[i]);
  }
  printf("  ok strict pick\n");
}

/* A woken critical request that lost its unit goes back to the head and is
 * still picked before older standard waiters. */
static void
test_front_reinsert_keeps_band(void)
{
  fc_state_t fc;
  fc_permit_t run, s1, s2, c1, thief;

  pool_with(&fc, 1, 4, FC_WAKE_STRICT, 0, 0);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  fc_permit_init(&run);
  fc_permit_init(&s1);
  fc_permit_init(&s2);
  fc_permit_init(&c1);
  fc_permit_init(&thief);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  park(&fc, &s1, S, 20, MS(1));
  park(&fc, &s2, S, 21, MS(2));
  park(&fc, &c1, C, 22, MS(3));
  fc_permit_release(&run);
  assert(woken_n == 1 && woken_fd[0] == 22);
  /* A critical newcomer takes the unit before the woken one runs (no
   * critical waiter is left). */
  assert(admit(&fc, &thief, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_queue_resumed(&fc, &c1, MS(10));
  assert(admit(&fc, &c1, C, 1, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(fc_queue_push(&fc, &c1, 22, 1, MS(10), 1) == 0);
  /* Going back is the same park: queued counted once for it. */
  assert(bo(&fc, C, FC_BO_QUEUED) == 1);
  fc_permit_release(&thief);
  assert(woken_n == 2 && woken_fd[1] == 22);
  fc_queue_resumed(&fc, &c1, MS(11));
  assert(admit(&fc, &c1, C, 1, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(bo(&fc, C, FC_BO_ADMITTED) == 2);
  fc_permit_release(&c1);
  assert(woken_n == 3 && woken_fd[2] == 20);
  fc_queue_resumed(&fc, &s1, MS(12));
  assert(admit(&fc, &s1, S, 1, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release(&s1);
  assert(woken_n == 4 && woken_fd[3] == 21);
  fc_queue_resumed(&fc, &s2, MS(13));
  assert(admit(&fc, &s2, S, 1, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release(&s2);
  assert_split(&fc);
  assert(bo(&fc, S, FC_BO_QUEUED) == 2 && bo(&fc, S, FC_BO_ADMITTED) == 3);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
  printf("  ok front re-insert keeps the band\n");
}

static void
test_eviction(void)
{
  fc_state_t fc;
  fc_permit_t run, b1, b2, s1, c1, c2;

  /* Depth 3: two sheddable and one standard waiting. A critical arrival
   * evicts the youngest sheddable and takes its place. */
  pool_with(&fc, 1, 3, FC_WAKE_STRICT, 1, 0);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  fc_permit_init(&run);
  fc_permit_init(&b1);
  fc_permit_init(&b2);
  fc_permit_init(&s1);
  fc_permit_init(&c1);
  fc_permit_init(&c2);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  park(&fc, &b1, B, 30, MS(1));
  park(&fc, &s1, S, 31, MS(2));
  park(&fc, &b2, B, 32, MS(3));
  assert(fc_queued(&fc) == 3);
  park(&fc, &c1, C, 33, MS(4));
  assert(fc_queued(&fc) == 3 && fc_queue_evicted(&fc) == 1);
  assert(fc_band_queued(&fc, B) == 1 && fc_band_queued(&fc, C) == 1);
  /* Counted shed where decided, its owner woken for the answer. */
  assert(dec(&fc, FC_R_SHED) == 1 && bo(&fc, B, FC_BO_SHED) == 1);
  assert(woken_n == 1 && woken_fd[0] == 32);
  /* Its own resume claims the answer once; nobody else can. */
  assert(fc_queue_holds(&fc, &b2) == 0);
  assert(fc_queue_evicted_claim(&fc, 32, 1) == 1);
  assert(fc_queue_evicted_claim(&fc, 32, 1) == 0);
  assert(fc_queue_evicted(&fc) == 0);
  b2.state = FC_P_NONE;

  /* A standard arrival evicts too; the last sheddable goes. */
  {
    fc_permit_t s2;
    fc_permit_init(&s2);
    park(&fc, &s2, S, 34, MS(5));
    assert(fc_band_queued(&fc, B) == 0 && fc_queue_evicted(&fc) == 1);
    assert(woken_n == 2 && woken_fd[1] == 30);
    /* The evicted client leaves before its answer: the departure claims it,
     * nothing is cancelled and nobody is woken (no unit was freed). */
    fc_permit_release(&b1);
    assert(fc_queue_evicted(&fc) == 0);
    assert(dec(&fc, FC_R_CANCELLED) == 0 && woken_n == 2);
    /* Queue full of standard and critical: nobody to evict, refused as a
     * full queue; a sheddable arrival never evicts. */
    assert(admit(&fc, &c2, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
    assert(fc_queue_push(&fc, &c2, 35, 1, MS(6), 0) == -1);
    assert(dec(&fc, FC_R_QUEUE_FULL) == 1);
    fc_permit_release(&s2);
  }
  assert_split(&fc);
  fc_permit_release(&s1);
  fc_permit_release(&c1);
  fc_permit_release(&run);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
  printf("  ok eviction\n");
}

static void
test_no_eviction_with_shed_queue_off(void)
{
  fc_state_t fc;
  fc_permit_t run, s[2], c;

  /* The mirror: fc_shed_queue off. Sheddable never waits, so a full queue
   * holds none; a critical arrival is refused as a full queue. */
  pool_with(&fc, 1, 2, FC_WAKE_STRICT, 0, 0);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  fc_permit_init(&run);
  fc_permit_init(&c);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  for (int i = 0; i < 2; i++) {
    fc_permit_init(&s[i]);
    park(&fc, &s[i], S, 40 + i, MS(1 + i));
  }
  assert(admit(&fc, &c, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(fc_queue_push(&fc, &c, 42, 1, MS(5), 0) == -1);
  assert(fc_queue_evicted(&fc) == 0 && woken_n == 0);
  assert(dec(&fc, FC_R_SHED) == 0 && dec(&fc, FC_R_QUEUE_FULL) == 1);
  /* Even with a sheddable entry left over from when it was on: the switch
   * turned off evicts nobody. */
  fc.cfg.shed_queue = 0;
  for (int i = 0; i < 2; i++)
    fc_permit_release(&s[i]);
  fc_permit_release(&run);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
  printf("  ok no eviction with fc_shed_queue off\n");
}

static int swept_fd[FC_EVICT_PENDING + 4];
static int swept_n;

static int
record_sweep(void *ctx, const fc_queue_ent_t *e)
{
  (void)ctx;
  assert(e->band == B);
  swept_fd[swept_n++] = e->fd;
  return 1;
}

static void
test_evicted_list_bounded_and_swept(void)
{
  fc_state_t fc;
  fc_permit_t run, b[FC_EVICT_PENDING + 1], c[FC_EVICT_PENDING + 1];
  int depth = FC_EVICT_PENDING + 1;

  /* Lost wakes: every evicted waiter stays owed. Once the list is full,
   * nobody more is evicted and the arrival is refused as a full queue. */
  pool_with(&fc, 1, (uint32_t)depth, FC_WAKE_STRICT, 1, 0);
  fc_set_wake_hook(record_wake);
  wake_refuse = 1;
  fc_permit_init(&run);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  for (int i = 0; i < depth; i++) {
    fc_permit_init(&b[i]);
    park(&fc, &b[i], B, 200 + i, MS(1 + i));
  }
  for (int i = 0; i < FC_EVICT_PENDING; i++) {
    fc_permit_init(&c[i]);
    park(&fc, &c[i], C, 300 + i, MS(100 + i));
  }
  assert(fc_queue_evicted(&fc) == FC_EVICT_PENDING);
  fc_permit_init(&c[FC_EVICT_PENDING]);
  assert(admit(&fc, &c[FC_EVICT_PENDING], C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(fc_queue_push(&fc, &c[FC_EVICT_PENDING], 399, 1, MS(200), 0) == -1);
  assert(fc_band_queued(&fc, B) == 1);
  /* The 1 Hz pass answers those evicted at or before its bound, oldest
   * first; the youngest evicted (the first sheddable picked was the
   * youngest waiter) are the first on the list. */
  swept_n = 0;
  assert(fc_queue_evicted_sweep(&fc, MS(103), record_sweep, NULL) == 4);
  assert(swept_n == 4 && swept_fd[0] == 200 + depth - 1);
  assert(fc_queue_evicted(&fc) == FC_EVICT_PENDING - 4);
  /* A drain takes the rest. */
  assert(fc_queue_evicted_sweep(&fc, UINT64_MAX, record_sweep, NULL) ==
         FC_EVICT_PENDING - 4);
  assert(fc_queue_evicted(&fc) == 0);
  assert(dec(&fc, FC_R_SHED) == FC_EVICT_PENDING);
  wake_refuse = 0;
  fc_set_wake_hook(NULL);
  assert_split(&fc);
  fc_state_destroy(&fc);
  printf("  ok evicted list bounded and swept\n");
}

/* More evictions in one second than the evicted list holds: the bound is on
 * how long an answer may wait, never on whether it comes. Every third wake
 * is lost; the woken are claimed by their owners at once, the rest by the
 * 1 Hz pass (bound: evicted at least 1 s before it). Each evicted waiter is
 * answered exactly once, by the second pass after its eviction, and the
 * shed count is the evictions. */
#define XE_N (2 * FC_EVICT_PENDING + 4)
static uint64_t xe_answered[XE_N];
static int xe_wakes;
static uint64_t xe_now;

static int
xe_wake(int fd, uint64_t gen)
{
  (void)gen;
  if (xe_wakes++ % 3 == 2)
    return -1;
  assert(woken_n < 64);
  woken_fd[woken_n++] = fd;
  return 0;
}

static int
xe_sweep(void *ctx, const fc_queue_ent_t *e)
{
  (void)ctx;
  assert(e->band == B && e->fd >= 500 && e->fd < 500 + XE_N);
  assert(xe_answered[e->fd - 500] == 0);
  xe_answered[e->fd - 500] = xe_now;
  return 1;
}

static void
test_more_evictions_than_the_list_holds(void)
{
  fc_state_t fc;
  fc_permit_t run, b[XE_N], c[XE_N];
  uint64_t evicted_at[XE_N];
  uint64_t pass = MS(1500);
  int ev = 0;

  pool_with(&fc, 1, XE_N, FC_WAKE_STRICT, 1, 0);
  fc_set_wake_hook(xe_wake);
  woken_n = 0;
  xe_wakes = 0;
  memset(xe_answered, 0, sizeof(xe_answered));
  fc_permit_init(&run);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  for (int i = 0; i < XE_N; i++) {
    fc_permit_init(&b[i]);
    park(&fc, &b[i], B, 500 + i, MS(1 + i));
  }
  /* XE_N critical arrivals 25 ms apart: all inside one second. */
  for (int i = 0; i < XE_N; i++) {
    uint64_t t = MS(1000) + (uint64_t)i * MS(25);

    while (pass <= t) {
      xe_now = pass;
      fc_queue_evicted_sweep(&fc, pass - MS(1000), xe_sweep, NULL);
      pass += MS(1000);
    }
    woken_n = 0;
    fc_permit_init(&c[i]);
    park(&fc, &c[i], C, 700 + i, t);
    /* The youngest sheddable still waiting is the one evicted. */
    evicted_at[XE_N - 1 - i] = t;
    ev++;
    for (int k = 0; k < woken_n; k++) {
      assert(fc_queue_evicted_claim(&fc, woken_fd[k], 1) == 1);
      assert(xe_answered[woken_fd[k] - 500] == 0);
      xe_answered[woken_fd[k] - 500] = t;
    }
  }
  assert(ev == XE_N && ev > FC_EVICT_PENDING);
  assert(evicted_at[0] - evicted_at[XE_N - 1] < MS(1000));
  assert(fc_band_queued(&fc, B) == 0 && fc_band_queued(&fc, C) == XE_N);
  /* Two more passes after the last eviction. */
  for (int k = 0; k < 2; k++, pass += MS(1000)) {
    xe_now = pass;
    fc_queue_evicted_sweep(&fc, pass - MS(1000), xe_sweep, NULL);
  }
  assert(fc_queue_evicted(&fc) == 0);
  for (int i = 0; i < XE_N; i++) {
    /* The second 1 Hz pass after its eviction (passes at 1.5 s, 2.5 s, ...). */
    uint64_t first = MS(1500);
    while (first <= evicted_at[i])
      first += MS(1000);
    assert(xe_answered[i] >= evicted_at[i]);
    assert(xe_answered[i] <= first + MS(1000));
  }
  assert(dec(&fc, FC_R_SHED) == (uint64_t)XE_N);
  assert(bo(&fc, B, FC_BO_SHED) == (uint64_t)XE_N);
  assert(dec(&fc, FC_R_QUEUE_FULL) == 0);
  fc_set_wake_hook(NULL);
  assert_split(&fc);
  fc_state_destroy(&fc);
  printf("  ok more evictions in a second than the list holds: all answered by the second pass\n");
}

static void
test_outcomes_split_the_decisions(void)
{
  fc_state_t fc;
  fc_permit_t run, a, b, c;

  pool_with(&fc, 1, 4, FC_WAKE_STRICT, 1, 0);
  fc_permit_init(&run);
  fc_permit_init(&a);
  fc_permit_init(&b);
  fc_permit_init(&c);
  /* A standard request admitted moves no band counter. */
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  for (int o = 0; o < FC_BO_COUNT; o++)
    assert(atomic_load(&fc.band_outcome[C][o]) == 0 &&
           atomic_load(&fc.band_outcome[B][o]) == 0);
  assert(bo(&fc, S, FC_BO_ADMITTED) == 1);
  /* Parks, a cancel, a deadline take (the health pass's counting). */
  park(&fc, &a, C, 50, MS(1));
  park(&fc, &b, B, 51, MS(2));
  park(&fc, &c, S, 52, MS(3));
  fc_permit_release(&a);                 /* client left while queued */
  assert(fc_queue_take(&fc, &b) == 1);   /* its window ended */
  fc_count_band(&fc, FC_R_QUEUE_TIMEOUT, b.band);
  b.state = FC_P_NONE;
  assert(bo(&fc, C, FC_BO_QUEUED) == 1 && bo(&fc, C, FC_BO_CANCELLED) == 1);
  assert(bo(&fc, B, FC_BO_QUEUED) == 1 && bo(&fc, B, FC_BO_EXPIRED) == 1);
  assert(bo(&fc, S, FC_BO_QUEUED) == 1);
  assert_split(&fc);
  fc_permit_release(&c);
  fc_permit_release(&run);
  fc_state_destroy(&fc);
  /* A sheddable request refused by band policy. */
  pool_with(&fc, 1, 4, FC_WAKE_STRICT, 0, 0);
  fc_permit_init(&run);
  fc_permit_init(&a);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &a, B, 0, fc_tenant_key(NULL)) == FC_BAND_SHED);
  fc_count_band(&fc, FC_R_SHED, a.band);
  assert(bo(&fc, B, FC_BO_SHED) == 1 && bo(&fc, S, FC_BO_SHED) == 0);
  /* Reasons outside the five move no band counter. */
  fc_count_band(&fc, FC_R_QUEUE_FULL, C);
  assert(dec(&fc, FC_R_QUEUE_FULL) == 1);
  assert_split(&fc);
  assert(strcmp(fc_band_outcome_name(FC_BO_EXPIRED), "expired") == 0);
  assert(strcmp(fc_reason_name(FC_R_SHED), "shed") == 0);
  fc_permit_release(&run);
  fc_state_destroy(&fc);
  printf("  ok outcomes split the decisions\n");
}

/* The queue-wait histogram takes one sample per park, when the park ends,
 * and the sample is the whole wait since the first park: a woken request
 * that goes back to its place is not a second sample, and its resume is not
 * the end. A client that leaves while it waits ends its park; an evicted
 * waiter's park ends where it is evicted, and its claim adds nothing. */
static uint64_t
qw(fc_state_t *fc)
{
  return atomic_load(&fc->qwait_count);
}

static void
test_queue_wait_once_per_park(void)
{
  fc_state_t fc;
  fc_permit_t run, a, thief, x, b1, s1, c1;
  /* The admission's sample is read on the gate's own clock: the park is
   * dated 300 ms back, the going back 100 ms back. */
  uint64_t t0 = fc_now_ns();

  pool_with(&fc, 1, 2, FC_WAKE_STRICT, 1, 0);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  fc_permit_init(&run);
  fc_permit_init(&a);
  fc_permit_init(&thief);
  fc_permit_init(&x);
  fc_permit_init(&b1);
  fc_permit_init(&s1);
  fc_permit_init(&c1);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  park(&fc, &a, S, 40, t0 - MS(300));
  fc_permit_release(&run);
  assert(woken_n == 1 && woken_fd[0] == 40);
  /* A newcomer takes the unit first: a goes back to its place. */
  assert(admit(&fc, &thief, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_queue_resumed(&fc, &a, t0 - MS(100));
  assert(qw(&fc) == 0);
  assert(admit(&fc, &a, S, 1, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(fc_queue_push(&fc, &a, 40, 1, t0 - MS(100), 1) == 0);
  assert(qw(&fc) == 0);
  fc_permit_release(&thief);
  fc_queue_resumed(&fc, &a, t0);
  assert(admit(&fc, &a, S, 1, fc_tenant_key(NULL)) == FC_ADMIT);
  /* One park, one sample, the whole wait since the first park (not the
   * 100 ms since it went back). */
  assert(qw(&fc) == 1);
  assert(atomic_load(&fc.qwait_sum_ms) >= 300);
  /* Admitted, it is in no park: nothing more. */
  fc_permit_release(&a);
  assert(qw(&fc) == 1);

  /* A client that leaves while it waits. */
  fc_permit_init(&run);
  assert(admit(&fc, &run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  park(&fc, &x, S, 41, MS(30));
  fc_permit_release(&x);
  assert(dec(&fc, FC_R_CANCELLED) == 1 && qw(&fc) == 2);

  /* A sheddable waiter evicted at the full queue: one sample where it is
   * evicted, none when its departure claims the answer. */
  park(&fc, &b1, B, 42, MS(40));
  park(&fc, &s1, S, 43, MS(41));
  park(&fc, &c1, C, 44, MS(50));
  assert(fc_queue_evicted(&fc) == 1 && qw(&fc) == 3);
  fc_permit_release(&b1);
  assert(fc_queue_evicted(&fc) == 0 && qw(&fc) == 3);

  fc_permit_release(&s1);
  fc_permit_release(&c1);
  fc_permit_release(&run);
  fc_state_destroy(&fc);
  printf("  ok the queue wait is one sample per park\n");
}

/* The standard count is derived from three counters read one after the
 * other: a critical request counted between the reads makes the difference
 * read low once. The count a reader returns never steps back. */
static void
test_standard_never_steps_back(void)
{
  fc_state_t fc;

  pool_with(&fc, 1, 4, FC_WAKE_STRICT, 0, 0);
  atomic_store(&fc.decisions[FC_R_ADMITTED], 10);
  atomic_store(&fc.band_outcome[C][FC_BO_ADMITTED], 2);
  assert(bo(&fc, S, FC_BO_ADMITTED) == 8);
  /* A critical admission whose band count is read before its decision. */
  atomic_store(&fc.band_outcome[C][FC_BO_ADMITTED], 3);
  assert(bo(&fc, S, FC_BO_ADMITTED) == 8);
  /* Its decision read: exact again. */
  atomic_store(&fc.decisions[FC_R_ADMITTED], 11);
  assert(bo(&fc, S, FC_BO_ADMITTED) == 8);
  /* A standard admission moves it on. */
  atomic_store(&fc.decisions[FC_R_ADMITTED], 12);
  assert(bo(&fc, S, FC_BO_ADMITTED) == 9);
  assert_split(&fc);
  fc_state_destroy(&fc);
  printf("  ok the standard count never steps back\n");
}

int
main(void)
{
  printf("test_fc_band_shed\n");
  test_order_round_trip();
  test_sheddable_is_shed_unless_it_may_wait();
  test_strict_newcomer_rule();
  test_strict_pick();
  test_front_reinsert_keeps_band();
  test_eviction();
  test_no_eviction_with_shed_queue_off();
  test_evicted_list_bounded_and_swept();
  test_more_evictions_than_the_list_holds();
  test_outcomes_split_the_decisions();
  test_standard_never_steps_back();
  test_queue_wait_once_per_park();
  printf("test_fc_band_shed: all passed\n");
  return 0;
}
