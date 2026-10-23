/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * test_fc_deadline.c - a configured wait window is the enforced window.
 *
 *   make test_fc_deadline
 *
 * The real timer (timerfd), real pools, real time: a park arms the timer to
 * its deadline; the pass runs when the timer fires, reads one word per pool,
 * enters only the queues whose earliest deadline has passed and ends the
 * expired waits through the CAS settle (fc_queue_take); it re-arms to the
 * earliest deadline left, never earlier than the grain after it fired; with
 * no waiter anywhere it is not armed and nothing wakes up (asserted over
 * 10 s, as the owner asked).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sockproxy_fc.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)

static uint64_t
now_ns(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void
pool_with(fc_state_t *fc, uint32_t wait_ms)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = 1;
  cfg.max_queue_depth = 8;
  cfg.max_queue_wait_ms = wait_ms;
  fc_state_apply(fc, &cfg);
}

static int
record_wake(int fd, uint64_t gen)
{
  (void)fd;
  (void)gen;
  return 0;
}

/* The pools the pass reads, and the permit each parked fd waits with. */
static fc_state_t *pools[8];
static int npools;
static fc_permit_t *permit_of_fd[64];

static void
pools_fn(void *ctx, fc_pool_visit_fn visit, void *vctx)
{
  (void)ctx;
  for (int i = 0; i < npools; i++)
    visit(vctx, pools[i]);
}

/* What expired, in order, and when the pass saw it; each is ended through
 * the CAS settle exactly as the proxy ends it. */
static struct { fc_state_t *fc; int fd; uint64_t at; } expired[64];
static int nexp;

static void
expire_fn(void *ctx, fc_state_t *fc, const fc_queue_ent_t *e, uint64_t at)
{
  fc_permit_t *p = permit_of_fd[e->fd];

  (void)ctx;
  assert(p);
  assert(fc_queue_take(fc, p) == 1);
  expired[nexp].fc = fc;
  expired[nexp].fd = e->fd;
  expired[nexp].at = at;
  nexp++;
}

static void
park(fc_state_t *fc, fc_permit_t *p, int fd)
{
  memset(p, 0, sizeof(*p));
  permit_of_fd[fd] = p;
  assert(fc_queue_push(fc, p, fd, 1, now_ns(), 0) == 0);
  assert(p->state == FC_P_QUEUED);
}

/* Fire-driven passes until `want` waits expired or `budget_ms` passed.
 * Returns how many firings it took. */
static int
run_until(fc_deadline_t *d, int want, int budget_ms)
{
  uint64_t end = now_ns() + MS(budget_ms);
  int fired = 0;

  while (nexp < want && now_ns() < end) {
    int rc = fc_deadline_wait(d, 50);
    if (rc == 1) {
      fired++;
      fc_deadline_pass(d, now_ns(), pools_fn, expire_fn, NULL);
    }
  }
  return fired;
}

static void
test_idle_makes_no_wakeups(fc_deadline_t *d)
{
  uint64_t before = atomic_load(&d->wakeups);

  npools = 0;
  assert(fc_deadline_pass(d, now_ns(), pools_fn, expire_fn, NULL) == 0);
  assert(atomic_load(&d->armed_ns) == 0);
  /* The owner's condition, literally: 10 s with no waiter, no wake-up. */
  assert(fc_deadline_wait(d, 10000) == 0);
  assert(atomic_load(&d->wakeups) == before);
  printf("  idle: no waiter anywhere, no deadline-pass wake-up over 10 s\n");
}

static void
test_window_is_enforced_per_pool(fc_deadline_t *d)
{
  fc_state_t a, b;
  fc_permit_t pa, pb;
  uint64_t t0, da, db, next;
  int fired;

  pool_with(&a, 100);
  pool_with(&b, 700);
  pools[0] = &a;
  pools[1] = &b;
  npools = 2;
  nexp = 0;
  t0 = now_ns();
  park(&a, &pa, 7);
  park(&b, &pb, 8);
  da = fc_queue_next_deadline(&a);
  db = fc_queue_next_deadline(&b);
  assert(da >= t0 + MS(100) && da < t0 + MS(110));
  assert(db >= t0 + MS(700) && db < t0 + MS(710));
  /* The park armed the timer to the earliest pending deadline. */
  assert(atomic_load(&d->armed_ns) == da);

  fired = run_until(d, 1, 1000);
  assert(nexp == 1 && expired[0].fd == 7 && expired[0].fc == &a);
  /* Enforced within the grain of its window, not within a second. */
  assert(expired[0].at >= da && expired[0].at < da + MS(50));
  assert(fired == 1);
  /* Only the pool whose deadline passed was entered: b still waits, a is
   * empty, and the timer is set to b's deadline. */
  assert(fc_queued(&a) == 0 && fc_queued(&b) == 1);
  assert(fc_queue_next_deadline(&a) == 0);
  assert(fc_queue_next_deadline(&b) == db);
  assert(atomic_load(&d->armed_ns) == db);
  next = fc_deadline_pass(d, now_ns(), pools_fn, expire_fn, NULL);
  assert(next == db && nexp == 1);
  printf("  window: a 100 ms wait ended at %llu ms, the 700 ms one left waiting\n",
         (unsigned long long)((expired[0].at - t0) / 1000000ULL));

  /* A park with an earlier deadline re-arms the timer at once. */
  {
    fc_state_t c;
    fc_permit_t pc;
    uint64_t dc, t1 = now_ns();

    pool_with(&c, 100);
    pools[2] = &c;
    npools = 3;
    park(&c, &pc, 9);
    dc = fc_queue_next_deadline(&c);
    assert(dc < db && atomic_load(&d->armed_ns) == dc);
    run_until(d, 2, 1000);
    assert(nexp == 2 && expired[1].fd == 9);
    assert(expired[1].at >= dc && expired[1].at < dc + MS(50));
    assert(fc_queued(&b) == 1 && atomic_load(&d->armed_ns) == db);
    printf("  re-arm: a later park with an earlier deadline fired at %llu ms\n",
           (unsigned long long)((expired[1].at - t1) / 1000000ULL));
    fc_state_destroy(&c);
    /* c leaves with its block: the pass must not read it again. */
    pools[2] = NULL;
    npools = 2;
  }

  /* b's wait ends at its window too; then nothing waits anywhere: the
   * timer is disarmed by that pass, and nothing fires afterwards. */
  run_until(d, 3, 1500);
  assert(nexp == 3 && expired[2].fd == 8);
  assert(expired[2].at >= db && expired[2].at < db + MS(50));
  assert(atomic_load(&d->armed_ns) == 0);
  assert(fc_deadline_wait(d, 300) == 0);
  printf("  last waiter: ended at its window, the timer disarmed, no firing after\n");
  fc_state_destroy(&a);
  fc_state_destroy(&b);
  npools = 0;
}

static void
test_removal_keeps_the_earliest_exact(fc_deadline_t *d)
{
  fc_state_t a;
  fc_permit_t p1, p2, p3;
  uint64_t d1, d2, d3;

  (void)d;
  pool_with(&a, 300);
  park(&a, &p1, 11);
  d1 = fc_queue_next_deadline(&a);
  /* Later parks never lower the earliest; an earlier one would. */
  park(&a, &p2, 12);
  park(&a, &p3, 13);
  d2 = p2.q_deadline_ns;
  d3 = p3.q_deadline_ns;
  assert(fc_queue_next_deadline(&a) == d1 && d1 <= d2 && d2 <= d3);
  /* The earliest leaves (its turn, a cancellation): the next one is read
   * from the entries that remain, not left stale. */
  assert(fc_queue_take(&a, &p1) == 1);
  assert(fc_queue_next_deadline(&a) == d2);
  assert(fc_queue_take(&a, &p3) == 1);
  assert(fc_queue_next_deadline(&a) == d2);
  assert(fc_queue_take(&a, &p2) == 1);
  assert(fc_queue_next_deadline(&a) == 0);
  /* Nothing past its time: nothing copied. */
  {
    fc_queue_ent_t out[4];
    park(&a, &p1, 11);
    assert(fc_queue_expired(&a, now_ns(), out, 4) == 0);
    assert(fc_queue_expired(&a, p1.q_deadline_ns, out, 4) == 1 && out[0].fd == 11);
    assert(fc_queue_take(&a, &p1) == 1);
  }
  fc_state_destroy(&a);
  printf("  earliest: exact after every removal, 0 when nobody waits\n");
}

static void
test_grain(fc_deadline_t *d)
{
  fc_state_t a, b;
  fc_permit_t pa, pb;
  uint64_t t0;

  /* Two deadlines a few ms apart in two pools: the second firing is at
   * least the grain after the first, and both well inside 200 ms. */
  pool_with(&a, 100);
  pool_with(&b, 105);
  pools[0] = &a;
  pools[1] = &b;
  npools = 2;
  nexp = 0;
  t0 = now_ns();
  park(&a, &pa, 21);
  park(&b, &pb, 22);
  run_until(d, 2, 1000);
  assert(nexp == 2 && expired[0].fd == 21 && expired[1].fd == 22);
  assert(expired[1].at - expired[0].at >= FC_DEADLINE_GRAIN_NS - MS(1));
  assert(expired[1].at < t0 + MS(200));
  assert(atomic_load(&d->armed_ns) == 0);
  fc_state_destroy(&a);
  fc_state_destroy(&b);
  npools = 0;
  printf("  grain: two deadlines 5 ms apart fired %llu ms apart (>= %llu)\n",
         (unsigned long long)((expired[1].at - expired[0].at) / 1000000ULL),
         (unsigned long long)(FC_DEADLINE_GRAIN_NS / 1000000ULL));
}

int
main(void)
{
  fc_deadline_t *d = fc_deadline_global();

  fc_set_wake_hook(record_wake);
  assert(fc_deadline_init(d) == 0);
  test_removal_keeps_the_earliest_exact(d);
  test_window_is_enforced_per_pool(d);
  test_grain(d);
  test_idle_makes_no_wakeups(d);
  fc_deadline_close(d);
  printf("test_fc_deadline: all passed\n");
  return 0;
}
