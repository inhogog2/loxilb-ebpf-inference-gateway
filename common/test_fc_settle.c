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
 * A waiting request leaves the queue once: its owner's resume and the paths
 * that end a wait from elsewhere (the 1 Hz pass answering an eviction, the
 * deadline, a drain) each try one compare-and-swap on the permit's state,
 * and only the one that makes it answers. Driven here with the functions the
 * proxy calls (fc_queue_owner_resume for the owner, fc_queue_evicted_sweep
 * with a callback that settles the way sp_fc_drain_cb does, fc_queue_take
 * for the deadline): the owner late after the pass, the owner first, each
 * of them inside the other's window, and the two racing on two threads.
 * In every order there is one answer, and the counts are those of one.
 *
 * Build: make test_fc_settle (also run by `make test_fc`).
 */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)
#define C FC_BAND_CRITICAL
#define S FC_BAND_STANDARD
#define B FC_BAND_SHEDDABLE

static int woken_n;

static int
count_wake(int fd, uint64_t gen)
{
  (void)fd;
  (void)gen;
  woken_n++;
  return 0;
}

static void
pool(fc_state_t *fc, uint32_t depth)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = 1;
  cfg.max_queue_depth = depth;
  cfg.max_queue_wait_ms = 5000;
  cfg.wake_policy = FC_WAKE_STRICT;
  cfg.shed_queue = 1;
  fc_state_apply(fc, &cfg);
}

static fc_verdict_t
admit(fc_state_t *fc, fc_permit_t *p, uint8_t band)
{
  fc_verdict_t v = fc_service_acquire_h1_band(fc, p, 0, fc_tenant_key(NULL), band);

  if (v == FC_ADMIT && p->state == FC_P_EXECUTING)
    assert(fc_ep_acquire(fc, p, 0, FC_ROLE_NORMAL) == FC_ADMIT);
  return v;
}

static void
park(fc_state_t *fc, fc_permit_t *p, uint8_t band, int fd, uint64_t now)
{
  assert(admit(fc, p, band) == FC_QUEUE);
  assert(fc_queue_push(fc, p, fd, 1, now, 0) == 0);
}

static uint64_t
dec(const fc_state_t *fc, enum fc_reason r)
{
  return atomic_load(&fc->decisions[r]);
}

/* The sweep's callback, deciding as sp_fc_drain_cb does: it answers only
 * when it takes the entry and swaps the permit to FC_P_EVICTED in one step
 * (fc_queue_evicted_settle). `victim` is the permit the connection (fd, gen)
 * holds NOW, as the proxy's lookup finds it. `hook` runs inside the window:
 * 1 the owner's resume before the swap, 2 after it; 3 the owner answers its
 * eviction, `leaver` leaves the queue and the connection's next request
 * parks under the same (fd, gen); 4 as 3, then `extra` evicts that next
 * request too, and the callback skips (its lookup failed). */
struct sweep_ctx {
  fc_state_t *fc;
  fc_permit_t *victim;           /* the permit behind the evicted entry */
  fc_permit_t *leaver;           /* hooks 3, 4: a waiter whose client leaves */
  fc_permit_t *extra;            /* hook 4: a critical arrival */
  int answered;                  /* the 429 this path wrote */
  int hook;
  int owner_rc;                  /* what that owner's resume returned */
};

static int
sweep_fn(void *ctx, const fc_queue_ent_t *e)
{
  struct sweep_ctx *s = ctx;

  assert(e->band == B);
  if (s->hook == 1)
    s->owner_rc = fc_queue_owner_resume(s->fc, s->victim, MS(2000));
  if (s->hook >= 3) {
    s->owner_rc = fc_queue_owner_resume(s->fc, s->victim, MS(2000));
    fc_permit_release(s->leaver);
    park(s->fc, s->victim, B, e->fd, MS(2500));
    assert(s->victim->q_gen == e->gen);
  }
  if (s->hook == 4) {
    park(s->fc, s->extra, C, 12, MS(2600));
    return 0;
  }
  if (!fc_queue_evicted_settle(s->fc, s->victim, e->fd, e->gen))
    return 0;
  if (s->hook == 2)
    s->owner_rc = fc_queue_owner_resume(s->fc, s->victim, MS(2000));
  s->answered++;
  return 1;
}

/* One running, one sheddable waiting (fd 10) at depth 1, then a critical
 * arrival (fd 11) that evicts it: the sheddable is owed its 429. */
static void
evicted_setup(fc_state_t *fc, fc_permit_t *run, fc_permit_t *b, fc_permit_t *c)
{
  pool(fc, 1);
  fc_set_wake_hook(count_wake);
  woken_n = 0;
  fc_permit_init(run);
  fc_permit_init(b);
  fc_permit_init(c);
  assert(admit(fc, run, S) == FC_ADMIT);
  park(fc, b, B, 10, MS(1));
  park(fc, c, C, 11, MS(2));
  assert(fc_queue_evicted(fc) == 1 && woken_n == 1);
  assert(dec(fc, FC_R_SHED) == 1);
}

static void
evicted_teardown(fc_state_t *fc, fc_permit_t *run, fc_permit_t *b, fc_permit_t *c)
{
  int w = woken_n;

  /* The evicted client's connection ends: nothing to cancel, nobody woken
   * for a turn it never had. */
  fc_permit_release(b);
  /* Released, or NONE: the owner answered its own eviction and the
   * permit was left for the next request (a release of NONE is nothing). */
  assert((b->state == FC_P_RELEASED || b->state == FC_P_NONE) && woken_n == w);
  assert(dec(fc, FC_R_CANCELLED) == 0);
  fc_permit_release(c);
  fc_permit_release(run);
  fc_set_wake_hook(NULL);
  fc_state_destroy(fc);
}

static void
test_owner_stalled_sweep_wins(void)
{
  fc_state_t fc;
  fc_permit_t run, b, c;
  struct sweep_ctx s = { .fc = &fc, .victim = &b };

  evicted_setup(&fc, &run, &b, &c);
  /* The owner's resume is a second late: the 1 Hz pass answers. */
  assert(fc_queue_evicted_sweep(&fc, UINT64_MAX, sweep_fn, &s) == 1);
  assert(s.answered == 1 && b.state == FC_P_EVICTED && fc_queue_evicted(&fc) == 0);
  /* The late resume finds the request decided and does nothing: no second
   * answer, no turn, nothing admitted. */
  assert(fc_queue_owner_resume(&fc, &b, MS(3000)) == FC_RESUME_DECIDED);
  assert(b.state == FC_P_EVICTED && b.woken == 0);
  assert(dec(&fc, FC_R_SHED) == 1 && dec(&fc, FC_R_ADMITTED) == 1);
  evicted_teardown(&fc, &run, &b, &c);
  printf("  ok owner stalled: the pass answers, the late resume does nothing\n");
}

static void
test_owner_first_sweep_skips(void)
{
  fc_state_t fc;
  fc_permit_t run, b, c;
  struct sweep_ctx s = { .fc = &fc, .victim = &b };

  evicted_setup(&fc, &run, &b, &c);
  /* The owner resumes in time: the eviction's answer is its own. */
  assert(fc_queue_owner_resume(&fc, &b, MS(500)) == FC_RESUME_EVICTED);
  assert(b.state == FC_P_NONE && fc_queue_evicted(&fc) == 0);
  /* The pass finds nobody owed. */
  assert(fc_queue_evicted_sweep(&fc, UINT64_MAX, sweep_fn, &s) == 0);
  assert(s.answered == 0);
  assert(dec(&fc, FC_R_SHED) == 1 && dec(&fc, FC_R_ADMITTED) == 1);
  evicted_teardown(&fc, &run, &b, &c);
  printf("  ok owner first: its resume answers, the pass skips\n");
}

static void
test_each_inside_the_others_window(void)
{
  fc_state_t fc;
  fc_permit_t run, b, c;

  /* The pass has the entry in hand; the owner claims it before the pass
   * swaps: the owner answers, the pass loses the swap and writes nothing. */
  {
    struct sweep_ctx s = { .fc = &fc, .victim = &b, .hook = 1 };

    evicted_setup(&fc, &run, &b, &c);
    assert(fc_queue_evicted_sweep(&fc, UINT64_MAX, sweep_fn, &s) == 0);
    assert(s.owner_rc == FC_RESUME_EVICTED && s.answered == 0);
    assert(fc_queue_evicted(&fc) == 0 && dec(&fc, FC_R_SHED) == 1);
    evicted_teardown(&fc, &run, &b, &c);
  }
  /* The pass takes the entry and swaps first; the owner's resume then finds
   * the permit decided and does nothing. */
  {
    struct sweep_ctx s = { .fc = &fc, .victim = &b, .hook = 2 };

    evicted_setup(&fc, &run, &b, &c);
    assert(fc_queue_evicted_sweep(&fc, UINT64_MAX, sweep_fn, &s) == 1);
    assert(s.owner_rc == FC_RESUME_DECIDED && s.answered == 1);
    assert(b.state == FC_P_EVICTED && fc_queue_evicted(&fc) == 0);
    evicted_teardown(&fc, &run, &b, &c);
  }
  printf("  ok inside each other's window: one answer either way\n");
}

/* (fd, gen) names a connection, not a wait. The owner answers its eviction
 * (429, the connection kept) while the pass has the entry in hand, and the
 * connection's next request parks under the same pair: the pass must leave
 * that request alone. And when that request is evicted too while the pass
 * skips the first entry, its own entry stays owed. */
static void
test_same_connection_next_request(void)
{
  fc_state_t fc;
  fc_permit_t run, b, c, d;

  {
    struct sweep_ctx s = { .fc = &fc, .victim = &b, .leaver = &c, .hook = 3 };

    evicted_setup(&fc, &run, &b, &c);
    assert(fc_queue_evicted_sweep(&fc, UINT64_MAX, sweep_fn, &s) == 0);
    assert(s.owner_rc == FC_RESUME_EVICTED && s.answered == 0);
    assert(b.state == FC_P_QUEUED && fc_queue_holds(&fc, &b));
    assert(fc_queue_evicted(&fc) == 0 && dec(&fc, FC_R_SHED) == 1);
    assert(fc_queue_take(&fc, &b) == 1 && b.state == FC_P_ENDED);
    fc_permit_release(&b);
    fc_permit_release(&run);
    fc_set_wake_hook(NULL);
    fc_state_destroy(&fc);
  }
  {
    struct sweep_ctx s = { .fc = &fc, .victim = &b, .leaver = &c, .extra = &d, .hook = 4 };

    evicted_setup(&fc, &run, &b, &c);
    fc_permit_init(&d);
    assert(fc_queue_evicted_sweep(&fc, UINT64_MAX, sweep_fn, &s) == 0);
    assert(s.answered == 0 && dec(&fc, FC_R_SHED) == 2);
    /* The second eviction is still owed: its owner claims it. */
    assert(fc_queue_evicted(&fc) == 1);
    assert(fc_queue_owner_resume(&fc, &b, MS(3000)) == FC_RESUME_EVICTED);
    assert(fc_queue_evicted(&fc) == 0);
    fc_permit_release(&b);
    fc_permit_release(&d);
    fc_permit_release(&run);
    fc_set_wake_hook(NULL);
    fc_state_destroy(&fc);
  }
  printf("  ok the next request on the same connection: the pass leaves it alone\n");
}

static void
test_deadline_and_turn(void)
{
  fc_state_t fc;
  fc_permit_t run, w;

  /* The deadline takes a waiter: the permit leaves QUEUED with the entry,
   * and a resume after it (a stale wake) does nothing. */
  pool(&fc, 2);
  fc_set_wake_hook(count_wake);
  woken_n = 0;
  fc_permit_init(&run);
  fc_permit_init(&w);
  assert(admit(&fc, &run, S) == FC_ADMIT);
  park(&fc, &w, S, 20, MS(1));
  assert(fc_queue_owner_resume(&fc, &w, MS(100)) == FC_RESUME_WAIT);
  assert(fc_queue_take(&fc, &w) == 1 && w.state == FC_P_ENDED);
  assert(fc_queue_take(&fc, &w) == 0);
  assert(fc_queue_owner_resume(&fc, &w, MS(6000)) == FC_RESUME_DECIDED);
  /* Its connection ends: the deadline answered it, nobody is woken. */
  fc_permit_release(&w);
  assert(w.state == FC_P_RELEASED && woken_n == 0);
  assert(dec(&fc, FC_R_CANCELLED) == 0);

  /* The mirror: popped for its turn, the owner takes it and the deadline
   * finds nothing to take. */
  fc_permit_init(&w);
  park(&fc, &w, S, 21, MS(2));
  fc_permit_release(&run);               /* the unit frees: w's turn */
  assert(woken_n == 1);
  assert(fc_queue_owner_resume(&fc, &w, MS(10)) == FC_RESUME_TURN);
  assert(w.state == FC_P_NONE && w.woken == 1);
  assert(fc_queue_take(&fc, &w) == 0);
  assert(admit(&fc, &w, S) == FC_ADMIT);
  fc_permit_release(&w);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
  printf("  ok deadline: the take decides, a late resume does nothing; a turn is the owner's\n");
}

static int
drain_fn(void *ctx, const fc_queue_ent_t *e)
{
  fc_permit_t *p = ctx;

  (void)e;
  return fc_permit_settle(p, FC_P_ENDED);
}

static void
test_drain(void)
{
  fc_state_t fc;
  fc_permit_t run, w;

  pool(&fc, 2);
  fc_permit_init(&run);
  fc_permit_init(&w);
  assert(admit(&fc, &run, S) == FC_ADMIT);
  park(&fc, &w, S, 30, MS(1));
  fc_queue_drain(&fc, drain_fn, &w);
  assert(w.state == FC_P_ENDED && dec(&fc, FC_R_DRAINED) == 1);
  assert(fc_queue_owner_resume(&fc, &w, MS(10)) == FC_RESUME_DECIDED);
  fc_permit_release(&w);
  fc_permit_release(&run);
  fc_state_destroy(&fc);
  printf("  ok drain: the drain decides, a late resume does nothing\n");
}

/* Two threads, many times: the pass and the owner's resume start together
 * on an eviction; then the deadline and a stale resume on a waiter. */
/* Both threads start together: each arrives, then waits for the other. */
typedef struct { atomic_int n; } start_t;

static void
start_wait(start_t *g)
{
  atomic_fetch_add(&g->n, 1);
  while (atomic_load(&g->n) < 2)
    ;
}

struct race {
  fc_state_t *fc;
  fc_permit_t *p;
  start_t *bar;
  struct sweep_ctx *s;
  int rc;
};

static void *
race_sweep(void *arg)
{
  struct race *r = arg;

  start_wait(r->bar);
  r->rc = (int)fc_queue_evicted_sweep(r->fc, UINT64_MAX, sweep_fn, r->s);
  return NULL;
}

static void *
race_owner(void *arg)
{
  struct race *r = arg;

  start_wait(r->bar);
  r->rc = fc_queue_owner_resume(r->fc, r->p, MS(2000));
  return NULL;
}

static void *
race_take(void *arg)
{
  struct race *r = arg;

  start_wait(r->bar);
  r->rc = fc_queue_take(r->fc, r->p);
  return NULL;
}

static void
test_threads(void)
{
  int owner_won = 0, sweep_won = 0;

  for (int i = 0; i < 2000; i++) {
    fc_state_t fc;
    fc_permit_t run, b, c;
    start_t bar = { 0 };
    struct sweep_ctx s = { .fc = &fc, .victim = &b };
    struct race rs = { .fc = &fc, .bar = &bar, .s = &s };
    struct race ro = { .fc = &fc, .p = &b, .bar = &bar };
    pthread_t t1, t2;

    evicted_setup(&fc, &run, &b, &c);
    pthread_create(&t1, NULL, race_sweep, &rs);
    pthread_create(&t2, NULL, race_owner, &ro);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    /* Exactly one of them answers; the other did nothing. */
    assert(s.answered + (ro.rc == FC_RESUME_EVICTED) == 1);
    assert(ro.rc == FC_RESUME_EVICTED || ro.rc == FC_RESUME_DECIDED);
    assert(fc_queue_evicted(&fc) == 0 && dec(&fc, FC_R_SHED) == 1);
    owner_won += ro.rc == FC_RESUME_EVICTED;
    sweep_won += s.answered;
    evicted_teardown(&fc, &run, &b, &c);
  }
  for (int i = 0; i < 2000; i++) {
    fc_state_t fc;
    fc_permit_t run, w;
    start_t bar = { 0 };
    struct race rt = { .fc = &fc, .p = &w, .bar = &bar };
    struct race ro = { .fc = &fc, .p = &w, .bar = &bar };
    pthread_t t1, t2;

    pool(&fc, 2);
    fc_permit_init(&run);
    fc_permit_init(&w);
    assert(admit(&fc, &run, S) == FC_ADMIT);
    park(&fc, &w, S, 40, MS(1));
    pthread_create(&t1, NULL, race_take, &rt);
    pthread_create(&t2, NULL, race_owner, &ro);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    /* Nobody popped it: the deadline takes it, and the stale resume is
     * either before (still waiting) or after (decided), never a turn. */
    assert(rt.rc == 1 && w.state == FC_P_ENDED);
    assert(ro.rc == FC_RESUME_WAIT || ro.rc == FC_RESUME_DECIDED);
    fc_permit_release(&w);
    fc_permit_release(&run);
    fc_state_destroy(&fc);
  }
  printf("  ok two threads x2000 each: one answer every time (owner %d, pass %d)\n",
         owner_won, sweep_won);
}

int
main(void)
{
  printf("test_fc_settle:\n");
  test_owner_stalled_sweep_wins();
  test_owner_first_sweep_skips();
  test_each_inside_the_others_window();
  test_same_connection_next_request();
  test_deadline_and_turn();
  test_drain();
  test_threads();
  printf("test_fc_settle: all passed\n");
  return 0;
}
