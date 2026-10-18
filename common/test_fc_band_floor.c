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
 * The floors and the reserve of the capacity gate, driven alone.
 *
 * A floor (fc_band_min_share_pct) is a guarantee under contention, not a
 * reservation: it binds only while its band has a waiter. The reserve
 * (fc_critical_reserve_pct) is the one true reservation: units no other band
 * may take even while critical is idle. The resume rule the gate implements:
 * when a unit frees, the highest-ranked band that is below its floor and has
 * a runnable waiter takes it; when no band is below its floor, the wake
 * policy chooses. A request of a band at or above its own floor takes a unit
 * only if the units left after it still cover what every other band with a
 * waiter is short of its floor, and what critical is short of its reserve.
 *
 * Covered: the unit arithmetic (rounding in the band's favour, never the
 * whole ceiling for a share under 100, the claims never above the ceiling);
 * a floor costs nothing without demand; a floor binds with a waiter, on the
 * HTTP/1.1 path and on a path that cannot wait (an HTTP/2 stream, a role
 * leg); the reserve holds with critical idle; the resume order under floors
 * and, with every band at its floor, the policy's; a floor follows the
 * adaptive ceiling; a waiter held back by its tenant's share is no demand;
 * a wake loop promises each unit once; a unit that is reserved wakes
 * nobody; and the starvation case (strict, saturating critical demand, a 10 %
 * sheddable floor holds sheddable throughput, with the floor at 0 it is
 * starved).
 *
 * Build: make test_fc_band_floor (also run by `make test_fc`).
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

typedef struct pool_opts {
  uint32_t cap;
  uint32_t depth;
  uint8_t  wake;
  uint8_t  floor[FC_BANDS];      /* by band */
  uint8_t  weight[FC_BANDS];     /* by band; read with the weighted wake */
  uint8_t  reserve;
  uint8_t  share_pct;
  uint8_t  adaptive;
} pool_opts_t;

static void
pool_make(fc_state_t *fc, const pool_opts_t *o)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = o->cap;
  cfg.max_queue_depth = o->depth;
  cfg.max_queue_wait_ms = o->depth ? 5000 : 0;
  cfg.wake_policy = o->wake;
  cfg.shed_queue = o->depth ? 1 : 0;
  cfg.tenant_share_pct = o->share_pct;
  cfg.adaptive = o->adaptive;
  memcpy(cfg.band_min_share_pct, o->floor, sizeof(cfg.band_min_share_pct));
  memcpy(cfg.band_weight, o->weight, sizeof(cfg.band_weight));
  cfg.critical_reserve_pct = o->reserve;
  fc_state_apply(fc, &cfg);
}

static int woken_fd[512];
static int woken_n;

static int
record_wake(int fd, uint64_t gen)
{
  (void)gen;
  assert(woken_n < 512);
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

/* A request that cannot wait: an HTTP/2 stream or a role leg. */
static fc_verdict_t
admit_nowait(fc_state_t *fc, fc_permit_t *p, uint8_t band)
{
  fc_verdict_t v = fc_service_acquire_band(fc, p, fc_tenant_key(NULL), band);

  if (v == FC_ADMIT && p->state == FC_P_EXECUTING)
    assert(fc_ep_acquire(fc, p, 0, FC_ROLE_NORMAL) == FC_ADMIT);
  return v;
}

/* A waiter put in the queue by hand, as a request that lost its unit. */
static void
wait_by_hand(fc_state_t *fc, fc_permit_t *w, uint8_t band, int fd, uint64_t now,
             uint64_t tkey)
{
  fc_permit_init(w);
  w->band = band;
  w->tkey = tkey;
  assert(fc_queue_push(fc, w, fd, 1, now, 0) == 0);
}

static void
take_fd(fc_state_t *fc, fc_permit_t *w, uint8_t band, uint64_t tkey)
{
  fc_queue_resumed(fc, w, MS(1000));
  assert(admit(fc, w, band, 1, tkey) == FC_ADMIT);
}

/* ---- unit arithmetic ------------------------------------------------------ */

typedef struct claim_case {
  uint32_t cap;
  uint8_t  floor[FC_BANDS];      /* by band */
  uint8_t  reserve;
  uint32_t want_floor[FC_BANDS];
  uint32_t want_reserve;
} claim_case_t;

static void
test_unit_arithmetic(void)
{
  /* The shared vectors: the Go read-back mirrors this table. */
  assert(fc_floor_units(4, 25) == 1);
  assert(fc_floor_units(1, 50) == 0);    /* never the whole ceiling */
  assert(fc_floor_units(2, 99) == 1);
  assert(fc_floor_units(10, 10) == 1);
  assert(fc_floor_units(10, 100) == 10); /* 100 is the whole ceiling, asked for */
  assert(fc_floor_units(0, 50) == 0);
  assert(fc_floor_units(10, 0) == 0);
  assert(fc_floor_units(7, 20) == 2);    /* 1.4 rounds up, in the band's favour */
  assert(fc_floor_units(3, 34) == 2);    /* 1.02 rounds up, not to the ceiling */

  {
    fc_cfg_t c;
    uint32_t f[FC_BANDS], r;

    memset(&c, 0, sizeof(c));
    /* 34:33:33 of 4 rounds to 2 each, 6 > 4: clamped in rank order. */
    c.band_min_share_pct[C] = 34;
    c.band_min_share_pct[S] = 33;
    c.band_min_share_pct[B] = 33;
    fc_floor_claims(&c, 4, f, &r);
    assert(f[C] == 2 && f[S] == 2 && f[B] == 0 && r == 0);
    assert(f[C] + f[S] + f[B] <= 4);

    /* A reserve alone: critical's claim is the reserve. */
    memset(&c, 0, sizeof(c));
    c.critical_reserve_pct = 25;
    fc_floor_claims(&c, 4, f, &r);
    assert(r == 1 && f[C] == 0 && f[S] == 0 && f[B] == 0);

    /* Critical holds the larger of its floor and its reserve: the others
     * are clamped against that, not against the sum. */
    memset(&c, 0, sizeof(c));
    c.critical_reserve_pct = 30;
    c.band_min_share_pct[C] = 10;
    c.band_min_share_pct[S] = 40;
    c.band_min_share_pct[B] = 30;
    fc_floor_claims(&c, 10, f, &r);
    assert(r == 3 && f[C] == 1 && f[S] == 4 && f[B] == 3);
    assert(3 + f[S] + f[B] <= 10);

    /* The reserve is clamped to the ceiling it is part of. */
    memset(&c, 0, sizeof(c));
    c.critical_reserve_pct = 100;
    c.band_min_share_pct[S] = 50;
    fc_floor_claims(&c, 6, f, &r);
    assert(r == 6 && f[S] == 0);

    /* No ceiling: nothing is owed. */
    fc_floor_claims(&c, 0, f, &r);
    assert(r == 0 && f[C] == 0 && f[S] == 0 && f[B] == 0);
  }
  printf("  ok unit arithmetic\n");
}

/* ---- a floor is not a reservation ----------------------------------------- */

static void
test_floor_costs_nothing_without_demand(void)
{
  pool_opts_t o = { .cap = 10, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t p[10], extra;
  fc_state_t fc;

  /* A 20 % sheddable floor and no sheddable demand: standard takes 100 %. */
  o.floor[B] = 20;
  pool_make(&fc, &o);
  for (int i = 0; i < 10; i++) {
    fc_permit_init(&p[i]);
    assert(admit(&fc, &p[i], S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  }
  assert(fc_inflight(&fc) == 10);
  fc_permit_init(&extra);
  assert(admit(&fc, &extra, S, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  for (int i = 0; i < 10; i++)
    fc_permit_release(&p[i]);
  fc_state_destroy(&fc);

  /* The same for critical, and for an HTTP/2 stream. */
  pool_make(&fc, &o);
  for (int i = 0; i < 10; i++) {
    fc_permit_init(&p[i]);
    assert(admit_nowait(&fc, &p[i], i & 1 ? C : S) == FC_ADMIT);
  }
  assert(admit_nowait(&fc, &extra, S) == FC_SHED);
  for (int i = 0; i < 10; i++)
    fc_permit_release(&p[i]);
  fc_state_destroy(&fc);
  printf("  ok a floor costs nothing without demand\n");
}

static void
test_floor_binds_with_a_waiter(void)
{
  pool_opts_t o = { .cap = 4, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t c[3], w, n;
  fc_state_t fc;

  o.floor[B] = 25;                     /* one unit of four */
  pool_make(&fc, &o);
  for (int i = 0; i < 3; i++) {
    fc_permit_init(&c[i]);
    assert(admit(&fc, &c[i], C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  }
  /* A free unit, and a sheddable waiter below its floor. */
  wait_by_hand(&fc, &w, B, 40, MS(1), fc_tenant_key(NULL));
  fc_permit_init(&n);
  assert(admit(&fc, &n, S, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(admit(&fc, &n, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  /* A second sheddable request waits behind the one of its own band. */
  assert(admit(&fc, &n, B, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(fc_inflight(&fc) == 3);

  /* The waiter gone, the unit is anybody's: a floor is not a reservation. */
  fc_permit_release(&w);
  assert(admit(&fc, &n, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release_nowake(&n);

  /* A band at its floor owes nothing to the waiter of that band. */
  fc_permit_init(&n);
  assert(admit(&fc, &n, B, 0, fc_tenant_key(NULL)) == FC_ADMIT);     /* sheddable at 1 */
  wait_by_hand(&fc, &w, B, 41, MS(2), fc_tenant_key(NULL));
  {
    fc_permit_t m;
    fc_permit_init(&m);
    /* All four held (3 critical + the sheddable): no unit to take. */
    assert(admit(&fc, &m, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
    fc_permit_release_nowake(&n);
    /* Three held; the floor of the waiting sheddable band is unmet again. */
    assert(admit(&fc, &m, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  }
  fc_permit_release(&w);
  for (int i = 0; i < 3; i++)
    fc_permit_release(&c[i]);
  fc_state_destroy(&fc);
  printf("  ok a floor binds while its band has a waiter\n");
}

/* A band below its floor does not wait behind the other bands' waiters. */
static void
test_below_floor_newcomer_is_not_made_to_wait(void)
{
  pool_opts_t o = { .cap = 4, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t c1, c2, wc, n;
  fc_state_t fc;

  o.floor[B] = 25;
  pool_make(&fc, &o);
  fc_permit_init(&c1);
  fc_permit_init(&c2);
  assert(admit(&fc, &c1, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &c2, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  /* A critical waiter is queued (a wake on its way) and two units are free:
   * a sheddable newcomer, below its floor, takes one rather than queue
   * behind a higher band; a standard newcomer, at no floor, queues. */
  wait_by_hand(&fc, &wc, C, 120, MS(1), fc_tenant_key(NULL));
  fc_permit_init(&n);
  assert(admit(&fc, &n, S, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(admit(&fc, &n, B, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release_nowake(&n);
  fc_permit_release(&wc);
  fc_permit_release(&c1);
  fc_permit_release(&c2);
  fc_state_destroy(&fc);
  printf("  ok a band below its floor is not made to wait behind another band\n");
}

/* The same on a pool with a tenant share, read under the lock. */
static void
test_below_floor_newcomer_on_a_pool_with_a_share(void)
{
  pool_opts_t o = { .cap = 4, .depth = 8, .wake = FC_WAKE_STRICT, .share_pct = 50 };
  fc_permit_t c1, wc, n;
  fc_state_t fc;

  o.floor[B] = 25;
  pool_make(&fc, &o);
  fc_permit_init(&c1);
  assert(admit(&fc, &c1, C, 0, fc_tenant_key("t1")) == FC_ADMIT);
  wait_by_hand(&fc, &wc, C, 140, MS(1), fc_tenant_key("t2"));
  fc_permit_init(&n);
  assert(admit(&fc, &n, S, 0, fc_tenant_key("t3")) == FC_QUEUE);
  assert(admit(&fc, &n, B, 0, fc_tenant_key("t3")) == FC_ADMIT);
  fc_permit_release_nowake(&n);
  fc_permit_release(&wc);
  fc_permit_release(&c1);
  fc_state_destroy(&fc);
  printf("  ok a band below its floor on a pool with a share\n");
}

/* Critical below the larger of its floor and its reserve takes its own units. */
static void
test_critical_claim_is_the_larger_of_floor_and_reserve(void)
{
  pool_opts_t o = { .cap = 10, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t c[2], s[4], w, n;
  fc_state_t fc;

  o.floor[C] = 30;                     /* three units */
  o.reserve = 10;                      /* one unit */
  o.floor[B] = 40;                     /* four units */
  pool_make(&fc, &o);
  for (int i = 0; i < 2; i++) {
    fc_permit_init(&c[i]);
    assert(admit(&fc, &c[i], C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  }
  for (int i = 0; i < 4; i++) {
    fc_permit_init(&s[i]);
    assert(admit(&fc, &s[i], S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  }
  /* Six held, a sheddable waiter owed four. Critical holds two of its
   * three: it is below its floor, so it takes the next unit; standard,
   * at no floor, is held back by the sheddable floor. */
  wait_by_hand(&fc, &w, B, 130, MS(1), fc_tenant_key(NULL));
  fc_permit_init(&n);
  assert(admit(&fc, &n, S, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(admit(&fc, &n, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  /* Critical at three is at its floor: it yields to the sheddable floor. */
  {
    fc_permit_t m;
    fc_permit_init(&m);
    assert(admit(&fc, &m, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  }
  fc_permit_release_nowake(&n);
  fc_permit_release(&w);
  for (int i = 0; i < 2; i++)
    fc_permit_release(&c[i]);
  for (int i = 0; i < 4; i++)
    fc_permit_release(&s[i]);
  fc_state_destroy(&fc);
  printf("  ok critical's claim is the larger of its floor and its reserve\n");
}

/* ---- the reserve ---------------------------------------------------------- */

static void
test_reserve_holds_with_critical_idle(void)
{
  pool_opts_t o = { .cap = 4, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t s[3], c, x;
  fc_state_t fc;

  o.reserve = 25;                      /* one unit of four */
  pool_make(&fc, &o);
  for (int i = 0; i < 3; i++) {
    fc_permit_init(&s[i]);
    assert(admit(&fc, &s[i], S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  }
  /* Critical is idle and there is no waiter anywhere: the fourth unit is
   * still not standard's, nor sheddable's. */
  fc_permit_init(&x);
  assert(admit(&fc, &x, S, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(admit(&fc, &x, B, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  fc_permit_init(&c);
  assert(admit(&fc, &c, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  /* Critical above its reserve takes from the pool like any band. */
  fc_permit_release(&c);
  fc_permit_init(&c);
  fc_permit_release(&s[0]);
  assert(admit(&fc, &c, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  {
    fc_permit_t c2;
    fc_permit_init(&c2);
    assert(admit(&fc, &c2, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
    fc_permit_release(&c2);
  }
  fc_permit_release(&c);
  fc_permit_release(&s[1]);
  fc_permit_release(&s[2]);
  fc_state_destroy(&fc);

  /* A path that cannot wait is refused the same way. */
  pool_make(&fc, &o);
  for (int i = 0; i < 3; i++) {
    fc_permit_init(&s[i]);
    assert(admit_nowait(&fc, &s[i], S) == FC_ADMIT);
  }
  fc_permit_init(&x);
  assert(admit_nowait(&fc, &x, S) == FC_SHED);
  assert(admit_nowait(&fc, &x, B) == FC_SHED);    /* shed queue on: not the band's shed */
  fc_permit_init(&c);
  assert(admit_nowait(&fc, &c, C) == FC_ADMIT);
  fc_permit_release(&c);
  for (int i = 0; i < 3; i++)
    fc_permit_release(&s[i]);
  fc_state_destroy(&fc);
  printf("  ok the reserve holds with critical idle\n");
}

static void
test_reserve_unused_wakes_nobody(void)
{
  pool_opts_t o = { .cap = 4, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t s[3], w, c;
  fc_state_t fc;

  o.reserve = 25;
  pool_make(&fc, &o);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  for (int i = 0; i < 3; i++) {
    fc_permit_init(&s[i]);
    assert(admit(&fc, &s[i], S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  }
  wait_by_hand(&fc, &w, S, 50, MS(1), fc_tenant_key(NULL));
  /* One unit free, and it is the reserve: nobody is woken for it. */
  fc_queue_wake_one(&fc);
  assert(woken_n == 0 && fc_queued(&fc) == 1);
  fc_permit_init(&c);
  assert(admit(&fc, &c, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release(&c);                 /* the reserve is back: still nobody */
  assert(woken_n == 0);
  fc_permit_release(&s[0]);              /* a unit that is not the reserve */
  assert(woken_n == 1 && woken_fd[0] == 50);
  take_fd(&fc, &w, S, fc_tenant_key(NULL));
  fc_permit_release(&w);
  fc_permit_release(&s[1]);
  fc_permit_release(&s[2]);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
  printf("  ok a reserved unit wakes nobody\n");
}

/* ---- the resume order ----------------------------------------------------- */

static void
test_resume_order_below_floor_first(void)
{
  pool_opts_t o = { .cap = 2, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t c1, c2, wc, wb;
  fc_state_t fc;

  o.floor[B] = 50;                     /* one unit of two */
  pool_make(&fc, &o);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  fc_permit_init(&c1);
  fc_permit_init(&c2);
  assert(admit(&fc, &c1, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &c2, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  /* The critical waiter is older and ranks higher; the sheddable waiter is
   * below its floor. A freed unit goes to the one below its floor. */
  wait_by_hand(&fc, &wc, C, 60, MS(1), fc_tenant_key(NULL));
  wait_by_hand(&fc, &wb, B, 61, MS(2), fc_tenant_key(NULL));
  fc_permit_release(&c1);
  assert(woken_n == 1 && woken_fd[0] == 61);
  take_fd(&fc, &wb, B, fc_tenant_key(NULL));
  /* The sheddable band is at its floor: the policy decides again. */
  fc_permit_release(&c2);
  assert(woken_n == 2 && woken_fd[1] == 60);
  take_fd(&fc, &wc, C, fc_tenant_key(NULL));
  fc_permit_release(&wc);
  fc_permit_release(&wb);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
  printf("  ok a band below its floor is served before the policy's choice\n");
}

static void
test_resume_order_policy_decides_at_floors(void)
{
  static const struct { uint8_t wake; int want; } k[] = {
    { FC_WAKE_STRICT, 22 },            /* the highest band */
    { FC_WAKE_WEIGHTED, 22 },          /* a fresh round: the highest band with credit */
  };

  for (unsigned i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
    pool_opts_t o = { .cap = 4, .depth = 8, .wake = k[i].wake,
                      .weight = { [C] = 8, [S] = 3, [B] = 1 } };
    fc_permit_t c1, c2, b1, s1, wb, ws, wc;
    fc_state_t fc;

    o.floor[B] = 25;                   /* one unit of four */
    pool_make(&fc, &o);
    fc_set_wake_hook(record_wake);
    woken_n = 0;
    fc_permit_init(&c1);
    fc_permit_init(&c2);
    fc_permit_init(&b1);
    fc_permit_init(&s1);
    assert(admit(&fc, &c1, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
    assert(admit(&fc, &c2, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
    assert(admit(&fc, &b1, B, 0, fc_tenant_key(NULL)) == FC_ADMIT);
    assert(admit(&fc, &s1, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
    /* Every band is at or above its floor: sheddable holds exactly one. */
    wait_by_hand(&fc, &wb, B, 20, MS(1), fc_tenant_key(NULL));
    wait_by_hand(&fc, &ws, S, 21, MS(2), fc_tenant_key(NULL));
    wait_by_hand(&fc, &wc, C, 22, MS(3), fc_tenant_key(NULL));
    fc_permit_release(&s1);
    assert(woken_n == 1 && woken_fd[0] == k[i].want);
    fc_permit_release(&wb);
    fc_permit_release(&ws);
    fc_permit_release(&wc);
    fc_permit_release(&c1);
    fc_permit_release(&c2);
    fc_permit_release(&b1);
    fc_set_wake_hook(NULL);
    fc_state_destroy(&fc);
  }
  printf("  ok at or above their floors the policy decides\n");
}

/* ---- paths that cannot wait ------------------------------------------------ */

static void
test_floor_on_a_path_that_cannot_wait(void)
{
  pool_opts_t o = { .cap = 4, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t p[4], w, x;
  fc_state_t fc;

  o.floor[B] = 25;
  pool_make(&fc, &o);
  /* No waiter of the floored band: an HTTP/2 stream takes every unit. */
  for (int i = 0; i < 4; i++) {
    fc_permit_init(&p[i]);
    assert(admit_nowait(&fc, &p[i], i & 1 ? C : S) == FC_ADMIT);
  }
  for (int i = 0; i < 4; i++)
    fc_permit_release(&p[i]);

  /* With an HTTP/1.1 waiter of that band, a stream of another band is
   * refused the unit the waiter is owed, with the plain capacity refusal. */
  for (int i = 0; i < 3; i++) {
    fc_permit_init(&p[i]);
    assert(admit_nowait(&fc, &p[i], S) == FC_ADMIT);
  }
  wait_by_hand(&fc, &w, B, 70, MS(1), fc_tenant_key(NULL));
  fc_permit_init(&x);
  assert(admit_nowait(&fc, &x, S) == FC_SHED);
  assert(admit_nowait(&fc, &x, C) == FC_SHED);
  /* A stream of the floored band does not overtake its own band's waiter
   * either: the unit is the waiter's. */
  assert(admit_nowait(&fc, &x, B) == FC_SHED);
  fc_permit_release(&w);
  for (int i = 0; i < 3; i++)
    fc_permit_release(&p[i]);
  fc_state_destroy(&fc);
  printf("  ok a floor on a path that cannot wait\n");
}

/* ---- the adaptive ceiling -------------------------------------------------- */

static void
test_floor_follows_the_adaptive_ceiling(void)
{
  pool_opts_t o = { .cap = 10, .depth = 8, .wake = FC_WAKE_STRICT, .adaptive = 1 };
  fc_permit_t p[10], w, n;
  fc_state_t fc;

  o.floor[B] = 20;
  pool_make(&fc, &o);
  assert(fc_svc_cap(&fc) == 10);
  wait_by_hand(&fc, &w, B, 80, MS(1), fc_tenant_key(NULL));
  /* At 10 the floor is 2 units: critical may hold 8, not 9. */
  for (int i = 0; i < 8; i++) {
    fc_permit_init(&p[i]);
    assert(admit(&fc, &p[i], C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  }
  fc_permit_init(&n);
  assert(admit(&fc, &n, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  for (int i = 0; i < 8; i++)
    fc_permit_release_nowake(&p[i]);

  /* The ceiling tightens to 5: the floor is 1 unit, critical may hold 4,
   * and what was in flight is not cut. */
  atomic_store(&fc.eff_max, 5);
  for (int i = 0; i < 4; i++) {
    fc_permit_init(&p[i]);
    assert(admit(&fc, &p[i], C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  }
  assert(admit(&fc, &n, C, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  atomic_store(&fc.eff_max, 3);
  assert(fc_inflight(&fc) == 4);
  for (int i = 0; i < 4; i++)
    fc_permit_release_nowake(&p[i]);
  fc_permit_release(&w);
  fc_state_destroy(&fc);
  printf("  ok a floor follows the adaptive ceiling\n");
}

/* ---- a tenant share --------------------------------------------------------- */

static void
test_floor_waiter_held_by_its_tenant_share_is_no_demand(void)
{
  pool_opts_t o = { .cap = 4, .depth = 8, .wake = FC_WAKE_STRICT, .share_pct = 50 };
  fc_permit_t s1, s2, c1, w, n;
  fc_state_t fc;

  o.floor[B] = 25;
  pool_make(&fc, &o);
  fc_permit_init(&s1);
  fc_permit_init(&s2);
  fc_permit_init(&c1);
  assert(admit(&fc, &s1, S, 0, fc_tenant_key("t1")) == FC_ADMIT);
  assert(admit(&fc, &s2, S, 0, fc_tenant_key("t1")) == FC_ADMIT);
  assert(admit(&fc, &c1, C, 0, fc_tenant_key("t2")) == FC_ADMIT);
  /* t1 holds its share (two units): its sheddable waiter cannot run, so it
   * is no demand and the free unit is anybody's. */
  wait_by_hand(&fc, &w, B, 90, MS(1), fc_tenant_key("t1"));
  fc_permit_init(&n);
  assert(admit(&fc, &n, C, 0, fc_tenant_key("t3")) == FC_ADMIT);
  fc_permit_release_nowake(&n);
  fc_permit_release(&w);
  /* The same waiter from a tenant with room is demand. */
  wait_by_hand(&fc, &w, B, 91, MS(2), fc_tenant_key("t4"));
  fc_permit_init(&n);
  assert(admit(&fc, &n, C, 0, fc_tenant_key("t3")) == FC_QUEUE);
  fc_permit_release(&w);
  fc_permit_release(&s1);
  fc_permit_release(&s2);
  fc_permit_release(&c1);
  fc_state_destroy(&fc);
  printf("  ok a waiter held by its tenant's share is no demand\n");
}

/* ---- a wake loop promises each unit once ----------------------------------- */

static void
test_wake_room_promises_each_unit_once(void)
{
  pool_opts_t o = { .cap = 2, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t c1, c2, wb1, wb2, wc1;
  fc_state_t fc;
  fc_cfg_t cfg;

  o.floor[B] = 25;
  pool_make(&fc, &o);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  fc_permit_init(&c1);
  fc_permit_init(&c2);
  assert(admit(&fc, &c1, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &c2, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  wait_by_hand(&fc, &wb1, B, 100, MS(1), fc_tenant_key(NULL));
  wait_by_hand(&fc, &wb2, B, 101, MS(2), fc_tenant_key(NULL));
  wait_by_hand(&fc, &wc1, C, 102, MS(3), fc_tenant_key(NULL));
  /* The ceiling grows by two: two units are given, not both to sheddable.
   * The floor is one unit of four. */
  cfg = fc.cfg;
  cfg.max_outstanding = 4;
  fc_state_apply(&fc, &cfg);
  fc_queue_wake_room(&fc);
  assert(woken_n == 2);
  assert(woken_fd[0] == 100 && woken_fd[1] == 102);
  fc_permit_release(&wb1);
  fc_permit_release(&wb2);
  fc_permit_release(&wc1);
  fc_permit_release(&c1);
  fc_permit_release(&c2);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
  printf("  ok a wake loop promises each unit once\n");
}

/* ---- off, observe ---------------------------------------------------------- */

static void
test_floors_off_and_observe(void)
{
  pool_opts_t o = { .cap = 2, .depth = 8, .wake = FC_WAKE_STRICT };
  fc_permit_t a, b, w;
  fc_state_t fc;

  /* No floor, no reserve: the gate is today's. */
  pool_make(&fc, &o);
  assert(!fc_floors_on(&fc.cfg));
  wait_by_hand(&fc, &w, B, 110, MS(1), fc_tenant_key(NULL));
  fc_permit_init(&a);
  fc_permit_init(&b);
  assert(admit(&fc, &a, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &b, C, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release_nowake(&a);
  fc_permit_release_nowake(&b);
  fc_permit_release(&w);
  fc_state_destroy(&fc);

  /* Observe mode decides nothing, floors or not. */
  o.floor[B] = 50;
  o.reserve = 50;
  pool_make(&fc, &o);
  fc.cfg.mode = FC_MODE_OBSERVE;
  assert(admit(&fc, &a, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  assert(admit(&fc, &b, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release(&a);
  fc_permit_release(&b);
  fc_state_destroy(&fc);

  /* A pool with no ceiling owes nothing to a floor. */
  o.cap = 0;
  pool_make(&fc, &o);
  fc_permit_init(&a);
  assert(admit(&fc, &a, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
  fc_permit_release(&a);
  fc_state_destroy(&fc);
  printf("  ok floors off, observe, no ceiling\n");
}

/* ---- the starvation case ---------------------------------------------------- */

#define SIM_REQS 4096

typedef struct sim {
  fc_state_t fc;
  fc_permit_t req[SIM_REQS];
  uint8_t band[SIM_REQS];
  int finish[SIM_REQS];
  int held[SIM_REQS];            /* request numbers in flight */
  int n_held;
  int next;
  int adm[FC_BANDS];
} sim_t;

static sim_t *sim;

static int
sim_new(uint8_t band)
{
  int k = sim->next++;

  assert(k < SIM_REQS);
  fc_permit_init(&sim->req[k]);
  sim->band[k] = band;
  return k;
}

static void
sim_take(int k, int now, int hold)
{
  sim->finish[k] = now + hold;
  sim->held[sim->n_held++] = k;
  sim->adm[sim->band[k]]++;
}

static void
sim_drain_wakes(int now, int hold)
{
  while (woken_n > 0) {
    int fd = woken_fd[--woken_n];
    int k = fd - 1000;

    fc_queue_resumed(&sim->fc, &sim->req[k], MS(now));
    if (admit(&sim->fc, &sim->req[k], sim->band[k], 1, fc_tenant_key(NULL)) == FC_ADMIT)
      sim_take(k, now, hold);
    else
      assert(fc_queue_push(&sim->fc, &sim->req[k], fd, 1, MS(now), 1) == 0);
  }
}

/* A request of `band` arrives: it runs or parks. */
static void
sim_arrive(uint8_t band, int now, int hold)
{
  int k = sim_new(band);

  if (admit(&sim->fc, &sim->req[k], band, 0, fc_tenant_key(NULL)) == FC_ADMIT)
    sim_take(k, now, hold);
  else
    assert(fc_queue_push(&sim->fc, &sim->req[k], 1000 + k, 1, MS(now), 0) == 0);
}

/* Critical demand saturates a pool of ten units; sheddable keeps requests
 * waiting. Returns the sheddable requests admitted over `ticks`. */
static int
run_starvation(uint8_t shed_floor_pct, int ticks, int hold, int *crit_adm)
{
  pool_opts_t o = { .cap = 10, .depth = 4000, .wake = FC_WAKE_STRICT };

  sim = calloc(1, sizeof(*sim));
  assert(sim);
  o.floor[B] = shed_floor_pct;
  pool_make(&sim->fc, &o);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  /* Critical fills the pool, then every band keeps waiters. */
  for (int i = 0; i < 10; i++)
    sim_arrive(C, 0, hold);
  for (int t = 0; t < ticks; t++) {
    for (int i = 0; i < sim->n_held;) {
      int k = sim->held[i];

      if (sim->finish[k] <= t) {
        sim->held[i] = sim->held[--sim->n_held];
        fc_permit_release(&sim->req[k]);
        sim_drain_wakes(t, hold);
      } else {
        i++;
      }
    }
    while (fc_band_queued(&sim->fc, C) < 12)
      sim_arrive(C, t, hold);
    while (fc_band_queued(&sim->fc, B) < 3)
      sim_arrive(B, t, hold);
  }
  fc_set_wake_hook(NULL);
  if (crit_adm)
    *crit_adm = sim->adm[C];
  {
    int shed = sim->adm[B];

    for (int i = 0; i < sim->n_held; i++)
      fc_permit_release_nowake(&sim->req[sim->held[i]]);
    fc_state_destroy(&sim->fc);
    free(sim);
    sim = NULL;
    return shed;
  }
}

static void
test_starvation_and_its_mirror(void)
{
  int ticks = 400, hold = 4, crit, shed, crit0, shed0;

  /* Strict, saturating critical demand, a 10 % sheddable floor (one unit of
   * ten): sheddable never falls below it. One unit held for `hold` ticks is
   * ticks/hold requests; allow the start-up and the last window. */
  shed = run_starvation(10, ticks, hold, &crit);
  assert(shed >= ticks / hold - 2);
  assert(crit > 0);
  /* And it is a floor, not a lift: sheddable gets about its floor, not more
   * than a small multiple of it, while critical keeps the rest. */
  assert(shed <= ticks / hold + 2);
  assert(crit >= (ticks / hold) * 8);

  /* The mirror: the floor at 0, the same demand, sheddable is starved. The
   * floor is what did it. */
  shed0 = run_starvation(0, ticks, hold, &crit0);
  assert(shed0 == 0);
  assert(crit0 > crit);
  printf("  ok starvation: floor 10%% admitted %d sheddable (critical %d), floor 0 admitted %d (critical %d)\n",
         shed, crit, shed0, crit0);
}

int
main(void)
{
  printf("test_fc_band_floor\n");
  test_unit_arithmetic();
  test_floor_costs_nothing_without_demand();
  test_floor_binds_with_a_waiter();
  test_below_floor_newcomer_is_not_made_to_wait();
  test_below_floor_newcomer_on_a_pool_with_a_share();
  test_critical_claim_is_the_larger_of_floor_and_reserve();
  test_reserve_holds_with_critical_idle();
  test_reserve_unused_wakes_nobody();
  test_resume_order_below_floor_first();
  test_resume_order_policy_decides_at_floors();
  test_floor_on_a_path_that_cannot_wait();
  test_floor_follows_the_adaptive_ceiling();
  test_floor_waiter_held_by_its_tenant_share_is_no_demand();
  test_wake_room_promises_each_unit_once();
  test_floors_off_and_observe();
  test_starvation_and_its_mirror();
  printf("test_fc_band_floor: all passed\n");
  return 0;
}
