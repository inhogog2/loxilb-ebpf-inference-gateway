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
 * The weighted wake and the tenant rotation of the capacity gate, driven
 * alone.
 *
 * Weighted is a deficit round robin with unit cost: each band that has a
 * waiter able to take the unit gets its weight in credits per round, the
 * highest band with credit left is served first, one wake costs one credit,
 * and a band with no such waiter forfeits its turn. A round that starts with
 * every band waiting serves critical, then standard, then sheddable, as many
 * times as their weights say; over whole rounds the wakes split exactly as
 * the weights do. With every waiter standard it is today's FIFO. A change of
 * policy or weights starts a new round and loses no waiter. A wake that
 * cannot be delivered gives its credit back.
 *
 * The round-robin tenant wake rotates, inside one band, across the tenants
 * that have a waiter able to take the unit, oldest first inside one tenant;
 * it needs no tenant share. A wake that cannot be delivered does not move
 * the rotation.
 *
 * Build: make test_fc_band_wrr (also run by `make test_fc`).
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
#define MAXW 512

typedef struct opts {
  uint8_t wake;
  uint8_t weight[FC_BANDS];      /* by band */
  uint8_t rr;
  uint8_t share_pct;
  uint32_t depth;
} opts_t;

static void
pool_make(fc_state_t *fc, const opts_t *o)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = 1;
  cfg.max_queue_depth = o->depth ? o->depth : 400;
  cfg.max_queue_wait_ms = 60000;
  cfg.wake_policy = o->wake;
  memcpy(cfg.band_weight, o->weight, sizeof(cfg.band_weight));
  cfg.tenant_wake = o->rr ? FC_TENANT_WAKE_RR : FC_TENANT_WAKE_FIFO;
  cfg.tenant_share_pct = o->share_pct;
  fc_state_apply(fc, &cfg);
}

static int woken_fd[MAXW];
static int woken_n;
static int wake_refuse;

static int
record_wake(int fd, uint64_t gen)
{
  (void)gen;
  if (wake_refuse)
    return -1;
  assert(woken_n < MAXW);
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

/* A pool with one unit held, and a queue: waiter i sits in band bands[i] for
 * tenant tenants[i] (NULL = none) with fd 100 + i. */
typedef struct rig {
  fc_state_t fc;
  fc_permit_t run;
  fc_permit_t q[MAXW];
  int n;
} rig_t;

static void
rig_make(rig_t *r, const opts_t *o)
{
  memset(r, 0, sizeof(*r));
  pool_make(&r->fc, o);
  fc_set_wake_hook(record_wake);
  woken_n = 0;
  wake_refuse = 0;
  fc_permit_init(&r->run);
  assert(admit(&r->fc, &r->run, S, 0, fc_tenant_key(NULL)) == FC_ADMIT);
}

static void
rig_wait(rig_t *r, uint8_t band, const char *tenant)
{
  fc_permit_t *p = &r->q[r->n];

  fc_permit_init(p);
  p->band = band;
  p->tkey = fc_tenant_key(tenant);
  assert(fc_queue_push(&r->fc, p, 100 + r->n, 1, MS(10 + r->n), 0) == 0);
  r->n++;
}

/* Release the held unit, then let each woken request take it and hand it
 * back, until `n` wakes have been given. */
static void
rig_run(rig_t *r, int n)
{
  fc_permit_release(&r->run);
  for (int i = 0; i < n; i++) {
    int k;

    assert(woken_n == i + 1);
    k = woken_fd[i] - 100;
    fc_queue_resumed(&r->fc, &r->q[k], MS(1000));
    assert(admit(&r->fc, &r->q[k], r->q[k].band, 1, r->q[k].tkey) == FC_ADMIT);
    fc_permit_release(&r->q[k]);
  }
}

static void
rig_done(rig_t *r)
{
  fc_set_wake_hook(NULL);
  fc_state_destroy(&r->fc);
}

static int
band_of_fd(const rig_t *r, int fd)
{
  return r->q[fd - 100].band;
}

/* ---- weighted ------------------------------------------------------------- */

static void
test_round_order_and_exact_shares(void)
{
  opts_t o = { .wake = FC_WAKE_WEIGHTED, .weight = { [C] = 8, [S] = 3, [B] = 1 } };
  static rig_t r;
  int cnt[FC_BANDS] = {0};

  rig_make(&r, &o);
  for (int i = 0; i < 100; i++) { rig_wait(&r, C, NULL); rig_wait(&r, S, NULL); rig_wait(&r, B, NULL); }
  rig_run(&r, 60);
  /* The first round: critical eight times, standard three, sheddable once. */
  for (int i = 0; i < 12; i++) {
    int b = band_of_fd(&r, woken_fd[i]);

    assert(b == (i < 8 ? C : i < 11 ? S : B));
  }
  /* Whole rounds split exactly as the weights do: five rounds of twelve. */
  for (int i = 0; i < 60; i++)
    cnt[band_of_fd(&r, woken_fd[i])]++;
  assert(cnt[C] == 40 && cnt[S] == 15 && cnt[B] == 5);
  /* Inside a band the oldest goes first. */
  {
    int last[FC_BANDS] = { -1, -1, -1 };

    for (int i = 0; i < 60; i++) {
      int b = band_of_fd(&r, woken_fd[i]);

      assert(woken_fd[i] > last[b]);
      last[b] = woken_fd[i];
    }
  }
  rig_done(&r);
  printf("  ok weighted rounds serve the bands as their weights say\n");
}

static void
test_band_without_waiter_forfeits(void)
{
  opts_t o = { .wake = FC_WAKE_WEIGHTED, .weight = { [C] = 8, [S] = 3, [B] = 1 } };
  static rig_t r;
  int cnt[FC_BANDS] = {0};

  /* No critical waiter at all: standard and sheddable split 3:1, and the
   * critical credits are not owed to anyone. */
  rig_make(&r, &o);
  for (int i = 0; i < 40; i++) { rig_wait(&r, S, NULL); rig_wait(&r, B, NULL); }
  rig_run(&r, 8);
  for (int i = 0; i < 8; i++)
    cnt[band_of_fd(&r, woken_fd[i])]++;
  assert(cnt[C] == 0 && cnt[S] == 6 && cnt[B] == 2);
  rig_done(&r);

  /* One critical waiter among many standard: it is served first, once, then
   * the rounds go on without it. */
  rig_make(&r, &o);
  for (int i = 0; i < 10; i++) rig_wait(&r, S, NULL);
  rig_wait(&r, C, NULL);                         /* fd 110 */
  rig_wait(&r, B, NULL);
  rig_run(&r, 6);
  assert(woken_fd[0] == 110);
  assert(band_of_fd(&r, woken_fd[1]) == S && band_of_fd(&r, woken_fd[2]) == S &&
         band_of_fd(&r, woken_fd[3]) == S);
  assert(band_of_fd(&r, woken_fd[4]) == B);
  rig_done(&r);
  printf("  ok a band with no waiter forfeits its turn\n");
}

static void
test_arrival_mid_round_waits_for_the_next_round(void)
{
  opts_t o = { .wake = FC_WAKE_WEIGHTED, .weight = { [C] = 8, [S] = 3, [B] = 1 } };
  static rig_t r;

  rig_make(&r, &o);
  for (int i = 0; i < 10; i++) { rig_wait(&r, S, NULL); rig_wait(&r, B, NULL); }
  fc_permit_release(&r.run);
  /* Critical had no waiter when this round began: it forfeited its credits. */
  for (int i = 0; i < 2; i++) {
    int k = woken_fd[i] - 100;

    assert(band_of_fd(&r, woken_fd[i]) == S);
    fc_queue_resumed(&r.fc, &r.q[k], MS(1000));
    assert(admit(&r.fc, &r.q[k], r.q[k].band, 1, r.q[k].tkey) == FC_ADMIT);
    fc_permit_release(&r.q[k]);
  }
  rig_wait(&r, C, NULL);                       /* arrives in the middle of the round */
  /* ... so it waits for the next one: the rest of this round is standard, sheddable. */
  for (int i = 2; i < 6; i++) {
    int k = woken_fd[i] - 100;
    int want[] = { S, B, C, S };               /* S: the third credit; B: its one; then a new round */

    assert(band_of_fd(&r, woken_fd[i]) == want[i - 2]);
    fc_queue_resumed(&r.fc, &r.q[k], MS(1000));
    assert(admit(&r.fc, &r.q[k], r.q[k].band, 1, r.q[k].tkey) == FC_ADMIT);
    fc_permit_release(&r.q[k]);
  }
  rig_done(&r);
  printf("  ok a band that arrives in the middle of a round waits for the next\n");
}

static void
test_zero_weights_never_stall(void)
{
  opts_t o = { .wake = FC_WAKE_WEIGHTED };
  static rig_t r;

  rig_make(&r, &o);
  rig_wait(&r, B, NULL);
  rig_wait(&r, S, NULL);
  rig_wait(&r, C, NULL);
  rig_run(&r, 3);
  /* The control plane refuses a zero weight; a pick that met one still serves
   * every band, highest first. */
  assert(band_of_fd(&r, woken_fd[0]) == C && band_of_fd(&r, woken_fd[1]) == S &&
         band_of_fd(&r, woken_fd[2]) == B);
  rig_done(&r);
  printf("  ok a zero weight does not stall the round\n");
}

static void
test_all_standard_is_fifo(void)
{
  opts_t o = { .wake = FC_WAKE_WEIGHTED, .weight = { [C] = 8, [S] = 3, [B] = 1 } };
  static rig_t r;

  rig_make(&r, &o);
  for (int i = 0; i < 20; i++) rig_wait(&r, S, NULL);
  rig_run(&r, 20);
  for (int i = 0; i < 20; i++)
    assert(woken_fd[i] == 100 + i);
  rig_done(&r);
  printf("  ok with every waiter standard the weighted wake is the FIFO\n");
}

static void
test_replace_resets_the_round_and_loses_nobody(void)
{
  opts_t o = { .wake = FC_WAKE_WEIGHTED, .weight = { [C] = 8, [S] = 3, [B] = 1 } };
  static rig_t r;
  fc_cfg_t cfg;
  uint32_t queued;

  rig_make(&r, &o);
  for (int i = 0; i < 12; i++) { rig_wait(&r, C, NULL); rig_wait(&r, S, NULL); rig_wait(&r, B, NULL); }
  fc_permit_release(&r.run);
  /* Part of a round is gone: three critical credits spent. */
  for (int i = 0; i < 3; i++) {
    int k = woken_fd[i] - 100;

    assert(band_of_fd(&r, woken_fd[i]) == C);
    fc_queue_resumed(&r.fc, &r.q[k], MS(1000));
    assert(admit(&r.fc, &r.q[k], r.q[k].band, 1, r.q[k].tkey) == FC_ADMIT);
    if (i < 2)
      fc_permit_release(&r.q[k]);
  }
  /* The weights change with 33 waiters in the queue: a new round, nobody lost. */
  queued = fc_queued(&r.fc);
  cfg = r.fc.cfg;
  cfg.band_weight[C] = 1; cfg.band_weight[S] = 1; cfg.band_weight[B] = 1;
  fc_state_apply(&r.fc, &cfg);
  assert(fc_queued(&r.fc) == queued);
  assert(r.fc.queue.drr_credit[C] == 0 && r.fc.queue.drr_credit[S] == 0 &&
         r.fc.queue.drr_credit[B] == 0);
  fc_permit_release(&r.q[woken_fd[2] - 100]);
  /* 1:1:1 from a clean round: critical, standard, sheddable, then again. */
  {
    int k = woken_fd[3] - 100;
    int want[6] = { C, S, B, C, S, B };

    for (int i = 3; i < 9; i++) {
      assert(band_of_fd(&r, woken_fd[i]) == want[i - 3]);
      k = woken_fd[i] - 100;
      fc_queue_resumed(&r.fc, &r.q[k], MS(1000));
      assert(admit(&r.fc, &r.q[k], r.q[k].band, 1, r.q[k].tkey) == FC_ADMIT);
      fc_permit_release(&r.q[k]);
    }
  }
  /* And to strict and back: the credits are cleared each way. */
  cfg.wake_policy = FC_WAKE_STRICT;
  fc_state_apply(&r.fc, &cfg);
  cfg.wake_policy = FC_WAKE_WEIGHTED;
  fc_state_apply(&r.fc, &cfg);
  assert(r.fc.queue.drr_credit[C] == 0);
  rig_done(&r);
  printf("  ok a replace starts a new round and loses no waiter\n");
}

static void
test_undelivered_wake_gives_the_credit_back(void)
{
  opts_t o = { .wake = FC_WAKE_WEIGHTED, .weight = { [C] = 2, [S] = 1, [B] = 1 } };
  static rig_t r;

  rig_make(&r, &o);
  rig_wait(&r, C, NULL);
  rig_wait(&r, C, NULL);
  rig_wait(&r, S, NULL);
  /* The owner of the first critical waiter cannot be woken now. */
  wake_refuse = 1;
  fc_permit_release(&r.run);
  assert(woken_n == 0);
  assert(fc_queued(&r.fc) == 3);
  /* The pick began a round (critical: 2 credits) and spent one; the wake
   * was not delivered, so the credit is back: the round is whole. */
  assert(r.fc.queue.drr_credit[C] == 2);
  /* The waiter kept its place at the head: the next turn serves it. */
  wake_refuse = 0;
  fc_queue_wake_one(&r.fc);
  assert(woken_n == 1 && woken_fd[0] == 100);
  assert(r.fc.queue.drr_credit[C] == 1);
  rig_done(&r);
  printf("  ok a wake that cannot be delivered gives its credit back\n");
}

/* ---- tenant rotation ------------------------------------------------------ */

static void
test_rotation_across_tenants(void)
{
  opts_t o = { .wake = FC_WAKE_STRICT, .rr = 1 };
  static rig_t r;
  /* Arrival order: a a a b b c a b c (fds 100..108). */
  const char *t[] = { "a", "a", "a", "b", "b", "c", "a", "b", "c" };
  char seq[16] = "";

  rig_make(&r, &o);
  for (int i = 0; i < 9; i++)
    rig_wait(&r, S, t[i]);
  rig_run(&r, 9);
  /* Each turn goes to the next tenant that has a waiter; the tenants come
   * in the order the pool first saw them (a, b, c), and c, with two waiters,
   * has none left for the ninth turn. */
  for (int i = 0; i < 9; i++)
    seq[i] = t[woken_fd[i] - 100][0];
  assert(!strcmp(seq, "abcabcaba"));
  /* Inside one tenant, oldest first. */
  {
    int last = -1;

    for (int i = 0; i < 9; i++)
      if (!strcmp(t[woken_fd[i] - 100], "a")) {
        assert(woken_fd[i] > last);
        last = woken_fd[i];
      }
  }
  rig_done(&r);
  printf("  ok the round-robin wake rotates across tenants\n");
}

static void
test_fifo_wake_is_arrival_order_and_tenant_blind(void)
{
  opts_t o = { .wake = FC_WAKE_STRICT, .rr = 0 };
  static rig_t r;
  const char *t[] = { "a", "a", "a", "b", "b", "c" };

  rig_make(&r, &o);
  for (int i = 0; i < 6; i++)
    rig_wait(&r, S, t[i]);
  rig_run(&r, 6);
  for (int i = 0; i < 6; i++)
    assert(woken_fd[i] == 100 + i);
  rig_done(&r);
  printf("  ok the fifo wake ignores tenants\n");
}

static void
test_rotation_is_per_band(void)
{
  opts_t o = { .wake = FC_WAKE_WEIGHTED, .weight = { [C] = 1, [S] = 1, [B] = 1 }, .rr = 1 };
  static rig_t r;

  rig_make(&r, &o);
  /* Standard: a a b; sheddable: x x y; weights 1:1:1 alternate the bands, and
   * each band keeps its own place in its own rotation. */
  rig_wait(&r, S, "a"); rig_wait(&r, S, "a"); rig_wait(&r, S, "b");   /* 100 101 102 */
  rig_wait(&r, B, "x"); rig_wait(&r, B, "x"); rig_wait(&r, B, "y");   /* 103 104 105 */
  rig_run(&r, 6);
  assert(woken_fd[0] == 100 && woken_fd[1] == 103);   /* S a, B x */
  assert(woken_fd[2] == 102 && woken_fd[3] == 105);   /* S b, B y */
  assert(woken_fd[4] == 101 && woken_fd[5] == 104);   /* S a, B x again */
  rig_done(&r);
  printf("  ok each band has its own rotation\n");
}

static void
test_rotation_with_a_tenant_share(void)
{
  opts_t o = { .wake = FC_WAKE_STRICT, .rr = 1, .share_pct = 50, .depth = 64 };
  static rig_t r;
  const char *t[] = { "a", "a", "b", "b" };

  rig_make(&r, &o);
  for (int i = 0; i < 4; i++)
    rig_wait(&r, S, t[i]);
  rig_run(&r, 4);
  assert(woken_fd[0] == 100 && woken_fd[1] == 102 && woken_fd[2] == 101 && woken_fd[3] == 103);
  rig_done(&r);
  printf("  ok the rotation holds with a tenant share\n");
}

static void
test_undelivered_wake_does_not_move_the_rotation(void)
{
  opts_t o = { .wake = FC_WAKE_STRICT, .rr = 1 };
  static rig_t r;

  rig_make(&r, &o);
  rig_wait(&r, S, "a");     /* 100 */
  rig_wait(&r, S, "b");     /* 101 */
  wake_refuse = 1;
  fc_permit_release(&r.run);
  assert(woken_n == 0);
  wake_refuse = 0;
  fc_queue_wake_one(&r.fc);
  /* a had the turn that was not delivered; it still has it. */
  assert(woken_n == 1 && woken_fd[0] == 100);
  rig_done(&r);
  printf("  ok a wake that cannot be delivered leaves the rotation where it was\n");
}

static void
test_default_pool_is_untouched(void)
{
  opts_t o = { .wake = FC_WAKE_STRICT };
  static rig_t r;
  const uint8_t b[] = { S, B, C, S, C, B };
  const int want[] = { 2, 4, 0, 3, 1, 5 };

  rig_make(&r, &o);
  for (int i = 0; i < 6; i++)
    rig_wait(&r, b[i], "a");
  rig_run(&r, 6);
  for (int i = 0; i < 6; i++)
    assert(woken_fd[i] - 100 == want[i]);
  rig_done(&r);
  printf("  ok the default pool still serves the highest band first\n");
}

int
main(void)
{
  printf("test_fc_band_wrr\n");
  test_round_order_and_exact_shares();
  test_band_without_waiter_forfeits();
  test_arrival_mid_round_waits_for_the_next_round();
  test_zero_weights_never_stall();
  test_all_standard_is_fifo();
  test_replace_resets_the_round_and_loses_nobody();
  test_undelivered_wake_gives_the_credit_back();
  test_rotation_across_tenants();
  test_fifo_wake_is_arrival_order_and_tenant_blind();
  test_rotation_is_per_band();
  test_rotation_with_a_tenant_share();
  test_undelivered_wake_does_not_move_the_rotation();
  test_default_pool_is_untouched();
  printf("test_fc_band_wrr: all passed\n");
  return 0;
}
