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
 * Priority bands of the capacity gate, driven alone. A band is the class
 * constant (0 standard, 1 critical, 2 sheddable): a zeroed or freshly
 * initialised permit is standard, and a standard request moves no per-band
 * counter (standard is the total less the two counted bands). The per-band
 * service units and queue entries balance on every way a request leaves:
 * release, cancel while queued, the deadline's take, a drain, a wake, a
 * wake that could not be delivered (back at the head), a ring re-laid by
 * compaction or growth, and the pool's destruction; on a pool with a tenant
 * share and in observe mode as well.
 *
 * Build: make test_fc_priority (also run by `make test_fc`).
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
pool_with(fc_state_t *fc, uint8_t mode, uint32_t max_out, uint32_t depth,
          uint8_t share_pct)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = mode;
  cfg.max_outstanding = max_out;
  cfg.max_queue_depth = depth;
  cfg.max_queue_wait_ms = depth ? 5000 : 0;
  cfg.tenant_share_pct = share_pct;
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

static void
reset_anomalies(void)
{
  for (int i = 0; i < FC_A_COUNT; i++)
    atomic_store(&fc_anomaly_total[i], 0);
}

static uint64_t
anomalies(void)
{
  uint64_t n = 0;

  for (int i = 0; i < FC_A_COUNT; i++)
    n += atomic_load(&fc_anomaly_total[i]);
  return n;
}

/* The raw counters: only the critical and sheddable slots ever move. */
static void
assert_raw(const fc_state_t *fc, uint32_t in_c, uint32_t in_b, uint32_t q_c,
           uint32_t q_b)
{
  assert(atomic_load(&fc->band_inflight[S]) == 0);
  assert(atomic_load(&fc->band_queued[S]) == 0);
  assert(fc->queue.band_count[S] == 0);
  assert(atomic_load(&fc->band_inflight[C]) == in_c);
  assert(atomic_load(&fc->band_inflight[B]) == in_b);
  assert(atomic_load(&fc->band_queued[C]) == q_c);
  assert(atomic_load(&fc->band_queued[B]) == q_b);
  assert(fc->queue.band_count[C] == q_c);
  assert(fc->queue.band_count[B] == q_b);
}

/* Admit a request of `band` the way the HTTP/1 site does, units and all. */
static fc_verdict_t
admit(fc_state_t *fc, fc_permit_t *p, uint8_t band, int woken)
{
  fc_verdict_t v = fc_service_acquire_h1_band(fc, p, woken, fc_tenant_key(NULL),
                                              band);
  if (v == FC_ADMIT && p->state == FC_P_EXECUTING)
    assert(fc_ep_acquire(fc, p, 0, FC_ROLE_NORMAL) == FC_ADMIT);
  return v;
}

static void
park(fc_state_t *fc, fc_permit_t *p, uint8_t band, int fd, uint64_t now)
{
  assert(admit(fc, p, band, 0) == FC_QUEUE);
  assert(fc_queue_push(fc, p, fd, 1, now, 0) == 0);
  assert(p->band == band);
}

static void
test_zeroed_and_initialised_permits_are_standard(void)
{
  fc_permit_t p;

  memset(&p, 0, sizeof(p));
  assert(p.band == FC_BAND_STANDARD);
  memset(&p, 0xff, sizeof(p));
  p.fc = NULL;
  fc_permit_init(&p);
  assert(p.band == FC_BAND_STANDARD);

  /* Anything that is not a class constant is standard; ranks put critical
   * first and sheddable last. */
  assert(fc_band_of(7) == S && fc_band_of(-1) == S && fc_band_of(0) == S);
  assert(fc_band_of(1) == C && fc_band_of(2) == B);
  assert(fc_band_rank(C) < fc_band_rank(S) && fc_band_rank(S) < fc_band_rank(B));
}

static void
test_standard_moves_no_band_counter(void)
{
  fc_state_t fc;
  fc_permit_t run, wait[2], plain;
  uint64_t now = MS(1000);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 0);
  reset_anomalies();
  woken_n = 0;
  /* The forms without a band, and an out-of-range band, are standard. */
  assert(fc_service_acquire_h1(&fc, &run, 0) == FC_ADMIT);
  assert(run.band == S);
  park(&fc, &wait[0], S, 20, now);
  assert(fc_service_acquire_h1_tenant(&fc, &plain, 0, fc_tenant_key(NULL)) == FC_QUEUE);
  assert(plain.band == S);
  assert(admit(&fc, &wait[1], 9, 0) == FC_QUEUE);
  assert(wait[1].band == S);
  assert(fc_queue_push(&fc, &wait[1], 21, 1, now + 1, 0) == 0);
  assert_raw(&fc, 0, 0, 0, 0);
  assert(fc_band_inflight(&fc, S) == 1 && fc_band_queued(&fc, S) == 2);
  assert(fc_band_inflight(&fc, C) == 0 && fc_band_queued(&fc, B) == 0);

  fc_permit_release(&run);
  assert(woken_n == 1 && woken_fd[0] == 20);
  assert(admit(&fc, &wait[0], S, 1) == FC_ADMIT);
  assert_raw(&fc, 0, 0, 0, 0);
  fc_permit_release(&wait[0]);
  fc_permit_release(&wait[1]);   /* its client left while it waited */
  assert(fc_inflight(&fc) == 0 && fc_queued(&fc) == 0);
  assert_raw(&fc, 0, 0, 0, 0);
  assert(anomalies() == 0);
  fc_state_destroy(&fc);
}

static void
test_executing_units_per_band(void)
{
  fc_state_t fc;
  fc_permit_t p[6];

  pool_with(&fc, FC_MODE_ENFORCE, 6, 0, 0);
  reset_anomalies();
  assert(admit(&fc, &p[0], C, 0) == FC_ADMIT);
  assert(admit(&fc, &p[1], C, 0) == FC_ADMIT);
  assert(admit(&fc, &p[2], S, 0) == FC_ADMIT);
  assert(admit(&fc, &p[3], B, 0) == FC_ADMIT);
  assert_raw(&fc, 2, 1, 0, 0);
  assert(fc_band_inflight(&fc, S) == 1);
  /* The service-level form (HTTP/2, no wait). */
  assert(fc_service_acquire_band(&fc, &p[4], fc_tenant_key(NULL), B) == FC_ADMIT);
  assert_raw(&fc, 2, 2, 0, 0);
  for (int i = 0; i < 5; i++) {
    fc_permit_release(&p[i]);
    fc_permit_release(&p[i]);   /* idempotent: the band unit goes back once */
  }
  assert(fc_inflight(&fc) == 0);
  assert_raw(&fc, 0, 0, 0, 0);
  assert(anomalies() == 0);

  /* A refusal holds nothing in its band. */
  pool_with(&fc, FC_MODE_ENFORCE, 1, 0, 0);
  assert(admit(&fc, &p[0], C, 0) == FC_ADMIT);
  assert(fc_service_acquire_band(&fc, &p[1], fc_tenant_key(NULL), C) == FC_SHED);
  assert_raw(&fc, 1, 0, 0, 0);
  fc_permit_release(&p[1]);
  fc_permit_release(&p[0]);
  assert_raw(&fc, 0, 0, 0, 0);
  assert(anomalies() == 0);
  fc_state_destroy(&fc);
}

static void
test_queue_exits_per_band(void)
{
  fc_state_t fc;
  fc_permit_t run, w[6];
  fc_queue_ent_t e;
  uint64_t now = MS(1000);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 8, 0);
  reset_anomalies();
  woken_n = 0;
  wake_refuse = 0;
  assert(admit(&fc, &run, S, 0) == FC_ADMIT);
  park(&fc, &w[0], C, 30, now);
  park(&fc, &w[1], B, 31, now + 1);
  park(&fc, &w[2], C, 32, now + 2);
  park(&fc, &w[3], S, 33, now + 3);
  park(&fc, &w[4], B, 34, now + 4);
  assert_raw(&fc, 0, 0, 2, 2);
  assert(fc_band_queued(&fc, S) == 1);

  /* Cancelled while queued (the client left): the entry and its band. */
  fc_permit_release(&w[1]);
  assert_raw(&fc, 0, 0, 2, 1);
  /* The deadline's take. */
  assert(fc_queue_take(&fc, &w[2]) == 1);
  assert_raw(&fc, 0, 0, 1, 1);

  /* A wake that cannot be delivered puts the head back where it was. */
  wake_refuse = 1;
  fc_permit_release(&run);
  assert(fc_queued(&fc) == 3);
  assert_raw(&fc, 0, 0, 1, 1);
  wake_refuse = 0;
  /* Delivered: the oldest (critical) leaves its band and takes a unit in it. */
  fc_queue_wake_one(&fc);
  assert(woken_n == 1 && woken_fd[0] == 30);
  assert_raw(&fc, 0, 0, 0, 1);
  fc_queue_resumed(&fc, &w[0], now + MS(5));
  assert(admit(&fc, &w[0], C, 1) == FC_ADMIT);
  assert_raw(&fc, 1, 0, 0, 1);

  /* A drain ends the rest. */
  fc_queue_drain(&fc, NULL, NULL);
  assert(fc_queued(&fc) == 0);
  assert_raw(&fc, 1, 0, 0, 0);
  while (fc_queue_pop(&fc, &e))
    ;
  fc_permit_release(&w[0]);
  for (int i = 1; i < 5; i++)
    fc_permit_release(&w[i]);
  assert(fc_inflight(&fc) == 0);
  assert_raw(&fc, 0, 0, 0, 0);
  assert(anomalies() == 0);
  fc_state_destroy(&fc);
}

static void
test_relayout_and_destroy_keep_the_counts(void)
{
  fc_state_t fc;
  fc_permit_t run, w[12];
  fc_cfg_t cfg;
  uint64_t now = MS(1000);

  pool_with(&fc, FC_MODE_ENFORCE, 1, 4, 0);
  reset_anomalies();
  woken_n = 0;
  assert(admit(&fc, &run, S, 0) == FC_ADMIT);
  park(&fc, &w[0], C, 40, now);
  park(&fc, &w[1], B, 41, now + 1);
  park(&fc, &w[2], C, 42, now + 2);
  park(&fc, &w[3], B, 43, now + 3);
  /* Two tombstones at the tail end, then two newcomers: the ring is
   * re-laid in place to make room. */
  fc_permit_release(&w[1]);
  fc_permit_release(&w[2]);
  assert_raw(&fc, 0, 0, 1, 1);
  park(&fc, &w[4], C, 44, now + 4);
  park(&fc, &w[5], B, 45, now + 5);
  assert(fc.queue.cap == 4 && fc_queued(&fc) == 4);
  assert_raw(&fc, 0, 0, 2, 2);

  /* A deeper queue grows the ring: the counts are recomputed from the
   * entries it moves. */
  cfg = fc.cfg;
  cfg.max_queue_depth = 64;
  fc_state_apply(&fc, &cfg);
  assert(fc.queue.cap >= 64);
  assert_raw(&fc, 0, 0, 2, 2);
  park(&fc, &w[6], C, 46, now + 6);
  assert_raw(&fc, 0, 0, 3, 2);

  /* The pool goes with entries in it: nothing is left counted. */
  fc_state_destroy(&fc);
  assert(fc_queued(&fc) == 0);
  assert(fc.queue.band_count[C] == 0 && fc.queue.band_count[B] == 0);
  assert(atomic_load(&fc.band_queued[C]) == 0 && atomic_load(&fc.band_queued[B]) == 0);
}

static void
test_shared_pool_and_observe_mode(void)
{
  fc_state_t fc;
  fc_permit_t p[4];

  /* With a tenant share: the band moves on the shared path too. */
  pool_with(&fc, FC_MODE_ENFORCE, 4, 4, 50);
  assert(fc_share_active(&fc));
  reset_anomalies();
  assert(fc_service_acquire_h1_band(&fc, &p[0], 0, fc_tenant_key("t-a"), C) == FC_ADMIT);
  assert(fc_service_acquire_h1_band(&fc, &p[1], 0, fc_tenant_key("t-b"), B) == FC_ADMIT);
  assert_raw(&fc, 1, 1, 0, 0);
  fc_permit_release(&p[0]);
  fc_permit_release(&p[1]);
  assert_raw(&fc, 0, 0, 0, 0);
  assert(anomalies() == 0);
  fc_state_destroy(&fc);

  /* Observe: everything is admitted and counted, and handed back. */
  pool_with(&fc, FC_MODE_OBSERVE, 1, 0, 0);
  for (int i = 0; i < 3; i++)
    assert(fc_service_acquire_h1_band(&fc, &p[i], 0, fc_tenant_key(NULL), C) == FC_ADMIT);
  assert_raw(&fc, 3, 0, 0, 0);
  for (int i = 0; i < 3; i++)
    fc_permit_release(&p[i]);
  assert_raw(&fc, 0, 0, 0, 0);
  assert(anomalies() == 0);
  fc_state_destroy(&fc);

  /* Gate off: a bypass holds nothing. */
  pool_with(&fc, FC_MODE_OFF, 1, 0, 0);
  assert(fc_service_acquire_h1_band(&fc, &p[0], 0, fc_tenant_key(NULL), C) == FC_ADMIT);
  assert(p[0].state == FC_P_BYPASS);
  assert_raw(&fc, 0, 0, 0, 0);
  fc_permit_release(&p[0]);
  assert(anomalies() == 0);
  fc_state_destroy(&fc);
}

int
main(void)
{
  fc_set_wake_hook(record_wake);
  test_zeroed_and_initialised_permits_are_standard();
  test_standard_moves_no_band_counter();
  test_executing_units_per_band();
  test_queue_exits_per_band();
  test_relayout_and_destroy_keep_the_counts();
  test_shared_pool_and_observe_mode();
  printf("test_fc_priority: all passed\n");
  return 0;
}
