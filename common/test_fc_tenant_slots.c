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
 * The tenant table of the capacity gate at a size chosen when the pool is
 * created: the size the environment gives and its limits, a pool wider
 * than the smallest table tracking every tenant by name up to its size and
 * sharing the overflow past it, a pool without a share allocating nothing,
 * slots that stay put and are found again through any amount of coming and
 * going, the count of waiters that could run following a bound that moved,
 * the overflow counted once for a request that is refused and then waits,
 * a release that arrives after the pool was destroyed, and a pool that could
 * not get its table running without a share instead of refusing traffic.
 *
 * Build: make test_fc_tenant_slots (also run by `make test_fc`). The link
 * wraps calloc so one test can make the table's allocation fail.
 */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)

/* calloc as the gate sees it (-Wl,--wrap=calloc): fails while told to. */
static int fail_alloc;
void *__real_calloc(size_t n, size_t size);

void *
__wrap_calloc(size_t n, size_t size)
{
  if (fail_alloc)
    return NULL;
  return __real_calloc(n, size);
}

static uint64_t
anomaly(enum fc_anomaly a)
{
  return atomic_load(&fc_anomaly_total[a]);
}

static void
pool_slots(fc_state_t *fc, uint32_t slots, uint32_t max_out, uint32_t depth,
           uint8_t pct)
{
  fc_cfg_t cfg = {0};

  fc_state_init_slots(fc, slots);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = max_out;
  cfg.max_queue_depth = depth;
  cfg.max_queue_wait_ms = depth ? 5000 : 0;
  cfg.tenant_share_pct = pct;
  fc_state_apply(fc, &cfg);
}

static uint64_t
tkey(int i)
{
  char id[32];

  snprintf(id, sizeof(id), "tenant-%d", i);
  return fc_tenant_key(id);
}

static int
record_wake(int fd, uint64_t gen)
{
  (void)fd;
  (void)gen;
  return 0;
}

/* The HTTP/1 site: admit (and take the endpoint unit), or park, or refuse. */
static fc_verdict_t
gate(fc_state_t *fc, fc_permit_t *p, uint64_t key, int fd, int woken)
{
  fc_verdict_t v = fc_service_acquire_h1_tenant(fc, p, woken, key);
  int rc;

  if (v == FC_ADMIT) {
    if (p->state == FC_P_EXECUTING)
      assert(fc_ep_acquire(fc, p, 0, FC_ROLE_NORMAL) == FC_ADMIT);
    return v;
  }
  if (v == FC_QUEUE) {
    rc = fc_queue_push(fc, p, fd, 1, MS(1000) + (uint64_t)fd, woken);
    if (rc == 0)
      return FC_QUEUE;
    return rc == -2 ? FC_TENANT_SHARE : FC_SHED;
  }
  return v;
}

/* ---- size ---------------------------------------------------------------- */

static void
test_size_from_env(void)
{
  fc_state_t fc;

  unsetenv("LLB_FC_TENANT_SLOTS");
  assert(fc_tenant_slots_from_env() == FC_TENANT_SLOTS_DEFAULT);
  setenv("LLB_FC_TENANT_SLOTS", "1024", 1);
  assert(fc_tenant_slots_from_env() == 1024);
  setenv("LLB_FC_TENANT_SLOTS", "300", 1);
  assert(fc_tenant_slots_from_env() == 300);
  /* Out of range is held to the range; not a number is the default. */
  setenv("LLB_FC_TENANT_SLOTS", "1", 1);
  assert(fc_tenant_slots_from_env() == FC_TENANT_SLOTS);
  setenv("LLB_FC_TENANT_SLOTS", "0", 1);
  assert(fc_tenant_slots_from_env() == FC_TENANT_SLOTS);
  setenv("LLB_FC_TENANT_SLOTS", "999999", 1);
  assert(fc_tenant_slots_from_env() == FC_TENANT_SLOTS_MAX);
  setenv("LLB_FC_TENANT_SLOTS", "many", 1);
  assert(fc_tenant_slots_from_env() == FC_TENANT_SLOTS_DEFAULT);
  setenv("LLB_FC_TENANT_SLOTS", "-5", 1);
  assert(fc_tenant_slots_from_env() == FC_TENANT_SLOTS_DEFAULT);
  unsetenv("LLB_FC_TENANT_SLOTS");

  /* A pool keeps the size it was created with. */
  fc_state_init(&fc);
  assert(fc_tenant_slots(&fc) == FC_TENANT_SLOTS);
  fc_state_destroy(&fc);
  fc_state_init_slots(&fc, 300);
  assert(fc_tenant_slots(&fc) == 300);
  fc_state_destroy(&fc);
  fc_state_init_slots(&fc, 1);
  assert(fc_tenant_slots(&fc) == FC_TENANT_SLOTS);
  fc_state_destroy(&fc);
  fc_state_init_slots(&fc, 1u << 20);
  assert(fc_tenant_slots(&fc) == FC_TENANT_SLOTS_MAX);
  fc_state_destroy(&fc);
  /* Memory that was only zeroed reads as the smallest table. */
  memset(&fc, 0, sizeof(fc));
  assert(fc_tenant_slots(&fc) == FC_TENANT_SLOTS);
  assert(fc_tenant_slots(NULL) == 0);
  printf("  size: the environment value, held to %d..%d, default %d\n",
         FC_TENANT_SLOTS, FC_TENANT_SLOTS_MAX, FC_TENANT_SLOTS_DEFAULT);
}

/* ---- 300 tenants on 256 slots ------------------------------------------------ */

static void
test_300_tenants_on_256_slots(void)
{
  enum { SLOTS = 256, N = 300 };
  fc_state_t fc;
  static fc_permit_t p[N], extra;
  uint64_t before = anomaly(FC_A_TENANT_TABLE_FULL);

  /* ceiling 10000 at 1%: a hundred units per tenant */
  pool_slots(&fc, SLOTS, 10000, 0, 1);
  assert(fc_tenant_svc_bound(&fc) == 100);
  for (int i = 0; i < SLOTS; i++)
    assert(gate(&fc, &p[i], tkey(i), i + 1, 0) == FC_ADMIT);
  /* Every tenant up to the table size has its own slot: nothing shared. */
  assert(fc_tenants_active(&fc) == SLOTS);
  assert(anomaly(FC_A_TENANT_TABLE_FULL) == before);
  for (int i = 0; i < SLOTS; i++) {
    assert(p[i].tslot >= 0 && p[i].tslot < SLOTS);
    for (int j = 0; j < i; j++)
      assert(p[i].tslot != p[j].tslot);
  }
  /* Past it they share the last slot, each one counted. */
  for (int i = SLOTS; i < N; i++) {
    assert(gate(&fc, &p[i], tkey(i), i + 1, 0) == FC_ADMIT);
    assert(p[i].tslot == SLOTS);
  }
  assert(fc_tenants_active(&fc) == SLOTS + 1);
  assert(anomaly(FC_A_TENANT_TABLE_FULL) == before + (N - SLOTS));
  /* A tenant with a slot is still found by name with the table full. */
  assert(gate(&fc, &extra, tkey(7), N + 1, 0) == FC_ADMIT);
  assert(extra.tslot == p[7].tslot);
  assert(anomaly(FC_A_TENANT_TABLE_FULL) == before + (N - SLOTS));
  fc_permit_release(&extra);
  for (int i = 0; i < N; i++)
    fc_permit_release(&p[i]);
  assert(fc_tenants_active(&fc) == 0 && fc_inflight(&fc) == 0);
  assert(anomaly(FC_A_UNDERFLOW) == 0);
  /* Freed, the whole table is there again. */
  for (int i = 0; i < SLOTS; i++)
    assert(gate(&fc, &p[i], tkey(1000 + i), i + 1, 0) == FC_ADMIT);
  assert(fc_tenants_active(&fc) == SLOTS);
  assert(anomaly(FC_A_TENANT_TABLE_FULL) == before + (N - SLOTS));
  for (int i = 0; i < SLOTS; i++)
    fc_permit_release(&p[i]);
  assert(fc_tenants_active(&fc) == 0);
  fc_state_destroy(&fc);
  printf("  table: %d tenants on %d slots, %d past it shared and counted\n",
         N, SLOTS, N - SLOTS);
}

/* ---- no share, no table ------------------------------------------------------ */

static void
test_no_share_allocates_nothing(void)
{
  fc_state_t fc;
  fc_permit_t a, b;

  pool_slots(&fc, FC_TENANT_SLOTS_MAX, 2, 4, 0);
  assert(gate(&fc, &a, tkey(1), 1, 0) == FC_ADMIT);
  assert(gate(&fc, &b, tkey(2), 2, 0) == FC_ADMIT);
  assert(a.tslot < 0 && b.tslot < 0);
  assert(fc.tenants == NULL && fc.tenant_index == NULL);
  assert(fc_tenants_active(&fc) == 0);
  fc_permit_release(&a);
  fc_permit_release(&b);
  /* The first share brings the table, at the size the pool was given. */
  {
    fc_cfg_t cfg = fc.cfg;

    cfg.tenant_share_pct = 50;
    fc_state_apply(&fc, &cfg);
  }
  assert(fc.tenants != NULL && fc.tenant_index != NULL);
  assert(fc_tenant_slots(&fc) == FC_TENANT_SLOTS_MAX);
  fc_state_destroy(&fc);
  printf("  off: a pool without a share has no tenant table\n");
}

/* ---- coming and going -------------------------------------------------------- */

/* A deterministic generator: the run is the same every time. */
static uint32_t rng_state = 0x9e3779b9u;

static uint32_t
rng(void)
{
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 17;
  rng_state ^= rng_state << 5;
  return rng_state;
}

/* Tenants arrive and leave at random on a table kept close to full, checked
 * against a plain per-tenant count after every step: a tenant is found in
 * the slot it already holds however often the lookup index was re-laid
 * around it, its share binds on exactly its own units, and no slot is ever
 * given to two tenants. */
static void
test_churn_keeps_every_tenant_in_its_slot(void)
{
  enum { SLOTS = 64, TENANTS = 60, BOUND = 3, STEPS = 200000 };
  fc_state_t fc;
  static fc_permit_t held[TENANTS][BOUND];
  int units[TENANTS] = {0};
  int slot_of[TENANTS];
  int owner[SLOTS + 1];
  fc_permit_t over;
  uint64_t before = anomaly(FC_A_TENANT_TABLE_FULL);
  uint32_t active = 0;

  /* ceiling 300 at 1%: three units per tenant */
  pool_slots(&fc, SLOTS, 300, 0, 1);
  assert(fc_tenant_svc_bound(&fc) == BOUND);
  for (int i = 0; i < TENANTS; i++)
    slot_of[i] = -1;
  for (int i = 0; i <= SLOTS; i++)
    owner[i] = -1;
  for (int step = 0; step < STEPS; step++) {
    int t = (int)(rng() % TENANTS);

    if (rng() & 1) {
      if (units[t] == BOUND) {
        /* At its share: refused on its own count, nothing taken. */
        assert(gate(&fc, &over, tkey(t), 1, 0) == FC_TENANT_SHARE);
        continue;
      }
      assert(gate(&fc, &held[t][units[t]], tkey(t), 1, 0) == FC_ADMIT);
      if (units[t] == 0) {
        slot_of[t] = held[t][0].tslot;
        assert(slot_of[t] >= 0 && slot_of[t] < SLOTS);
        assert(owner[slot_of[t]] == -1);
        owner[slot_of[t]] = t;
        active++;
      } else {
        assert(held[t][units[t]].tslot == slot_of[t]);
      }
      units[t]++;
    } else if (units[t] > 0) {
      units[t]--;
      fc_permit_release(&held[t][units[t]]);
      if (units[t] == 0) {
        owner[slot_of[t]] = -1;
        slot_of[t] = -1;
        active--;
      }
    }
    assert(fc_tenants_active(&fc) == active);
  }
  for (int t = 0; t < TENANTS; t++)
    while (units[t] > 0)
      fc_permit_release(&held[t][--units[t]]);
  assert(fc_tenants_active(&fc) == 0 && fc_inflight(&fc) == 0);
  assert(fc.tenant_tombs == 0);
  assert(anomaly(FC_A_TENANT_TABLE_FULL) == before);
  assert(anomaly(FC_A_UNDERFLOW) == 0);
  fc_state_destroy(&fc);
  printf("  churn: %d steps over %d tenants, every one found in its own slot\n",
         STEPS, TENANTS);
}

/* One tenant holds a unit while every other slot is taken and given back
 * many times over: its slot does not move and is still the one its next
 * request and its release find. */
static void
test_a_held_slot_survives_the_others(void)
{
  enum { SLOTS = 64, ROUNDS = 200 };
  fc_state_t fc;
  fc_permit_t a0, a1, a2;
  static fc_permit_t p[SLOTS];
  uint64_t ka = fc_tenant_key("tenant-a");
  int slot;

  /* ceiling 200 at 1%: two units per tenant */
  pool_slots(&fc, SLOTS, 200, 0, 1);
  assert(gate(&fc, &a0, ka, 1, 0) == FC_ADMIT);
  slot = a0.tslot;
  for (int r = 0; r < ROUNDS; r++) {
    for (int i = 0; i < SLOTS - 1; i++)
      assert(gate(&fc, &p[i], tkey(r * SLOTS + i), i + 2, 0) == FC_ADMIT);
    assert(fc_tenants_active(&fc) == SLOTS);
    /* Released out of order, so buckets are freed inside probe runs. */
    for (int i = 0; i < SLOTS - 1; i += 2)
      fc_permit_release(&p[i]);
    for (int i = 1; i < SLOTS - 1; i += 2)
      fc_permit_release(&p[i]);
    assert(fc_tenants_active(&fc) == 1);
  }
  assert(gate(&fc, &a1, ka, 1, 0) == FC_ADMIT);
  assert(a1.tslot == slot);
  assert(gate(&fc, &a2, ka, 1, 0) == FC_TENANT_SHARE);
  fc_permit_release(&a0);
  fc_permit_release(&a1);
  assert(fc_tenants_active(&fc) == 0);
  assert(anomaly(FC_A_UNDERFLOW) == 0);
  fc_state_destroy(&fc);
  printf("  stable: a held slot kept its place through %d rounds of the rest\n",
         ROUNDS);
}

/* ---- waiters that could run -------------------------------------------------- */

/* A newcomer waits behind a waiter only when that waiter could take the
 * unit. Whether it could depends on the per-tenant bound, and the bound
 * moves with the configuration: the answer follows it. */
static void
test_runnable_waiters_follow_the_bound(void)
{
  fc_state_t fc;
  fc_permit_t a0, a1, b0, c0, d0;
  fc_cfg_t cfg;
  uint64_t ka = fc_tenant_key("tenant-a");
  uint64_t kb = fc_tenant_key("tenant-b");
  uint64_t kc = fc_tenant_key("tenant-c");
  uint64_t kd = fc_tenant_key("tenant-d");

  fc_set_wake_hook(record_wake);
  /* ceiling 4 at 25%: one unit per tenant */
  pool_slots(&fc, 256, 4, 8, 25);
  assert(fc_tenant_svc_bound(&fc) == 1);
  assert(gate(&fc, &a0, ka, 1, 0) == FC_ADMIT);
  assert(gate(&fc, &a1, ka, 2, 0) == FC_QUEUE);     /* A waits on its own share */
  /* A's waiter cannot run, so B is not made to wait behind it. */
  assert(gate(&fc, &b0, kb, 3, 0) == FC_ADMIT);
  /* The share is raised to two units: A's waiter could run now, and the
   * next newcomer goes behind it. */
  cfg = fc.cfg;
  cfg.tenant_share_pct = 50;
  fc_state_apply(&fc, &cfg);
  assert(fc_tenant_svc_bound(&fc) == 2);
  assert(gate(&fc, &c0, kc, 4, 0) == FC_QUEUE);
  /* Back at one unit: A's waiter cannot run again, C's (C holds nothing)
   * still can, so a newcomer with room of its own waits behind C. */
  cfg.tenant_share_pct = 25;
  fc_state_apply(&fc, &cfg);
  assert(fc_inflight(&fc) == 2);
  assert(gate(&fc, &d0, kd, 5, 0) == FC_QUEUE);
  /* C leaves the queue: nobody waiting could run, and D's tenant-mate is
   * admitted past the waiters. */
  fc_permit_release(&c0);
  fc_permit_release(&d0);
  assert(gate(&fc, &d0, kd, 6, 0) == FC_ADMIT);
  fc_permit_release(&d0);
  fc_permit_release(&a1);
  fc_permit_release(&a0);
  fc_permit_release(&b0);
  assert(fc_tenants_active(&fc) == 0);
  assert(fc.tenants_runnable_waiting == 0);
  assert(anomaly(FC_A_UNDERFLOW) == 0);
  fc_state_destroy(&fc);
  printf("  waiters: the count of waiters that could run followed the bound\n");
}

/* ---- the overflow, counted once per request ---------------------------------- */

static void
test_overflow_counted_once_when_it_waits(void)
{
  enum { SLOTS = 64 };
  fc_state_t fc;
  static fc_permit_t p[SLOTS];
  fc_permit_t late;
  uint64_t before;

  fc_set_wake_hook(record_wake);
  /* ceiling 64 at 50%, a queue: the ceiling is what the late tenant meets */
  pool_slots(&fc, SLOTS, SLOTS, 8, 50);
  for (int i = 0; i < SLOTS; i++)
    assert(gate(&fc, &p[i], tkey(i), i + 1, 0) == FC_ADMIT);
  before = anomaly(FC_A_TENANT_TABLE_FULL);
  /* Tenant 65 is past the table and the pool is full: it is looked up at
   * the gate and again when it is parked, and is one request. */
  assert(gate(&fc, &late, tkey(SLOTS), 100, 0) == FC_QUEUE);
  assert(anomaly(FC_A_TENANT_TABLE_FULL) == before + 1);
  assert(fc_tenants_active(&fc) == SLOTS + 1);
  fc_permit_release(&late);                          /* cancelled while it waits */
  assert(fc_tenants_active(&fc) == SLOTS);
  for (int i = 0; i < SLOTS; i++)
    fc_permit_release(&p[i]);
  assert(fc_tenants_active(&fc) == 0 && fc_queued(&fc) == 0);
  assert(anomaly(FC_A_UNDERFLOW) == 0);
  fc_state_destroy(&fc);
  printf("  overflow: a request past the table that waits is counted once\n");
}

/* ---- a release after the pool is gone ---------------------------------------- */

static void
test_release_after_destroy(void)
{
  fc_state_t fc;
  fc_permit_t a, b;

  pool_slots(&fc, 256, 4, 0, 50);
  assert(gate(&fc, &a, tkey(1), 1, 0) == FC_ADMIT);
  assert(gate(&fc, &b, tkey(2), 2, 0) == FC_ADMIT);
  fc_state_destroy(&fc);
  /* The table stays with the pool: late releases settle their tenants. */
  fc_permit_release(&a);
  fc_permit_release(&b);
  assert(fc_tenants_active(&fc) == 0 && fc_inflight(&fc) == 0);
  assert(anomaly(FC_A_UNDERFLOW) == 0);
  printf("  destroy: a release after the pool was destroyed settled its tenant\n");
}

/* ---- no memory for the table --------------------------------------------- */

static void
test_no_table_runs_without_a_share(void)
{
  fc_state_t fc;
  fc_permit_t a, b, c;
  fc_cfg_t cfg;

  /* ceiling 4 at 25%: one unit per tenant, if the pool had its table */
  fail_alloc = 1;
  pool_slots(&fc, 256, 4, 0, 25);
  fail_alloc = 0;
  /* The share is off and the read-back says so; the table size is still
   * what the pool was created with. */
  assert(fc.tenants == NULL && fc.tenant_index == NULL);
  assert(fc.cfg.tenant_share_pct == 0);
  assert(fc.cfg.src[FC_L_TENANT_SHARE] == FC_SRC_DEFAULT);
  assert(fc_tenant_svc_bound(&fc) == 0 && fc_tenant_slots(&fc) == 256);
  /* One tenant takes two units: nothing holds it to a share. */
  assert(gate(&fc, &a, tkey(1), 1, 0) == FC_ADMIT);
  assert(gate(&fc, &b, tkey(1), 2, 0) == FC_ADMIT);
  assert(a.tslot < 0 && b.tslot < 0 && fc_tenants_active(&fc) == 0);
  fc_permit_release(&a);
  fc_permit_release(&b);
  /* Applied again with memory to be had, the share is in force. */
  cfg = fc.cfg;
  cfg.tenant_share_pct = 25;
  fc_state_apply(&fc, &cfg);
  assert(fc.tenants != NULL && fc_tenant_svc_bound(&fc) == 1);
  assert(gate(&fc, &a, tkey(1), 1, 0) == FC_ADMIT);
  assert(gate(&fc, &b, tkey(1), 2, 0) == FC_TENANT_SHARE);
  fc_permit_release(&a);
  fc_state_destroy(&fc);

  /* A pool whose share is set without its table (memory that was only
   * zeroed, never through fc_state_apply) gets one at the first request, at
   * the smallest size; with no memory then either, the request is admitted
   * on the service ceiling alone. */
  memset(&fc, 0, sizeof(fc));
  pthread_mutex_init(&fc.queue.lock, NULL);
  fc.cfg.mode = FC_MODE_ENFORCE;
  fc.cfg.max_outstanding = 4;
  fc.cfg.tenant_share_pct = 25;
  fail_alloc = 1;
  assert(gate(&fc, &a, tkey(1), 1, 0) == FC_ADMIT);
  assert(gate(&fc, &b, tkey(1), 2, 0) == FC_ADMIT);
  fail_alloc = 0;
  assert(a.tslot < 0 && b.tslot < 0 && fc.tenants == NULL);
  assert(gate(&fc, &c, tkey(2), 3, 0) == FC_ADMIT);
  assert(c.tslot >= 0 && fc_tenant_slots(&fc) == FC_TENANT_SLOTS);
  assert(fc_tenants_active(&fc) == 1);
  fc_permit_release(&a);
  fc_permit_release(&b);
  fc_permit_release(&c);
  assert(fc_tenants_active(&fc) == 0 && fc_inflight(&fc) == 0);
  assert(anomaly(FC_A_UNDERFLOW) == 0);
  fc_state_destroy(&fc);
  printf("  memory: a pool without its table ran without a share, refusing nothing\n");
}

int
main(void)
{
  printf("fc tenant table:\n");
  test_size_from_env();
  test_300_tenants_on_256_slots();
  test_no_share_allocates_nothing();
  test_churn_keeps_every_tenant_in_its_slot();
  test_a_held_slot_survives_the_others();
  test_runnable_waiters_follow_the_bound();
  test_overflow_counted_once_when_it_waits();
  test_release_after_destroy();
  test_no_table_runs_without_a_share();
  printf("OK\n");
  return 0;
}
