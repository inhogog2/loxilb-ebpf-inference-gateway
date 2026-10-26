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
 * The wait windows, the queue shares and the client's TTL, driven alone.
 *
 * A band's wait window is a cap inside the rule's window (max_queue_wait_ms),
 * never above it; 0 is the rule's window. A band's queue share bounds that
 * band's own occupancy of max_queue_depth, a ceiling and not a reservation:
 * what a band does not use stays open to every other band, and the queue as
 * a whole never holds more than max_queue_depth. With fc_llmd_headers on, a
 * client's x-llm-d-inference-ttl shorter than the window that applies
 * shortens that request's wait; a longer one never extends it, and with the
 * switch off the TTL is not read.
 *
 * Build: make test_fc_band_ttl (also run by `make test_fc`).
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

typedef struct opts {
  uint32_t cap;
  uint32_t depth;
  uint32_t wait_ms;                 /* the rule's window */
  uint32_t band_wait_ms[FC_BANDS];  /* by band */
  uint8_t  band_queue_pct[FC_BANDS];
  uint8_t  shed_queue;
  uint8_t  llmd;
} opts_t;

static void
pool_make(fc_state_t *fc, const opts_t *o)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = o->cap;
  cfg.max_queue_depth = o->depth;
  cfg.max_queue_wait_ms = o->wait_ms;
  cfg.shed_queue = o->shed_queue;
  cfg.llmd_headers = o->llmd;
  memcpy(cfg.band_wait_ms, o->band_wait_ms, sizeof(cfg.band_wait_ms));
  memcpy(cfg.band_queue_pct, o->band_queue_pct, sizeof(cfg.band_queue_pct));
  fc_state_apply(fc, &cfg);
}

static int woken_n;

static int
record_wake(int fd, uint64_t gen)
{
  (void)fd; (void)gen;
  woken_n++;
  return 0;
}

/* One waiter pushed by hand, as a request that met the ceiling. */
static int
park(fc_state_t *fc, fc_permit_t *w, uint8_t band, int fd, uint64_t now,
     uint32_t ttl_ms)
{
  fc_permit_init(w);
  w->band = band;
  w->tkey = fc_tenant_key(NULL);
  w->q_ttl_ms = ttl_ms;
  return fc_queue_push(fc, w, fd, 1, now, 0);
}

static void
test_window_is_a_cap_inside_the_rule_window(void)
{
  fc_state_t fc;
  opts_t o = { .cap = 1, .depth = 8, .wait_ms = 5000,
               .band_wait_ms = { [C] = 0, [S] = 10000, [B] = 500 } };

  pool_make(&fc, &o);
  assert(fc_band_wait_ms(&fc, C) == 5000);     /* 0 = the rule's */
  assert(fc_band_wait_ms(&fc, S) == 5000);     /* above the rule's: held at it */
  assert(fc_band_wait_ms(&fc, B) == 500);      /* inside: its own */

  {
    fc_permit_t c, s;

    assert(park(&fc, &c, C, 10, MS(1000), 0) == 0);
    assert(park(&fc, &s, S, 11, MS(1000), 0) == 0);
    assert(c.q_deadline_ns == MS(1000) + MS(5000));
    assert(s.q_deadline_ns == MS(1000) + MS(5000));
  }
  /* A sheddable waiter with the shed queue on: its own, shorter window. */
  {
    fc_state_t f2;
    fc_permit_t b, s;

    o.shed_queue = 1;
    pool_make(&f2, &o);
    assert(park(&f2, &b, B, 20, MS(2000), 0) == 0);
    assert(park(&f2, &s, S, 21, MS(2000), 0) == 0);
    assert(b.q_deadline_ns == MS(2000) + MS(500));
    assert(s.q_deadline_ns == MS(2000) + MS(5000));
    assert(!b.q_ttl_cut && !s.q_ttl_cut);
    fc_state_destroy(&f2);
  }
  fc_state_destroy(&fc);
}

static void
test_no_band_window_is_todays_single_window(void)
{
  fc_state_t fc;
  opts_t o = { .cap = 1, .depth = 8, .wait_ms = 3000, .shed_queue = 1 };
  fc_permit_t p[3];

  pool_make(&fc, &o);
  for (int b = 0; b < FC_BANDS; b++) {
    assert(park(&fc, &p[b], (uint8_t)b, 30 + b, MS(100), 0) == 0);
    assert(p[b].q_deadline_ns == MS(100) + MS(3000));
  }
  fc_state_destroy(&fc);
}

static void
test_queue_share_is_a_ceiling_not_a_reservation(void)
{
  fc_state_t fc;
  opts_t o = { .cap = 1, .depth = 8, .wait_ms = 5000, .shed_queue = 0,
               .band_queue_pct = { [C] = 25, [S] = 50, [B] = 25 } };
  fc_permit_t w[16];
  int n = 0;

  pool_make(&fc, &o);
  assert(fc_band_queue_bound(&fc, C) == 2);
  assert(fc_band_queue_bound(&fc, S) == 4);
  assert(fc_band_queue_bound(&fc, B) == 2);
  {
    /* A share rounds up, in the band's favour: 25 % of 10 is 3. */
    fc_state_t f10;
    opts_t o10 = { .cap = 1, .depth = 10, .wait_ms = 5000,
                   .band_queue_pct = { [C] = 25, [S] = 1, [B] = 100 } };

    pool_make(&f10, &o10);
    assert(fc_band_queue_bound(&f10, C) == 3);
    assert(fc_band_queue_bound(&f10, S) == 1);      /* never below one */
    assert(fc_band_queue_bound(&f10, B) == 10);     /* 100 is the whole depth */
    assert(fc_band_queue_bound(NULL, C) == 0);
    fc_state_destroy(&f10);
  }

  /* A band stops at its own share although the queue has room. */
  assert(park(&fc, &w[n++], C, 100, MS(10), 0) == 0);
  assert(park(&fc, &w[n++], C, 101, MS(10), 0) == 0);
  assert(park(&fc, &w[n++], C, 102, MS(10), 0) == -1);
  assert(fc_queued(&fc) == 2);
  /* ... and the others still have theirs: the critical share is not held
   * back for critical, only bounded. */
  for (int i = 0; i < 4; i++)
    assert(park(&fc, &w[n++], S, 110 + i, MS(10), 0) == 0);
  assert(park(&fc, &w[n++], S, 120, MS(10), 0) == -1);
  assert(fc_queued(&fc) == 6);
  assert(park(&fc, &w[n++], B, 130, MS(10), 0) == 0);
  assert(park(&fc, &w[n++], B, 131, MS(10), 0) == 0);
  assert(park(&fc, &w[n++], B, 132, MS(10), 0) == -1);
  /* The queue as a whole is at its depth. */
  assert(fc_queued(&fc) == 8);
  assert(park(&fc, &w[n++], S, 140, MS(10), 0) == -1);
  assert(n <= 16);
  fc_state_destroy(&fc);
}

static void
test_unused_share_is_open_to_other_bands(void)
{
  fc_state_t fc;
  opts_t o = { .cap = 1, .depth = 4, .wait_ms = 5000,
               .band_queue_pct = { [C] = 50, [S] = 0, [B] = 0 } };
  fc_permit_t w[6];

  pool_make(&fc, &o);
  /* Critical holds none of its half: standard fills the whole depth. */
  for (int i = 0; i < 4; i++)
    assert(park(&fc, &w[i], S, 200 + i, MS(10), 0) == 0);
  assert(park(&fc, &w[4], S, 210, MS(10), 0) == -1);
  assert(park(&fc, &w[5], C, 211, MS(10), 0) == -1);  /* the depth, not its share */
  fc_state_destroy(&fc);
}

static void
test_band_at_its_share_evicts_nobody(void)
{
  fc_state_t fc;
  opts_t o = { .cap = 1, .depth = 4, .wait_ms = 5000, .shed_queue = 1,
               .band_queue_pct = { [C] = 25 } };
  fc_permit_t w[6];

  pool_make(&fc, &o);
  assert(fc_band_queue_bound(&fc, C) == 1);
  assert(park(&fc, &w[0], C, 300, MS(10), 0) == 0);
  for (int i = 0; i < 3; i++)
    assert(park(&fc, &w[1 + i], B, 310 + i, MS(10), 0) == 0);
  assert(fc_queued(&fc) == 4);
  /* The queue is full of sheddable and a critical arrival would evict one,
   * but critical is at its own share: a full-queue refusal, nobody evicted. */
  assert(park(&fc, &w[4], C, 301, MS(10), 0) == -1);
  assert(fc_queue_evicted(&fc) == 0);
  assert(fc_queued(&fc) == 4);
  /* Within its share the eviction still works: a standard arrival (no share). */
  assert(park(&fc, &w[5], S, 320, MS(10), 0) == 0);
  assert(fc_queue_evicted(&fc) == 1);
  fc_state_destroy(&fc);
}

static void
test_client_ttl_only_shortens(void)
{
  fc_state_t fc;
  opts_t o = { .cap = 1, .depth = 8, .wait_ms = 5000, .shed_queue = 1,
               .band_wait_ms = { [B] = 500 }, .llmd = 1 };
  fc_permit_t a, b, c, d, e, f;

  pool_make(&fc, &o);
  /* Shorter than the window: that request's wait ends at the TTL. */
  assert(park(&fc, &a, S, 400, MS(1000), 200) == 0);
  assert(a.q_deadline_ns == MS(1000) + MS(200) && a.q_ttl_cut == 1);
  /* Longer: the window stands. */
  assert(park(&fc, &b, S, 401, MS(1000), 9000) == 0);
  assert(b.q_deadline_ns == MS(1000) + MS(5000) && b.q_ttl_cut == 0);
  /* Equal: no cut either (the window is the TTL). */
  assert(park(&fc, &c, S, 402, MS(1000), 5000) == 0);
  assert(c.q_deadline_ns == MS(1000) + MS(5000) && c.q_ttl_cut == 0);
  /* Against the band's window, not the rule's. */
  assert(park(&fc, &d, B, 403, MS(1000), 300) == 0);
  assert(d.q_deadline_ns == MS(1000) + MS(300) && d.q_ttl_cut == 1);
  assert(park(&fc, &e, B, 404, MS(1000), 700) == 0);
  assert(e.q_deadline_ns == MS(1000) + MS(500) && e.q_ttl_cut == 0);
  /* None asked: today's. */
  assert(park(&fc, &f, C, 405, MS(1000), 0) == 0);
  assert(f.q_deadline_ns == MS(1000) + MS(5000) && f.q_ttl_cut == 0);
  fc_state_destroy(&fc);
}

static void
test_client_ttl_is_ignored_with_the_switch_off(void)
{
  fc_state_t fc;
  opts_t o = { .cap = 1, .depth = 8, .wait_ms = 5000, .llmd = 0 };
  fc_permit_t a;

  pool_make(&fc, &o);
  assert(park(&fc, &a, S, 500, MS(1000), 200) == 0);
  assert(a.q_deadline_ns == MS(1000) + MS(5000) && a.q_ttl_cut == 0);
  fc_state_destroy(&fc);
}

/* A request woken and finding no room goes back to its place with the
 * deadline it was first given, and it is still the client's TTL that ends it. */
static void
test_repark_keeps_the_deadline_and_whose_it_was(void)
{
  fc_state_t fc;
  opts_t o = { .cap = 1, .depth = 8, .wait_ms = 5000, .llmd = 1 };
  fc_permit_t h, w, x;
  uint64_t first;

  pool_make(&fc, &o);
  fc_set_wake_hook(record_wake);
  assert(fc_service_acquire_h1_band(&fc, &h, 0, fc_tenant_key(NULL), S) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &h, 0, FC_ROLE_NORMAL) == FC_ADMIT);
  assert(fc_service_acquire_h1_band(&fc, &w, 0, fc_tenant_key(NULL), S) == FC_QUEUE);
  w.q_ttl_ms = 300;
  assert(fc_queue_push(&fc, &w, 600, 1, MS(1000), 0) == 0);
  first = w.q_deadline_ns;
  assert(first == MS(1000) + MS(300) && w.q_ttl_cut == 1);

  /* The unit frees and the waiter is woken ... */
  woken_n = 0;
  fc_permit_release(&h);
  assert(woken_n == 1);
  /* ... a newcomer takes the unit first ... */
  assert(fc_service_acquire_h1_band(&fc, &x, 0, fc_tenant_key(NULL), S) == FC_ADMIT);
  /* ... and the woken one finds none: it goes back with its first deadline. */
  fc_queue_resumed(&fc, &w, MS(1100));
  assert(fc_service_acquire_h1_band(&fc, &w, 1, fc_tenant_key(NULL), S) == FC_QUEUE);
  assert(w.q_ttl_cut == 1);
  w.q_ttl_ms = 9000;                       /* a second ask changes nothing */
  assert(fc_queue_push(&fc, &w, 600, 1, MS(1100), 1) == 0);
  assert(w.q_deadline_ns == first && w.q_ttl_cut == 1);
  fc_set_wake_hook(NULL);
  fc_state_destroy(&fc);
}

int
main(void)
{
  printf("test_fc_band_ttl\n");
  test_window_is_a_cap_inside_the_rule_window();
  test_no_band_window_is_todays_single_window();
  test_queue_share_is_a_ceiling_not_a_reservation();
  test_unused_share_is_open_to_other_bands();
  test_band_at_its_share_evicts_nobody();
  test_client_ttl_only_shortens();
  test_client_ttl_is_ignored_with_the_switch_off();
  test_repark_keeps_the_deadline_and_whose_it_was();
  printf("test_fc_band_ttl: all passed\n");
  return 0;
}
