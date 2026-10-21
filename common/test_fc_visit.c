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
 * A walk over the waiting requests of a capacity queue, driven alone: it
 * visits every live entry once, oldest first, and no tombstone; it holds the
 * queue's lock while it calls back; it takes nothing out, so the count, the
 * mirror and the order the next wake follows are what they were.
 *
 * Build: make test_fc_visit (also run by `make test_fc`).
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define MS(n) ((uint64_t)(n) * 1000000ULL)

static void
pool_with(fc_state_t *fc, uint32_t max_out, uint32_t depth, uint32_t wait_ms)
{
  fc_cfg_t cfg = {0};

  memset(fc, 0, sizeof(*fc));
  pthread_mutex_init(&fc->queue.lock, NULL);
  cfg.mode = FC_MODE_ENFORCE;
  cfg.max_outstanding = max_out;
  cfg.max_queue_depth = depth;
  cfg.max_queue_wait_ms = wait_ms;
  fc_state_apply(fc, &cfg);
}

static int woken_fd[16];
static int woken_n;

static int
record_wake(int fd, uint64_t gen)
{
  (void)gen;
  assert(woken_n < 16);
  woken_fd[woken_n++] = fd;
  return 0;
}

struct seen {
  fc_state_t *fc;
  int fd[16];
  uint64_t gen[16];
  int n;
  int locked;   /* every call found the queue's lock taken */
};

static void
note(void *ctx, const fc_queue_ent_t *e)
{
  struct seen *s = ctx;

  assert(s->n < 16);
  s->fd[s->n] = e->fd;
  s->gen[s->n] = e->gen;
  s->n++;
  if (pthread_mutex_trylock(&s->fc->queue.lock) == 0) {
    pthread_mutex_unlock(&s->fc->queue.lock);
    s->locked = 0;
  }
}

/* Park a request the way the HTTP/1 site does. */
static void
park(fc_state_t *fc, fc_permit_t *p, int fd, uint64_t gen, uint64_t now)
{
  assert(fc_service_acquire_h1(fc, p, 0) == FC_QUEUE);
  assert(fc_queue_push(fc, p, fd, gen, now, 0) == 0);
}

static void
test_nothing_to_visit(void)
{
  fc_state_t fc;
  struct seen s = { .fc = &fc, .locked = 1 };

  assert(fc_queue_visit(NULL, note, &s) == 0);
  pool_with(&fc, 1, 4, 5000);
  assert(fc_queue_visit(&fc, NULL, &s) == 0);
  assert(fc_queue_visit(&fc, note, &s) == 0);
  assert(s.n == 0);
  fc_state_destroy(&fc);

  /* A pool with no queue configured has no ring: nothing, and no fault. */
  pool_with(&fc, 1, 0, 0);
  assert(!fc_queue_enabled(&fc));
  assert(fc_queue_visit(&fc, note, &s) == 0);
  assert(s.n == 0);
  fc_state_destroy(&fc);
}

static void
test_visits_live_entries_in_order_under_the_lock(void)
{
  fc_state_t fc;
  fc_permit_t exec, wait[3];
  struct seen s = { .fc = &fc, .locked = 1 };
  uint64_t now = MS(1000);

  pool_with(&fc, 1, 4, 5000);
  woken_n = 0;
  assert(fc_service_acquire_h1(&fc, &exec, 0) == FC_ADMIT);
  assert(fc_ep_acquire(&fc, &exec, 0, FC_ROLE_NORMAL) == FC_ADMIT);
  for (int i = 0; i < 3; i++)
    park(&fc, &wait[i], 20 + i, 7 + i, now + i);

  /* The middle one leaves (its client went away): a tombstone stays in the
   * ring between two live entries. */
  assert(fc_queue_take(&fc, &wait[1]) == 1);
  assert(fc_queued(&fc) == 2);

  assert(fc_queue_visit(&fc, note, &s) == 2);
  assert(s.n == 2);
  assert(s.fd[0] == 20 && s.gen[0] == 7);
  assert(s.fd[1] == 22 && s.gen[1] == 9);
  assert(s.locked == 1);

  /* Nothing was taken out: the count, the mirror and the next wake are
   * unchanged, and a second walk sees the same two. */
  assert(fc.queue.count == 2);
  assert(fc_queued(&fc) == 2);
  memset(&s, 0, sizeof(s));
  s.fc = &fc;
  s.locked = 1;
  assert(fc_queue_visit(&fc, note, &s) == 2);
  assert(s.fd[0] == 20 && s.fd[1] == 22);

  fc_permit_release(&exec);
  assert(woken_n == 1 && woken_fd[0] == 20);
  assert(fc_queued(&fc) == 1);
  memset(&s, 0, sizeof(s));
  s.fc = &fc;
  s.locked = 1;
  assert(fc_queue_visit(&fc, note, &s) == 1);
  assert(s.fd[0] == 22);

  fc_queue_resumed(&fc, &wait[0], now + MS(10));
  fc_permit_release(&wait[0]);
  fc_permit_release(&wait[1]);
  fc_permit_release(&wait[2]);
  assert(fc_queued(&fc) == 0);
  assert(fc_inflight(&fc) == 0);
  fc_state_destroy(&fc);
}

int
main(void)
{
  fc_set_wake_hook(record_wake);
  test_nothing_to_visit();
  test_visits_live_entries_in_order_under_the_lock();
  printf("test_fc_visit: all passed\n");
  return 0;
}
