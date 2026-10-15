/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * sockproxy_qsbr.c - grace periods for memory the notify workers read
 * without a lock (sockproxy_qsbr.h).
 *
 * Each reader slot holds 0 while its thread is offline, else the value of
 * the global epoch the thread read when it last came online. Deferring work
 * advances the epoch and stamps the work with the new value; the work is
 * run once every slot is offline or holds a value at or after the stamp.
 *
 * Ordering. A writer unlinks (a release store under the proxy lock), then
 * advances the epoch (a sequentially consistent read-modify-write), and the
 * reclaimer reads the slots after a sequentially consistent fence. A reader
 * coming online stores its slot, then runs a sequentially consistent fence
 * before its next read. Either the reclaimer sees the new slot value, which
 * is at or after the stamp only if the reader read the advanced epoch (and
 * so sees the unlink), or the reclaimer's fence is ordered before the
 * reader's, and the reader's reads after its fence see the unlink. A reader
 * going offline stores 0 with release, and the reclaimer reads its slot with
 * acquire, so everything the reader did before is ordered before the work.
 */
#define _GNU_SOURCE   /* pthread_setname_np */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <time.h>

#include "sockproxy_qsbr.h"

struct sp_qsbr_slot {
  _Atomic uint64_t seen;
  char pad[64 - sizeof(uint64_t)];
} __attribute__((aligned(64)));

static struct sp_qsbr_slot qsbr_slot[SP_QSBR_MAX_THREADS];
static _Atomic uint64_t qsbr_epoch = 1;   /* 0 means offline in a slot */
static __thread int qsbr_my_slot = -1;

static pthread_mutex_t qsbr_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qsbr_cond = PTHREAD_COND_INITIALIZER;
static sp_qsbr_work_t *qsbr_head;          /* stamps never decrease along the list */
static sp_qsbr_work_t *qsbr_tail;
static _Atomic uint64_t qsbr_waiting;
static int qsbr_started;

#define QSBR_POLL_NS (1000 * 1000)

void
sp_qsbr_register(int slot)
{
  if (slot < 0 || slot >= SP_QSBR_MAX_THREADS)
    return;
  qsbr_my_slot = slot;
  sp_qsbr_online();
}

void
sp_qsbr_unregister(void)
{
  sp_qsbr_offline();
  qsbr_my_slot = -1;
}

void
sp_qsbr_offline(void)
{
  if (qsbr_my_slot < 0)
    return;
  atomic_store_explicit(&qsbr_slot[qsbr_my_slot].seen, 0, memory_order_release);
}

void
sp_qsbr_online(void)
{
  uint64_t e;

  if (qsbr_my_slot < 0)
    return;
  e = atomic_load_explicit(&qsbr_epoch, memory_order_acquire);
  atomic_store_explicit(&qsbr_slot[qsbr_my_slot].seen, e, memory_order_release);
  atomic_thread_fence(memory_order_seq_cst);
}

static int
qsbr_grace_over(uint64_t stamp)
{
  atomic_thread_fence(memory_order_seq_cst);
  for (int i = 0; i < SP_QSBR_MAX_THREADS; i++) {
    uint64_t v = atomic_load_explicit(&qsbr_slot[i].seen, memory_order_acquire);
    if (v != 0 && v < stamp)
      return 0;
  }
  return 1;
}

void
sp_qsbr_defer(sp_qsbr_work_t *w, void (*fn)(sp_qsbr_work_t *w))
{
  w->fn = fn;
  w->next = NULL;
  pthread_mutex_lock(&qsbr_lock);
  /* Under the lock, so the stamps along the list never decrease. */
  w->epoch = atomic_fetch_add_explicit(&qsbr_epoch, 1, memory_order_seq_cst) + 1;
  if (qsbr_tail)
    qsbr_tail->next = w;
  else
    qsbr_head = w;
  qsbr_tail = w;
  atomic_fetch_add_explicit(&qsbr_waiting, 1, memory_order_relaxed);
  pthread_cond_signal(&qsbr_cond);
  pthread_mutex_unlock(&qsbr_lock);
}

int
sp_qsbr_run_ready(void)
{
  sp_qsbr_work_t *ready = NULL, *last = NULL, *w;
  int left;

  pthread_mutex_lock(&qsbr_lock);
  /* A grace period that is over for a stamp is over for every smaller one,
   * so the ready work is a prefix of the list. */
  while (qsbr_head && qsbr_grace_over(qsbr_head->epoch)) {
    w = qsbr_head;
    qsbr_head = w->next;
    if (!qsbr_head)
      qsbr_tail = NULL;
    w->next = NULL;
    if (last)
      last->next = w;
    else
      ready = w;
    last = w;
  }
  pthread_mutex_unlock(&qsbr_lock);

  /* Outside the lock: the work may defer more. */
  while (ready) {
    w = ready;
    ready = w->next;
    atomic_fetch_sub_explicit(&qsbr_waiting, 1, memory_order_relaxed);
    w->fn(w);
  }

  pthread_mutex_lock(&qsbr_lock);
  left = qsbr_head != NULL;
  pthread_mutex_unlock(&qsbr_lock);
  return left ? (int)atomic_load_explicit(&qsbr_waiting, memory_order_relaxed) : 0;
}

uint64_t
sp_qsbr_pending(void)
{
  return atomic_load_explicit(&qsbr_waiting, memory_order_relaxed);
}

static void *
qsbr_reclaimer(void *arg)
{
  (void)arg;
#ifdef __linux__
  pthread_setname_np(pthread_self(), "sp-reclaim");
#endif
  for (;;) {
    pthread_mutex_lock(&qsbr_lock);
    while (!qsbr_head)
      pthread_cond_wait(&qsbr_cond, &qsbr_lock);
    pthread_mutex_unlock(&qsbr_lock);

    if (sp_qsbr_run_ready() > 0) {
      struct timespec ts = { 0, QSBR_POLL_NS };
      while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
    }
  }
  return NULL;
}

int
sp_qsbr_start(void)
{
  pthread_t thr;
  int rc = 0;

  pthread_mutex_lock(&qsbr_lock);
  if (!qsbr_started) {
    rc = pthread_create(&thr, NULL, qsbr_reclaimer, NULL);
    if (rc == 0) {
      pthread_detach(thr);
      qsbr_started = 1;
    }
  }
  pthread_mutex_unlock(&qsbr_lock);
  return rc;
}
