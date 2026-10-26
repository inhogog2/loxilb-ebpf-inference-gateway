/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_hdr_deadline_test.c — the header-completion deadline resolution.
 *
 * Includes ONLY the pure header, so it runs without the proxy object graph:
 *
 *   T1  a configured value is enforced as given.
 *   T2  0 resolves to the product default — it does NOT disable the
 *       deadline. A listener with no deadline is a slowloris target, and
 *       the comment that once promised "0 = disabled" described a switch
 *       the code never had.
 *   T3  the default is the documented 10 s.
 *   T4  the clock measures header blocks only: a block that outlived the
 *       deadline is charged, a disarmed clock (a request in flight, the
 *       idle time between requests) never is, and a block that began
 *       just now is not charged with an earlier block's start.
 *   T5  an fd reused within one tick: the connection closes with an
 *       expired block armed, the next one is accepted on the same fd (the
 *       same shell), and the checker runs in between and after. The new
 *       connection is never charged with its predecessor's start.
 *   T6  publication order: the checker runs between the writer's stores.
 *       The start must be in place before the flag that says it is.
 *   T7  the shell changes hands between the checker's two generation
 *       reads: nothing is charged.
 *   T8  (threads, built with TSan too) a worker re-arming and disarming
 *       while the health pass reads: no data race, no false charge.
 *   T9  the next connection arms between the checker's two data loads:
 *       the old start is never paired with the new generation.
 *
 * Build + run: make test_hdrdl (ASan + UBSan, then TSan).
 * T5-T7 model the worst case, a shell whose clock was NOT zeroed on reuse
 * (the pool zeroes it today); the generation alone must protect it.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

struct sp_hdr_clock;
static void publish_hook(struct sp_hdr_clock *c);
static void read_hook(const struct sp_hdr_clock *c);
static void pair_hook(const struct sp_hdr_clock *c);
#define SP_HDR_PUBLISH_HOOK(c) publish_hook(c)
#define SP_HDR_READ_HOOK(c) read_hook(c)
#define SP_HDR_PAIR_HOOK(c) pair_hook(c)

#include "sockproxy_hdr_deadline.h"

static int g_failures = 0;

#define CHECK(cond, msg) do {                                          \
    if (cond) {                                                        \
      printf("  [PASS] %s\n", (msg));                                  \
    } else {                                                           \
      printf("  [FAIL] %s  (%s:%d)\n", (msg), __FILE__, __LINE__);     \
      g_failures++;                                                    \
    }                                                                  \
  } while (0)

#define DL_MS 10000           /* the default: charged past 10 s */
#define NOW   100000

/* One connection shell: its clock and its generation, bumped on every
 * reuse of the shell, as pfe->gen is. */
static struct { sp_hdr_clock_t clk; uint64_t gen; } conn;

/* What the checker concluded when a hook ran it. */
static int (*publish_check)(void), (*read_change)(void);
static int hook_expired = -1;

static int
checker(void)
{
  return sp_hdr_expired(&conn.clk, &conn.gen, NOW, DL_MS, NULL);
}

static int
bump_gen(void)
{
  __atomic_add_fetch(&conn.gen, 1, __ATOMIC_RELEASE);
  return 0;
}

static void
publish_hook(struct sp_hdr_clock *c)
{
  (void)c;
  if (publish_check)
    hook_expired = publish_check();
}

static void
read_hook(const struct sp_hdr_clock *c)
{
  (void)c;
  if (read_change)
    read_change();
}

static int (*pair_change)(void);

static void
pair_hook(const struct sp_hdr_clock *c)
{
  (void)c;
  if (pair_change)
    pair_change();
}

/* The next connection on the reused shell arms its first block now. */
static int
new_conn_arms(void)
{
  sp_hdr_arm(&conn.clk, NOW, __atomic_load_n(&conn.gen, __ATOMIC_RELAXED), 1);
  return 0;
}

static int stop;   /* __atomic: the reader polls it */

static void *
worker(void *arg)
{
  (void)arg;
  for (int i = 0; i < 200000; i++) {
    sp_hdr_arm(&conn.clk, NOW, __atomic_load_n(&conn.gen, __ATOMIC_RELAXED), i);
    sp_hdr_disarm(&conn.clk);
    if (i % 1000 == 0)
      bump_gen();
  }
  __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
  return NULL;
}

int
main(void)
{
  int64_t age;

  printf("T1 configured value is used as given\n");
  CHECK(sp_hdr_deadline_resolve_ms(1) == 1, "1 ms stays 1 ms");
  CHECK(sp_hdr_deadline_resolve_ms(2500) == 2500, "2500 ms stays 2500 ms");
  CHECK(sp_hdr_deadline_resolve_ms(0xFFFFFFFFu) == 0xFFFFFFFFu,
        "the largest value stays as given");

  printf("T2 zero resolves to the default, never to 'off'\n");
  CHECK(sp_hdr_deadline_resolve_ms(0) != 0,
        "0 does not disable the deadline");
  CHECK(sp_hdr_deadline_resolve_ms(0) == L7_TCP_INSPECT_DEFAULT_MS,
        "0 resolves to L7_TCP_INSPECT_DEFAULT_MS");

  printf("T3 the default is the documented value\n");
  CHECK(L7_TCP_INSPECT_DEFAULT_MS == 10000, "default is 10000 ms");

  printf("T4 the clock measures header blocks only\n");
  conn.gen = 5;
  sp_hdr_arm(&conn.clk, NOW - 20, conn.gen, 1);
  CHECK(sp_hdr_expired(&conn.clk, &conn.gen, NOW, DL_MS, &age) && age == 20,
        "a block open 20 s is charged, with its age");
  CHECK(!sp_hdr_expired(&conn.clk, &conn.gen, NOW - 10, DL_MS, NULL),
        "at exactly the deadline (10 s) it is not yet");
  sp_hdr_disarm(&conn.clk);
  CHECK(!sp_hdr_expired(&conn.clk, &conn.gen, NOW, DL_MS, &age) && age == -1,
        "disarmed (request in flight, or idle between requests): never charged");
  sp_hdr_arm(&conn.clk, NOW, conn.gen, 3);
  CHECK(!sp_hdr_expired(&conn.clk, &conn.gen, NOW, DL_MS, &age) && age == 0,
        "the next block starts its own clock");

  printf("T5 an fd reused within one tick\n");
  conn.gen = 7;
  sp_hdr_arm(&conn.clk, NOW - 20, conn.gen, 1);   /* the old connection's block */
  CHECK(checker(), "the old connection's own block is charged while it lives");
  bump_gen();                                      /* closed; the shell is reused */
  CHECK(!checker(), "between close and the new connection's first header byte: nothing charged");
  publish_check = checker;
  sp_hdr_arm(&conn.clk, NOW, conn.gen, 1);         /* accepted on the same fd */
  publish_check = NULL;
  CHECK(hook_expired == 0, "the checker run while the new connection arms charges nothing");
  CHECK(!checker(), "the new connection survives the next pass");

  printf("T6 the start is published before the flag\n");
  conn.gen = 9;
  sp_hdr_arm(&conn.clk, NOW - 20, conn.gen, 1);    /* block 1, long ago */
  sp_hdr_disarm(&conn.clk);                        /* END_HEADERS */
  hook_expired = -1;
  publish_check = checker;
  sp_hdr_arm(&conn.clk, NOW, conn.gen, 3);         /* block 2 begins now */
  publish_check = NULL;
  CHECK(hook_expired == 0,
        "a checker between the writer's stores never sees block 1's start as armed");

  printf("T7 the shell changes hands between the checker's reads\n");
  conn.gen = 11;
  sp_hdr_arm(&conn.clk, NOW - 20, conn.gen, 1);
  read_change = bump_gen;
  CHECK(!sp_hdr_expired(&conn.clk, &conn.gen, NOW, DL_MS, &age) && age == -1,
        "a generation that changed while the clock was read charges nothing");
  read_change = NULL;

  printf("T9 a new arm lands between the checker's two data loads\n");
  conn.gen = 15;
  sp_hdr_arm(&conn.clk, NOW - 20, conn.gen, 1);   /* the old connection's block */
  bump_gen();                                      /* the shell is reused */
  pair_change = new_conn_arms;                     /* the next one arms meanwhile */
  CHECK(!sp_hdr_expired(&conn.clk, &conn.gen, NOW, DL_MS, NULL),
        "the old start is never paired with the new connection's generation");
  pair_change = NULL;

  printf("T8 a worker re-arming while the health pass reads\n");
  {
    pthread_t t;
    long charged = 0, reads = 0;
    conn.gen = 13;
    sp_hdr_disarm(&conn.clk);
    __atomic_store_n(&stop, 0, __ATOMIC_RELAXED);
    pthread_create(&t, NULL, worker, NULL);
    while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
      charged += sp_hdr_expired(&conn.clk, &conn.gen, NOW, DL_MS, NULL);
      reads++;
    }
    pthread_join(t, NULL);
    CHECK(charged == 0, "no block armed at the current time is ever charged");
    printf("  (%ld concurrent reads)\n", reads);
  }

  if (g_failures) {
    printf("FAIL: %d check(s) failed\n", g_failures);
    return 1;
  }
  puts("PASS: header-completion deadline resolves 0 to the default, never to off; "
       "it charges only the header block of the connection that armed it");
  return 0;
}
