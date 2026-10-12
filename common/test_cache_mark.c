/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * test_cache_mark.c - which backpressure mark a relay cache runs under
 * (sockproxy_cache_mark.h).
 *
 * Build: gcc -Wall -Wextra -Werror -o test_cache_mark test_cache_mark.c -I.
 *
 * The header is pure over three fields of proxy_fd_ent_t
 * (is_chunked_response, rfd_ent[], n_rfd) and MAX_PROXY_EP, so this test
 * mirrors exactly those, the way test_pd_admission.c mirrors the struct
 * (skip sockproxy.h). If the production struct renames a field the build of
 * sockproxy_cache.c breaks, not this test -- the mirror is deliberate.
 *
 * The case that matters is #3: the client entry (own flag 0, where the
 * relay cache lives) whose backend leg carries the flag (where P7 writes
 * it). Before the fix that entry ran under the 12 MiB binary mark.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define MAX_PROXY_EP 32

typedef struct proxy_fd_ent {
  int fd;
  int odir;
  int is_chunked_response;
  struct proxy_fd_ent *rfd_ent[MAX_PROXY_EP];
  int n_rfd;
} proxy_fd_ent_t;

#include "sockproxy_cache_mark.h"

static int checks, failures;

static size_t hw(proxy_fd_ent_t *e) { size_t h = 0; proxy_cache_marks(e, &h, NULL); return h; }
static size_t lw(proxy_fd_ent_t *e) { size_t l = 0; proxy_cache_marks(e, NULL, &l); return l; }
#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (!(cond)) {                                                   \
      failures++;                                                    \
      printf("  FAIL %s:%d: ", __FILE__, __LINE__);                  \
      printf(__VA_ARGS__);                                           \
      printf("\n");                                                  \
    }                                                                \
  } while (0)

static void
link_legs(proxy_fd_ent_t *client, proxy_fd_ent_t *backend)
{
  memset(client, 0, sizeof(*client));
  memset(backend, 0, sizeof(*backend));
  client->fd = 10; client->odir = 0;
  backend->fd = 11; backend->odir = 1;
  client->rfd_ent[0] = backend; client->n_rfd = 1;
  backend->rfd_ent[0] = client; backend->n_rfd = 1;
}

int
main(void)
{
  proxy_fd_ent_t c, b;

  printf("test_cache_mark: backpressure mark selection\n");

  /* 1. Plain binary relay: no flag anywhere -> 12 MiB / 4 MiB. */
  link_legs(&c, &b);
  CHECK(proxy_cache_chunked(&c) == 0, "binary client not chunked");
  CHECK(hw(&c) == (size_t)PROXY_CACHE_HIGH_WATER, "binary high");
  CHECK(lw(&c) == (size_t)PROXY_CACHE_LOW_WATER, "binary low");

  /* 2. Own flag set -> chunked marks (the only case the old code saw). */
  link_legs(&c, &b);
  c.is_chunked_response = 1;
  CHECK(proxy_cache_chunked(&c) == 1, "own flag");
  CHECK(hw(&c) == (size_t)PROXY_CACHE_HIGH_WATER_CHUNKED, "own high");
  CHECK(lw(&c) == (size_t)PROXY_CACHE_LOW_WATER_CHUNKED, "own low");

  /* 3. F-PRIO-3: the response path. P7 wrote the flag on the backend leg;
   * the relay cache is on the client. The client must run under 768 KiB. */
  link_legs(&c, &b);
  b.is_chunked_response = 1;
  CHECK(c.is_chunked_response == 0, "client's own flag stays 0 (P7)");
  CHECK(proxy_cache_chunked(&c) == 1, "client resolves chunked through its backend leg");
  CHECK(hw(&c) == 768 * 1024, "client high = 768 KiB, was 12 MiB");
  CHECK(lw(&c) == 384 * 1024, "client low = 384 KiB");
  /* and the backend entry itself still reports chunked (own flag) */
  CHECK(proxy_cache_chunked(&b) == 1, "backend own flag");

  /* 4. A client with no legs yet (n_rfd 0): binary, and no deref. */
  memset(&c, 0, sizeof(c));
  CHECK(proxy_cache_chunked(&c) == 0, "no legs -> binary");
  CHECK(hw(&c) == (size_t)PROXY_CACHE_HIGH_WATER, "no legs high");

  /* 5. A NULL slot inside n_rfd (leg torn down, slot not compacted) is
   * skipped, and a flagged leg beyond it is still found. */
  link_legs(&c, &b);
  c.rfd_ent[0] = NULL;
  c.rfd_ent[1] = &b;
  c.n_rfd = 2;
  b.is_chunked_response = 1;
  CHECK(proxy_cache_chunked(&c) == 1, "NULL slot skipped, flagged leg at [1] found");

  /* 6. Flagged leg at the last valid index. */
  link_legs(&c, &b);
  memset(c.rfd_ent, 0, sizeof(c.rfd_ent));
  c.rfd_ent[MAX_PROXY_EP - 1] = &b;
  c.n_rfd = MAX_PROXY_EP;
  b.is_chunked_response = 1;
  CHECK(proxy_cache_chunked(&c) == 1, "flagged leg at [MAX_PROXY_EP-1] found");

  /* 7. A bogus n_rfd past the array is clamped, never read past the end. */
  link_legs(&c, &b);
  memset(c.rfd_ent, 0, sizeof(c.rfd_ent));
  c.n_rfd = MAX_PROXY_EP + 7;
  CHECK(proxy_cache_chunked(&c) == 0, "n_rfd past MAX_PROXY_EP clamped, all NULL -> binary");
  c.rfd_ent[MAX_PROXY_EP - 1] = &b;
  b.is_chunked_response = 1;
  CHECK(proxy_cache_chunked(&c) == 1, "clamped scan still reaches the last slot");

  /* 8. Negative n_rfd (never valid, but the loop must not run). */
  link_legs(&c, &b);
  c.n_rfd = -3;
  b.is_chunked_response = 1;
  CHECK(proxy_cache_chunked(&c) == 0, "negative n_rfd: no legs scanned");

  /* 9. Mark sanity: both pairs release below where they arm. */
  CHECK(PROXY_CACHE_LOW_WATER_CHUNKED < PROXY_CACHE_HIGH_WATER_CHUNKED, "chunked low < high");
  CHECK(PROXY_CACHE_LOW_WATER < PROXY_CACHE_HIGH_WATER, "binary low < high");
  CHECK(PROXY_CACHE_HIGH_WATER_CHUNKED < PROXY_CACHE_HIGH_WATER, "chunked mark is the lower one");

  /* 10. One call fills both marks and returns the verdict; NULL outputs
   * are allowed (each cache site asks for one side only). */
  link_legs(&c, &b);
  b.is_chunked_response = 1;
  {
    size_t h = 0, l = 0;
    CHECK(proxy_cache_marks(&c, &h, &l) == 1, "marks() returns the chunked verdict");
    CHECK(h == PROXY_CACHE_HIGH_WATER_CHUNKED && l == PROXY_CACHE_LOW_WATER_CHUNKED,
          "both marks filled from one verdict");
    CHECK(proxy_cache_marks(&c, NULL, NULL) == 1, "NULL outputs tolerated");
    b.is_chunked_response = 0;
    CHECK(proxy_cache_marks(&c, &h, &l) == 0 && h == PROXY_CACHE_HIGH_WATER &&
          l == PROXY_CACHE_LOW_WATER, "binary pair from one verdict");
  }

  printf("test_cache_mark: %d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
