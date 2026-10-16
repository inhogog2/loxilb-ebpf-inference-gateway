/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_hold.c - a half-closed HTTP/2 client is never held, and one of its
 * backend legs ending leaves no mark on it.
 *
 * The hold (sockproxy_hold.c) keeps a client that half-closed after its
 * request until the answer it is owed has come, and ends it early when the
 * leg that carries that answer ends ("nothing more can come"). That is
 * HTTP/1.1 framing: one answer on one leg. An HTTP/2 client carries streams
 * on several legs at once, so one leg ending says nothing about the others.
 * HTTP/2 never writes the hold's counts, but a connection that switched to
 * HTTP/2 after an HTTP/1.1 request still carries that request's counts.
 *
 * Each case first shows the state IS held on an HTTP/1.1 client (the
 * control), then that the same state on an HTTP/2 client is not, and that a
 * leg ending marks the HTTP/1.1 client and not the HTTP/2 one. Drives the
 * REAL sp_client_eof_keep / sp_hold_leg_ended / sp_hold_settle. The twins in
 * wp8/twins-h2leg.sh remove each HTTP/2 guard and must turn this red.
 *
 * Build: make test_h2hold (ASan + UBSan).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_h2.h"
#include "sockproxy_internal.h"
#include "sockproxy_hold.h"
#include "sockproxy_hold_core.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("  (%s:%d)\n", __FILE__, __LINE__);                     \
    }                                                                \
  } while (0)

/* What the hold calls outside itself: the event loop and the deferred
 * close. Recorded, not run. */
static int disarmed, deferred, armed;

int notify_disarm_ent(void *ctx, int fd) { (void)ctx; (void)fd; disarmed++; return 0; }
void proxy_defer_close_mark(proxy_fd_ent_t *pfe) { (void)pfe; deferred++; }
int notify_rearm_ent(void *ctx, int fd, notify_type_t type, void *priv, uint64_t gen)
{ (void)ctx; (void)fd; (void)type; (void)priv; (void)gen; armed++; return 0; }
int notify_add_ent(void *ctx, int fd, notify_type_t type, void *priv, uint64_t gen)
{ (void)ctx; (void)fd; (void)type; (void)priv; (void)gen; armed++; return 0; }

static proxy_struct_t pstruct;
proxy_struct_t *proxy_struct = &pstruct;

/* A connection pair: client c, its leg be, one request forwarded and its
 * answer not complete; plaintext, no direction in the kernel unless asked. */
typedef struct {
  proxy_fd_ent_t c, be;
  proxy_epval_t epv;
  proxy_h2_session_t h2;
  int sv[2], bv[2];
} pair_t;

static void
pair_init(pair_t *p, int h2, int accel_branch)
{
  memset(p, 0, sizeof(*p));
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, p->sv) == 0);
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, p->bv) == 0);
  p->c.fd = p->sv[0];
  p->c.odir = 0;
  p->be.fd = p->bv[0];
  p->be.odir = 1;
  p->c.rfd_ent[0] = &p->be;
  p->c.rfd[0] = p->be.fd;
  p->c.n_rfd = 1;
  p->be.rfd_ent[0] = &p->c;
  p->be.n_rfd = 1;
  p->epv.hold_mode = SP_HOLD_MODE_HOLD;
  p->c.epv = &p->epv;
  atomic_store(&p->c.cresp_forwarded, 1);
  atomic_store(&p->c.cresp_completed, 0);
  if (accel_branch) {
    /* the half-close deferral: response direction in the kernel */
    p->c.resp_outstanding = 1;
    p->be.peer_map_resp_verdict = 1;
  }
  pthread_rwlock_init(&p->c.lock, NULL);
  if (h2)
    p->c.h2_session = &p->h2;
}

static void
pair_fini(pair_t *p)
{
  close(p->sv[0]); close(p->sv[1]);
  close(p->bv[0]); close(p->bv[1]);
}

/* Kept in any way: a flag set, the event loop told, or the client's socket
 * half-shut for reading (recv sees EOF only after a SHUT_RD). */
static int
kept(pair_t *p, int before)
{
  char b;
  int rd_shut = recv(p->sv[0], &b, 1, MSG_DONTWAIT) == 0;

  return p->c.client_half_closed || atomic_load(&p->c.eof_hold) ||
         disarmed + deferred + armed != before || rd_shut;
}

int
main(void)
{
  pair_t p;
  int r, calls;

  setvbuf(stdout, NULL, _IONBF, 0);

  /* --- the hold: plaintext, rule mode hold, an answer owed --- */
  pair_init(&p, 0, 0);
  r = sp_client_eof_keep(&p.c);
  CHECK(r == 1 && atomic_load(&p.c.eof_hold), "control: an HTTP/1.1 client in this state is held");
  sp_hold_leg_ended(&p.c, &p.be);
  CHECK(atomic_load(&p.c.hold_leg_ended) != 0, "control: its leg ending marks it");
  CHECK(sp_hold_settle(&p.c) == 1, "control: and the mark ends the hold");
  pair_fini(&p);

  pair_init(&p, 1, 0);
  calls = disarmed + deferred + armed;
  r = sp_client_eof_keep(&p.c);
  CHECK(r == 0 && !kept(&p, calls), "an HTTP/2 client in the same state is not held (r=%d)", r);
  sp_hold_leg_ended(&p.c, &p.be);
  CHECK(atomic_load(&p.c.hold_leg_ended) == 0, "one of its legs ending leaves no mark");
  pair_fini(&p);

  /* --- the half-close deferral: response direction in the kernel --- */
  pair_init(&p, 0, 1);
  r = sp_client_eof_keep(&p.c);
  CHECK(r == 1 && p.c.client_half_closed, "control: an HTTP/1.1 client is kept for its answer");
  pair_fini(&p);

  pair_init(&p, 1, 1);
  calls = disarmed + deferred + armed;
  r = sp_client_eof_keep(&p.c);
  CHECK(r == 0 && !kept(&p, calls), "an HTTP/2 client in the same state is not (r=%d)", r);
  pair_fini(&p);

  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
