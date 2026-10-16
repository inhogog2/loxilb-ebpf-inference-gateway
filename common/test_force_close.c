/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_force_close.c - an endpoint's force-close (sockproxy_health.c) frees
 * HTTP/1.1 pairs inline and hands every HTTP/2 entry to its own worker.
 *
 * force_close_endpoint_connections runs under PROXY_LOCK on the health
 * thread. An HTTP/2 client's session is walked by its worker with no lock
 * held, so no entry of an HTTP/2 connection may be freed from there: it is
 * shut down instead, and its worker's hangup runs the full teardown. Drives
 * the REAL force_close_endpoint_connections / pd_teardown_conn over a
 * connection list holding:
 *   c2/l2  an HTTP/2 client and its HTTP/2 leg to the endpoint
 *   c1/l1  an HTTP/1.1 pair to the endpoint
 *   c3/l3  a connection that switched to HTTP/2 after an HTTP/1.1 request,
 *          its HTTP/1.1 leg still on the endpoint
 *   w      an HTTP/1.1 client a worker already claimed (deregister -ENOENT)
 * and checks what was freed, what was shut down, and that the scan ends.
 * The twins in wp8/twins-h2leg.sh remove each guard and must turn this red.
 *
 * The reaper-fallback shape (an HTTP/2 client with no leg left, handed to
 * pd_teardown_conn itself) is driven directly.
 *
 * Build: make test_forceclose (ASan + UBSan).
 */
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_internal.h"
#include "sockproxy_h2.h"
#include "sockproxy_health.h"

/* The teardown under test is file-static: compiled in here. */
#include "sockproxy_health.c"

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

static proxy_struct_t pstruct;
proxy_struct_t *proxy_struct = &pstruct;

/* The teardown primitives the force-close calls, recorded. A reset release
 * unlinks the entry from its rule's list, as the real one does. */
static int w_fd = -1, w_deregs;
static proxy_fd_ent_t *released[16], *freed[16];
static int n_released, n_freed;

int
notify_deregister_ent(void *ns, int fd)
{
  (void)ns;
  if (fd == w_fd) {
    w_deregs++;
    return -ENOENT;   /* a worker cleared it first and owns the teardown */
  }
  return 0;
}

void
proxy_release_fd_ctx(proxy_fd_ent_t *e, int reset)
{
  released[n_released++] = e;
  if (reset && e->head) {
    proxy_fd_ent_t **pp = &((proxy_map_ent_t *)e->head)->val.fdlist;
    while (*pp && *pp != e)
      pp = &(*pp)->next;
    if (*pp)
      *pp = e->next;
  }
}

void
proxy_try_free_fd_ctx(proxy_fd_ent_t *e)
{
  freed[n_freed++] = e;
}

/* The reaper's hand-off: the owner is found and woken. */
int
notify_owner_thr(void *ctx, int fd)
{
  (void)ctx; (void)fd;
  return 3;
}

int
notify_wake_worker(void *ctx, int thr, int fd)
{
  (void)ctx; (void)thr; (void)fd;
  return 0;
}

/* The causes recorded for an HTTP/2 client's end line, as called. */
static struct { proxy_fd_ent_t *pfe; int reason; const proxy_fd_ent_t *leg; } marks[64];
static int n_marks;

void
proxy_h2_client_end_mark(proxy_fd_ent_t *pfe, int reason, int err,
                         const proxy_fd_ent_t *leg)
{
  (void)err;
  if (n_marks == (int)(sizeof(marks) / sizeof(marks[0])))
    return;
  marks[n_marks].pfe = pfe;
  marks[n_marks].reason = reason;
  marks[n_marks].leg = leg;
  n_marks++;
}

void
proxy_h2_client_end_log(proxy_fd_ent_t *pfe)
{
  (void)pfe;
}

/* 1 when e was marked with reason and leg. */
static int
marked(proxy_fd_ent_t *e, int reason, const proxy_fd_ent_t *leg)
{
  for (int i = 0; i < n_marks; i++)
    if (marks[i].pfe == e && marks[i].reason == reason && marks[i].leg == leg)
      return 1;
  return 0;
}

static int
marked_any(proxy_fd_ent_t *e)
{
  for (int i = 0; i < n_marks; i++)
    if (marks[i].pfe == e)
      return 1;
  return 0;
}

static int
was(proxy_fd_ent_t **set, int n, proxy_fd_ent_t *e)
{
  for (int i = 0; i < n; i++)
    if (set[i] == e)
      return 1;
  return 0;
}

static int
linked(proxy_map_ent_t *ent, proxy_fd_ent_t *e)
{
  for (proxy_fd_ent_t *p = ent->val.fdlist; p; p = p->next)
    if (p == e)
      return 1;
  return 0;
}

/* 1 when the far end of e's socketpair reads EOF: e was shut down. */
static int peer[64];
static int
shut(proxy_fd_ent_t *e)
{
  char b;
  return recv(peer[e->fd], &b, 1, MSG_DONTWAIT) == 0;
}

static void
mk(proxy_map_ent_t *ent, proxy_fd_ent_t *e, int odir, int ep)
{
  int sv[2];

  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && sv[0] < 64);
  memset(e, 0, sizeof(*e));
  e->fd = sv[0];
  peer[sv[0]] = sv[1];
  e->odir = odir;
  e->ep_num = ep;
  e->head = ent;
  e->next = ent->val.fdlist;
  ent->val.fdlist = e;
}

static void
pair(proxy_fd_ent_t *c, proxy_fd_ent_t *l, int slot)
{
  c->rfd_ent[slot] = l;
  c->rfd[slot] = l->fd;
  c->n_rfd = slot + 1;
  l->rfd_ent[0] = c;
  l->rfd[0] = c->fd;
  l->n_rfd = 1;
}

static void
spin(int sig)
{
  (void)sig;
  printf("FAIL 0 - the force-close scan did not end (livelock)\n");
  _exit(1);
}

int
main(void)
{
  proxy_map_ent_t ent;
  proxy_fd_ent_t c2, l2, c1, l1, c3, l3, w, wl;
  proxy_h2_session_t h2a, h2b;
  backend_h2_session_t bs;
  const int EP = 1;

  setvbuf(stdout, NULL, _IONBF, 0);
  memset(&ent, 0, sizeof(ent));
  memset(&h2a, 0, sizeof(h2a));
  memset(&h2b, 0, sizeof(h2b));
  memset(&bs, 0, sizeof(bs));

  mk(&ent, &c2, 0, EP);  c2.h2_session = &h2a;   /* its last stream went to EP */
  mk(&ent, &l2, 1, EP);  l2.backend_h2_session = &bs;
  pair(&c2, &l2, 0);
  mk(&ent, &c1, 0, EP);
  mk(&ent, &l1, 1, -1);
  pair(&c1, &l1, 0);
  mk(&ent, &c3, 0, 0);   c3.h2_session = &h2b;   /* switched; not on EP itself */
  mk(&ent, &l3, 1, EP);
  pair(&c3, &l3, 0);
  mk(&ent, &w, 0, EP);
  mk(&ent, &wl, 1, -1);
  pair(&w, &wl, 0);
  w_fd = w.fd;

  signal(SIGALRM, spin);
  alarm(5);
  force_close_endpoint_connections(&ent, EP);
  alarm(0);
  CHECK(1, "the scan ends");

  CHECK(!was(released, n_released, &c2) && linked(&ent, &c2) && !shut(&c2),
        "the HTTP/2 client is neither freed nor shut down: it goes on over its other legs");
  CHECK(!was(released, n_released, &l2) && linked(&ent, &l2) && shut(&l2),
        "its leg to the endpoint is shut down, not freed: its worker ends it");
  CHECK(was(freed, n_freed, &c1) && was(freed, n_freed, &l1) &&
        !linked(&ent, &c1) && !linked(&ent, &l1),
        "the HTTP/1.1 pair is freed inline, as before");
  CHECK(!was(released, n_released, &c3) && !was(released, n_released, &l3) && shut(&l3),
        "the switched connection's HTTP/1.1 leg is handed to its worker");
  CHECK(!shut(&c3) && linked(&ent, &c3),
        "and its HTTP/2 client is not touched from here");
  /* The worker that ends a handed-off client sees only the hangup, which
   * reads as the client leaving: the cause is recorded before it. */
  CHECK(marked(&c3, SP_H2_END_TEARDOWN, &l3),
        "the switched client's end is recorded as the teardown, through its leg");
  CHECK(!marked_any(&c2),
        "the HTTP/2 client that goes on records no end");
  /* Passed, not retried in place: once per scan (here the first pass and the
   * rescan after c1's free), never the endless retry of the same entry. */
  CHECK(w_deregs >= 1 && w_deregs <= 2 && !was(freed, n_freed, &w) && linked(&ent, &w),
        "a client a worker already claimed is passed, at most once per scan (%d tries)", w_deregs);

  /* The reaper's fallback (its owner could not be woken) hands a client to
   * pd_teardown_conn itself; an HTTP/2 client with no leg left has no peer
   * to recognise it by. */
  {
    proxy_map_ent_t ent2;
    proxy_fd_ent_t lone;
    proxy_h2_session_t h2c;

    memset(&ent2, 0, sizeof(ent2));
    memset(&h2c, 0, sizeof(h2c));
    mk(&ent2, &lone, 0, EP);
    lone.h2_session = &h2c;
    n_released = n_freed = 0;
    CHECK(pd_teardown_conn(&lone) == 0 && n_released == 0 && shut(&lone) && linked(&ent2, &lone),
          "an HTTP/2 client with no leg, reaped, is shut down for its worker, not freed");
    CHECK(marked(&lone, SP_H2_END_TEARDOWN, NULL),
          "and its end is recorded as the teardown before the hangup");
  }

  /* The reaper hands an unanswered request to the connection's owner, which
   * finishes it and sees only its own hangup: the cause is recorded before
   * the hand-off, or the end line would name the wrong actor. */
  {
    proxy_map_ent_t ent3;
    proxy_fd_ent_t rc;
    proxy_h2_session_t h2r;

    memset(&ent3, 0, sizeof(ent3));
    memset(&h2r, 0, sizeof(h2r));
    mk(&ent3, &rc, 0, EP);
    rc.h2_session = &h2r;
    pstruct.ns = &pstruct;              /* any non-NULL notifier */
    n_marks = 0;
    pd_reap_respond(&rc, SP_REAP_PD_PARK_TIMEOUT);
    pstruct.ns = NULL;
    CHECK(rc.reap_resp == SP_REAP_PD_PARK_TIMEOUT && marked(&rc, SP_H2_END_REAPER, NULL),
          "a reaped client handed to its owner is recorded as the reaper's end");
  }

  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
