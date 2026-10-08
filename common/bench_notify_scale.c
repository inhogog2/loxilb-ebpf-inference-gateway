/* SPDX-License-Identifier: BSD-3-Clause
 *
 * bench_notify_scale.c - notifier throughput against the relay worker count.
 *
 * W relay shards, P echo pairs pinned onto each, C client threads driving
 * one-byte round trips as fast as they can. Each round trip is one epoll
 * wakeup and one dispatch (a read-side notifier lookup plus the callback), so
 * the aggregate rate against W is the notifier's scaling curve on this
 * machine, free of HTTP parsing and backend I/O. Compare W=4 (the historical
 * fixed worker count) with W=nproc to decide what LLB_PROXY_WORKERS should be
 * on a given box; the number to watch is round_trips/s, not CPU.
 *
 *   bench_notify_scale <workers> <pairs_per_worker> <clients> <seconds>
 *   for W in 1 2 4 8 16; do ./bench_notify_scale $W 64 $((W*2)) 5; done
 *
 * Build: make bench_notify_scale (not part of any test target).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include "log.h"
#include "notify.h"

__thread volatile sig_atomic_t g_llb_proxy_worker = 0;

static int
cb(int fd, notify_type_t t, void *p, uint64_t g)
{
  char b[64];

  (void)g; (void)p;
  if (t & NOTI_TYPE_IN) {
    ssize_t n = recv(fd, b, sizeof b, MSG_DONTWAIT);
    if (n > 0) {
      ssize_t w = send(fd, b, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
      (void)w;
    }
  }
  return 0;
}

static void pd(void *p) { (void)p; }
static void *run(void *a) { notify_start(a); return NULL; }

static atomic_long g_rt;
static atomic_int g_stop;

typedef struct { int *peers; int n; } carg_t;

static void *
client(void *a)
{
  carg_t *c = a;
  char b = 'x';
  long rt = 0;

  while (!atomic_load(&g_stop)) {
    for (int i = 0; i < c->n; i++) {
      if (send(c->peers[i], &b, 1, 0) != 1 || recv(c->peers[i], &b, 1, 0) != 1) {
        atomic_fetch_add(&g_rt, rt);
        return NULL;
      }
      rt++;
    }
  }
  atomic_fetch_add(&g_rt, rt);
  return NULL;
}

int
main(int argc, char **argv)
{
  int W, P, C, secs;
  struct rlimit rl;
  notify_cbs_t cbs;
  void *ns;
  pthread_t thr;
  int total, *peers, k = 0;
  pthread_t *ct;
  carg_t *ca;
  int per;

  if (argc != 5) {
    fprintf(stderr, "usage: %s <workers> <pairs_per_worker> <clients> <seconds>\n", argv[0]);
    return 2;
  }
  W = atoi(argv[1]); P = atoi(argv[2]); C = atoi(argv[3]); secs = atoi(argv[4]);
  if (W < 1 || W > NOTIFY_MAX_RELAY_SHARDS || P < 1 || C < 1 || secs < 1) {
    fprintf(stderr, "bad arguments (workers 1..%d)\n", NOTIFY_MAX_RELAY_SHARDS);
    return 2;
  }
  log_set_quiet(true);
  rl.rlim_cur = rl.rlim_max = 65536;
  setrlimit(RLIMIT_NOFILE, &rl);

  memset(&cbs, 0, sizeof(cbs));
  cbs.notify = cb;
  cbs.pdestroy = pd;
  ns = notify_ctx_new(&cbs, W);
  if (!ns) {
    fprintf(stderr, "notify_ctx_new(%d) failed\n", W);
    return 1;
  }
  pthread_create(&thr, NULL, run, ns);
  usleep(50000);

  /* P pairs per shard: the first pair of a shard lands where fd modulo W
   * says, the rest are pinned to it, so every shard carries P whatever the
   * fd numbering does. */
  total = W * P;
  peers = calloc(total, sizeof(int));
  {
    int *pin = calloc(W, sizeof(int));
    int filled = 0;
    for (int w = 0; w < W; w++) pin[w] = -1;
    while (filled < total) {
      int sv[2];
      int shard;
      if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
        perror("socketpair");
        return 1;
      }
      shard = sv[0] % W;
      if (pin[shard] < 0) {
        notify_add_ent(ns, sv[0], NOTI_TYPE_IN | NOTI_TYPE_HUP, &peers[k], 1);
        pin[shard] = sv[0];
        peers[k++] = sv[1];
        filled++;
        /* pin the rest of this shard's pairs to its first fd */
        for (int i = 1; i < P; i++) {
          int sp[2];
          if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp)) {
            perror("socketpair");
            return 1;
          }
          notify_add_ent_pinned(ns, sp[0], NOTI_TYPE_IN | NOTI_TYPE_HUP, &peers[k], 1, pin[shard]);
          peers[k++] = sp[1];
          filled++;
        }
      } else {
        /* this shard is full: burn the pair, shift the numbering */
        close(sv[0]);
        close(sv[1]);
        {
          int filler = dup(0);   /* leaked on purpose: it shifts the numbering */
          if (filler < 0) {
            perror("dup");
            return 1;
          }
        }
      }
    }
    free(pin);
  }

  ct = calloc(C, sizeof *ct);
  ca = calloc(C, sizeof *ca);
  per = total / C;
  if (per < 1) {
    fprintf(stderr, "more clients than pairs\n");
    return 2;
  }
  for (int c = 0; c < C; c++) {
    ca[c].peers = peers + c * per;
    ca[c].n = per;
    pthread_create(&ct[c], NULL, client, &ca[c]);
  }
  sleep(secs);
  atomic_store(&g_stop, 1);
  for (int c = 0; c < C; c++) {
    pthread_join(ct[c], NULL);
  }
  printf("workers=%d pairs/worker=%d clients=%d round_trips/s=%ld\n",
         W, P, C, atomic_load(&g_rt) / secs);
  return 0;
}
