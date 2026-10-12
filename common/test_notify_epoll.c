/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_notify_epoll.c - the relay shards wait with epoll, not poll(2).
 *
 * Every worker used to copy its whole pollfd array under the notifier lock
 * and hand it to poll(2) on each round, then scan every slot for revents.
 * The cost of ONE wakeup therefore grew with the number of idle connections
 * the shard owned: a streamed inference emits one small chunk per token, so
 * a fleet of long idle streams made every token of every other stream pay
 * for all of them. The worker now waits on an epoll instance and is handed
 * only the ready fds.
 *
 * This unit runs real socket pairs through a running notifier and checks
 * that the dispatch contract of notify.h survived the change:
 *   - a readable fd is dispatched with NOTI_TYPE_IN on its owner shard;
 *   - OUT is dispatched when asked for and folded into IN as before;
 *   - a peer's shutdown(SHUT_WR) is RDHUP (non-fatal), a peer's close is HUP
 *     and releases the registration through cbs.pdestroy exactly once;
 *   - a disarmed fd is not dispatched for IN while HUP still comes through;
 *   - notify_wake_worker resumes a fd on ITS OWNER worker;
 *   - a pinned backend leg dispatches on its client's worker;
 *   - the per-event cost does not grow with the idle population (the oracle
 *     of the change: measured with 8 idle fds and again with 4000);
 *   - a context with 16 relay shards dispatches on every shard, and the
 *     read-side lookup lets the shards dispatch concurrently (round trips
 *     per second across 16 shards exceed what one shard delivers alone).
 *
 * Build (wired into `make test_notify_epoll`):
 *   gcc -Wall -Wextra -Werror -o test_notify_epoll test_notify_epoll.c notify.c log.c -I. -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sys/wait.h>
#include <sched.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include "notify.h"

__thread volatile sig_atomic_t g_llb_proxy_worker = 0;

static int failures = 0;
static int checks   = 0;

#define N_RELAY 2

static void
check(const char *name, int ok, long got, long want)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAIL %-60s got %ld want %ld\n", name, got, want);
  } else {
    printf("ok   %-60s (%ld)\n", name, got);
  }
}

static void
sleep_ms(int ms)
{
  struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
  nanosleep(&ts, NULL);
}

static uint64_t
now_us(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

/* ---- the fixture: one priv per registered fd, counters per event type ---- */

typedef struct tpriv {
  int fd;
  atomic_int in, out, hup, rdhup, err;
  atomic_int destroyed;
  atomic_int worker;        /* the worker id the last dispatch ran on */
  atomic_int echo;          /* 1: drain the socket on IN and echo one byte back */
  atomic_int resumed;       /* cbs.resume calls */
  atomic_int resume_worker;
} tpriv_t;

static void *g_ns;
static tpriv_t *g_privs[70000];

static int
cb_notify(int fd, notify_type_t type, void *priv, uint64_t gen)
{
  tpriv_t *p = priv;
  (void)gen;
  if (!p || p->fd != fd) {
    return 0;
  }
  atomic_store(&p->worker, notify_worker_id());
  if (type & NOTI_TYPE_IN) {
    atomic_fetch_add(&p->in, 1);
    if (atomic_load(&p->echo)) {
      char buf[256];
      ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
      if (n > 0) {
        ssize_t w = send(fd, buf, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
        (void)w;
      }
    }
  }
  if (type & NOTI_TYPE_OUT) {
    atomic_fetch_add(&p->out, 1);
    /* OUT is level-triggered: drop it again or the worker spins */
    notify_add_ent(g_ns, fd, NOTI_TYPE_IN | NOTI_TYPE_HUP, p, 1);
  }
  if (type & NOTI_TYPE_HUP) {
    atomic_fetch_add(&p->hup, 1);
  }
  if (type & NOTI_TYPE_RDHUP) {
    atomic_fetch_add(&p->rdhup, 1);
    /* a half-closed source is parked, as the relay does */
    notify_disarm_ent(g_ns, fd);
  }
  if (type & NOTI_TYPE_ERROR) {
    atomic_fetch_add(&p->err, 1);
  }
  return 0;
}

static void
cb_destroy(void *priv)
{
  tpriv_t *p = priv;
  if (p) {
    atomic_fetch_add(&p->destroyed, 1);
  }
}

static void
cb_resume(int fd)
{
  tpriv_t *p = (fd > 0 && fd < 70000) ? g_privs[fd] : NULL;
  if (p) {
    atomic_fetch_add(&p->resumed, 1);
    atomic_store(&p->resume_worker, notify_worker_id());
  }
}

static void *
run_shards(void *arg)
{
  notify_start(arg);
  return NULL;
}

static tpriv_t *
priv_for(int fd)
{
  tpriv_t *p = calloc(1, sizeof(*p));
  p->fd = fd;
  g_privs[fd] = p;
  return p;
}

/* a connected pair; [0] is registered, [1] is the peer the test drives */
static int
pair(int sv[2])
{
  return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}

static int
wait_for(atomic_int *v, int want, int ms)
{
  for (int i = 0; i < ms; i++) {
    if (atomic_load(v) >= want) {
      return 1;
    }
    sleep_ms(1);
  }
  return atomic_load(v) >= want;
}

/* one readable byte -> one IN dispatch (level-triggered, drained by echo) */
static void
case_in_dispatch(void)
{
  int sv[2];
  tpriv_t *p;
  char b = 'x';

  check("pair for IN", pair(sv) == 0, 0, 0);
  p = priv_for(sv[0]);
  atomic_store(&p->echo, 1);
  check("register for IN|HUP", notify_add_ent(g_ns, sv[0], NOTI_TYPE_IN | NOTI_TYPE_HUP, p, 1) == 0, 0, 0);
  check("peer writes", send(sv[1], &b, 1, 0) == 1, 0, 0);
  check("IN dispatched", wait_for(&p->in, 1, 500), atomic_load(&p->in), 1);
  check("IN ran on the fd's shard", atomic_load(&p->worker) == notify_ent_thr(g_ns, sv[0]),
        atomic_load(&p->worker), notify_ent_thr(g_ns, sv[0]));
  check("echo came back", recv(sv[1], &b, 1, 0) == 1, 0, 0);
  sleep_ms(30);
  check("nothing dispatched while idle", atomic_load(&p->in) == 1, atomic_load(&p->in), 1);

  /* OUT is folded into IN, as the poll dispatcher did */
  check("ask for OUT", notify_add_ent(g_ns, sv[0], NOTI_TYPE_IN | NOTI_TYPE_OUT | NOTI_TYPE_HUP, p, 1) == 0, 0, 0);
  check("OUT dispatched", wait_for(&p->out, 1, 500), atomic_load(&p->out), 1);
  check("OUT folded into IN", atomic_load(&p->in) >= 2, atomic_load(&p->in), 2);
  sleep_ms(30);
  check("OUT dropped again by the callback", atomic_load(&p->out) == 1, atomic_load(&p->out), 1);

  /* a half-close from the peer is RDHUP, not HUP */
  shutdown(sv[1], SHUT_WR);
  check("RDHUP dispatched", wait_for(&p->rdhup, 1, 500), atomic_load(&p->rdhup), 1);
  check("RDHUP is not HUP", atomic_load(&p->hup) == 0, atomic_load(&p->hup), 0);
  check("RDHUP did not release the registration", notify_ent_thr(g_ns, sv[0]) >= 0,
        notify_ent_thr(g_ns, sv[0]), 0);
  check("not destroyed on RDHUP", atomic_load(&p->destroyed) == 0, atomic_load(&p->destroyed), 0);
  /* disarmed by the callback: a readable byte must not dispatch IN now */
  sleep_ms(30);
  {
    int in_before = atomic_load(&p->in);
    sleep_ms(50);
    check("disarmed: no IN while readable (EOF)", atomic_load(&p->in) == in_before,
          atomic_load(&p->in), in_before);
  }
  /* the full close is HUP and releases exactly once */
  close(sv[1]);
  check("HUP after peer close", wait_for(&p->hup, 1, 500), atomic_load(&p->hup), 1);
  check("released by the HUP", wait_for(&p->destroyed, 1, 500), atomic_load(&p->destroyed), 1);
  sleep_ms(30);
  check("released exactly once", atomic_load(&p->destroyed) == 1, atomic_load(&p->destroyed), 1);
  check("unregistered after HUP", notify_ent_thr(g_ns, sv[0]) == -1, notify_ent_thr(g_ns, sv[0]), -1);
  close(sv[0]);
}

/* a backend leg pinned to its client dispatches on the client's worker */
static void
case_pinned(void)
{
  int c[2], b[2];
  tpriv_t *pc, *pb;
  char x = 'y';
  int thr;

  check("pair client", pair(c) == 0, 0, 0);
  check("pair backend", pair(b) == 0, 0, 0);
  pc = priv_for(c[0]);
  pb = priv_for(b[0]);
  atomic_store(&pc->echo, 1);
  atomic_store(&pb->echo, 1);
  check("register client", notify_add_ent(g_ns, c[0], NOTI_TYPE_IN | NOTI_TYPE_HUP, pc, 1) == 0, 0, 0);
  check("register backend pinned", notify_add_ent_pinned(g_ns, b[0], NOTI_TYPE_IN | NOTI_TYPE_HUP, pb, 1, c[0]) == 0, 0, 0);
  thr = notify_ent_thr(g_ns, c[0]);
  check("backend on the client's shard", notify_ent_thr(g_ns, b[0]) == thr, notify_ent_thr(g_ns, b[0]), thr);
  check("backend peer writes", send(b[1], &x, 1, 0) == 1, 0, 0);
  check("backend IN dispatched", wait_for(&pb->in, 1, 500), atomic_load(&pb->in), 1);
  check("backend dispatched on the client's worker", atomic_load(&pb->worker) == thr, atomic_load(&pb->worker), thr);
  check("deregister backend (no destroy)", notify_deregister_ent(g_ns, b[0]) == 0, 0, 0);
  check("deregister did not destroy", atomic_load(&pb->destroyed) == 0, atomic_load(&pb->destroyed), 0);
  check("delete client (destroy)", notify_delete_ent(g_ns, c[0], 0) == 0, 0, 0);
  check("delete destroyed once", atomic_load(&pc->destroyed) == 1, atomic_load(&pc->destroyed), 1);
  close(c[0]); close(c[1]); close(b[0]); close(b[1]);
}

/* notify_wake_worker lands cbs.resume on the fd's owner worker */
static void
case_resume(void)
{
  int sv[2];
  tpriv_t *p;
  int thr;

  check("pair for resume", pair(sv) == 0, 0, 0);
  p = priv_for(sv[0]);
  check("register for resume", notify_add_ent(g_ns, sv[0], NOTI_TYPE_IN | NOTI_TYPE_HUP, p, 1) == 0, 0, 0);
  thr = notify_owner_thr(g_ns, sv[0]);
  check("owner is the registered shard", thr == notify_ent_thr(g_ns, sv[0]), thr, notify_ent_thr(g_ns, sv[0]));
  check("wake the owner", notify_wake_worker(g_ns, thr, sv[0]) == 0, 0, 0);
  check("resumed", wait_for(&p->resumed, 1, 500), atomic_load(&p->resumed), 1);
  check("resumed on the owner worker", atomic_load(&p->resume_worker) == thr, atomic_load(&p->resume_worker), thr);
  check("wake a bad worker is refused", notify_wake_worker(g_ns, 7, sv[0]) == -EINVAL, notify_wake_worker(g_ns, 7, sv[0]), -EINVAL);
  notify_deregister_ent(g_ns, sv[0]);
  close(sv[0]); close(sv[1]);
}

/* ---- the oracle: per-event cost vs idle population ---- */

/* round trips through one echoing pair on a shard that also owns `idle`
 * registered-but-silent fds; returns the mean us per round trip */
static double
round_trip_us(int idle, int rounds)
{
  int sv[2];
  tpriv_t *p;
  int (*idle_sv)[2] = calloc(idle > 0 ? idle : 1, sizeof(*idle_sv));
  tpriv_t **idle_p = calloc(idle > 0 ? idle : 1, sizeof(*idle_p));
  int shard;
  int n_idle = 0;
  uint64_t t0, t1;
  char b = 'z';

  if (pair(sv)) {
    return -1;
  }
  p = priv_for(sv[0]);
  atomic_store(&p->echo, 1);
  notify_add_ent(g_ns, sv[0], NOTI_TYPE_IN | NOTI_TYPE_HUP, p, 1);
  shard = notify_ent_thr(g_ns, sv[0]);

  /* idle fds pinned onto the SAME shard, so they share its wait */
  for (int i = 0; i < idle; i++) {
    if (pair(idle_sv[i])) {
      break;
    }
    idle_p[i] = priv_for(idle_sv[i][0]);
    if (notify_add_ent_pinned(g_ns, idle_sv[i][0], NOTI_TYPE_IN | NOTI_TYPE_HUP, idle_p[i], 1, sv[0]) != 0) {
      break;
    }
    n_idle++;
  }
  (void)shard;

  /* warm up */
  for (int i = 0; i < 50; i++) {
    if (send(sv[1], &b, 1, 0) != 1 || recv(sv[1], &b, 1, 0) != 1) break;
  }
  t0 = now_us();
  for (int i = 0; i < rounds; i++) {
    if (send(sv[1], &b, 1, 0) != 1 || recv(sv[1], &b, 1, 0) != 1) {
      break;
    }
  }
  t1 = now_us();

  for (int i = 0; i < n_idle; i++) {
    notify_deregister_ent(g_ns, idle_sv[i][0]);
    close(idle_sv[i][0]);
    close(idle_sv[i][1]);
  }
  notify_deregister_ent(g_ns, sv[0]);
  close(sv[0]);
  close(sv[1]);
  free(idle_sv);
  free(idle_p);
  return (double)(t1 - t0) / rounds;
}

static void
case_scaling(void)
{
  double few, many;
  const int rounds = 2000;

  few = round_trip_us(8, rounds);
  many = round_trip_us(4000, rounds);
  printf("     round trip: %.1f us with 8 idle fds, %.1f us with 4000 idle fds\n", few, many);
  check("round trips completed", few > 0 && many > 0, (long)few, 1);
  /* With poll(2) each wakeup copied and scanned the whole array, so 4000
   * idle fds multiplied the per-event cost several times over (measured
   * 10-23x on the pre-change notifier, 350-570 us against 25-33 us). epoll
   * hands back the ready fd alone:
   * the two must be of the same order. */
  check("per-event cost does not grow with idle fds (<2.5x)", many < few * 2.5, (long)(many * 10 / few), 25);
}

/* ---- many shards: every shard dispatches, and together they go faster ---- */

static double
shard_rate(int n_relay, int pairs_per_shard, int rounds)
{
  notify_cbs_t cbs;
  void *ns;
  pthread_t thr;
  int total = n_relay * pairs_per_shard;
  int (*sv)[2] = calloc(total, sizeof(*sv));
  tpriv_t **pv = calloc(total, sizeof(*pv));
  int *seen = calloc(n_relay, sizeof(int));
  uint64_t t0, t1;
  char b = 'q';
  int shards_hit = 0;

  memset(&cbs, 0, sizeof(cbs));
  cbs.notify = cb_notify;
  cbs.pdestroy = cb_destroy;
  ns = notify_ctx_new(&cbs, n_relay);
  if (!ns) {
    return -1;
  }
  /* the fixture's callbacks look up g_ns; point it at this context */
  g_ns = ns;
  pthread_create(&thr, NULL, run_shards, ns);
  sleep_ms(50);

  /* Placement is fd modulo the relay count, and socketpair() hands out fd
   * numbers two at a time, so pairs made back to back cover only half of
   * the residues. Keep a pair only when its shard still has fewer than
   * pairs_per_shard, and burn one fd number between attempts so the
   * numbering walks every residue. */
  {
    int *per = calloc(n_relay, sizeof(int));
    int kept = 0, attempts = 0;
    int fillers[64];
    int n_fill = 0;
    while (kept < total && attempts < 64 * total) {
      int s2[2];
      int shard;
      attempts++;
      if (pair(s2)) {
        return -1;
      }
      shard = s2[0] % n_relay;
      if (per[shard] < pairs_per_shard) {
        per[shard]++;
        sv[kept][0] = s2[0];
        sv[kept][1] = s2[1];
        pv[kept] = priv_for(s2[0]);
        atomic_store(&pv[kept]->echo, 1);
        notify_add_ent(ns, s2[0], NOTI_TYPE_IN | NOTI_TYPE_HUP, pv[kept], 1);
        kept++;
      } else {
        close(s2[0]);
        close(s2[1]);
        /* shift the numbering by one so the next pair lands elsewhere */
        if (n_fill < 64) {
          fillers[n_fill++] = dup(0);
        }
      }
    }
    for (int f = 0; f < n_fill; f++) {
      close(fillers[f]);
    }
    free(per);
    if (kept < total) {
      return -1;
    }
  }
  /* one round trip on each pair; every shard that owns a pair must have run */
  for (int i = 0; i < total; i++) {
    if (send(sv[i][1], &b, 1, 0) != 1 || recv(sv[i][1], &b, 1, 0) != 1) {
      return -1;
    }
    seen[atomic_load(&pv[i]->worker)]++;
  }
  for (int s = 0; s < n_relay; s++) {
    if (seen[s]) {
      shards_hit++;
    }
  }
  if (shards_hit != n_relay) {
    printf("     %d of %d shards dispatched\n", shards_hit, n_relay);
    return -2;
  }
  /* throughput: walk every pair `rounds` times, as fast as one client can */
  t0 = now_us();
  for (int r = 0; r < rounds; r++) {
    for (int i = 0; i < total; i++) {
      if (send(sv[i][1], &b, 1, 0) != 1 || recv(sv[i][1], &b, 1, 0) != 1) {
        return -1;
      }
    }
  }
  t1 = now_us();
  for (int i = 0; i < total; i++) {
    notify_deregister_ent(ns, sv[i][0]);
    close(sv[i][0]);
    close(sv[i][1]);
  }
  free(sv);
  free(pv);
  free(seen);
  return (double)rounds * total * 1e6 / (double)(t1 - t0);
}

/* Each timed arm runs in a fresh exec: prior notifier workers and retained
 * contexts cannot contaminate the next arm. This also preserves raw samples. */
static double isolated_shard_rate(int shards)
{
  int fds[2], status; char count[12]; double rate=-1;
  snprintf(count,sizeof(count),"%d",shards);
  if (pipe(fds)) return -1;
  pid_t child=fork();
  if (child==0) {
    close(fds[0]);
    if (dup2(fds[1],STDOUT_FILENO)<0) _exit(126);
    close(fds[1]);
    execl("/proc/self/exe","test_notify_epoll","--measure-shards",count,(char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  if (child<0) {close(fds[0]);return -1;}
  FILE *in=fdopen(fds[0],"r");
  if (in) {if (fscanf(in,"RATE %lf",&rate)!=1) rate=-1;fclose(in);}
  else close(fds[0]);
  if (waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)) rate=-1;
  return rate;
}
static void measurement_environment(void)
{
  cpu_set_t affinity; CPU_ZERO(&affinity);
  if (!sched_getaffinity(0,sizeof(affinity),&affinity))
    printf("     measurement affinity CPU count=%d; online CPUs=%ld\n",CPU_COUNT(&affinity),sysconf(_SC_NPROCESSORS_ONLN));
  const char *paths[]={"/sys/fs/cgroup/cpu.max","/sys/fs/cgroup/cpu.stat","/proc/stat"};
  for (unsigned i=0;i<sizeof(paths)/sizeof(paths[0]);i++) {
    FILE *f=fopen(paths[i],"r");char line[256];
    if (!f) {printf("     telemetry unavailable: %s\n",paths[i]);continue;}
    printf("     telemetry %s:\n",paths[i]);
    unsigned limit=i==2 ? 1:16;
    while (limit-- && fgets(line,sizeof(line),f)) printf("       %s",line);
    fclose(f);
  }
  struct rusage usage;
  if (!getrusage(RUSAGE_CHILDREN,&usage))
    printf("     child context switches voluntary=%ld involuntary=%ld\n",usage.ru_nvcsw,usage.ru_nivcsw);
}
static void case_many_shards(void)
{
  enum { SAMPLES=6 };
  double ratios[SAMPLES]; int valid=1;
  measurement_environment();
  for (unsigned i=0;i<SAMPLES;i++) {
    double one,many;
    if (i%2) {many=isolated_shard_rate(16);one=isolated_shard_rate(1);}
    else {one=isolated_shard_rate(1);many=isolated_shard_rate(16);}
    ratios[i]=(one>0 && many>0) ? many/one:-1;
    if (ratios[i]<0) valid=0;
    printf("     paired sample %u order=%s one=%.0f rt/s many=%.0f rt/s ratio=%.6f raw_threshold=%s\n",
        i+1,i%2?"16,1":"1,16",one,many,ratios[i],ratios[i]>=0.5?"PASS":"FAIL");
  }
  measurement_environment();
  check("16-shard context: every shard dispatched in all measured arms",valid,valid,1);
  for (unsigned i=1;i<SAMPLES;i++) {
    double v=ratios[i];unsigned j=i;
    while (j && ratios[j-1]>v) {ratios[j]=ratios[j-1];j--;}
    ratios[j]=v;
  }
  double median=(ratios[SAMPLES/2-1]+ratios[SAMPLES/2])/2;
  /* Prespecified median of ALL six pairs; no retries or selected successful
   * arms. This is a sequential-client dispatch check, not parallel scaling. */
  printf("     all-pair median ratio=%.6f; unchanged threshold=0.5\n",median);
  check("16 shards are not slower than one (all-pair median >= 0.5x)",valid && median>=0.5,(long)(median*10),5);
}

int
main(int argc,char **argv)
{
  if (argc==3 && !strcmp(argv[1],"--measure-shards")) {
    int shards=atoi(argv[2]);
    if (shards!=1 && shards!=16) return 2;
    double rate=shard_rate(shards,16/shards,200);
    printf("RATE %.17g\n",rate);
    return rate>0 ? 0:1;
  }
  notify_cbs_t cbs;
  pthread_t thr;
  struct rlimit rl;

  if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < 16384) {
    rl.rlim_cur = rl.rlim_max < 16384 ? rl.rlim_max : 16384;
    setrlimit(RLIMIT_NOFILE, &rl);
  }

  memset(&cbs, 0, sizeof(cbs));
  cbs.notify = cb_notify;
  cbs.pdestroy = cb_destroy;
  cbs.resume = cb_resume;
  g_ns = notify_ctx_new(&cbs, N_RELAY);
  check("context", g_ns != NULL, g_ns != NULL, 1);
  pthread_create(&thr, NULL, run_shards, g_ns);
  sleep_ms(50);

  case_in_dispatch();
  case_pinned();
  case_resume();
  case_scaling();
  case_many_shards();

  printf("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
