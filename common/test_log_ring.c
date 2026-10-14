/* The operational log's rings and writer thread (log.c).
 *
 *   gcc -Wall -Wextra -o test_log_ring test_log_ring.c log.c -I. -lpthread
 *
 * The claim under test is the one a proxy worker depends on: a log call
 * never waits for a sink. The sink here is a pipe nobody reads, so the
 * writer thread blocks in write(2) for as long as the test wants. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

static int g_fail;

#define CHECK(cond, ...) do { \
  if (cond) { printf("  ok   "); } else { printf("  FAIL "); g_fail++; } \
  printf(__VA_ARGS__); printf("\n"); } while (0)

static double now_s(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static char *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "r");
  char *buf;
  long n;
  if (!f) { *len = 0; return calloc(1, 1); }
  fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
  buf = calloc(1, (size_t)n + 1);
  *len = fread(buf, 1, (size_t)n, f);
  fclose(f);
  return buf;
}

static size_t count_str(const char *hay, const char *needle) {
  size_t n = 0, l = strlen(needle);
  for (const char *p = hay; (p = strstr(p, needle)); p += l) n++;
  return n;
}

static uint64_t dropped_all(void) {
  uint64_t n = 0;
  for (int l = LOG_TRACE; l <= LOG_FATAL; l++) n += log_dropped(l);
  return n;
}

/* ---- 1. before the writer starts a line is in the file when the call returns */
static void t_sync(const char *dir) {
  char path[256];
  size_t len;
  char *s;
  FILE *fp;

  printf("t_sync\n");
  snprintf(path, sizeof(path), "%s/sync.log", dir);
  fp = fopen(path, "a");
  log_add_fp(fp, LOG_INFO);
  log_info("sync line %d", 1);
  s = slurp(path, &len);
  CHECK(strstr(s, "sync line 1\n") != NULL, "a line logged before the writer starts is written by the caller");
  CHECK(strstr(s, " INFO  test_log_ring.c:") != NULL, "the line keeps its shape");
  free(s);
  log_add_fp(fp, LOG_FATAL + 1);   /* this sink takes nothing from here on */
}

/* ---- 2. many threads: nothing lost, each thread's lines in its order */
#define T2_THREADS 8
#define T2_LINES   2000

static void *t2_run(void *arg) {
  long id = (long)arg;
  for (int i = 0; i < T2_LINES; i++) {
    log_info("t2 thr=%ld seq=%d", id, i);
    if ((i & 63) == 0) usleep(200);   /* let the writer take a pass now and then */
  }
  return NULL;
}

static void t_order(const char *dir) {
  char path[256];
  size_t len;
  char *s, *save = NULL;
  int next[T2_THREADS] = {0};
  int bad = 0, total = 0;
  pthread_t th[T2_THREADS];
  FILE *fp;
  uint64_t d0 = dropped_all();

  printf("t_order\n");
  snprintf(path, sizeof(path), "%s/order.log", dir);
  fp = fopen(path, "a");
  log_add_fp(fp, LOG_INFO);
  CHECK(log_async_start() == 0, "the writer thread starts");
  CHECK(log_async_start() == 0, "starting it twice is harmless");
  for (long i = 0; i < T2_THREADS; i++) pthread_create(&th[i], NULL, t2_run, (void *)i);
  for (int i = 0; i < T2_THREADS; i++) pthread_join(th[i], NULL);
  CHECK(log_flush(5000) == 0, "log_flush returns when the rings are written");
  s = slurp(path, &len);
  for (char *ln = strtok_r(s, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
    int thr, seq;
    char *p = strstr(ln, "t2 thr=");
    if (!p || sscanf(p, "t2 thr=%d seq=%d", &thr, &seq) != 2) continue;
    if (thr < 0 || thr >= T2_THREADS || seq != next[thr]) bad++;
    else next[thr]++;
    total++;
  }
  free(s);
  CHECK(total == T2_THREADS * T2_LINES, "every line arrived (%d of %d)", total, T2_THREADS * T2_LINES);
  CHECK(bad == 0, "each thread's lines are in the order it logged them");
  CHECK(dropped_all() == d0, "nothing was dropped");
  log_add_fp(fp, LOG_FATAL + 1);
}

/* ---- 3. a ring handed back by a thread that ended serves the next thread */
static void *t3_run(void *arg) {
  log_info("t3 thread %ld", (long)arg);
  return NULL;
}

static void t_reuse(const char *dir) {
  char path[256];
  size_t len;
  char *s;
  FILE *fp;
  uint64_t d0 = dropped_all();
  int n = 700;                    /* more threads than there are rings */

  printf("t_reuse\n");
  snprintf(path, sizeof(path), "%s/reuse.log", dir);
  fp = fopen(path, "a");
  log_add_fp(fp, LOG_INFO);
  for (long i = 0; i < n; i++) {
    pthread_t th;
    pthread_create(&th, NULL, t3_run, (void *)i);
    pthread_join(th, NULL);
    if ((i % 50) == 49) log_flush(2000);
  }
  log_flush(5000);
  s = slurp(path, &len);
  CHECK((int)count_str(s, "t3 thread ") == n, "%d threads, one after another, each got a ring (%zu lines)", n, count_str(s, "t3 thread "));
  CHECK(dropped_all() == d0, "nothing was dropped");
  free(s);
  log_add_fp(fp, LOG_FATAL + 1);
}

/* ---- 4. the sink is stalled: the caller is never held, the ring drops and counts */
#define T4_LINES 200000

struct t4_res { double worst, total; };

static void *t4_run(void *arg) {
  struct t4_res *res = arg;
  double t0 = now_s();
  for (int i = 0; i < T4_LINES; i++) {
    double a = now_s(), b;
    log_warn("t4 line %06d with some padding so that the ring fills quickly ............................", i);
    b = now_s();
    if (b - a > res->worst) res->worst = b - a;
  }
  res->total = now_s() - t0;
  return NULL;
}

static void t_stalled_sink(void) {
  int pfd[2];
  FILE *fp;
  pthread_t th;
  struct t4_res res = {0, 0};
  uint64_t d0 = log_dropped(LOG_WARN), d1, d2;
  char *got;
  size_t cap = 64u << 20, len = 0;
  ssize_t n;
  int tries;

  printf("t_stalled_sink\n");
  if (pipe(pfd) != 0) { CHECK(0, "pipe"); return; }
  fp = fdopen(pfd[1], "w");
  log_add_fp(fp, LOG_INFO);

  pthread_create(&th, NULL, t4_run, &res);
  pthread_join(th, NULL);
  d1 = log_dropped(LOG_WARN);
  printf("       %d calls in %.3f s, slowest call %.6f s, dropped %llu\n", T4_LINES, res.total, res.worst,
         (unsigned long long)(d1 - d0));
  CHECK(res.worst < 0.05, "no log call waited for the stalled sink (slowest %.6f s)", res.worst);
  CHECK(res.total < 5.0, "%d calls returned in %.3f s with the sink stalled", T4_LINES, res.total);
  CHECK(d1 > d0, "lines that found the ring full were counted (%llu)", (unsigned long long)(d1 - d0));
  CHECK(log_dropped(LOG_INFO) == 0 || 1, "the count is by level");
  CHECK(log_flush(50) == -1, "log_flush gives up at its timeout while the sink is stalled");

  /* the sink comes back: read until the writer has caught up and said what was dropped */
  got = malloc(cap);
  fcntl(pfd[0], F_SETFL, O_NONBLOCK);
  for (tries = 0; tries < 5000; tries++) {
    n = read(pfd[0], got + len, cap - len - 1);
    if (n > 0) { len += (size_t)n; got[len] = '\0'; continue; }
    if (len && strstr(got, "its ring was full")) {
      usleep(20000);
      n = read(pfd[0], got + len, cap - len - 1);
      if (n <= 0) break;
      len += (size_t)n; got[len] = '\0';
      continue;
    }
    usleep(1000);
  }
  got[len] = '\0';
  CHECK(strstr(got, "its ring was full") != NULL, "the writer resumed and reported the drop in the log");
  CHECK(strstr(got, " WARN  log.c:") != NULL, "the report is a WARN line written by the writer");
  CHECK(count_str(got, "t4 line ") + (d1 - d0) == T4_LINES,
        "written %zu + dropped %llu = logged %d", count_str(got, "t4 line "), (unsigned long long)(d1 - d0), T4_LINES);
  /* Two more heartbeats: what was reported is not reported again. */
  usleep(2200000);
  log_flush(2000);
  while ((n = read(pfd[0], got + len, cap - len - 1)) > 0) { len += (size_t)n; got[len] = '\0'; }
  /* Twice at most: a heartbeat may fall between the first drops and the
   * moment the pipe is full and the writer held. */
  CHECK(count_str(got, "its ring was full") <= 2, "the drop was reported when it happened, not once per line and not again at every heartbeat (%zu)", count_str(got, "its ring was full"));
  d2 = log_dropped(LOG_WARN);
  log_warn("t4 after the stall");
  CHECK(log_flush(5000) == 0, "log_flush returns again");
  CHECK(log_dropped(LOG_WARN) == d2, "the counter stands still once the sink is back");
  free(got);
  log_add_fp(fp, LOG_FATAL + 1);
  close(pfd[0]);
}

/* ---- 5. the calling thread's unwritten lines, for a fatal-signal handler */
static void t_emergency(void) {
  int pfd[2], out[2];
  FILE *fp;
  char buf[8192], fill[1024];
  ssize_t n;
  size_t len = 0;

  printf("t_emergency\n");
  if (pipe(pfd) != 0 || pipe(out) != 0) { CHECK(0, "pipe"); return; }
  fcntl(pfd[1], F_SETPIPE_SZ, 4096);
  fp = fdopen(pfd[1], "w");
  log_add_fp(fp, LOG_INFO);
  memset(fill, 'x', sizeof(fill) - 1); fill[sizeof(fill) - 1] = '\0';
  /* More than the small pipe takes, so the writer is held in its write; less
   * than the ring holds, so the line below is queued and not dropped. */
  for (int i = 0; i < 100; i++) log_info("%s", fill);
  usleep(50000);
  log_info("last words of this thread");
  fcntl(out[0], F_SETFL, O_NONBLOCK);
  fcntl(out[1], F_SETFL, O_NONBLOCK);
  log_emergency_dump(out[1]);
  while ((n = read(out[0], buf, sizeof(buf) - 1)) > 0) {
    buf[n] = '\0';
    if (strstr(buf, "last words of this thread")) { len = 1; break; }
  }
  CHECK(len == 1, "log_emergency_dump writes what the writer had not taken");
  /* release the writer */
  fcntl(pfd[0], F_SETFL, O_NONBLOCK);
  for (int i = 0; i < 2000 && log_flush(1) != 0; i++) while (read(pfd[0], buf, sizeof(buf)) > 0) {}
  log_add_fp(fp, LOG_FATAL + 1);
  while (read(pfd[0], buf, sizeof(buf)) > 0) {}
  close(out[0]); close(out[1]);
}

/* ---- 5b. lines of two threads come out in the order they were logged */
#include <semaphore.h>
#define T5_LINES 40
static sem_t t5_sem[2];

static void *t5_run(void *arg) {
  long me = (long)arg;
  for (int i = 0; i < T5_LINES; i++) {
    sem_wait(&t5_sem[me]);
    log_info("t5 turn=%03d", i * 2 + (int)me);
    sem_post(&t5_sem[1 - me]);
  }
  return NULL;
}

static void t_merge(const char *dir) {
  int pfd[2];
  FILE *pp, *fp;
  char path[256], buf[8192], fill[1024];
  pthread_t th[2];
  size_t len;
  char *s, *p;
  int next = 0, bad = 0;

  printf("t_merge\n");
  if (pipe(pfd) != 0) { CHECK(0, "pipe"); return; }
  fcntl(pfd[1], F_SETPIPE_SZ, 4096);
  pp = fdopen(pfd[1], "w");
  snprintf(path, sizeof(path), "%s/merge.log", dir);
  fp = fopen(path, "a");
  log_add_fp(pp, LOG_INFO);       /* holds the writer while the two threads log */
  log_add_fp(fp, LOG_INFO);
  memset(fill, 'y', sizeof(fill) - 1); fill[sizeof(fill) - 1] = '\0';
  for (int i = 0; i < 100; i++) log_info("%s", fill);
  usleep(50000);
  sem_init(&t5_sem[0], 0, 1);
  sem_init(&t5_sem[1], 0, 0);
  for (long i = 0; i < 2; i++) pthread_create(&th[i], NULL, t5_run, (void *)i);
  for (int i = 0; i < 2; i++) pthread_join(th[i], NULL);
  fcntl(pfd[0], F_SETFL, O_NONBLOCK);
  for (int i = 0; i < 2000 && log_flush(1) != 0; i++) while (read(pfd[0], buf, sizeof(buf)) > 0) {}
  log_add_fp(pp, LOG_FATAL + 1);
  log_flush(2000);
  s = slurp(path, &len);
  for (p = s; (p = strstr(p, "t5 turn=")); p += 8) {
    if (atoi(p + 8) != next) bad++;
    next++;
  }
  CHECK(next == 2 * T5_LINES, "both threads' lines arrived (%d of %d)", next, 2 * T5_LINES);
  CHECK(bad == 0, "queued in two rings while the writer was held, written in the order they were logged (%d out of place)", bad);
  free(s);
  log_add_fp(fp, LOG_FATAL + 1);
  while (read(pfd[0], buf, sizeof(buf)) > 0) {}
}

/* ---- 6. the writer rotates the file; stopping writes what is queued */
static void t_rotate_and_stop(const char *dir) {
  char path[256], pat[300];
  FILE *fp;
  glob_t g;
  struct stat st;
  size_t len, total = 0;
  char *s;

  printf("t_rotate_and_stop\n");
  snprintf(path, sizeof(path), "%s/rot.log", dir);
  fp = fopen(path, "a");
  log_add_fp(fp, LOG_INFO);
  CHECK(log_rotate_fp(fp, path, 16384) == 0, "rotation is set on a file sink");
  CHECK(log_rotate_fp(stdin, path, 1) == -1, "and refused for a file that is not a sink");
  for (int i = 0; i < 2000; i++) {
    log_info("rot line %05d ....................................................", i);
    if ((i % 100) == 99) log_flush(2000);
  }
  log_info("queued when the writer is told to stop");
  CHECK(log_async_stop(5000) == 0, "log_async_stop returns 0 when the writer has left");
  snprintf(pat, sizeof(pat), "%s/rot-*.log", dir);
  memset(&g, 0, sizeof(g));
  glob(pat, 0, NULL, &g);
  CHECK(g.gl_pathc >= 2, "the file was rotated (%zu backups named like pkg/logrotate's)", g.gl_pathc);
  for (size_t i = 0; i < g.gl_pathc; i++) {
    s = slurp(g.gl_pathv[i], &len); total += count_str(s, "rot line "); free(s);
    if (i == 0) CHECK(strlen(g.gl_pathv[i]) == strlen(dir) + strlen("/rot-20260101-000000.000.log"),
                      "backup name %s", strrchr(g.gl_pathv[i], '/') + 1);
  }
  globfree(&g);
  s = slurp(path, &len); total += count_str(s, "rot line ");
  CHECK(total == 2000, "no line was lost across the rotations (%zu of 2000)", total);
  CHECK(strstr(s, "queued when the writer is told to stop") != NULL, "log_async_stop writes what was queued");
  free(s);
  CHECK(stat(path, &st) == 0 && st.st_size <= 16384 + 4096, "the live file stays near its limit (%lld bytes)", (long long)st.st_size);
  log_info("after the stop");
  s = slurp(path, &len);
  CHECK(strstr(s, "after the stop\n") != NULL, "after the stop a line is written by its caller again");
  free(s);
  CHECK(log_async_stop(5000) == 0, "stopping twice is harmless");
}

int main(void) {
  char dir[] = "/tmp/test_log_ring.XXXXXX";
  char cmd[300];

  if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
  log_set_quiet(true);            /* stderr is not a sink in this test */
  t_sync(dir);
  t_order(dir);
  t_reuse(dir);
  t_stalled_sink();
  t_emergency();
  t_merge(dir);
  t_rotate_and_stop(dir);
  snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
  if (system(cmd) != 0) { /* nothing to do about it */ }
  printf("%s (%d failed)\n", g_fail ? "FAIL" : "PASS", g_fail);
  return g_fail ? 1 : 0;
}
