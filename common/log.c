/*
 * Copyright (c) 2020 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "log.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_CALLBACKS 32
#define LOG_NLEVELS   6

#define LOG_LINE_MAX 4096
#define LOG_DATE_LEN 11          /* "YYYY-MM-DD " — the stderr copy skips it */
#define LOG_OUT_BYTES 65536      /* what the writer hands a sink in one write(2) */

typedef struct {
  _Atomic(log_LogFn) fn;         /* published last: a reader that sees it sees the rest */
  void *udata;
  _Atomic int level;
  /* rotation of a file sink, done by the writer thread (log_rotate_fp) */
  _Atomic(const char *) rot_path;
  _Atomic uint64_t rot_max;
  /* writer thread only */
  char *out;
  size_t out_len;
} Callback;

static struct {
  void *udata;
  log_LockFn lock;
  _Atomic int level;
  _Atomic bool quiet;
  Callback callbacks[MAX_CALLBACKS];
} L;


static const char *level_strings[] = {
  "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};


/* Each line is formatted once, in log_log, into a stack buffer.
 *
 * Until log_async_start() the sinks are written by the calling thread, one
 * write(2) per line and sink (start-up, shutdown, unit tests). After it, a
 * line is copied into the calling thread's own ring and the one writer
 * thread does every write: the caller makes no system call, takes no lock
 * the writer holds and never waits for a sink. A ring that is full drops
 * the line and counts it (log_dropped). A FATAL line is always written by
 * the caller. */

static void write_all(int fd, const char *buf, size_t len) {
  while (len > 0) {
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      return;                    /* a sink that fails is not worth blocking on */
    }
    buf += n; len -= (size_t)n;
  }
}

static void stdout_callback(log_Event *ev) {
  /* stderr keeps its historical "HH:MM:SS LEVEL file:line: msg" shape */
  write_all(STDERR_FILENO, ev->line_buf + LOG_DATE_LEN, ev->line_len - LOG_DATE_LEN);
}


static void file_callback(log_Event *ev) {
  FILE *fp = ev->udata;
  if (!fp) return;
  fflush(fp);                    /* anything an earlier stdio user left behind */
  write_all(fileno(fp), ev->line_buf, ev->line_len);
}


static void lock(void)   {
  if (L.lock) { L.lock(true, L.udata); }
}


static void unlock(void) {
  if (L.lock) { L.lock(false, L.udata); }
}


const char* log_level_string(int level) {
  return level_strings[level];
}


void log_set_lock(log_LockFn fn, void *udata) {
  L.lock = fn;
  L.udata = udata;
}


void log_set_level(int level) {
  atomic_store(&L.level, level);
}


void log_set_quiet(bool enable) {
  atomic_store(&L.quiet, enable);
}


int log_add_callback(log_LogFn fn, void *udata, int level) {
  for (int i = 0; i < MAX_CALLBACKS; i++) {
    if (atomic_load(&L.callbacks[i].fn) && L.callbacks[i].udata == udata) {
      atomic_store(&L.callbacks[i].level, level);
      return 0;
    }
  }
  for (int i = 0; i < MAX_CALLBACKS; i++) {
    if (!atomic_load(&L.callbacks[i].fn)) {
      L.callbacks[i].udata = udata;
      atomic_store(&L.callbacks[i].level, level);
      atomic_store(&L.callbacks[i].fn, fn);
      return 0;
    }
  }
  return -1;
}


int log_add_fp(FILE *fp, int level) {
  return log_add_callback(file_callback, fp, level);
}


int log_rotate_fp(FILE *fp, const char *path, uint64_t max_bytes) {
  for (int i = 0; i < MAX_CALLBACKS; i++) {
    Callback *cb = &L.callbacks[i];
    if (atomic_load(&cb->fn) == file_callback && cb->udata == fp) {
      if (path && !atomic_load(&cb->rot_path)) {
        char *copy = strdup(path);
        if (!copy) return -1;
        atomic_store(&cb->rot_path, copy);
      }
      atomic_store(&cb->rot_max, max_bytes);
      return 0;
    }
  }
  return -1;
}


static void init_event(log_Event *ev, void *udata) {
  ev->udata = udata;
}


/* "YYYY-MM-DD HH:MM:SS LEVEL file:line: " + the message + one newline.
 * Returns the length; a message longer than the buffer is truncated, the
 * newline is always the last byte. */
static size_t format_head(char *buf, size_t cap, const struct tm *tm,
                          int level, const char *file, int line) {
  size_t n = strftime(buf, cap, "%Y-%m-%d %H:%M:%S", tm);
  int m = snprintf(buf + n, cap - n, " %-5s %s:%d: ",
                   level_strings[level], file, line);
  if (m > 0) n += (size_t)m;
  if (n > cap - 2) n = cap - 2;
  return n;
}

static size_t format_tail(char *buf, size_t cap, size_t n) {
  if (n > cap - 2) n = cap - 2;
  if (n > 0 && buf[n - 1] == '\n') n--;   /* one newline, even if the format carried its own */
  buf[n++] = '\n';
  buf[n] = '\0';
  return n;
}

static size_t format_line(log_Event *ev, char *buf, size_t cap, va_list ap) {
  size_t n = format_head(buf, cap, ev->time, ev->level, ev->file, ev->line);
  int m = vsnprintf(buf + n, cap - 1 - n, ev->fmt, ap);
  if (m > 0) n += (size_t)m;
  return format_tail(buf, cap, n);
}


/* ---- the rings ---------------------------------------------------------
 *
 * One ring per thread that logs, single producer (its thread), single
 * consumer (the writer). prod and cons count bytes ever queued and taken;
 * neither side waits for the other and neither takes a lock. A record is a
 * 16-byte header and the line, padded to 8 bytes. A thread's ring goes back
 * to the pool when the thread ends, after the writer has emptied it. */

#define LOG_RING_BYTES (256u * 1024u)       /* a power of two */
#define LOG_RING_MASK  (LOG_RING_BYTES - 1)
#define LOG_MAX_RINGS  256
#define LOG_REC_HDR    16

enum { RING_FREE = 0, RING_CLAIMING, RING_LIVE, RING_DEAD };

typedef struct {
  uint64_t ts_ns;
  uint32_t len;
  uint8_t  level;
  uint8_t  pad[3];
} log_rec_t;

_Static_assert(sizeof(log_rec_t) == LOG_REC_HDR, "record header size");

typedef struct log_ring {
  _Atomic uint64_t prod;
  char _pad0[56];
  _Atomic uint64_t cons;
  char _pad1[56];
  _Atomic int state;
  _Atomic int tid;
  char *buf;
  _Atomic uint64_t dropped[LOG_NLEVELS];
  uint64_t warned;               /* writer only: the drops already reported */
} log_ring_t;

static log_ring_t g_rings[LOG_MAX_RINGS];
static _Atomic uint64_t g_noring_dropped[LOG_NLEVELS];  /* no ring to be had */
static uint64_t g_noring_warned;

static _Atomic int g_async;      /* callers queue instead of writing */
static _Atomic int g_stop;
static _Atomic int g_exited;
static _Atomic uint64_t g_passes;
static pthread_t g_writer;
static pthread_mutex_t g_ctl = PTHREAD_MUTEX_INITIALIZER;  /* start / stop only */
static int g_running;

static __thread log_ring_t *t_ring;
static __thread int t_ring_tried;
static pthread_key_t g_ring_key;
static pthread_once_t g_ring_key_once = PTHREAD_ONCE_INIT;

static void ring_thread_exit(void *p) {
  log_ring_t *r = p;
  t_ring = NULL;                 /* a later destructor that logs gets no ring */
  t_ring_tried = 1;
  atomic_store(&r->state, RING_DEAD);
}

static void ring_key_init(void) {
  pthread_key_create(&g_ring_key, ring_thread_exit);
}

static log_ring_t *ring_get(void) {
  if (t_ring) return t_ring;
  if (t_ring_tried) return NULL;
  t_ring_tried = 1;
  pthread_once(&g_ring_key_once, ring_key_init);
  for (int i = 0; i < LOG_MAX_RINGS; i++) {
    log_ring_t *r = &g_rings[i];
    int want = RING_FREE;
    if (!atomic_compare_exchange_strong(&r->state, &want, RING_CLAIMING)) continue;
    if (!r->buf) r->buf = malloc(LOG_RING_BYTES);
    if (!r->buf || pthread_setspecific(g_ring_key, r) != 0) {
      atomic_store(&r->state, RING_FREE);
      return NULL;
    }
    atomic_store(&r->tid, (int)syscall(SYS_gettid));
    t_ring = r;
    atomic_store(&r->state, RING_LIVE);
    return r;
  }
  return NULL;
}

static void ring_put(log_ring_t *r, uint64_t pos, const void *src, size_t n) {
  size_t off = (size_t)(pos & LOG_RING_MASK);
  size_t first = LOG_RING_BYTES - off;
  if (first > n) first = n;
  memcpy(r->buf + off, src, first);
  if (n > first) memcpy(r->buf, (const char *)src + first, n - first);
}

static void ring_take(const log_ring_t *r, uint64_t pos, void *dst, size_t n) {
  size_t off = (size_t)(pos & LOG_RING_MASK);
  size_t first = LOG_RING_BYTES - off;
  if (first > n) first = n;
  memcpy(dst, r->buf + off, first);
  if (n > first) memcpy((char *)dst + first, r->buf, n - first);
}

static size_t rec_size(size_t len) {
  return LOG_REC_HDR + ((len + 7) & ~(size_t)7);
}

/* 0 = queued, -1 = no room. Never waits. */
static int ring_push(log_ring_t *r, int level, uint64_t ts_ns, const char *line, size_t len) {
  uint64_t prod = atomic_load_explicit(&r->prod, memory_order_relaxed);
  uint64_t cons = atomic_load_explicit(&r->cons, memory_order_acquire);
  size_t need = rec_size(len);
  log_rec_t h = { .ts_ns = ts_ns, .len = (uint32_t)len, .level = (uint8_t)level };

  if (prod - cons + need > LOG_RING_BYTES) return -1;
  ring_put(r, prod, &h, LOG_REC_HDR);
  ring_put(r, prod + LOG_REC_HDR, line, len);
  atomic_store_explicit(&r->prod, prod + need, memory_order_release);
  return 0;
}

uint64_t log_dropped(int level) {
  uint64_t n;
  if (level < 0 || level >= LOG_NLEVELS) return 0;
  n = atomic_load(&g_noring_dropped[level]);
  for (int i = 0; i < LOG_MAX_RINGS; i++) n += atomic_load(&g_rings[i].dropped[level]);
  return n;
}

/* ---- the writer thread ------------------------------------------------- */

static uint64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void sleep_ms(long ms) {
  struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
  nanosleep(&ts, NULL);
}

static char g_err_out[LOG_OUT_BYTES];
static size_t g_err_len;

static void err_flush(void) {
  if (g_err_len) write_all(STDERR_FILENO, g_err_out, g_err_len);
  g_err_len = 0;
}

/* "<base>-<UTC YYYYMMDD-HHMMSS.mmm><ext>": the name pkg/logrotate gives a
 * backup, so its sweeper compresses and prunes what is renamed here. */
static void rot_backup_name(const char *path, char *out, size_t cap) {
  const char *slash = strrchr(path, '/');
  const char *dot = strrchr(slash ? slash : path, '.');
  struct timespec ts;
  struct tm tm;
  char stamp[32];

  if (!dot) dot = path + strlen(path);
  clock_gettime(CLOCK_REALTIME, &ts);
  gmtime_r(&ts.tv_sec, &tm);
  strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm);
  snprintf(out, cap, "%.*s-%s.%03ld%s", (int)(dot - path), path, stamp,
           ts.tv_nsec / 1000000L, dot);
}

/* The file keeps its descriptor number: the new file is opened beside it and
 * put in its place, so the FILE the sink was given stays good. */
static void cb_rotate(Callback *cb, int fd) {
  const char *path = atomic_load(&cb->rot_path);
  char bak[PATH_MAX];
  int nfd;

  rot_backup_name(path, bak, sizeof(bak));
  if (rename(path, bak) != 0 && errno != ENOENT) return;
  nfd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0644);
  if (nfd < 0) return;
  dup2(nfd, fd);
  close(nfd);
}

static void cb_flush(Callback *cb) {
  FILE *fp = cb->udata;
  uint64_t max = atomic_load(&cb->rot_max);
  int fd;

  if (!cb->out_len) return;
  fd = fileno(fp);
  if (max && atomic_load(&cb->rot_path)) {
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > 0 &&
        (uint64_t)st.st_size + cb->out_len > max) cb_rotate(cb, fd);
  }
  write_all(fd, cb->out, cb->out_len);
  cb->out_len = 0;
}

static void sinks_flush(void) {
  err_flush();
  for (int i = 0; i < MAX_CALLBACKS && atomic_load(&L.callbacks[i].fn); i++) {
    if (L.callbacks[i].out) cb_flush(&L.callbacks[i]);
  }
}

/* One line to every sink that wants its level; writer thread only. */
static void sinks_emit(int level, const char *line, size_t len) {
  if (!atomic_load(&L.quiet) && level >= atomic_load(&L.level) && len > LOG_DATE_LEN) {
    size_t n = len - LOG_DATE_LEN;
    if (g_err_len + n > sizeof(g_err_out)) err_flush();
    memcpy(g_err_out + g_err_len, line + LOG_DATE_LEN, n);
    g_err_len += n;
  }
  for (int i = 0; i < MAX_CALLBACKS; i++) {
    Callback *cb = &L.callbacks[i];
    log_LogFn fn = atomic_load(&cb->fn);
    if (!fn) break;
    if (level < atomic_load(&cb->level)) continue;
    if (fn == file_callback) {
      if (!cb->udata) continue;
      if (!cb->out && !(cb->out = malloc(LOG_OUT_BYTES))) continue;
      if (cb->out_len + len > LOG_OUT_BYTES) cb_flush(cb);
      memcpy(cb->out + cb->out_len, line, len);
      cb->out_len += len;
    } else {
      /* a foreign sink gets the finished line; there is no va_list here */
      log_Event ev = { .fmt = "%s", .file = "", .level = level, .udata = cb->udata,
                       .line_buf = line, .line_len = len };
      fn(&ev);
    }
  }
}

static void writer_note(int line_no, const char *fmt, ...) {
  char buf[512];
  struct tm tm;
  time_t t = time(NULL);
  size_t n;
  int m;
  va_list ap;

  localtime_r(&t, &tm);
  n = format_head(buf, sizeof(buf), &tm, LOG_WARN, __FILE__, line_no);
  va_start(ap, fmt);
  m = vsnprintf(buf + n, sizeof(buf) - 1 - n, fmt, ap);
  va_end(ap);
  if (m > 0) n += (size_t)m;
  n = format_tail(buf, sizeof(buf), n);
  sinks_emit(LOG_WARN, buf, n);
}

static uint64_t dropped_sum(_Atomic uint64_t *d, char *by, size_t cap) {
  uint64_t sum = 0;
  size_t off = 0;
  by[0] = '\0';
  for (int l = 0; l < LOG_NLEVELS; l++) {
    uint64_t v = atomic_load(&d[l]);
    sum += v;
    if (v && off < cap) {
      int m = snprintf(by + off, cap - off, "%s%s %llu", off ? ", " : "",
                       level_strings[l], (unsigned long long)v);
      if (m > 0) off += (size_t)m;
    }
  }
  return sum;
}

/* One line per producer that dropped since the last heartbeat, written by
 * the writer thread and never by the thread that dropped. */
static void writer_heartbeat(void) {
  char by[160];
  uint64_t sum;

  for (int i = 0; i < LOG_MAX_RINGS; i++) {
    log_ring_t *r = &g_rings[i];
    sum = dropped_sum(r->dropped, by, sizeof(by));
    if (sum > r->warned) {
      writer_note(__LINE__, "log: thread %d dropped %llu lines, its ring was full "
                  "(%llu since start: %s)", atomic_load(&r->tid),
                  (unsigned long long)(sum - r->warned), (unsigned long long)sum, by);
      r->warned = sum;
    }
  }
  sum = dropped_sum(g_noring_dropped, by, sizeof(by));
  if (sum > g_noring_warned) {
    writer_note(__LINE__, "log: %llu lines dropped by threads that had no ring "
                "(%llu since start: %s)", (unsigned long long)(sum - g_noring_warned),
                (unsigned long long)sum, by);
    g_noring_warned = sum;
  }
}

typedef struct {
  log_ring_t *r;
  uint64_t pos, end;
  log_rec_t h;
} log_cur_t;

static log_cur_t g_cur[LOG_MAX_RINGS];

/* Everything queued when the pass starts, oldest line first across the
 * rings. Returns the number of lines taken. */
static size_t writer_pass(void) {
  static char line[LOG_LINE_MAX + 8];
  size_t lines = 0;
  int n = 0;

  for (int i = 0; i < LOG_MAX_RINGS; i++) {
    log_ring_t *r = &g_rings[i];
    int st = atomic_load(&r->state);
    uint64_t end, pos;
    if (st != RING_LIVE && st != RING_DEAD) continue;
    end = atomic_load_explicit(&r->prod, memory_order_acquire);
    pos = atomic_load_explicit(&r->cons, memory_order_relaxed);
    if (pos == end) {
      if (st == RING_DEAD) atomic_store(&r->state, RING_FREE);
      continue;
    }
    g_cur[n].r = r; g_cur[n].pos = pos; g_cur[n].end = end;
    ring_take(r, pos, &g_cur[n].h, LOG_REC_HDR);
    n++;
  }

  while (n > 0) {
    int k = 0;
    log_cur_t *c;
    for (int i = 1; i < n; i++) if (g_cur[i].h.ts_ns < g_cur[k].h.ts_ns) k = i;
    c = &g_cur[k];
    if (c->h.len == 0 || c->h.len > LOG_LINE_MAX || c->h.level >= LOG_NLEVELS ||
        c->pos + rec_size(c->h.len) > c->end) {
      c->pos = c->end;           /* not a record: give the ring back whole */
    } else {
      ring_take(c->r, c->pos + LOG_REC_HDR, line, c->h.len);
      sinks_emit(c->h.level, line, c->h.len);
      c->pos += rec_size(c->h.len);
      lines++;
    }
    atomic_store_explicit(&c->r->cons, c->pos, memory_order_release);
    if (c->pos == c->end) g_cur[k] = g_cur[--n];
    else ring_take(c->r, c->pos, &c->h, LOG_REC_HDR);
  }
  return lines;
}

static void *writer_main(void *arg) {
  uint64_t beat = mono_ns();
  int idle = 0;
  (void)arg;

  for (;;) {
    int stop = atomic_load(&g_stop);
    size_t n = writer_pass();
    uint64_t now = mono_ns();

    if (now - beat >= 1000000000ull) { writer_heartbeat(); beat = now; }
    sinks_flush();
    atomic_fetch_add(&g_passes, 1);
    if (n) { idle = 0; continue; }
    if (stop) break;
    sleep_ms(++idle < 20 ? 1 : 10);
  }
  writer_heartbeat();
  sinks_flush();
  atomic_store(&g_exited, 1);
  return NULL;
}

int log_async_start(void) {
  int rc = 0;
  pthread_mutex_lock(&g_ctl);
  if (!g_running) {
    atomic_store(&g_stop, 0);
    atomic_store(&g_exited, 0);
    rc = pthread_create(&g_writer, NULL, writer_main, NULL);
    if (rc == 0) {
      g_running = 1;
      atomic_store(&g_async, 1);
    }
  }
  pthread_mutex_unlock(&g_ctl);
  return rc ? -1 : 0;
}

/* 0 = the writer wrote what was queued and is gone; -1 = it is still inside
 * a sink that does not return (its device is stalled) and was left there:
 * shutdown does not wait for a device. */
int log_async_stop(int timeout_ms) {
  int rc = 0;
  pthread_mutex_lock(&g_ctl);
  if (g_running) {
    uint64_t until = mono_ns() + (uint64_t)(timeout_ms > 0 ? timeout_ms : 0) * 1000000ull;
    atomic_store(&g_async, 0);   /* callers write for themselves again */
    atomic_store(&g_stop, 1);
    while (!atomic_load(&g_exited) && mono_ns() < until) sleep_ms(1);
    if (atomic_load(&g_exited)) {
      pthread_join(g_writer, NULL);
      g_running = 0;
      writer_pass();             /* a line queued while the writer left */
      sinks_flush();
    } else {
      rc = -1;
    }
  }
  pthread_mutex_unlock(&g_ctl);
  return rc;
}

int log_flush(int timeout_ms) {
  uint64_t want, until;
  if (!atomic_load(&g_async)) return 0;
  want = atomic_load(&g_passes) + 2;   /* one pass may have begun before the call */
  until = mono_ns() + (uint64_t)(timeout_ms > 0 ? timeout_ms : 0) * 1000000ull;
  while (atomic_load(&g_passes) < want) {
    if (mono_ns() >= until) return -1;
    sleep_ms(1);
  }
  return 0;
}

/* For a fatal-signal handler: what the calling thread queued and the writer
 * has not taken yet, straight to fd. Only write(2), no lock, no allocation;
 * the writer may put the same lines out a second time. */
void log_emergency_dump(int fd) {
  log_ring_t *r = t_ring;
  uint64_t pos, end;

  if (!r || !r->buf) return;
  pos = atomic_load(&r->cons);
  end = atomic_load(&r->prod);
  while (pos + LOG_REC_HDR <= end) {
    log_rec_t h;
    size_t off, first;
    ssize_t w;
    ring_take(r, pos, &h, LOG_REC_HDR);
    if (h.len == 0 || h.len > LOG_LINE_MAX || pos + rec_size(h.len) > end) break;
    off = (size_t)((pos + LOG_REC_HDR) & LOG_RING_MASK);
    first = LOG_RING_BYTES - off;
    if (first > h.len) first = h.len;
    w = write(fd, r->buf + off, first);
    if (w >= 0 && h.len > first) w = write(fd, r->buf, h.len - first);
    (void)w;
    pos += rec_size(h.len);
  }
}


void log_log(int level, const char *file, int line, const char *fmt, ...) {
  log_Event ev = {
    .fmt   = fmt,
    .file  = file,
    .line  = line,
    .level = level,
  };
  char buf[LOG_LINE_MAX];
  struct timespec ts;
  struct tm tm;
  int i, wanted = 0;

  /* Cheap early-out: nothing is formatted, and no lock is taken, for a line
   * below every sink's level (the common case for log_debug at info). */
  if (!atomic_load(&L.quiet) && level >= atomic_load(&L.level)) wanted = 1;
  for (i = 0; i < MAX_CALLBACKS && !wanted && atomic_load(&L.callbacks[i].fn); i++) {
    if (level >= atomic_load(&L.callbacks[i].level)) wanted = 1;
  }
  if (!wanted) return;

  clock_gettime(CLOCK_REALTIME, &ts);
  ev.time = localtime_r(&ts.tv_sec, &tm);
  va_start(ev.ap, fmt);
  ev.line_len = format_line(&ev, buf, sizeof(buf), ev.ap);
  va_end(ev.ap);
  ev.line_buf = buf;

  if (atomic_load(&g_async) && level >= 0 && level < LOG_FATAL) {
    log_ring_t *r = ring_get();
    uint64_t ts_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    if (!r) atomic_fetch_add(&g_noring_dropped[level], 1);
    else if (ring_push(r, level, ts_ns, buf, ev.line_len) != 0) atomic_fetch_add(&r->dropped[level], 1);
    return;
  }

  lock();

  if (!atomic_load(&L.quiet) && level >= atomic_load(&L.level)) {
    init_event(&ev, stderr);
    stdout_callback(&ev);
  }

  for (i = 0; i < MAX_CALLBACKS; i++) {
    Callback *cb = &L.callbacks[i];
    log_LogFn fn = atomic_load(&cb->fn);
    if (!fn) break;
    if (level >= atomic_load(&cb->level)) {
      init_event(&ev, cb->udata);
      va_start(ev.ap, fmt);     /* an external callback may still format ev->fmt itself */
      fn(&ev);
      va_end(ev.ap);
    }
  }

  unlock();
}
