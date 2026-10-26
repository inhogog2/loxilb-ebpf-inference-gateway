#!/usr/bin/env python3
"""A P/D stream the health thread reaps leaves the active-streams gauge
(loxilb_ai_active_streams) where it started.

The production P/D passes of check_draining_endpoints (sockproxy_health.c:
the graceful-[DONE] sweep, the stream timeout ERR-01 and the generic idle
reaper, in their order) run once a second against one active SSE stream whose
decode engine went silent, from its activation until a reaper ends it. The
gauge is +1 at activation (proxy_sse_activate) and counts every
llb_ai_stream_end. The connection then ends the way that reaper kind ends it:
a teardown kind is freed inline by pd_teardown_conn, which ends no stream (and
proxy_pdestroy, whose settle would, never runs); a shutdown kind is cleaned up
by the event loop, whose settle ends a stream still marked active. Both are
tied to the source below.

Configurations:
  default      every per-rule field 0: sweep 25 s, ERR-01 120 s, idle cap 180 s.
               The sweep ends the stream first.
  F-14         a decode idle cap at or above the stream timeout (no rule sets
               it today) lets ERR-01, or the idle reaper, reach the active
               stream first; the inline free (pd_teardown_conn) ends it.
The gauge must come back in every one. test_reap_stream_gauge_mutations.py
drops the inline end and must turn this red."""
from pathlib import Path
import os, re, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
health = (root / 'sockproxy_health.c').read_text()
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('GAUGE_TEST_HEALTH'):
    health = Path(os.environ['GAUGE_TEST_HEALTH']).read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

# What ends the gauge besides the passes under test: the inline teardown
# (pd_teardown_stream_end, for the client it frees: the reaped client itself,
# or the client of a reaped leg) and the event loop's settle; never the
# connection release.
td = body(health, 'static int\npd_teardown_conn(')
assert 'llb_ai_stream_end' not in td and 'sse_active' not in td, \
    'pd_teardown_conn ends streams outside pd_teardown_stream_end: update this model'
inline_end = 'pd_teardown_stream_end(client);' in td
stream_end = body(health, 'static void\npd_teardown_stream_end(')
conn = (root / 'sockproxy_conn.c').read_text()
for fn in ('proxy_release_fd_ctx(', 'proxy_try_free_fd_ctx('):
    m = re.search(r'\n[a-z_ ]+\n' + re.escape(fn), conn)
    assert m, fn + ' not found in sockproxy_conn.c: update this model'
    assert 'llb_ai_stream_end' not in body(conn, m.group(0).split('\n', 2)[1] + '\n' + fn), \
        fn + ' now ends streams: update this model'
assert 'teardown_owes_stream_end(&v)' in body(http, 'static void\nproxy_collect_conn_settles(')

t0 = health.index('typedef struct sp_reap_text {')
t1 = health.index('\n};\n', health.index('[SP_REAP_SSE_STALL]', t0)) + 4
a = health.index('        uint32_t decode_idle_cap = PROXY_PD_DECODE_IDLE_CAP_SEC;')
a = health.rindex('\n  {\n', 0, a) + 1
b = health.index('\n  PROXY_UNLOCK();', a)
passes = health[a:b]
assert passes.count('pd_reap_respond(pfe, ') == 3, 'the P/D passes changed shape'
leak = (root / 'sockproxy_pd_leak.h').read_text()
pred = (body(leak, 'static inline int\npd_should_graceful_complete(')
        + body(leak, 'static inline int\npd_reap_error_phase('))
lifecycle = body(health, 'static void\npd_reap_lifecycle(')
if not inline_end:
    stream_end = stream_end.replace('static void\npd_teardown_stream_end(',
                                    'static void\npd_teardown_stream_end_unused(')

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define log_warn(...) ((void)0)
#define log_error(...) ((void)0)
#define log_debug(...) ((void)0)
#define PROXY_PD_DECODE_IDLE_CAP_SEC 25
enum { PD_PHASE_NONE, PD_PHASE_PREFILL_SENDING, PD_PHASE_PREFILL_WAITING, PD_PHASE_PREFILL_DONE,
       PD_PHASE_DECODE_SENDING, PD_PHASE_DECODE_STREAMING, PD_PHASE_COMPLETE, PD_PHASE_ERROR };
enum { SP_REAP_NONE = 0, SP_REAP_SSE_CAP, SP_REAP_PD_PREFILL_TIMEOUT, SP_REAP_PD_DECODE_TIMEOUT,
  SP_REAP_PD_PARK_TIMEOUT, SP_REAP_PD_GRACEFUL_DONE, SP_REAP_PD_STREAM_TIMEOUT, SP_REAP_PD_IDLE_TIMEOUT,
  SP_REAP_FC_QUEUE_TIMEOUT, SP_REAP_FC_DRAINED, SP_REAP_EPP_TIMEOUT, SP_REAP_EPP_EVICT_429, SP_REAP_EPP_EVICT_CUT, SP_REAP_SSE_STALL, SP_REAP_FC_SHED,
  SP_REAP_FC_TTL, SP_REAP_KINDS };
typedef struct proxy_epval {
  uint32_t pd_prefill_timeout_sec, pd_decode_timeout_sec, pd_idle_cap_sec, pd_decode_idle_cap_sec;
} proxy_epval_t;
typedef struct proxy_fd_ent proxy_fd_ent_t;
struct proxy_fd_ent {
  proxy_fd_ent_t *next; int fd; int odir; int pd_phase; uint8_t sse_active;
  _Atomic uint8_t pd_client_finished;   /* the stream's finish evidence */
  time_t stream_end_ts, pd_last_decode_ts, pd_phase_start_ts;
  uint64_t pd_prefill_start_ns, pd_decode_start_ns; int pd_kv_params_len;
  void *epv;
};
typedef struct proxy_map_ent { struct { proxy_fd_ent_t *fdlist; } val; struct proxy_map_ent *next; } proxy_map_ent_t;
static struct { proxy_map_ent_t *head; } proxy_struct_v, *proxy_struct = &proxy_struct_v;
static struct { _Atomic uint64_t pd_terminator_synthesized; } global_stats;
static proxy_epval_t *sp_pool_holder_peek(void *const *h) { return (proxy_epval_t *)*h; }
static const char *proxy_effective_model(proxy_fd_ent_t *p) { (void)p; return "model-a"; }
static long gauge;
static void llb_ai_stream_end(const char *t, char *m) { (void)t; (void)m; gauge--; }
static int records, last_phase;
static void sp_pd_record(proxy_fd_ent_t *p, const char *m, int64_t a, int64_t b, int k, int ph) {
  (void)p; (void)m; (void)a; (void)b; (void)k; records++; last_phase = ph; }
static int last_kind;
static void pd_reap_respond(proxy_fd_ent_t *pfe, uint8_t kind);
'''

after = r'''
static proxy_map_ent_t node;
/* The real hand-off's end of the connection, as far as the gauge goes: a
 * teardown kind frees the client inline (pd_teardown_conn), a shutdown kind
 * leaves it to the event loop's settle. */
static void pd_reap_respond(proxy_fd_ent_t *pfe, uint8_t kind) {
  last_kind = kind;
  if (sp_reap_texts[kind].teardown) {
#if INLINE_END
    pd_teardown_stream_end(pfe);
#endif
  } else if (pfe->sse_active) gauge--;  /* event-loop settle */
  node.val.fdlist = NULL;   /* the connection is gone either way */
}
static const char *kname(int k) {
  return k == SP_REAP_PD_GRACEFUL_DONE ? "graceful-[DONE] sweep" :
         k == SP_REAP_PD_STREAM_TIMEOUT ? "stream timeout (ERR-01)" :
         k == SP_REAP_PD_IDLE_TIMEOUT ? "generic idle reaper" : "?";
}
static void tick(time_t now) {
''' + passes + r'''
}
/* One active SSE stream, engine silent from t=1000; ticks once a second.
 * finished: the stream's finish evidence (a finish event for every choice,
 * then only choice-less events) was seen before the silence. */
static int finished;
static int run(const char *name, proxy_epval_t cfg, long *end_gauge, int *at) {
  static proxy_fd_ent_t c; static proxy_epval_t e;
  memset(&c, 0, sizeof(c)); e = cfg; c.epv = &e; c.fd = 9;
  c.pd_phase = PD_PHASE_DECODE_STREAMING; c.sse_active = 1;
  c.pd_client_finished = (uint8_t)finished;
  c.pd_phase_start_ts = 1000; c.pd_last_decode_ts = 1000;
  c.pd_prefill_start_ns = 1; c.pd_decode_start_ns = 2;
  node.val.fdlist = &c; node.next = NULL; proxy_struct->head = &node;
  gauge = 1; records = 0; last_kind = 0;               /* llb_ai_stream_start */
  time_t now;
  for (now = 1000; now < 2000 && node.val.fdlist; now++) tick(now);
  *end_gauge = gauge; *at = (int)(now - 1 - 1000);
  printf("  %-44s %-24s at %3d s idle; gauge 1 -> %ld; P/D record phase %d\n",
         name, kname(last_kind), *at, gauge, last_phase);
  return last_kind;
}
int main(void) {
  long g; int at, k;
  k = run("default (all fields 0)", (proxy_epval_t){0}, &g, &at);
  assert(k == SP_REAP_PD_GRACEFUL_DONE && at == 25);
  assert(g == 0 && records == 1 && last_phase == 8);
  k = run("default, prefill timeout 600 s", (proxy_epval_t){ .pd_prefill_timeout_sec = 600 }, &g, &at);
  assert(k == SP_REAP_PD_GRACEFUL_DONE && g == 0);
  puts("stream gauge: under the default configuration the sweep ends a silent P/D stream first and the active-streams gauge returns to its start PASS");

  /* The same silence after the stream finished (finish evidence): the sweep
   * ends it the same way, at the same time, and records a completion, not a
   * truncation; the lost terminator is still the gateway's to write. */
  finished = 1;
  k = run("default, the stream had finished", (proxy_epval_t){0}, &g, &at);
  assert(k == SP_REAP_PD_GRACEFUL_DONE && at == 25);
  assert(g == 0 && records == 1 && last_phase == 0);
  assert(atomic_load(&global_stats.pd_terminator_synthesized) == 3);
  finished = 0;
  k = run("default, no finish evidence again", (proxy_epval_t){0}, &g, &at);
  assert(k == SP_REAP_PD_GRACEFUL_DONE && records == 1 && last_phase == 8);
  puts("stream gauge: with finish evidence the sweep records the silent stream a completion, without it decode/truncated PASS");

  /* F-14: configurations no rule sets today. */
  k = run("F-14: decode idle cap 300 s (>= 120 s)", (proxy_epval_t){ .pd_decode_idle_cap_sec = 300 }, &g, &at);
  assert(k == SP_REAP_PD_STREAM_TIMEOUT && at == 120);
  if (g != 0) { puts("FAIL F-14: ERR-01 leaves the active-streams gauge at 1"); return 1; }
  k = run("F-14: decode idle cap 300 s, idle cap 100 s", (proxy_epval_t){ .pd_decode_idle_cap_sec = 300,
      .pd_idle_cap_sec = 100 }, &g, &at);
  assert(k == SP_REAP_PD_IDLE_TIMEOUT && at == 100);
  if (g != 0) { puts("FAIL F-14: the idle reaper leaves the active-streams gauge at 1"); return 1; }
  puts("stream gauge: ERR-01 and the idle reaper, reaching an active P/D stream first, end it on the inline free PASS");
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tdir:
    p = Path(tdir)
    (p / 'test.c').write_text(prefix + '#define INLINE_END %d\n' % inline_end + health[t0:t1] + pred
                              + lifecycle + stream_end + after)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-Wno-missing-field-initializers',
                    '-fsanitize=address,undefined', '-o', str(p / 'gauge'), str(p / 'test.c')],
                   check=True)
    sys.exit(subprocess.run([str(p / 'gauge')]).returncode)
