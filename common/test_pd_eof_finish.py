#!/usr/bin/env python3
"""The decode leg closes under an open P/D stream (sp_pd_decode_stream_eof,
sockproxy_http.c, run from the source against stubs).

Without the stream's finish evidence the engine died: decode/error is
recorded, the EP death counted, the request moved to ERROR, the drain leg
closed with the coupling count, the stream left to the leg's teardown, 0
returned. With it (a finish event for every choice, then only choice-less
events: the usage event, [DONE]) the engine finished and closed: a completion
is recorded, no death, the stream's gauge ended once, the terminator counted
as synthesized, the leg unlinked from the client, 1 returned (the caller
hands the client to the reaper for the terminator). The same decision as the
graceful-[DONE] sweep's, for the same evidence.
test_pd_eof_finish_mutations.py breaks each of those and must turn this red."""
from pathlib import Path
import os, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('EOF_TEST_HTTP'):
    http = Path(os.environ['EOF_TEST_HTTP']).read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

fn = body(http, 'static int\nsp_pd_decode_stream_eof(')
pd = body(http, 'void\nproxy_pdestroy(')
assert 'if (sp_pd_decode_stream_eof(pfe, client_pfe)) {' in pd, \
    'proxy_pdestroy no longer asks sp_pd_decode_stream_eof'
i = pd.index('if (sp_pd_decode_stream_eof(pfe, client_pfe)) {')
assert 'pd_done_pend[n_pd_done_pend++] = client_pfe;' in pd[i:i + 600], \
    'a finished stream is not handed to the reaper'
j = pd.index('sp_reap_request(pd_done_pend[di], SP_REAP_PD_GRACEFUL_DONE);')
assert 'PROXY_LOCK();' in pd[j - 200:j] and 'PROXY_UNLOCK();' in pd[j:j + 200], \
    'the reaper hand-off is not made under PROXY_LOCK alone'
assert pd.rindex('PROXY_UNLOCK();', 0, j - 200) > pd.index('PROXY_ENT_UNLOCK(pfe);'), \
    "the hand-off runs before the leg's entry lock and PROXY_LOCK were released"

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define log_error(...) ((void)0)
#define log_debug(...) ((void)0)
#define MAX_PROXY_EP 8
enum { PD_PHASE_NONE, PD_PHASE_PREFILL_SENDING, PD_PHASE_PREFILL_WAITING, PD_PHASE_PREFILL_DONE,
       PD_PHASE_DECODE_SENDING, PD_PHASE_DECODE_STREAMING, PD_PHASE_COMPLETE, PD_PHASE_ERROR };
typedef struct proxy_fd_ent proxy_fd_ent_t;
struct proxy_fd_ent {
  int fd, pd_phase, n_rfd, rfd[MAX_PROXY_EP], is_pd_decode_backend, pd_kv_params_len;
  uint8_t sse_active; _Atomic uint8_t pd_client_finished;
  time_t stream_end_ts; uint64_t pd_prefill_start_ns, pd_decode_start_ns;
  proxy_fd_ent_t *rfd_ent[MAX_PROXY_EP];
};
static struct { _Atomic uint64_t pd_decode_ep_died, pd_terminator_synthesized; } global_stats;
static const char *proxy_effective_model(proxy_fd_ent_t *p) { (void)p; return "model-a"; }
static int records, last_phase; static int64_t last_decode_ms;
static void sp_pd_record(proxy_fd_ent_t *p, const char *m, int64_t a, int64_t b, int k, int ph) {
  (void)p; (void)m; (void)a; (void)k; records++; last_phase = ph; last_decode_ms = b; }
static int drains, drain_counted;
static void pd_sg_close_drain(proxy_fd_ent_t *p, int count) { (void)p; drains++; drain_counted += count; }
static long gauge;
static void llb_ai_stream_end(const char *t, char *m) { (void)t; (void)m; gauge--; }
'''
test = r'''
static proxy_fd_ent_t cl, leg, drain;
static void reset(int finished) {
  memset(&cl, 0, sizeof(cl)); memset(&leg, 0, sizeof(leg)); memset(&drain, 0, sizeof(drain));
  cl.fd = 7; cl.pd_phase = PD_PHASE_DECODE_STREAMING; cl.sse_active = 1;
  cl.pd_prefill_start_ns = 1; cl.pd_decode_start_ns = 2; cl.pd_kv_params_len = 3;
  cl.rfd_ent[0] = &drain; cl.rfd[0] = 8; cl.rfd_ent[1] = &leg; cl.rfd[1] = 9; cl.n_rfd = 2;
  leg.fd = 9; leg.is_pd_decode_backend = 1; leg.rfd_ent[0] = &cl; leg.rfd[0] = 7; leg.n_rfd = 1;
  cl.pd_client_finished = (uint8_t)finished;
  records = 0; last_phase = -1; drains = drain_counted = 0; gauge = 1;
  atomic_store(&global_stats.pd_decode_ep_died, 0);
  atomic_store(&global_stats.pd_terminator_synthesized, 0);
}
int main(void) {
  int bad = 0, r;
  reset(0);
  r = sp_pd_decode_stream_eof(&leg, &cl);
  printf("  %-40s -> %d; record phase %d x%d; deaths %llu; phase %d; drain %d/%d; gauge %ld; linked %d\n",
         "no finish evidence: the engine died", r, last_phase, records,
         (unsigned long long)atomic_load(&global_stats.pd_decode_ep_died), cl.pd_phase,
         drains, drain_counted, gauge, cl.rfd_ent[1] == &leg);
  if (r != 0 || records != 1 || last_phase != 2 || atomic_load(&global_stats.pd_decode_ep_died) != 1 ||
      cl.pd_phase != PD_PHASE_ERROR || drains != 1 || drain_counted != 1 || gauge != 1 ||
      cl.sse_active != 1 || cl.rfd_ent[1] != &leg || cl.n_rfd != 2 ||
      atomic_load(&global_stats.pd_terminator_synthesized) != 0) bad = 1;

  reset(1);
  r = sp_pd_decode_stream_eof(&leg, &cl);
  printf("  %-40s -> %d; record phase %d x%d; deaths %llu; phase %d; drain %d/%d; gauge %ld; linked %d; synthesized %llu\n",
         "finish evidence: the engine finished", r, last_phase, records,
         (unsigned long long)atomic_load(&global_stats.pd_decode_ep_died), cl.pd_phase,
         drains, drain_counted, gauge, cl.rfd_ent[1] == &leg,
         (unsigned long long)atomic_load(&global_stats.pd_terminator_synthesized));
  if (r != 1 || records != 1 || last_phase != 0 || last_decode_ms < 0 ||
      atomic_load(&global_stats.pd_decode_ep_died) != 0 || cl.pd_phase != PD_PHASE_COMPLETE ||
      drains != 1 || drain_counted != 0 || gauge != 0 || cl.sse_active != 0 || cl.stream_end_ts == 0 ||
      cl.rfd_ent[1] != NULL || cl.rfd[1] != -1 || cl.n_rfd != 1 || cl.rfd_ent[0] != &drain ||
      leg.rfd_ent[0] != &cl /* the leg's side is the caller's */ ||
      atomic_load(&global_stats.pd_terminator_synthesized) != 1) bad = 1;

  reset(1); cl.sse_active = 0;   /* the gauge was already ended: not twice */
  r = sp_pd_decode_stream_eof(&leg, &cl);
  printf("  %-40s -> %d; gauge %ld\n", "finished, stream already ended", r, gauge);
  if (r != 1 || gauge != 1 || last_phase != 0) bad = 1;

  printf(bad ? "FAILED\n" : "test_pd_eof_finish: ok\n");
  return bad;
}
'''
with tempfile.TemporaryDirectory() as d:
    src = Path(d) / 'test.c'
    src.write_text(prefix + fn + test)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-fsanitize=address,undefined',
                    '-o', str(Path(d) / 't'), str(src)], check=True)
    sys.exit(subprocess.run([str(Path(d) / 't')]).returncode)
