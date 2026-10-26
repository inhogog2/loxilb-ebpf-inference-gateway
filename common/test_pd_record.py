#!/usr/bin/env python3
"""Run the production sp_pd_record (sockproxy_http.c): one P/D lifecycle record
crosses as llb_ai_pd_record then llb_ai_pd_record_extra, both every time, in
that order, with the same model; the extra half carries the decode TTFT in
microseconds (first event minus decode dispatch) and the fallback reason, and
consumes them, so a second record for the same request carries 0/0."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parent
src = (root / 'sockproxy_http.c').read_text()
if os.environ.get('PD_RECORD_TEST_SOURCE'):
    src = Path(os.environ['PD_RECORD_TEST_SOURCE']).read_text()
a = src.index('void\nsp_pd_record(proxy_fd_ent_t *pfe')
b = src.index('\n}\n', a) + 3

prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint64_t pd_decode_start_ns, pd_first_event_ns; uint8_t pd_fallback_reason; } proxy_fd_ent_t;
static int calls; static char order[8];
static const char *rec_model, *ext_model; static int64_t rec_dec, ext_ttft; static int rec_phase, ext_fb;
static void llb_ai_pd_record(char *m, int64_t p, int64_t d, int kv, int ph)
{ (void)p; (void)kv; order[calls++] = 'r'; rec_model = m; rec_dec = d; rec_phase = ph; }
static void llb_ai_pd_record_extra(char *m, int64_t t, int fb)
{ order[calls++] = 'x'; ext_model = m; ext_ttft = t; ext_fb = fb; }
'''
main = r'''
static void reset(void) { calls = 0; memset(order, 0, sizeof(order)); }
int main(void) {
  proxy_fd_ent_t p; const char *m = "model-a";
  /* a stream with its first event 1.5 ms after dispatch, after a 5xx fallback */
  memset(&p, 0, sizeof(p)); p.pd_decode_start_ns = 1000000000ULL;
  p.pd_first_event_ns = 1001500000ULL; p.pd_fallback_reason = 1; reset();
  sp_pd_record(&p, m, 7, 42, 1, 0);
  assert(calls == 2 && !strcmp(order, "rx") && rec_model == m && ext_model == m);
  assert(rec_dec == 42 && rec_phase == 0 && ext_ttft == 1500 && ext_fb == 1);
  /* consumed: a second record for the same request carries 0/0, still both calls */
  reset(); sp_pd_record(&p, m, 0, 0, 1, 2);
  assert(calls == 2 && !strcmp(order, "rx") && ext_ttft == 0 && ext_fb == 0 && rec_phase == 2);
  /* no event (a buffered answer, or a request that failed before one) */
  memset(&p, 0, sizeof(p)); p.pd_decode_start_ns = 5; p.pd_fallback_reason = 5; reset();
  sp_pd_record(&p, m, 0, 0, 0, 2);
  assert(calls == 2 && ext_ttft == 0 && ext_fb == 5);
  /* no decode dispatch (a prefill failure), or an event stamped before it */
  memset(&p, 0, sizeof(p)); p.pd_first_event_ns = 9; reset();
  sp_pd_record(&p, m, 0, 0, 0, 4);
  assert(calls == 2 && ext_ttft == 0);
  memset(&p, 0, sizeof(p)); p.pd_decode_start_ns = 10; p.pd_first_event_ns = 9; reset();
  sp_pd_record(&p, m, 0, 0, 0, 0);
  assert(calls == 2 && ext_ttft == 0);
  /* sub-millisecond answers keep their sample: microseconds */
  memset(&p, 0, sizeof(p)); p.pd_decode_start_ns = 1000; p.pd_first_event_ns = 1000 + 250000; reset();
  sp_pd_record(&p, m, 0, 0, 0, 0);
  assert(ext_ttft == 250);
  puts("sp_pd_record: both calls every time, record then extra, same model; TTFT in us from dispatch; values consumed once PASS");
  return 0;
}
'''
with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    (p / 'test.c').write_text(prefix + src[a:b] + main)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-o', str(p / 'rec'), str(p / 'test.c')], check=True)
    subprocess.run([str(p / 'rec')], check=True)
