#!/usr/bin/env python3
"""Run the production decision a closing P/D decode leg makes about its client,
after the flow completed: the client is kept for its next request when its
answer was framed (a length or chunking), and is not kept when the answer ran to
the engine's EOF, since only the client's own connection closing can then end
it. The SGLang drain leg, an HTTP/2 client and a connection the framer never
saw keep the client as before."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parent
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('ANSWER_TEST_HTTP'):
    http = Path(os.environ['ANSWER_TEST_HTTP']).read_text()

a = http.index('static int\nsp_answer_ended_by_eof(proxy_fd_ent_t *client)')
b = http.index('\nvoid\npd_resp_parser_init(', a)
prod = http[a:b]

# The US-H202 branch asks the predicate, and nothing else, whether to keep.
h0 = http.index('/* US-H202: Decode backend closing after P/D already completed')
h1 = http.index('[US-H202] Decode backend fd=%d detaching', h0)
assert 'if (pd_decode_eof_keeps_client(pfe, client_pfe)) {' in http[h0:h1], \
    'the US-H202 branch does not ask pd_decode_eof_keeps_client'
# The EOF that ends an unframed answer marks it ended; a new answer clears that.
assert 'atomic_store_explicit(&client->cresp_eof_ended, 1' in prod, \
    'cresp_note_backend_eof does not mark the answer ended'
hc0 = http.index('cresp_on_headers_complete(llhttp_t *parser)')
hc1 = http.index('\n}\n', hc0)
assert 'atomic_store_explicit(&pfe->cresp_eof_ended, 0' in http[hc0:hc1], \
    'a new answer does not clear cresp_eof_ended'

src = r'''
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
enum { PD_PHASE_NONE = 0, PD_PHASE_DECODE_STREAMING = 5 };
typedef struct proxy_fd_ent proxy_fd_ent_t;
struct proxy_fd_ent {
  int pd_phase, pd_sg_drain, is_pd_decode_backend, mcp_capture;
  void *h2_session; int cresp_parser_inited;
  _Atomic uint8_t cresp_unframed, cresp_eof_ended, mcp_inflight;
  _Atomic uint32_t cresp_completed; int fc, cresp_in_msg;
};
#define PROXY_ENT_LOCK(p) ((void)(p))
#define PROXY_ENT_UNLOCK(p) ((void)(p))
static void fc_permit_release(int *f) { (void)f; }
static void hc_resp_done(proxy_fd_ent_t *p) { (void)p; }
static void sp_hold_answer_ended(proxy_fd_ent_t *p) { (void)p; }
static void sp_answer_msg_done(int *m) { (void)m; }
static void epp_report_resp_eos(proxy_fd_ent_t *p) { (void)p; }
''' + prod + r'''
static proxy_fd_ent_t client(int unframed) {
  proxy_fd_ent_t c; memset(&c, 0, sizeof(c));
  c.cresp_parser_inited = 1; c.pd_phase = PD_PHASE_NONE;
  atomic_store(&c.cresp_unframed, (uint8_t)unframed);
  return c;
}
int main(void) {
  proxy_fd_ent_t dec; memset(&dec, 0, sizeof(dec)); dec.is_pd_decode_backend = 1;
  proxy_fd_ent_t drain; memset(&drain, 0, sizeof(drain)); drain.pd_sg_drain = 1;
  proxy_fd_ent_t c;

  /* framed answer (length or chunked): kept for the next request */
  c = client(0); cresp_note_backend_eof(&c);
  assert(pd_decode_eof_keeps_client(&dec, &c) == 1);
  /* unframed answer, its EOF seen first: the client is not kept */
  c = client(1); cresp_note_backend_eof(&c);
  assert(atomic_load(&c.cresp_unframed) == 0 && atomic_load(&c.cresp_eof_ended) == 1);
  assert(atomic_load(&c.cresp_completed) == 1);
  assert(pd_decode_eof_keeps_client(&dec, &c) == 0);
  /* unframed answer, the leg going without a read EOF: not kept either */
  c = client(1);
  assert(pd_decode_eof_keeps_client(&dec, &c) == 0);
  /* the drain leg's EOF ends nothing the client reads */
  c = client(1);
  assert(pd_decode_eof_keeps_client(&drain, &c) == 1);
  /* HTTP/2 client and a client the framer never saw: as before */
  c = client(1); c.h2_session = &c;
  assert(pd_decode_eof_keeps_client(&dec, &c) == 1);
  c = client(1); c.cresp_parser_inited = 0;
  assert(pd_decode_eof_keeps_client(&dec, &c) == 1);
  /* a flow still in flight is not this branch's to decide */
  c = client(0); c.pd_phase = PD_PHASE_DECODE_STREAMING;
  assert(pd_decode_eof_keeps_client(&dec, &c) == 0);
  puts("decode EOF: a client whose answer ran to the engine's EOF is not kept open; framed answers, the drain leg, HTTP/2 and unframed-by-nobody keep it PASS");
  return 0;
}
'''

with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    (p / 'test.c').write_text(src)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-o', str(p / 'eof'), str(p / 'test.c')], check=True)
    subprocess.run([str(p / 'eof')], check=True)
