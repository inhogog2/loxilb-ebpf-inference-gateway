#!/usr/bin/env python3
"""Each mutation of the 502 for a leg ending before any answer must turn
test_leg_ended_unanswered.py red: a dropped guard (kernel answers, P/D rule,
P/D in flight, HTTP/2, drain leg, whole request, answer begun, status,
record, a named end, AI gateway), a missing TLS shutdown, and the call moved
under PROXY_LOCK or dropped from proxy_pdestroy."""
import os, subprocess, sys, tempfile
from pathlib import Path
root = Path(__file__).resolve().parent; h = (root / 'sockproxy_http.c').read_text()
G = '''  if (!client || client->odir != 0 || client->fd <= 0 || !client->ai_gw_mode ||
      client->pd_rule || client->pd_phase != PD_PHASE_NONE ||
      client->h2_session || client->resp_kernel) {'''
R = '''  if (client->metric_req_start_ns > 0 && !client->metric_ai_recorded &&
      client->metric_response_status == 0 && !client->end_cause &&
      !sp_answer_started(client)) {'''
C = '''  proxy_h2_backend_leg_end(pfe);
  /* An HTTP/1.1 leg ending under a request it never answered: the client
   * gets its 502 here, for the same reason. */
  proxy_backend_leg_ended_unanswered(pfe);

  PROXY_LOCK();
'''
muts = {
 'answers by the kernel get a 502': (G, G.replace(' || client->resp_kernel', '')),
 'a P/D rule gets a 502': (G, G.replace('      client->pd_rule || ', '      ')),
 'a P/D request in flight gets a 502': (G, G.replace('client->pd_phase != PD_PHASE_NONE ||\n', '\n')),
 'an HTTP/2 client gets a 502': (G, G.replace('client->h2_session || ', '')),
 'not AI gateway gets a 502': (G, G.replace(' || !client->ai_gw_mode', '')),
 'a drain leg answers the client': ('  if (pfe->odir != 1 || pfe->pd_sg_drain || pfe->n_rfd <= 0) {',
                                    '  if (pfe->odir != 1 || pfe->n_rfd <= 0) {'),
 'a request not yet whole gets a 502': (R, R.replace('client->metric_req_start_ns > 0 && ', '')),
 'a recorded request gets a 502': (R, R.replace(' && !client->metric_ai_recorded', '')),
 'a status already sent gets a 502': (R, R.replace('      client->metric_response_status == 0 && ', '      ')),
 'a reaper-named end gets a 502': (R, R.replace(' && !client->end_cause', '')),
 'an answer begun gets a 502': (R, R.replace(' &&\n      !sp_answer_started(client)', '')),
 'the answer is not noted': ('      cresp_note_local_answer(client);\n    }\n    /* The answer says Connection: close; a TLS client is told the stream\n     * ended here, so it does not read the close that follows as a cut. */\n    if (client->ssl) {\n      (void)SSL_shutdown(client->ssl);\n    }\n  }\n  PROXY_ENT_UNLOCK(client);\n}\n\nstatic int\nproxy_sock_read_err',
                             '      (void)0;\n    }\n    /* The answer says Connection: close; a TLS client is told the stream\n     * ended here, so it does not read the close that follows as a cut. */\n    if (client->ssl) {\n      (void)SSL_shutdown(client->ssl);\n    }\n  }\n  PROXY_ENT_UNLOCK(client);\n}\n\nstatic int\nproxy_sock_read_err'),
 'a TLS client is not told the stream ended': ('    if (client->ssl) {\n      (void)SSL_shutdown(client->ssl);\n    }\n  }\n  PROXY_ENT_UNLOCK(client);\n}\n\nstatic int\nproxy_sock_read_err',
                                               '  }\n  PROXY_ENT_UNLOCK(client);\n}\n\nstatic int\nproxy_sock_read_err'),
 'the teardown does not call it': (C, C.replace('  proxy_backend_leg_ended_unanswered(pfe);\n', '')),
 'the teardown calls it under PROXY_LOCK': (C, C.replace('  proxy_backend_leg_ended_unanswered(pfe);\n\n  PROXY_LOCK();\n',
                                                          '\n  PROXY_LOCK();\n  proxy_backend_leg_ended_unanswered(pfe);\n')),
}
killed = 0
for name, (a, b) in muts.items():
    assert h.count(a) == 1, name
    assert a != b, name
    with tempfile.NamedTemporaryFile('w', suffix='.c', delete=False) as f:
        f.write(h.replace(a, b)); mp = f.name
    r = subprocess.run([sys.executable, str(root / 'test_leg_ended_unanswered.py')],
                       env={**os.environ, 'LEG_TEST_HTTP': mp}, capture_output=True, text=True)
    os.unlink(mp)
    ok = r.returncode != 0; killed += ok
    print(('killed: ' if ok else 'SURVIVED: ') + name)
print(f'test_leg_ended_unanswered mutations: {killed}/{len(muts)} killed')
sys.exit(0 if killed == len(muts) else 1)
