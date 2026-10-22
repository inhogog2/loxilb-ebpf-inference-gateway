#!/usr/bin/env python3
"""Each mutation of sp_pd_decode_stream_eof must turn test_pd_eof_finish.py
red: the finish evidence ignored or inverted, the finished stream recorded
truncated or counted a death, its gauge left open, the leg left linked, and
the cut stream no longer counted a death."""
import os, subprocess, sys, tempfile
from pathlib import Path
root = Path(__file__).resolve().parent; h = (root / 'sockproxy_http.c').read_text()
muts = {
 'the EOF ignores the finish evidence':
   ('  if (atomic_load_explicit(&client->pd_client_finished, memory_order_acquire)) {',
    '  if (0) {'),
 'the EOF reads the finish evidence inverted':
   ('  if (atomic_load_explicit(&client->pd_client_finished, memory_order_acquire)) {',
    '  if (!atomic_load_explicit(&client->pd_client_finished, memory_order_acquire)) {'),
 'the finished stream is recorded truncated':
   ('                     0 /*complete: finish evidence*/);',
    '                     8 /*decode truncated*/);'),
 'the finished stream counts a decode death':
   ('    client->pd_phase = PD_PHASE_COMPLETE;\n',
    '    client->pd_phase = PD_PHASE_COMPLETE;\n    atomic_fetch_add(&global_stats.pd_decode_ep_died, 1);\n'),
 'the finished stream leaves its gauge open':
   ('      llb_ai_stream_end("", (char *)model);\n      client->sse_active = 0;\n',
    '      client->sse_active = 0;\n'),
 'the finished stream keeps the leg linked':
   ('        client->rfd_ent[i] = NULL;\n        client->rfd[i] = -1;\n',
    '        client->rfd[i] = -1;\n'),
 'the cut stream counts no death':
   ('  atomic_fetch_add(&global_stats.pd_decode_ep_died, 1);\n  {\n',
    '  {\n'),
}
killed = 0
for name, (a, b) in muts.items():
    assert h.count(a) == 1, name
    with tempfile.NamedTemporaryFile('w', suffix='.c', delete=False) as f:
        f.write(h.replace(a, b)); mp = f.name
    r = subprocess.run([sys.executable, str(root / 'test_pd_eof_finish.py')],
                       env={**os.environ, 'EOF_TEST_HTTP': mp}, capture_output=True, text=True)
    os.unlink(mp)
    ok = r.returncode != 0; killed += ok
    print(('killed: ' if ok else 'SURVIVED: ') + name)
print(f'test_pd_eof_finish mutations: {killed}/{len(muts)} killed')
sys.exit(0 if killed == len(muts) else 1)
