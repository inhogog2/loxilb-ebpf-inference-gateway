#!/usr/bin/env python3
"""Each mutation of the inline teardown's stream end must turn
test_reap_stream_gauge.py red: the call dropped from pd_teardown_conn, the
gauge call dropped from the helper, the helper reading a leg's flag."""
import os, subprocess, sys, tempfile
from pathlib import Path
root = Path(__file__).resolve().parent; h = (root / 'sockproxy_health.c').read_text()
muts = {
 'pd_teardown_conn no longer ends the stream of the client it frees':
   ('    pd_teardown_stream_end(client);\n', ''),
 'the helper ends no stream':
   ('    llb_ai_stream_end("", (char *)proxy_effective_model(e));\n', ''),
 'the helper ends a leg\'s stream, not the client\'s':
   ('  if (e && e->odir == 0 && e->sse_active) {', '  if (e && e->odir == 1 && e->sse_active) {'),
}
killed = 0
for name, (a, b) in muts.items():
    assert h.count(a) == 1, name
    with tempfile.NamedTemporaryFile('w', suffix='.c', delete=False) as f:
        f.write(h.replace(a, b)); mp = f.name
    r = subprocess.run([sys.executable, str(root / 'test_reap_stream_gauge.py')],
                       env={**os.environ, 'GAUGE_TEST_HEALTH': mp}, capture_output=True, text=True)
    os.unlink(mp)
    ok = r.returncode != 0; killed += ok
    print(('killed: ' if ok else 'SURVIVED: ') + name)
print(f'test_reap_stream_gauge mutations: {killed}/{len(muts)} killed')
sys.exit(0 if killed == len(muts) else 1)
