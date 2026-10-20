#!/usr/bin/env python3
"""Each mutation of the reaper's body framing must turn test_reap_framing.py
red: a decision read off a backend leg (the first, or any), a dropped
answer-open guard, a missing 0-chunk, and an unframed write on the owner
worker or in the health-thread fallback."""
import os, subprocess, sys, tempfile
from pathlib import Path
root = Path(__file__).resolve().parent; h = (root / 'sockproxy_health.c').read_text()
NEW = '''  return atomic_load_explicit(&pfe->cresp_answer_open, memory_order_relaxed) &&
         (pfe->cresp_parser.flags & F_CHUNKED) != 0;'''
muts = {
 'the decision reads the first backend leg (the old code)': (NEW,
   '''  proxy_fd_ent_t *leg;
  if (pfe->n_rfd <= 0)
    return 0;
  leg = __atomic_load_n(&pfe->rfd_ent[0], __ATOMIC_ACQUIRE);
  return leg && leg->is_chunked_response;'''),
 'the decision reads any backend leg': (NEW,
   '''  for (int i = 0; i < pfe->n_rfd && i < 2; i++)
    if (pfe->rfd_ent[i] && pfe->rfd_ent[i]->is_chunked_response) return 1;
  return 0;'''),
 'the answer-open guard is dropped': (NEW, '''  return (pfe->cresp_parser.flags & F_CHUNKED) != 0;'''),
 'the 0-chunk is not written': ('"%zx\\r\\n%s\\r\\n0\\r\\n\\r\\n", t->len, t->text);', '"%zx\\r\\n%s\\r\\n", t->len, t->text);'),
 'the owner worker writes the text unframed': ('    size_t fl = sp_reap_body_frame(pfe, t, framed, sizeof(framed));\n    if (fl > 0) {', '    size_t fl = 0;\n    if (fl > 0) {'),
 'the health-thread fallback writes the text unframed': ('      size_t fl = sp_reap_body_frame(pfe, t, framed, sizeof(framed));\n', '      size_t fl = 0; (void)framed;\n'),
}
killed = 0
for name, (a, b) in muts.items():
    assert h.count(a) == 1, name
    with tempfile.NamedTemporaryFile('w', suffix='.c', delete=False) as f:
        f.write(h.replace(a, b)); mp = f.name
    r = subprocess.run([sys.executable, str(root / 'test_reap_framing.py')], env={**os.environ, 'ANSWER_TEST_HEALTH': mp},
                       capture_output=True, text=True)
    ok = r.returncode != 0; killed += ok
    print(('killed: ' if ok else 'SURVIVED: ') + name)
print(f'test_reap_framing mutations: {killed}/{len(muts)} killed')
sys.exit(0 if killed == len(muts) else 1)
