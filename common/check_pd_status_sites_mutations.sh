#!/bin/sh
# Mutation tests for check_pd_status_sites.sh: each rule added for the P/D
# lifecycle record is broken once in a scratch copy of the sources, and the
# check must fail with that rule's message. The unmutated copy must pass.
# Exit 1 when a mutation survives.
#
#   sh check_pd_status_sites_mutations.sh    (from anywhere; needs python3)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

survived=0
n=0

fresh() {
  rm -rf "$work/src"
  mkdir "$work/src"
  cp "$here"/sockproxy*.c "$here"/sockproxy*.h "$here/check_pd_status_sites.sh" "$work/src/"
}

# mut FILE OLD NEW: replace the one occurrence of OLD (it must exist once).
mut() {
  python3 - "$work/src/$1" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
if s.count(old) != 1:
    sys.exit("mutation anchor found %d times in %s: %r" % (s.count(old), p, old))
open(p, "w").write(s.replace(old, new))
PY
}

# expect NAME MESSAGE: the check fails, and says MESSAGE.
expect() {
  n=$((n + 1))
  if out=$(sh "$work/src/check_pd_status_sites.sh" 2>&1); then
    echo "SURVIVED: $1 (the check passed)"
    survived=1
  elif ! printf '%s\n' "$out" | grep -qF "$2"; then
    echo "SURVIVED: $1 (failed without: $2)"
    printf '%s\n' "$out" | sed 's/^/    /'
    survived=1
  else
    echo "killed: $1"
  fi
}

fresh
sh "$work/src/check_pd_status_sites.sh" >/dev/null ||
  { echo "the unmutated sources fail the check"; exit 1; }

# 5: a non-SSE decode completion records a literal success on a continuation line.
fresh
mut sockproxy_http.c '        sp_pd_record(rfd_ent, ns_model, prefill_ms, decode_ms, pd_kv,
                         pd_decode_error_phase(rfd_ent->metric_response_status));' '        sp_pd_record(rfd_ent, ns_model, prefill_ms, decode_ms, pd_kv,
                         0);'
expect "5: the body-complete record is a literal success" "a P/D completion records a literal success (0)"

# 5b: the graceful-[DONE] sweep records decode/truncated.
fresh
mut sockproxy_health.c '8 /*decode truncated*/);' '0);'
expect "5b: the sweep records a success again" "a reaper records a literal success (0)"
fresh
mut sockproxy_health.c '8 /*decode truncated*/);' '2 /*decode error*/);'
expect "5b: the sweep records decode/error" "the graceful-[DONE] sweep must record decode/truncated (8) once"
fresh
mut sockproxy_health.c 'sp_pd_record(pfe, pd_tmo_model, t_prefill_ms, 0, t_kv, 1);' 'sp_pd_record(pfe, pd_tmo_model, t_prefill_ms, 0, t_kv, 0);'
expect "5b: another reaper records a success" "a reaper records a literal success (0)"

# 6: every reaper and the decode EOF mid-stream record the request.
for k in PD_STREAM_TIMEOUT PD_IDLE_TIMEOUT SSE_CAP SSE_STALL; do
  fresh
  python3 - "$work/src/sockproxy_health.c" "$k" <<'PY'
import sys
p, k = sys.argv[1], sys.argv[2]
s = open(p).read()
i = s.index("pd_reap_respond(pfe, SP_REAP_%s);" % k)
j = s.rindex("pd_reap_lifecycle(pfe, ", 0, i)
e = s.index(";", j) + 1
s = s[:j] + "(void)0;" + s[e:]
open(p, "w").write(s)
PY
  expect "6: the $k reap makes no lifecycle record" "the SP_REAP_$k reap is not preceded by its lifecycle record"
done
fresh
mut sockproxy_http.c '            sp_pd_record(client_pfe, pd_model, prefill_ms, 0, pd_kv,
                             2 /*decode error*/);
          }
          client_pfe->pd_phase = PD_PHASE_ERROR;' '          }'
expect "6: the decode EOF mid-stream records nothing" "the decode EOF mid-stream must record decode/error"
fresh
mut sockproxy_http.c '                             2 /*decode error*/);
          }
          client_pfe->pd_phase = PD_PHASE_ERROR;' '                             2 /*decode error*/);
          }'
expect "6: the decode EOF mid-stream leaves the request to the sweep" "the decode EOF mid-stream must record decode/error"

# 6b: the reaped stream's request record.
fresh
mut sockproxy_health.c '    proxy_record_reaped_stream(pfe);
    break;' '    break;'
expect "6b: the stream the sweep ended has no request record" "sp_reap_record must write the request record of a stream the sweep ended"

# 7: one record, both calls, through the helper only.
fresh
mut sockproxy_pd_trtllm.c 'sp_pd_record(client_pfe, model, prefill_ms, 0, 0, 0);' 'llb_ai_pd_record((char *)model, prefill_ms, 0, 0, 0);'
expect "7: a site records without the helper" "a P/D lifecycle record made without sp_pd_record"
fresh
mut sockproxy_http.c '  llb_ai_pd_record((char *)model, prefill_ms, decode_ms, kv, error_phase);
  llb_ai_pd_record_extra' '  llb_ai_pd_record((char *)model, prefill_ms, decode_ms, kv, error_phase);
  if (fb == 0 && ttft_us == 0) return;
  llb_ai_pd_record_extra'
expect "7: the extra half is skipped when it carries nothing" "sp_pd_record must call llb_ai_pd_record once and llb_ai_pd_record_extra as its next statement"
fresh
mut sockproxy_http.c '  llb_ai_pd_record_extra((char *)model, ttft_us, fb);
' ''
expect "7: the extra half is gone" "sp_pd_record must call llb_ai_pd_record once and llb_ai_pd_record_extra as its next statement"

# 8: the stamp and the fallback reason.
fresh
mut sockproxy_http.c 'if (sp_sse_body(&pfe->cresp_sse, at, len) && pfe->pd_first_event_ns == 0 &&' 'if (sp_sse_body(&pfe->cresp_sse, at, len) &&'
expect "8a: the stamp is taken again at every first object" "cresp_on_body must stamp the first event once"
fresh
mut sockproxy_http.c '        (pfe->pd_phase == PD_PHASE_DECODE_SENDING ||
         pfe->pd_phase == PD_PHASE_DECODE_STREAMING)) {' '        1) {'
expect "8a: the stamp is taken outside a P/D decode leg" "cresp_on_body must stamp the first event once"
fresh
python3 - "$work/src/sockproxy_pd_vllm.c" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = s.index("  /* Every path from here goes to the decode leg.")
b = s.index("pd_prefill_fallback_reason(pr_status, l_prefill_truncated);", a) + len("pd_prefill_fallback_reason(pr_status, l_prefill_truncated);")
blk = s[a:b]; s = s[:a] + s[b:]
r = s.index("  if (pd_prefill_status_verdict(pr_status, l_prefill_truncated) == PD_PR_RELAY) {")
s = s[:r] + blk + "\n\n" + s[r:]
open(p, "w").write(s)
PY
expect "8b: the fallback reason is set before the relay verdict" "the fallback reason must be set once, after the relay verdict"

# 7c: the helper's unit (test_pd_record.py) catches a helper that keeps the
# values for a second record, or reports milliseconds.
unit() {
  n=$((n + 1))
  if PD_RECORD_TEST_SOURCE="$work/src/sockproxy_http.c" python3 "$here/test_pd_record.py" >/dev/null 2>&1; then
    echo "SURVIVED: $1 (test_pd_record.py passed)"
    survived=1
  else
    echo "killed: $1"
  fi
}
fresh
mut sockproxy_http.c '  pfe->pd_first_event_ns = 0;
  pfe->pd_fallback_reason = 0;
' ''
unit "7c: the values are not consumed"
fresh
mut sockproxy_http.c '/
                        1000ULL);' '/
                        1000000ULL);'
unit "7c: the TTFT goes out in milliseconds"

echo "check_pd_status_sites.sh mutations: $((n - survived)) of $n killed"
[ "$survived" = "0" ]
