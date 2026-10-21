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
mut sockproxy_health.c '            sp_pd_record(pfe, gc_model, prefill_ms, decode_ms, pd_kv,
                             8 /*decode truncated*/);' '            sp_pd_record(pfe, gc_model, prefill_ms, decode_ms, pd_kv,
                             0);'
expect "5b: the sweep records a success again" "a reaper records a literal success (0)"
fresh
mut sockproxy_health.c '            sp_pd_record(pfe, gc_model, prefill_ms, decode_ms, pd_kv,
                             8 /*decode truncated*/);' '            sp_pd_record(pfe, gc_model, prefill_ms, decode_ms, pd_kv,
                             2 /*decode error*/);'
expect "5b: the sweep records decode/error" "the graceful-[DONE] sweep must record decode/truncated (8) once"
fresh
mut sockproxy_health.c 'sp_pd_record(pfe, pd_tmo_model, t_prefill_ms, 0, t_kv, 1);' 'sp_pd_record(pfe, pd_tmo_model, t_prefill_ms, 0, t_kv, 0);'
expect "5b: another reaper records a success" "a reaper records a literal success (0)"

# 6: every reaper and the decode EOF mid-stream record the request, by cause.
for k in PD_STREAM_TIMEOUT PD_IDLE_TIMEOUT SSE_CAP; do
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
for k in PD_STREAM_TIMEOUT SSE_CAP; do
  fresh
  python3 - "$work/src/sockproxy_health.c" "$k" <<'PY'
import sys
p, k = sys.argv[1], sys.argv[2]
s = open(p).read()
i = s.index("pd_reap_respond(pfe, SP_REAP_%s);" % k)
j = s.rindex("pd_reap_lifecycle(pfe, 8 /*decode truncated*/);", 0, i)
s = s[:j] + "pd_reap_lifecycle(pfe, 2 /*decode error*/);" + s[j + len("pd_reap_lifecycle(pfe, 8 /*decode truncated*/);"):]
open(p, "w").write(s)
PY
  expect "6: the $k reap names the engine's death" "the SP_REAP_$k reap must record decode/truncated (8)"
done
fresh
mut sockproxy_health.c '            pd_reap_lifecycle(pfe, 9 /*aborted*/);
            pd_reap_respond(pfe, SP_REAP_SSE_STALL);' '            pd_reap_lifecycle(pfe, 8 /*decode truncated*/);
            pd_reap_respond(pfe, SP_REAP_SSE_STALL);'
expect "6: the stalled client is recorded as the gateway's" "the stalled-client reap must record aborted (9)"
fresh
mut sockproxy_health.c '            pd_reap_lifecycle(pfe, 9 /*aborted*/);
            pd_reap_respond(pfe, SP_REAP_SSE_STALL);' '            pd_reap_respond(pfe, SP_REAP_SSE_STALL);'
expect "6: the stalled client makes no lifecycle record" "the stalled-client reap must record aborted (9)"
fresh
mut sockproxy_health.c '            pfe->end_cause = SP_END_CLIENT_STALL;
' ''
expect "6: the stall does not name its end" "the stalled-client reap must record aborted (9) and name its end client_stall"
fresh
mut sockproxy_pd_leak.h '  if (pd_phase == 5) return 8;' '  if (pd_phase == 5) return 2;'
expect "6: the idle reaper names a begun answer decode/error" "a reaper records decode/error (2)"
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

# 6b: the request record of an answer a teardown reaper ended.
fresh
mut sockproxy_health.c '  if (sp_reap_texts[kind].teardown) {
    proxy_record_reaped_answer(pfe, sp_reap_end(kind));
  }' ''
expect "6b: an answer a teardown reaper ended has no request record" "sp_reap_record must write the request record of an answer a teardown reaper ended"
fresh
mut sockproxy_health.c '    proxy_record_reaped_answer(pfe, sp_reap_end(kind));' '    proxy_record_reaped_answer(pfe, SP_END_NONE);'
expect "6b: a reaper's cut is recorded as a whole answer" "sp_reap_record must write the request record of an answer a teardown reaper ended"

# 6c: an answer the client did not get whole is recorded by its end.
fresh
mut sockproxy_health.c '            pfe->end_cause = SP_END_DURATION_CAP;' ''
expect "6c: the duration cap does not name its cut" "the duration cap must name its cut"
fresh
mut sockproxy_http.c '        pfe->end_cause, shape == TEARDOWN_LISTENER,' '        SP_END_NONE, shape == TEARDOWN_LISTENER,'
expect "6c: the teardown ignores the end recorded when the answer ended" "the teardown record must read how the answer ended"
fresh
mut sockproxy_http.c '        !pfe->h2_session &&
            atomic_load_explicit(&pfe->cresp_answer_open, memory_order_relaxed),' '        0,'
expect "6c: an open answer at teardown reads as whole" "the teardown record must read how the answer ended"
fresh
mut sockproxy_http.c '                   (pfe->pd_kv_params_len > 0) ? 1 : 0, 9 /*aborted*/);
      pfe->pd_phase = PD_PHASE_ERROR;' '                   (pfe->pd_kv_params_len > 0) ? 1 : 0, 9 /*aborted*/);'
expect "6c: the P/D client's abort can be recorded twice" "a P/D client that left record aborted (9) once"
fresh
mut sockproxy_http.c '                            (char *)sp_end_code(u->end),
                            u->request_id,' '                            "",
                            u->request_id,'
expect "6c: the teardown record drops the end" "the teardown's request record must name the end"
fresh
mut sockproxy_http.c 'memory_order_relaxed)) {
            cl->end_cause = SP_END_BACKEND_DIED;' 'memory_order_relaxed)) {
            (void)0;'
expect "6c: a dying leg does not name the engine" "must name the engine (SP_END_BACKEND_DIED)"
fresh
mut sockproxy_http.c '        teardown_owes_abort_record(&v));' '        0);'
expect "6c: the teardown reads no request as left before its answer" "the teardown record must read how the answer ended"
fresh
mut sockproxy_http.c '    if (u->owes_record && sp_end_client_left(u->end) &&' '    if (u->owes_record && u->end == SP_END_CLIENT_GONE &&'
expect "6c: the client leaving before an answer gets no aborted (9)" "a P/D client that left record aborted (9) once"

# 6d: a request its client left before any answer is recorded once.
fresh
mut sockproxy_teardown_settle.h '         teardown_owes_abort_record(c) || teardown_owes_usage_missing(c) ||' '         teardown_owes_usage_missing(c) ||'
expect "6d: the teardown rule owes nothing for a request left before its answer" "must be owed its abort record by the teardown rule"
fresh
mut sockproxy_teardown_settle.h '      c->metric_response_status != 0 || c->has_h2_session || c->resp_kernel) {' '      c->has_h2_session || c->resp_kernel) {'
expect "6d: a request a status accounts for is recorded again" "must be owed its abort record by the teardown rule"
fresh
mut sockproxy_teardown_settle.h 'c->ai_gw_mode || c->metric_ai_recorded ||' 'c->ai_gw_mode ||'
expect "6d: a recorded request is owed its abort record again" "must be owed its abort record by the teardown rule"
fresh
mut sockproxy_teardown_settle.h '  if (c->pd_rule && c->pd_in_flight) {
    return 1;
  }
' ''
expect "6d: a P/D request in flight before it is whole is not owed" "must be owed its abort record by the teardown rule"
fresh
mut sockproxy_http.c '  v->pd_in_flight          = pd_reap_error_phase(pfe->pd_phase) >= 0;
' ''
expect "6d: the view does not say the request is in flight" "the teardown must collect and record a request that ended before any answer"
fresh
mut sockproxy_http.c '  if ((teardown_owes_completion(&v) || teardown_owes_abort_record(&v) ||' '  if ((teardown_owes_completion(&v) ||'
expect "6d: the teardown does not collect it" "the teardown must collect and record a request that ended before any answer"
fresh
mut sockproxy_http.c '    if (teardown_owes_abort_record(&v) && sp_end_recorded_before_answer(u->end)) {
      u->owes_record = 1;
    }
' ''
expect "6d: its request record is not owed" "the teardown must collect and record a request that ended before any answer"
fresh
mut sockproxy_http.c '    if (teardown_owes_abort_record(&v) && sp_end_recorded_before_answer(u->end)) {' '    if (u->end == SP_END_CLIENT_NO_ANSWER) {'
expect "6d: the engine's end before any answer is not recorded" "the teardown must collect and record a request that ended before any answer"
fresh
mut sockproxy_http.c '         (u->end == SP_END_CLIENT_NO_ANSWER && pfe->pd_rule))) {' '         0)) {'
expect "6c: a P/D client leaving at the gate, queued or parked gets no aborted (9)" "a P/D client that left record aborted (9) once"
fresh
mut sockproxy_end_cause.h '  return end == SP_END_CLIENT_NO_ANSWER || end == SP_END_LISTENER_CLOSED ||' '  return end == SP_END_CLIENT_NO_ANSWER ||'
expect "6f: the listener going before any answer is not an end recorded then" "a request is recorded before any answer when the client left"
fresh
mut sockproxy_end_cause.h '         end == SP_END_BACKEND_DIED;' '         0;'
expect "6f: the leg ending before any answer is not an end recorded then" "a request is recorded before any answer when the client left"

# 6e: off P/D, the request record alone, for a whole request the client left.
fresh
mut sockproxy_teardown_settle.h '  return c->req_framed && !c->hold_gw_ended;' '  return 1;'
expect "6e: a request not yet whole is owed an abort record" "off P/D, the abort record is owed for a whole request only"
fresh
mut sockproxy_teardown_settle.h '  return c->req_framed && !c->hold_gw_ended;' '  return c->req_framed;'
expect "6e: a hold the gateway ended reads as the client leaving" "off P/D, the abort record is owed for a whole request only"
fresh
mut sockproxy_http.c '    npfe1->pd_rule = ent_pool0->pd_disagg_enabled ? 1 : 0;
' ''
expect "6e: the connection does not know its rule is P/D" "the teardown view must say whether the rule is P/D"
fresh
mut sockproxy_http.c '  v->req_framed            = pfe->metric_req_start_ns > 0;' '  v->req_framed            = 1;'
expect "6e: the view calls every request whole" "the teardown view must say whether the rule is P/D"
fresh
mut sockproxy_http.c '    v->hold_gw_ended = he == SP_HOLD_END_EXPIRED || he == SP_HOLD_END_RELEASED;' '    v->hold_gw_ended = he == SP_HOLD_END_EXPIRED;'
expect "6e: an operator's release reads as the client leaving" "the teardown view must say whether the rule is P/D"
fresh
mut sockproxy_http.c '              !cl->metric_ai_recorded && cl->metric_response_status == 0) {
            cl->end_cause = SP_END_BACKEND_DIED;' '              !cl->metric_ai_recorded && cl->metric_response_status == 0) {
            (void)0;'
expect "6e: a leg dying before any answer reads as the client leaving" "off P/D, a leg ending before any answer must name the engine"

# 6h: the listener going before any answer: listener_closed.
fresh
mut sockproxy_end_cause.h '    return listener ? SP_END_LISTENER_CLOSED : SP_END_CLIENT_NO_ANSWER;' '    return listener ? SP_END_NONE : SP_END_CLIENT_NO_ANSWER;'
expect "6h: the listener going before any answer is not recorded" "the listener going before any answer must be the gateway's end"

# 6g: a connection whose answers go by the kernel owes nothing before any answer.
fresh
mut sockproxy_teardown_settle.h 'c->has_h2_session || c->resp_kernel) {' 'c->has_h2_session) {'
expect "6g: a kernel-answered request reads as left before any answer" "a connection whose answers go by the kernel must owe no record"
fresh
mut sockproxy_http.c '  v->resp_kernel           = pfe->resp_kernel ? 1 : 0;
' ''
expect "6g: the view drops the kernel pairing" "a connection whose answers go by the kernel must owe no record"
fresh
mut sockproxy_http.c '          pfe->resp_kernel = 1;
' ''
expect "6g: the pairing does not mark the client" "a connection whose answers go by the kernel must owe no record"
fresh
mut sockproxy_http.c '!cl->pd_rule &&
              !cl->resp_kernel && cl->odir == 0' '!cl->pd_rule &&
              cl->odir == 0'
expect "6g: a kernel-answered leg's close names the engine" "off P/D, a leg ending before any answer must name the engine"

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
r = s.index("  if (pd_prefill_status_verdict(pr_status) == PD_PR_RELAY) {")
s = s[:r] + blk + "\n\n" + s[r:]
open(p, "w").write(s)
PY
expect "8b: the fallback reason is set before the relay verdict" "the fallback reason must be set once, after the relay verdict"

# 3b: a cut 4xx is relayed by its status with the gateway's body.
fresh
mut sockproxy_pd_leak.h 'pd_prefill_status_verdict(int status)
{
  return (status >= 400 && status < 500 && status != 408 && status != 429)' 'pd_prefill_status_verdict(int status, int truncated)
{
  return (status >= 400 && status < 500 && status != 408 && status != 429 &&
          !truncated)'
expect "3b: the verdict sends a cut 4xx to decode again" "pd_prefill_status_verdict must decide by the status alone"
fresh
mut sockproxy_pd_vllm.c '                            is_trt, l_body_len, l_prefill_truncated);' '                            is_trt, l_body_len, 0);'
expect "3b: the relay is not told the reply was cut" "must be relayed with the gateway's body"
fresh
mut sockproxy_pd_vllm.c '    resp = cl ? (const uint8_t *)cut : NULL;' '    (void)cl;'
expect "3b: the cut reply is written as it is" "must be relayed with the gateway's body"

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

# 1f: the framer no longer records the answer: a status line split across
# reads is lost to the class counter and the TTFB sample again.
fresh
mut sockproxy_http.c '    if (proxy_note_client_response(pfe, status))
      proxy_origin_status_feed(pfe, status);' '    (void)status;'
expect "1f: the framer does not record the answer" "cresp_on_headers_complete must record the answer"

# 1f: the framer records, but before it knows the status is an answer: an
# interim 100 would take the latch from the real answer.
fresh
mut sockproxy_http.c '  if (!cresp_is_answer(parser->status_code)) {
    return 0;
  }
  /* The answer'"'"'s record' '  {
    uint16_t status = (uint16_t)parser->status_code;
    if (proxy_note_client_response(pfe, status))
      proxy_origin_status_feed(pfe, status);
  }
  if (!cresp_is_answer(parser->status_code)) {
    return 0;
  }
  /* The answer'"'"'s record'
expect "1f: the framer records an interim response" "cresp_on_headers_complete must record the answer"

# 1f: the capture stops feeding the breaker.
fresh
mut sockproxy_http.c '          if (noted) proxy_origin_status_feed(rfd_ent, status);' '          (void)noted;'
expect "1f: the capture does not feed the breaker" "must feed the breaker through proxy_origin_status_feed"

echo "check_pd_status_sites.sh mutations: $((n - survived)) of $n killed"
[ "$survived" = "0" ]
