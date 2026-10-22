#!/bin/sh
# Source invariant: a P/D request reports the status of the response its
# client received, never the prefill leg's.
#
# The response path captures the first backend status line of a request into
# metric_response_status (and, in trace builds, response_status_code). On the
# sequential P/D machine (vLLM, TensorRT-LLM) the first one to arrive is the
# prefill reply, which is buffered and never relayed, so both captures skip a
# packet while the client is in PD_PHASE_PREFILL_WAITING. A path that answers
# the client from the prefill leg itself then owns the response record, and
# must take it where it relays, or the request is recorded with status 0 and
# is missing from the responses-by-status class counter and the TTFB sample.
#
# The record (status, class counter, TTFB sample) has one writer,
# proxy_note_response_, latched once per request, reached through
# proxy_note_client_response for a backend reply (TTFB sampled) and
# proxy_note_local_answer for the gateway's own answers (check_local_answers.sh).
# Every site that answers the client with a backend reply calls the first:
# the capture, and each relay of the prefill reply.
#
#   sh check_pd_status_sites.sh    (from anywhere; exit 1 on a violation)
set -eu
cd "$(dirname "$0")"

fail=0

# 1. Both status captures skip the prefill leg. The skip is the line after the
#    capture's "== 0 && len > 16 &&" opening.
for field in metric_response_status response_status_code; do
  n=$(grep -c "rfd_ent->$field == 0 && len > 16 &&\$" ./sockproxy_http.c || true)
  if [ "$n" != "1" ]; then
    echo "sockproxy_http.c: expected one '$field == 0 && len > 16 &&' capture opening; found $n"
    fail=1
    continue
  fi
  next=$(grep -A1 "rfd_ent->$field == 0 && len > 16 &&\$" ./sockproxy_http.c | sed -n 2p)
  case "$next" in
    *"rfd_ent->pd_phase != PD_PHASE_PREFILL_WAITING"*) ;;
    *)
      echo "sockproxy_http.c: the $field capture does not skip the prefill leg (PD_PHASE_PREFILL_WAITING):"
      echo "  $next"
      fail=1 ;;
  esac
done

# 1b. The capture records through the helper.
cap=$(grep -A24 'rfd_ent->metric_response_status == 0 && len > 16 &&$' ./sockproxy_http.c || true)
if ! printf '%s\n' "$cap" | grep -q 'proxy_note_client_response(rfd_ent, status)'; then
  echo "sockproxy_http.c: the L7 METRICS capture must record through proxy_note_client_response(rfd_ent, status)"
  fail=1
fi

# 1f. The framer records the answer too. A status line split across reads
#     ("HTTP/1.1 200" then " OK\r\n…") is never a read that begins "HTTP/1."
#     with 16 bytes behind it, so the capture misses it and the request is
#     missing from the class counter and the TTFB sample while its AI record
#     carries the status the framer read (MON-02-EDGE). llhttp assembles the
#     line whatever the read boundaries: cresp_on_headers_complete records
#     through the same helper once the status is an answer, and the latch
#     makes the second of the two sites a no-op. Both sites feed the origin
#     breaker through proxy_origin_status_feed when their note took the latch.
fr=$(awk '/^cresp_on_headers_complete\(/ {on = 1} on {print} on && /^}/ {exit}' ./sockproxy_http.c)
ans_ln=$(printf '%s\n' "$fr" | grep -n 'if (!cresp_is_answer(parser->status_code)) {' | head -1 | cut -d: -f1)
rec_ln=$(printf '%s\n' "$fr" | tr '\n' ' ' | grep -o 'if (proxy_note_client_response(pfe, status)) *proxy_origin_status_feed(pfe, status);' | head -1)
rec_pos=$(printf '%s\n' "$fr" | grep -n 'if (proxy_note_client_response(pfe, status))' | head -1 | cut -d: -f1)
if [ -z "$ans_ln" ] || [ -z "$rec_ln" ] || [ -z "$rec_pos" ] || [ "$rec_pos" -lt "$ans_ln" ]; then
  echo "sockproxy_http.c: cresp_on_headers_complete must record the answer through proxy_note_client_response(pfe, status) after cresp_is_answer, and feed the breaker when its note took the latch (a status line split across reads is recorded by the framer)"
  fail=1
fi
if ! printf '%s\n' "$cap" | grep -q 'if (noted) proxy_origin_status_feed(rfd_ent, status);'; then
  echo "sockproxy_http.c: the L7 METRICS capture must feed the breaker through proxy_origin_status_feed when its note took the latch"
  fail=1
fi
feeds=$(grep -c 'proxy_origin_status_feed(' ./sockproxy_http.c || true)
if [ "$feeds" != "3" ]; then
  echo "sockproxy_http.c: proxy_origin_status_feed has one definition and two callers (the capture, the framer); found $feeds mentions"
  fail=1
fi

# 1c. The writer is the only one of the class counters and the TTFB sample,
#     so no path can record a response around it (or twice). The product
#     sources are the paths; a test fixture that links sockproxy_http.c
#     defines the sample as a no-op boundary (test_pd_retry_lifecycle.c), and
#     a definition records nothing.
h_from=$(grep -n '^proxy_note_response_(' ./sockproxy_http.c | head -1 | cut -d: -f1)
h_to=$(awk -v f="${h_from:-0}" 'NR > f && /^}/ {print NR; exit}' ./sockproxy_http.c)
if [ -z "$h_from" ] || ! sed -n "${h_from},${h_to}p" ./sockproxy_http.c | grep -q 'resp_note_take(&pfe->metric_resp_noted'; then
  echo "sockproxy_http.c: proxy_note_response_ must take the once-per-request latch (resp_note_take)"
  fail=1
fi
outside=$(grep -nE 'global_stats\.http_(responses_total|status_[1-5]xx)|record_latency_sample\(' ./*.c \
            | grep -v '^\./sockproxy_metrics\.c:' | grep -v '^\./test_' \
            | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(\*|/\*|//)' \
            | awk -F: -v a="${h_from:-0}" -v b="${h_to:-0}" '!($1 == "./sockproxy_http.c" && $2 >= a && $2 <= b)' || true)
if [ -n "$outside" ]; then
  printf '%s\n' "$outside"
  echo "  ^ a response record outside proxy_note_response_"
  fail=1
fi

# 1d. A P/D dialect never sets the status alone: it records the response.
direct=$(grep -nE 'metric_response_status[[:space:]]*=[^=]' ./sockproxy_pd*.c \
           | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(\*|/\*|//)' || true)
if [ -n "$direct" ]; then
  printf '%s\n' "$direct"
  echo "  ^ sets the status without proxy_note_client_response (class counter and TTFB sample missed)"
  fail=1
fi

# 1e. Every relay of the prefill reply records the response first. A call that
#     hands the client and the claimed prefill reply together, F(client_pfe,
#     l_prefill, ...), answers the client from the prefill leg: F records
#     itself, or its block calls proxy_note_client_response before it. The
#     prefill reply is never written to the client directly.
fn=$(awk '/^pd_initiate_decode\(/ {on = 1} on {print} on && /^}/ {exit}' ./sockproxy_pd_vllm.c)
if printf '%s\n' "$fn" | grep -qE '(send|SSL_write)\([^;]*l_prefill'; then
  echo "sockproxy_pd_vllm.c: pd_initiate_decode writes the prefill reply to the client directly; relay it through a function that records"
  fail=1
fi
relays=$(printf '%s\n' "$fn" | grep -nE '[a-z_]+\(client_pfe, l_prefill' | sed -E 's/^([0-9]+):[[:space:]]*([a-z_]+)\(.*/\1 \2/' || true)
[ -n "$relays" ] || { echo "sockproxy_pd_vllm.c: no prefill-reply relay found in pd_initiate_decode"; fail=1; }
for r in $(printf '%s\n' "$relays" | tr ' ' ':'); do
  ln=${r%%:*}; name=${r#*:}
  body=$(awk -v n="$name" '$0 ~ "^"n"\\(" {on = 1} on {print} on && /^}/ {exit}' ./sockproxy_pd_*.c)
  printf '%s\n' "$body" | grep -q 'proxy_note_client_response(' && continue
  blk=$(printf '%s\n' "$fn" | sed -n "1,${ln}p" | awk '/^  if \(/ {b = ""} {b = b $0 "\n"} END {printf "%s", b}')
  if ! printf '%s' "$blk" | grep -q 'proxy_note_client_response(client_pfe'; then
    echo "sockproxy_pd_vllm.c: $name (pd_initiate_decode line $ln) answers the client from the prefill leg without proxy_note_client_response"
    fail=1
  fi
done

# 2. The TensorRT-LLM early exit answers from the prefill leg: it records the
#    response before it relays.
trt=$(awk '/if \(is_trt && pr_status == 200 &&/ {on = 1} on {print} on && /goto out;/ {exit}' ./sockproxy_pd_vllm.c)
if [ -z "$trt" ]; then
  echo "sockproxy_pd_vllm.c: TensorRT-LLM early-exit block (if (is_trt && pr_status == 200 && ...) not found"
  fail=1
else
  set_ln=$(printf '%s\n' "$trt" | grep -n 'proxy_note_client_response(client_pfe' | head -1 | cut -d: -f1)
  relay_ln=$(printf '%s\n' "$trt" | grep -n 'pd_trt_early_exit_relay(' | head -1 | cut -d: -f1)
  if [ -z "$set_ln" ] || [ -z "$relay_ln" ] || [ "$set_ln" -gt "$relay_ln" ]; then
    echo "sockproxy_pd_vllm.c: the TensorRT-LLM early exit must call proxy_note_client_response before pd_trt_early_exit_relay:"
    printf '%s\n' "$trt"
    fail=1
  fi
fi

# 3. An origin 4xx prefill reply is decided before the decode leg is built:
#    pd_initiate_decode consults pd_prefill_status_verdict ahead of the
#    transfer-params extract, and the relay that answers from it sets the status.
fn=$(awk '/^pd_initiate_decode\(/ {on = 1} on {print} on && /^}/ {exit}' ./sockproxy_pd_vllm.c)
verdict_ln=$(printf '%s\n' "$fn" | grep -n 'pd_prefill_status_verdict(pr_status' | head -1 | cut -d: -f1)
extract_ln=$(printf '%s\n' "$fn" | grep -n '1. Extract the transfer params' | head -1 | cut -d: -f1)
if [ -z "$verdict_ln" ] || [ -z "$extract_ln" ] || [ "$verdict_ln" -gt "$extract_ln" ]; then
  echo "sockproxy_pd_vllm.c: pd_initiate_decode must call pd_prefill_status_verdict(pr_status) before the transfer-params extract"
  fail=1
fi
relay=$(awk '/^pd_prefill_reject_relay\(/ {on = 1} on {print} on && /^}/ {exit}' ./sockproxy_pd_vllm.c)
if ! printf '%s\n' "$relay" | grep -q 'proxy_note_client_response(client_pfe'; then
  echo "sockproxy_pd_vllm.c: pd_prefill_reject_relay must record the response (proxy_note_client_response)"
  fail=1
fi
# 3b. A 4xx reply cut at the buffer cap is relayed by its status, not sent to
#     the decode leg (F-12): the verdict does not read the cut, the relay is
#     told of it, and writes the gateway's short body in place of the cut one.
if ! grep -q '^pd_prefill_status_verdict(int status)$' ./sockproxy_pd_leak.h; then
  echo "sockproxy_pd_leak.h: pd_prefill_status_verdict must decide by the status alone (a cut 4xx is relayed, not recomputed)"
  fail=1
fi
if ! printf '%s\n' "$fn" | tr '\n' ' ' | grep -q 'pd_prefill_reject_relay(client_pfe, l_prefill, l_prefill_len, pr_status, *is_trt, l_body_len, l_prefill_truncated);' || \
   ! printf '%s\n' "$relay" | tr '\n' ' ' | grep -q 'if (truncated) { *size_t cl = pd_prefill_cut_reject(status, cut, sizeof(cut)); *resp = cl ? (const uint8_t \*)cut : NULL;'; then
  echo "sockproxy_pd_vllm.c: a prefill 4xx cut at the buffer cap must be relayed with the gateway's body (pd_prefill_cut_reject), not the cut reply"
  fail=1
fi
if ! printf '%s\n' "$trt" | grep -q 'ret = PD_DECODE_ANSWERED;'; then
  echo "sockproxy_pd_vllm.c: the TensorRT-LLM early exit must return PD_DECODE_ANSWERED so its caller records the request"
  fail=1
fi

# 4. Every caller of pd_initiate_decode records a request the prefill leg
#    answered: nothing later on that path does.
calls=$(grep 'pd_initiate_decode(' ./sockproxy_http.c | grep -cvE '^[[:space:]]*(\*|/\*|//)' || true)
handled=$(grep -A4 '== PD_DECODE_ANSWERED' ./sockproxy_http.c | grep -c 'proxy_ai_record_completion(' || true)
if [ "$calls" -lt 1 ] || [ "$calls" != "$handled" ]; then
  echo "sockproxy_http.c: $calls pd_initiate_decode() call(s), $handled record a PD_DECODE_ANSWERED request (proxy_ai_record_completion)"
  fail=1
fi

# 5. A completed decode leg is recorded by its status. In sockproxy_http.c the
#    completions allowed a literal success (0) are the SSE [DONE] one, whose
#    stream exists only for a 2xx event-stream, and the decode-leg EOF of a
#    stream that had FINISHED (5c below); the non-SSE completions (the
#    Content-Length/chunked one and the decode-backend EOF one) take
#    pd_decode_error_phase(metric_response_status).
lit0=$(awk '/sp_pd_record\(/ {buf = $0; while (buf !~ /\);/ && (getline nl) > 0) buf = buf " " nl;
            if (buf ~ /,[ \t]*0[ \t]*(\/\*[^*]*\*\/)?[ \t]*\);/ && buf !~ /sse_model/ &&
                buf !~ /0 \/\*complete: finish evidence\*\//) print NR": "buf}' ./sockproxy_http.c)
if [ -n "$lit0" ]; then
  echo "sockproxy_http.c: a P/D completion records a literal success (0) whatever its status; use pd_decode_error_phase():"
  printf '%s\n' "$lit0"
  fail=1
fi
# 5c. The decode leg's EOF under an open stream completes the stream only on
#     its finish evidence (pd_client_finished: a finish event for every
#     choice, then only choice-less events), in sp_pd_decode_stream_eof and
#     nowhere else; without it the EOF is the engine's death (rule 6).
n=$(grep -c '0 /\*complete: finish evidence\*/' ./sockproxy_http.c || true)
if [ "$n" != "1" ]; then
  echo "sockproxy_http.c: expected one evidence-gated completion record (0 /*complete: finish evidence*/); found $n"
  fail=1
fi
eoff=$(awk '/^sp_pd_decode_stream_eof\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_http.c | tr '\n' ' ')
if ! printf '%s' "$eoff" | grep -q 'if (atomic_load_explicit(&client->pd_client_finished, memory_order_acquire)) {.*0 /\*complete: finish evidence\*/);.*return 1;.*decode backend EOF mid-stream'; then
  echo "sockproxy_http.c: sp_pd_decode_stream_eof must complete the stream on its finish evidence (pd_client_finished) and only then, before the cut-stream path"
  fail=1
fi
n=$(grep -c 'pd_decode_error_phase([a-z_]*->metric_response_status)' ./sockproxy_http.c || true)
if [ "$n" != "2" ]; then
  echo "sockproxy_http.c: expected the two non-SSE decode completions to use pd_decode_error_phase(...->metric_response_status); found $n"
  fail=1
fi

# 5b. A stream the gateway ended is not a success, unless the stream had
#     finished. In sockproxy_health.c no P/D record is a literal success (0)
#     except the graceful-[DONE] sweep's, the one completion there, and that
#     one only on the stream's finish evidence (pd_client_finished, written by
#     the response framer from the events the client received): with it the
#     engine finished and lost its terminator, a completion (0); without it
#     the engine went silent and the gateway wrote the terminator,
#     decode/truncated (8). The two outcomes are one ternary on the evidence.
lit0h=$(awk '/sp_pd_record\(/ {buf = $0; while (buf !~ /\);/ && (getline nl) > 0) buf = buf " " nl;
             if (buf ~ /,[ \t]*0[ \t]*(\/\*[^*]*\*\/)?[ \t]*\);/ ||
                 (buf ~ /0 \/\*complete/ &&
                  buf !~ /\? *0 \/\*complete: finish evidence\*\/ *: *8 \/\*decode truncated\*\//)) print NR": "buf}' ./sockproxy_health.c)
if [ -n "$lit0h" ]; then
  echo "sockproxy_health.c: a reaper records a literal success (0) for an answer the gateway ended:"
  printf '%s\n' "$lit0h"
  fail=1
fi
sweep=$(awk '/uint32_t decode_idle_cap = PROXY_PD_DECODE_IDLE_CAP_SEC;/ {on = 1} on && /pd_reap_respond\(/ {exit} on' ./sockproxy_health.c | tr '\n' ' ')
g=$(printf '%s' "$sweep" | grep -c 'sp_pd_record([^;]*finished ? 0 /\*complete: finish evidence\*/ *: 8 /\*decode truncated\*/);' || true)
if [ "$g" != "1" ]; then
  echo "sockproxy_health.c: the graceful-[DONE] sweep must record a completion (0) on finish evidence and decode/truncated (8) without it, once; found $g"
  fail=1
fi
if ! printf '%s' "$sweep" | grep -q 'int finished = atomic_load_explicit(&pfe->pd_client_finished,'; then
  echo "sockproxy_health.c: the graceful-[DONE] sweep must read the stream's finish evidence (pd_client_finished)"
  fail=1
fi

# 6. A P/D request a reaper or a dying decode leg ends is recorded by its
#    cause, never by the mechanism that ended it. The stream timeout (ERR-01),
#    the generic idle reaper and the duration cap each call pd_reap_lifecycle
#    right before handing the connection to pd_reap_respond; ERR-01 and the cap
#    name decode/truncated (8): engine silence, a policy cap. The stalled-client
#    abort is the client's, not the engine's: aborted (9), its end
#    named client_stall. No reaper records decode/error (2), and pd_reap_error_phase never
#    returns it: 2 is the engine's death, which the decode EOF mid-stream
#    records, moving the request to ERROR before the sweep can see it.
for kind in SP_REAP_PD_STREAM_TIMEOUT SP_REAP_PD_IDLE_TIMEOUT SP_REAP_SSE_CAP; do
  ok=$(grep -B3 "pd_reap_respond(pfe, $kind);" ./sockproxy_health.c | grep -c 'pd_reap_lifecycle(pfe, ' || true)
  if [ "$ok" != "1" ]; then
    echo "sockproxy_health.c: the $kind reap is not preceded by its lifecycle record (pd_reap_lifecycle)"
    fail=1
  fi
done
for kind in SP_REAP_PD_STREAM_TIMEOUT SP_REAP_SSE_CAP; do
  ok=$(grep -B3 "pd_reap_respond(pfe, $kind);" ./sockproxy_health.c | grep -c 'pd_reap_lifecycle(pfe, 8 /\*decode truncated\*/);' || true)
  if [ "$ok" != "1" ]; then
    echo "sockproxy_health.c: the $kind reap must record decode/truncated (8): the gateway ended the answer, the engine did not die"
    fail=1
  fi
done
st=$(grep -B12 'pd_reap_respond(pfe, SP_REAP_SSE_STALL);' ./sockproxy_health.c)
if ! printf '%s' "$st" | grep -q 'pd_reap_lifecycle(pfe, 9 /\*aborted\*/);' || \
   ! printf '%s' "$st" | grep -q 'pfe->end_cause = SP_END_CLIENT_STALL;'; then
  echo "sockproxy_health.c: the stalled-client reap must record aborted (9) and name its end client_stall"
  fail=1
fi
r2=$(grep -n '2 /\*decode error\*/' ./sockproxy_health.c || true)
r2f=$(awk '/^pd_reap_error_phase\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_pd_leak.h | grep -n 'return 2;' || true)
if [ -n "$r2" ] || [ -n "$r2f" ]; then
  echo "a reaper records decode/error (2), the engine's death, for an answer the gateway ended:"
  printf '%s\n' "$r2" "$r2f" | sed '/^$/d'
  fail=1
fi
eofb=$(awk '/decode backend EOF mid-stream/ {on = 1} on; on && /pd_sg_close_drain\(/ {exit}' ./sockproxy_http.c | tr '\n' ' ')
if ! printf '%s' "$eofb" | grep -q 'sp_pd_record([^;]*2 /\*decode error\*/);.*pd_phase = PD_PHASE_ERROR;.*pd_sg_close_drain(client, 1);'; then
  echo "sockproxy_http.c: the decode EOF mid-stream must record decode/error and move the request to ERROR"
  fail=1
fi

# 6b. An answer a teardown reaper ended has its request record. A teardown
#     kind frees the client inline (pd_teardown_conn), so neither the [DONE]
#     scanner nor the teardown writes it: sp_reap_record writes what is owed for
#     every teardown kind, with the status the client received
#     (test_reap_request_record.py drives each reaper after a 200).
gd=$(awk '/^sp_reap_record\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_health.c | tr '\n' ' ' \
     | grep -c 'if (sp_reap_texts\[kind\].teardown) {[ ]*proxy_record_reaped_answer(pfe, sp_reap_end(kind));' || true)
if [ "$gd" != "1" ]; then
  echo "sockproxy_health.c: sp_reap_record must write the request record of an answer a teardown reaper ended (proxy_record_reaped_answer)"
  fail=1
fi

# 6c. An answer the client did not get whole is recorded aborted, by its end
#     (sockproxy_end_cause.h): the duration cap names its cut before the event
#     loop's teardown records it; the teardown record carries the end it read
#     (the cause recorded when it ended, or an open answer's client leaving);
#     a P/D client that left with its answer open records aborted (9)
#     there, once; a leg ending under an open answer names the engine.
cap=$(grep -B12 'pd_reap_respond(pfe, SP_REAP_SSE_CAP);' ./sockproxy_health.c)
if ! printf '%s' "$cap" | grep -q 'pfe->end_cause = SP_END_DURATION_CAP;'; then
  echo "sockproxy_health.c: the duration cap must name its cut (end_cause) for the teardown record"
  fail=1
fi
col=$(awk '/^proxy_collect_conn_settles\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_http.c | tr '\n' ' ')
if ! printf '%s' "$col" | grep -q 'u->end = sp_end_cause_at_teardown( *pfe->end_cause, shape == TEARDOWN_LISTENER, *!pfe->h2_session && *atomic_load_explicit(&pfe->cresp_answer_open, memory_order_relaxed), *teardown_owes_abort_record(&v));' || \
   ! printf '%s' "$col" | grep -q 'if (u->owes_record && sp_end_client_left(u->end) && *(pd_reap_error_phase(pfe->pd_phase) >= 0 || *(u->end == SP_END_CLIENT_NO_ANSWER && pfe->pd_rule))) {.*9 /\*aborted\*/); *pfe->pd_phase = PD_PHASE_ERROR;'; then
  echo "sockproxy_http.c: the teardown record must read how the answer ended, and a P/D client that left record aborted (9) once"
  fail=1
fi
if ! awk '/The connection.s last response \(collected above under PROXY_LOCK\)/ {on = 1} on && /llb_ai_record_usage_missing/ {exit} on' ./sockproxy_http.c \
     | tr '\n' ' ' | grep -q 'llb_ai_record_request(u->tenant, u->model, u->status, u->latency_ms, *u->prompt_toks, u->complet_toks, 0, 0, *(char \*)sp_end_code(u->end),'; then
  echo "sockproxy_http.c: the teardown's request record must name the end (sp_end_code(u->end))"
  fail=1
fi
if ! tr '\n' ' ' < ./sockproxy_http.c | grep -q 'atomic_load_explicit(&cl->cresp_answer_open, memory_order_relaxed)) { *cl->end_cause = SP_END_BACKEND_DIED;'; then
  echo "sockproxy_http.c: a leg ending under its client's open answer must name the engine (SP_END_BACKEND_DIED)"
  fail=1
fi

# 6d. A request that ended before any answer is recorded once: the shared
#     teardown rule owes it (status 0, nothing recorded; a P/D request in
#     flight, any request once whole at the gate, queued or parked), the
#     teardown collects it, and its request record is owed by its end:
#     client_abort_before_answer, or backend_died off P/D (status 0); on a
#     P/D rule the 6c branch then records aborted (9) for the client leaving,
#     at any stage. test_reap_request_record.py drives it.
tsh=$(awk '/^teardown_conn_owes_settle\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_teardown_settle.h | tr '\n' ' ')
oar=$(awk '/^teardown_owes_abort_record\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_teardown_settle.h | tr '\n' ' ')
if ! printf '%s' "$tsh" | grep -q 'teardown_owes_abort_record(c)' || \
   ! printf '%s' "$oar" | grep -q 'c->metric_ai_recorded ||' || \
   ! printf '%s' "$oar" | grep -q 'c->metric_response_status != 0 ||' || \
   ! printf '%s' "$oar" | grep -q 'if (c->pd_rule && c->pd_in_flight) { *return 1; *}'; then
  echo "sockproxy_teardown_settle.h: a request with no status, nothing recorded, must be owed its abort record by the teardown rule (a P/D request in flight, or any whole request)"
  fail=1
fi
if ! grep -q 'v->pd_in_flight          = pd_reap_error_phase(pfe->pd_phase) >= 0;' ./sockproxy_http.c || \
   ! printf '%s' "$col" | grep -q 'if ((teardown_owes_completion(&v) || teardown_owes_abort_record(&v) ||' || \
   ! printf '%s' "$col" | grep -q 'if (teardown_owes_abort_record(&v) && sp_end_recorded_before_answer(u->end)) { *u->owes_record = 1; *}'; then
  echo "sockproxy_http.c: the teardown must collect and record a request that ended before any answer (client_abort_before_answer, backend_died)"
  fail=1
fi

# 6f. The ends recorded before any answer are the client leaving and the
#     leg ending (sockproxy_end_cause.h), both status 0.
rba=$(awk '/^sp_end_recorded_before_answer\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_end_cause.h | tr '\n' ' ')
if ! printf '%s' "$rba" | grep -q 'return end == SP_END_CLIENT_NO_ANSWER || end == SP_END_LISTENER_CLOSED || *end == SP_END_BACKEND_DIED;'; then
  echo "sockproxy_end_cause.h: a request is recorded before any answer when the client left, the listener went or the leg ended (sp_end_recorded_before_answer)"
  fail=1
fi

# 6h. The rule's listener going before any answer is the gateway's end
#     (listener_closed, status 0), the request record alone (F-17: no listener
#     goes with requests on it in the product today; test_teardown_settle.c).
eat=$(awk '/^sp_end_cause_at_teardown\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_end_cause.h | tr '\n' ' ')
if ! printf '%s' "$eat" | grep -q 'if (no_answer) { *return listener ? SP_END_LISTENER_CLOSED : SP_END_CLIENT_NO_ANSWER;'; then
  echo "sockproxy_end_cause.h: the listener going before any answer must be the gateway's end (listener_closed)"
  fail=1
fi

# 6e. Off P/D, the request record alone (no lifecycle family pairs with it):
#     owed once the whole request reached the gate, not after the gateway
#     ended a half-close hold; the rule is known per connection from accept;
#     a leg ending before any answer names the engine, so the cascade's
#     teardown does not read it as the client leaving.
if ! printf '%s' "$oar" | grep -q 'return c->req_framed && !c->hold_gw_ended;'; then
  echo "sockproxy_teardown_settle.h: off P/D, the abort record is owed for a whole request only, and not after the gateway ended its hold"
  fail=1
fi
if ! grep -q 'npfe1->pd_rule = ent_pool0->pd_disagg_enabled ? 1 : 0;' ./sockproxy_http.c || \
   ! grep -q 'v->pd_rule               = pfe->pd_rule ? 1 : 0;' ./sockproxy_http.c || \
   ! grep -q 'v->req_framed            = pfe->metric_req_start_ns > 0;' ./sockproxy_http.c || \
   ! grep -q 'v->hold_gw_ended = he == SP_HOLD_END_EXPIRED || he == SP_HOLD_END_RELEASED;' ./sockproxy_http.c; then
  echo "sockproxy_http.c: the teardown view must say whether the rule is P/D, the request whole, and the hold ended by the gateway"
  fail=1
fi
if ! tr '\n' ' ' < ./sockproxy_http.c | grep -q '!cl->pd_rule && *!cl->resp_kernel && cl->odir == 0 && cl->metric_req_start_ns > 0 && *!cl->metric_ai_recorded && cl->metric_response_status == 0) { *cl->end_cause = SP_END_BACKEND_DIED;'; then
  echo "sockproxy_http.c: off P/D, a leg ending before any answer must name the engine, not leave it to read as the client leaving"
  fail=1
fi

# 6g. A connection whose answers go by the kernel (sockmap response pairing)
#     shows userspace no status, so status 0 there is no proof that no answer
#     came: no record is owed before any answer, and a leg ending does not
#     name the engine. The pairing marks the client; the view carries it.
if ! printf '%s' "$oar" | grep -q 'c->has_h2_session || c->resp_kernel) {' || \
   ! grep -q 'v->resp_kernel           = pfe->resp_kernel ? 1 : 0;' ./sockproxy_http.c || \
   ! tr '\n' ' ' < ./sockproxy_http.c | grep -q 'npfe2->peer_map_resp_verdict = 1; *hc_note_accel(pfe, HC_ACCEL_RESP);.*pfe->resp_kernel = 1;'; then
  echo "sockproxy_http.c/sockproxy_teardown_settle.h: a connection whose answers go by the kernel must owe no record before any answer"
  fail=1
fi

# 7. One lifecycle record crosses as two calls, always both. llb_ai_pd_record
#    is called only from sp_pd_record (sockproxy_http.c), and there the next
#    statement is llb_ai_pd_record_extra, with no branch, return or goto
#    between them; every P/D site records through sp_pd_record.
direct=$(grep -n 'llb_ai_pd_record(' ./sockproxy*.c | grep -v '^./sockproxy_ai_gw_stub.c:' \
         | grep -vE ':[0-9]+:[[:space:]]*(\*|/\*|//)' | grep -v '^./sockproxy_http.c:[0-9]*:  llb_ai_pd_record((char \*)model, prefill_ms, decode_ms, kv, error_phase);' || true)
if [ -n "$direct" ]; then
  echo "a P/D lifecycle record made without sp_pd_record (its extra half would be missing):"
  printf '%s\n' "$direct"
  fail=1
fi
helper=$(awk '/^sp_pd_record\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_http.c)
inpd=$(printf '%s\n' "$helper" | grep -c 'llb_ai_pd_record(' || true)
between=$(printf '%s\n' "$helper" | awk '/llb_ai_pd_record\(/ {on = 1; next} /llb_ai_pd_record_extra\(/ {exit} on')
if [ "$inpd" != "1" ] || ! printf '%s\n' "$helper" | grep -q 'llb_ai_pd_record_extra(' || \
   printf '%s' "$between" | grep -qE '\b(if|return|goto|else|switch)\b|;'; then
  echo "sockproxy_http.c: sp_pd_record must call llb_ai_pd_record once and llb_ai_pd_record_extra as its next statement"
  fail=1
fi
nsites=$(grep -c 'sp_pd_record(' ./sockproxy_health.c ./sockproxy_http.c ./sockproxy_pd_sglang.c \
           ./sockproxy_pd_trtllm.c ./sockproxy_pd_vllm.c | awk -F: '{s += $2} END {print s}')
if [ "$nsites" -lt 20 ]; then
  echo "expected at least 20 P/D lifecycle record sites through sp_pd_record; found $nsites"
  fail=1
fi

# 8. The two values the extra half carries have one writer each.
#    a. The first-event stamp is in the client's response framer (cresp_on_body),
#       taken from the observer's first-object report, once per request
#       (pd_first_event_ns == 0) and only while a P/D decode leg is in progress.
#    b. The fallback reason is set once, in pd_vllm.c, on the path that goes on
#       to the decode leg: after the relay verdict and the TRT early exit.
body=$(awk '/^static int cresp_on_body\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_http.c | tr '\n' ' ')
if ! printf '%s' "$body" | grep -q 'if (sp_sse_body(&pfe->cresp_sse, at, len) && pfe->pd_first_event_ns == 0 && *pfe->pd_decode_start_ns > 0 && *(pfe->pd_phase == PD_PHASE_DECODE_SENDING || *pfe->pd_phase == PD_PHASE_DECODE_STREAMING)) {'; then
  echo "sockproxy_http.c: cresp_on_body must stamp the first event once, from the observer, during a P/D decode leg"
  fail=1
fi
stamps=$(grep -c 'pd_first_event_ns = (uint64_t)' ./sockproxy*.c | awk -F: '{s += $2} END {print s}')
if [ "$stamps" != "1" ]; then
  echo "the decode first-event time must have one writer (cresp_on_body); found $stamps"
  fail=1
fi
fbw=$(grep -n 'pd_fallback_reason =' ./sockproxy*.c | grep -v '= 0;' || true)
fbn=$(printf '%s\n' "$fbw" | grep -c . || true)
fbl=$(printf '%s\n' "$fbw" | grep '^./sockproxy_pd_vllm.c:' | cut -d: -f2)
relay=$(grep -n 'pd_prefill_status_verdict(pr_status) == PD_PR_RELAY' ./sockproxy_pd_vllm.c | cut -d: -f1)
early=$(grep -n 'pd_trt_ctx_early_exit_check(l_prefill, l_prefill_len)' ./sockproxy_pd_vllm.c | cut -d: -f1)
if [ "$fbn" != "1" ] || [ -z "$fbl" ] || [ -z "$relay" ] || [ -z "$early" ] || \
   [ "$fbl" -le "$relay" ] || [ "$fbl" -le "$early" ]; then
  echo "sockproxy_pd_vllm.c: the fallback reason must be set once, after the relay verdict and the TRT early exit"
  fail=1
fi

[ "$fail" = "0" ] || exit 1
echo "P/D status sites: OK (captures skip the prefill leg; the framer records a status line split across reads; prefill-leg answers set their status and are recorded; decode completions record their status; a gateway-ended stream is decode/truncated; reaped and dying-leg requests are recorded by cause, a teardown reaper writes the request record; a cut answer is recorded by its end, a P/D client's abort is aborted at any stage, a P/D client leaving at the gate, queued or parked is recorded in both, off P/D a request ended before any answer (the client leaving, the engine ending it) is one request record; each record crosses as both calls; the first event and the fallback reason have one writer each)"
