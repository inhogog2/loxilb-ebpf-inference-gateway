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

# 1c. The writer is the only one of the class counters and the TTFB sample,
#     so no path can record a response around it (or twice).
h_from=$(grep -n '^proxy_note_response_(' ./sockproxy_http.c | head -1 | cut -d: -f1)
h_to=$(awk -v f="${h_from:-0}" 'NR > f && /^}/ {print NR; exit}' ./sockproxy_http.c)
if [ -z "$h_from" ] || ! sed -n "${h_from},${h_to}p" ./sockproxy_http.c | grep -q 'resp_note_take(&pfe->metric_resp_noted'; then
  echo "sockproxy_http.c: proxy_note_response_ must take the once-per-request latch (resp_note_take)"
  fail=1
fi
outside=$(grep -nE 'global_stats\.http_(responses_total|status_[1-5]xx)|record_latency_sample\(' ./*.c \
            | grep -v '^\./sockproxy_metrics\.c:' | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(\*|/\*|//)' \
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
  echo "sockproxy_pd_vllm.c: pd_initiate_decode must call pd_prefill_status_verdict(pr_status, ...) before the transfer-params extract"
  fail=1
fi
relay=$(awk '/^pd_prefill_reject_relay\(/ {on = 1} on {print} on && /^}/ {exit}' ./sockproxy_pd_vllm.c)
if ! printf '%s\n' "$relay" | grep -q 'proxy_note_client_response(client_pfe'; then
  echo "sockproxy_pd_vllm.c: pd_prefill_reject_relay must record the response (proxy_note_client_response)"
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
#    only completion allowed a literal success (0) is the SSE [DONE] one, whose
#    stream exists only for a 2xx event-stream; the non-SSE completions (the
#    Content-Length/chunked one and the decode-backend EOF one) take
#    pd_decode_error_phase(metric_response_status).
lit0=$(awk '/llb_ai_pd_record\(/ {buf = $0; while (buf !~ /\);/ && (getline nl) > 0) buf = buf " " nl;
            if (buf ~ /,[ \t]*0\);/ && buf !~ /sse_model/) print NR": "buf}' ./sockproxy_http.c)
if [ -n "$lit0" ]; then
  echo "sockproxy_http.c: a P/D completion records a literal success (0) whatever its status; use pd_decode_error_phase():"
  printf '%s\n' "$lit0"
  fail=1
fi
n=$(grep -c 'pd_decode_error_phase([a-z_]*->metric_response_status)' ./sockproxy_http.c || true)
if [ "$n" != "2" ]; then
  echo "sockproxy_http.c: expected the two non-SSE decode completions to use pd_decode_error_phase(...->metric_response_status); found $n"
  fail=1
fi

# 5b. A stream the gateway ended is not a success. In sockproxy_health.c no
#     P/D record is a literal success (0): the graceful-[DONE] sweep, the one
#     completion there, records decode/truncated (8), the engine having gone
#     silent and the gateway having written the terminator.
lit0h=$(awk '/llb_ai_pd_record\(/ {buf = $0; while (buf !~ /\);/ && (getline nl) > 0) buf = buf " " nl;
             if (buf ~ /,[ \t]*0\);/) print NR": "buf}' ./sockproxy_health.c)
if [ -n "$lit0h" ]; then
  echo "sockproxy_health.c: a reaper records a literal success (0) for an answer the gateway ended:"
  printf '%s\n' "$lit0h"
  fail=1
fi
g=$(awk '/\[PD_GRACEFUL_DONE\]/ {on = 1} on && /pd_reap_respond\(/ {exit} on' ./sockproxy_health.c \
    | tr '\n' ' ' | grep -c 'llb_ai_pd_record([^;]*8 /\*decode truncated\*/);' || true)
if [ "$g" != "1" ]; then
  echo "sockproxy_health.c: the graceful-[DONE] sweep must record decode/truncated (8) once; found $g"
  fail=1
fi

# 6. A P/D request a reaper or a dying decode leg ends has a lifecycle record.
#    The stream timeout (ERR-01), the generic idle reaper, the duration cap and
#    the stalled-client abort each call pd_reap_lifecycle right before handing
#    the connection to pd_reap_respond, and the decode EOF mid-stream records
#    decode/error and moves the request to ERROR before the sweep can see it.
for kind in SP_REAP_PD_STREAM_TIMEOUT SP_REAP_PD_IDLE_TIMEOUT SP_REAP_SSE_CAP SP_REAP_SSE_STALL; do
  ok=$(grep -B3 "pd_reap_respond(pfe, $kind);" ./sockproxy_health.c | grep -c 'pd_reap_lifecycle(pfe, ' || true)
  if [ "$ok" != "1" ]; then
    echo "sockproxy_health.c: the $kind reap is not preceded by its lifecycle record (pd_reap_lifecycle)"
    fail=1
  fi
done
eofb=$(awk '/decode backend EOF mid-stream/ {on = 1} on && /pd_sg_close_drain\(/ {exit} on' ./sockproxy_http.c | tr '\n' ' ')
if ! printf '%s' "$eofb" | grep -q 'llb_ai_pd_record([^;]*2 /\*decode error\*/);.*pd_phase = PD_PHASE_ERROR;'; then
  echo "sockproxy_http.c: the decode EOF mid-stream must record decode/error and move the request to ERROR"
  fail=1
fi

# 6b. The stream the sweep ended cleanly has its request record: the reaper's
#     record for that kind writes the completion with the status the client
#     received (the [DONE] scanner, which writes it otherwise, never ran).
gd=$(awk '/^sp_reap_record\(/ {on = 1} on && /^}/ {exit} on' ./sockproxy_health.c | tr '\n' ' ' \
     | grep -c 'case SP_REAP_PD_GRACEFUL_DONE:[^}]*proxy_record_reaped_stream(pfe);' || true)
if [ "$gd" != "1" ]; then
  echo "sockproxy_health.c: sp_reap_record must write the request record of a stream the sweep ended (proxy_record_reaped_stream)"
  fail=1
fi

[ "$fail" = "0" ] || exit 1
echo "P/D status sites: OK (captures skip the prefill leg; prefill-leg answers set their status and are recorded; decode completions record their status; a gateway-ended stream is decode/truncated; reaped and dying-leg requests are recorded)"
