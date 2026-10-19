#!/bin/sh
# Mutation tests for check_local_answers.sh: each rule is broken once in a
# scratch copy of the sources, and the check must fail with that rule's
# message. The unmutated copy must pass. Exit 1 when a mutation survives.
#
#   sh check_local_answers_mutations.sh    (from anywhere; needs python3)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

survived=0
n=0

fresh() {
  rm -rf "$work/src"
  mkdir "$work/src"
  cp "$here"/sockproxy*.c "$here"/sockproxy_resp_note.h "$here/check_local_answers.sh" "$work/src/"
}

# mut FILE OLD NEW: replace the one occurrence of OLD (it must exist once).
mut() {
  python3 - "$work/src/$1" "$2" "$3" <<'EOF'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
if s.count(old) != 1:
    sys.exit("mutation anchor found %d times in %s: %r" % (s.count(old), p, old))
open(p, "w").write(s.replace(old, new))
EOF
}

# expect NAME MESSAGE: the check fails, and says MESSAGE.
expect() {
  n=$((n + 1))
  if out=$(sh "$work/src/check_local_answers.sh" "$work/src" 2>&1); then
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
sh "$work/src/check_local_answers.sh" "$work/src" >/dev/null ||
  { echo "the unmutated sources fail the check"; exit 1; }

# Rule 1: a local answer that records nothing.
fresh
mut sockproxy_ep.c 'sp_send_local_refusal(pfe, AI_GW_STAGE_ROUTE, 503, "model_unavailable",' 'proxy_send_local_response(pfe,'
expect "rule 1: a route refusal sent raw" "sockproxy_ep.c:proxy_setup_ep__:proxy_send_local_response:-"

fresh
mut sockproxy_h2.c 'h2_send_local_refusal(pfe, stream, AI_GW_STAGE_ROUTE, 503, lookup_model,' 'proxy_h2_send_ai_deny(pfe, stream, 503, 0, 0,'
expect "rule 1: an HTTP/2 route refusal sent raw" "proxy_h2_send_ai_deny:model_unavailable"

fresh
mut sockproxy_http.c '  proxy_record_local_deny(pfe, stage, status, code);
  return proxy_send_local_response(pfe, buf, len);' '  return proxy_send_local_response(pfe, buf, len);'
expect "rule 1: the refusal sender drops its deny record" "sp_send_local_refusal must record: proxy_record_local_deny(pfe, stage"

fresh
mut sockproxy_http.c '  proxy_record_local_completion(pfe, status);
  return proxy_send_local_response(pfe, buf, len);' '  proxy_note_local_answer(pfe, status);
  return proxy_send_local_response(pfe, buf, len);'
expect "rule 1: the outage sender drops its completion" "sp_send_local_outage must record: proxy_record_local_completion(pfe, status)"

fresh
mut sockproxy_h2.c '  stream->metric_response_status = status_code;
' ''
expect "rule 1: the HTTP/2 outage sender drops its status" "h2_send_local_outage must record"

fresh
mut sockproxy_h2.c '  ai_gw_record_local_deny(stage, stream->request_id, notify_worker_id(),' '  ai_gw_record_local_xxxx(stage, stream->request_id, notify_worker_id(),'
expect "rule 1: the HTTP/2 deny record drops its export" "h2_record_local_deny must record: ai_gw_record_local_deny(stage"

fresh
mut sockproxy_health.c '    proxy_record_local_completion(pfe, 502);' '    ;'
expect "rule 1: the reaper drops a P/D timeout's completion" "sp_reap_record must record: proxy_record_local_completion(pfe, 502)"

fresh
mut sockproxy_l7policy.c '    proxy_record_local_deny(pfe, AI_GW_STAGE_ROUTE, code, "l7_policy_reject");' ''
expect "rule 1: an L7-policy REJECT drops its deny record" "l7_send_reject must record: proxy_record_local_deny(pfe, AI_GW_STAGE_ROUTE, code"

fresh
mut sockproxy_h2.c '      l7_stream->metric_response_status = status_code;' '      (void)0;'
expect "rule 1: an HTTP/2 L7 REDIRECT drops its status" "proxy_h2_send_l7_synthetic must record: l7_stream->metric_response_status = status_code"

fresh
mut sockproxy_http.c 'else shutdown(pfe->fd,SHUT_RDWR);' 'else proxy_send_local_response_and_shutdown(pfe,response,0);'
expect "rule 1: a second answer under one allowlist key" "allowlist entry covers 1 call(s), found 2"

fresh
mut sockproxy_http.c 'if (proxy_send_local_response(pfe, response, sizeof(response) - 1) != 0) {' 'if (sp_send_raw(pfe, response, sizeof(response) - 1) != 0) {'
expect "rule 1: an allowlist entry that matches nothing" "allowlist entry covers 1 call(s), found 0"

# Rule 1b: a raw write of a built response records first.
fresh
mut sockproxy_http.c '      proxy_record_local_completion(client, 502);
' ''
expect "rule 1b: the connect-failure 502 written raw without its record" "sockproxy_http.c:proxy_backend_connect_event:raw:lb_502"

fresh
mut sockproxy_pd_sglang.c '  proxy_record_local_completion(client_pfe, 502);
' ''
expect "rule 1b: a SGLang pair abort written raw without its record" "sockproxy_pd_sglang.c:pd_sg_abort_pair:raw:pd_sg_err"

fresh
mut sockproxy_pd_vllm.c '    proxy_record_local_completion(client_pfe, 503);
' ''
expect "rule 1b: the vLLM prefill failover 503 written raw without its record" "sockproxy_pd_vllm.c:pd_retry_prefill:raw:pd_prefill_err"

fresh
mut sockproxy_http.c '          proxy_note_local_answer(pfe, 403);
          proxy_record_local_deny(pfe, AI_GW_STAGE_SECURITY, 403, "llamafirewall_block");
' ''
expect "rule 1b: the LlamaFirewall block written raw without its record" "sockproxy_http.c:handle_on_message_complete:raw:block_response"

fresh
mut sockproxy_http.c '              send(pfe->fd, smuggle_400, sizeof(smuggle_400) - 1, MSG_NOSIGNAL);' '              send(pfe->fd, smuggle_400, sizeof(smuggle_400) - 1, MSG_NOSIGNAL);
              send(pfe->fd, smuggle_400, 0, MSG_NOSIGNAL);'
expect "rule 1b: a second raw write under one allowlist key" "allowlist entry covers 1 call(s), found 2"

# Rule 2: a local answer never samples TTFB.
fresh
mut sockproxy_http.c 'return proxy_note_response_(pfe, status, 0);' 'return proxy_note_response_(pfe, status, 1);'
expect "rule 2: the local wrapper samples TTFB" "proxy_note_local_answer must be proxy_note_response_(pfe, status, 0)"

fresh
mut sockproxy_http.c 'if ((take & RESP_NOTE_TTFB) && pfe->metric_req_start_ns > 0) {' 'if (pfe->metric_req_start_ns > 0) {'
expect "rule 2: the writer samples whatever the caller asked" "must sample TTFB only under (take & RESP_NOTE_TTFB)"

fresh
mut sockproxy_resp_note.h 'return RESP_NOTE_COUNT | (sample_ttfb ? RESP_NOTE_TTFB : 0);' 'return RESP_NOTE_COUNT | RESP_NOTE_TTFB;'
expect "rule 2: the latch hands every caller a TTFB sample" "resp_note_take must claim, then take TTFB only when sample_ttfb"

fresh
mut sockproxy_http.c 'proxy_note_local_answer(proxy_fd_ent_t *pfe, uint16_t status)
{' 'proxy_note_local_answer(proxy_fd_ent_t *pfe, uint16_t status)
{
  atomic_fetch_add(&global_stats.http_status_5xx, 1);'
expect "rule 2: a wrapper writes the record itself" "a wrapper writes the record itself"

# Rule 3: every refusal names its stage.
fresh
mut sockproxy_http.c '  proxy_record_local_deny(pfe, AI_GW_STAGE_FRAMING, status, code);
  sp_h1_send_admit_deny(pfe, status, 0, 0, code, msg);' '  sp_h1_send_admit_deny(pfe, status, 0, 0, code, msg);'
expect "rule 3: a framing 413 without its deny record" "sp_h1_send_framing_deny answers through sp_h1_send_admit_deny without the refusal's deny record"

fresh
mut sockproxy_http.c '  ai_gw_record_capacity_deny(proxy_request_id(pfe), notify_worker_id(),
                             svc_ident, proxy_effective_model(pfe),
                             pfe->tenant_id, pfe->auth_key_id,
                             pfe->auth_user_id, status, code,' '  ai_gw_record_capacity_xxxx(proxy_request_id(pfe), notify_worker_id(),
                             svc_ident, proxy_effective_model(pfe),
                             pfe->tenant_id, pfe->auth_key_id,
                             pfe->auth_user_id, status, code,'
expect "rule 3: an HTTP/1.1 capacity refusal without its deny record" "through sp_h1_send_capacity_deny without the refusal's deny record"

fresh
mut sockproxy_ep.c 'AI_GW_STAGE_ROUTE, 503, "no_rules"' 'AI_GW_STAGE_NONE, 503, "no_rules"'
expect "rule 3: a refusal recorded at stage NONE" "a local deny record without its AI_GW_STAGE_*"

fresh
mut sockproxy_ep.c 'AI_GW_STAGE_CAPACITY, 429, "pd_overloaded"' '0, 429, "pd_overloaded"'
expect "rule 3: a refusal recorded with a bare stage number" "a local deny record without its AI_GW_STAGE_*"

fresh
mut sockproxy_health.c 'ai_gw_record_capacity_deny(proxy_request_id(pfe), notify_worker_id(),' 'ai_gw_record_capacity_xxxx(proxy_request_id(pfe), notify_worker_id(),'
expect "rule 3: the reaper's capacity refusal without its deny record" "sp_reap_fc_format must take the queued refusal's deny record"

# Rule 4: the 100 Continue never records.
fresh
mut sockproxy_http.c '  pfe->json_stream_continue_sent = 1;' '  pfe->json_stream_continue_sent = 1;
  proxy_note_local_answer(pfe, 100);'
expect "rule 4: the 100 Continue takes the latch" "proxy_send_local_100_continue records"

[ "$survived" = "0" ] || { echo "check_local_answers.sh: a mutation survived"; exit 1; }
echo "check_local_answers.sh mutations: $n/$n killed"
