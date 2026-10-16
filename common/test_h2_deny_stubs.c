/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_deny_stubs.c - the rest of the gateway, for test_h2_deny_free.
 *
 * proxy_h2_forward_to_backend links most of the gateway. The functions the
 * test's four cases pass through get a stub that does nothing and answers 0
 * (no identity, no binding, nothing to record: the cases do not depend on
 * them). Every other one has not been reached by these cases and aborts with
 * its name, so a case that starts to reach one fails loudly instead of
 * running on a guess. No header here on purpose: these are link stand-ins,
 * called only through the product's own prototypes, and the ones that do
 * run return int, void or a pointer, where 0 in the return register is the
 * same answer for each.
 */
int puts(const char *s);
void abort(void);

#define REACHED(name) long name(void) { return 0; }
#define NOT_REACHED(name) \
  long name(void) { puts("test_h2_deny_stubs: " #name " reached"); abort(); return 0; }

/* The header guard: every header value of the test requests is valid. */
int l7_hdr_value_valid(const char *value) { (void)value; return 1; }

/* The lookup host: the authority without its port, as the product does. */
void
strip_port_from_hostname(const char *in, char *out, unsigned long size)
{
  unsigned long i = 0;

  if (!size)
    return;
  for (; in && in[i] && in[i] != ':' && i + 1 < size; i++)
    out[i] = in[i];
  out[i] = 0;
}

REACHED(ai_gw_class_on)
REACHED(ai_gw_mint_request_id)
REACHED(ai_gw_netid_bound)
REACHED(ai_gw_netid_fwd_any)
REACHED(ai_gw_netid_ifmatch)
REACHED(ai_gw_record_capacity_deny)
REACHED(ai_gw_svc_ident)
NOT_REACHED(ai_security_copy_api_key)
NOT_REACHED(ai_security_h2_upstream_hygiene)
NOT_REACHED(ai_security_should_strip_api_key)
NOT_REACHED(chwbl_dec_runtime)
NOT_REACHED(chwbl_hash_and_select_runtime)
NOT_REACHED(chwbl_inc_runtime)
NOT_REACHED(circuit_breaker_candidate)
NOT_REACHED(circuit_breaker_record_failure)
NOT_REACHED(circuit_breaker_record_success)
NOT_REACHED(compute_prefix_hash)
NOT_REACHED(extract_llm_prefix)
NOT_REACHED(extract_model_field)
NOT_REACHED(get_conversation_mapping)
REACHED(get_timestamp_ns)
NOT_REACHED(is_endpoint_healthy)
NOT_REACHED(json_null_top_key)
NOT_REACHED(l7_apply_req_filters)
NOT_REACHED(l7_cookie_node_match)
NOT_REACHED(l7_cookie_node_token_for_ep)
NOT_REACHED(l7_cookie_persist_active)
NOT_REACHED(l7_cookie_read_presented)
NOT_REACHED(l7_hsts_synthesize)
NOT_REACHED(l7_mcp_header_used)
NOT_REACHED(llb_ai_record_request)
REACHED(llb_ai_record_unmetered)
NOT_REACHED(llb_ai_record_usage_missing)
REACHED(llb_ai_token_quota_consume)
NOT_REACHED(llhttp_init)
NOT_REACHED(llhttp_settings_init)
REACHED(notify_worker_id)
NOT_REACHED(pd_dialect_plain)
NOT_REACHED(pfe_alloc)
REACHED(pfe_ent_accouting)
NOT_REACHED(pfe_recycle)
NOT_REACHED(proxy_build_ppv2_v4)
NOT_REACHED(proxy_conn_list_add)
NOT_REACHED(proxy_conn_list_del)
NOT_REACHED(proxy_leg_tls_stale)
REACHED(proxy_lock_trace_acquire)
REACHED(proxy_lock_trace_init)
REACHED(proxy_lock_trace_release)
REACHED(proxy_lock_trace_state)
REACHED(proxy_mono_ms)
NOT_REACHED(proxy_notify_add_fd)
NOT_REACHED(proxy_notify_add_fd_pinned)
NOT_REACHED(proxy_setup_ep_connect)
NOT_REACHED(select_healthy_endpoint)
REACHED(sp_fc_normal_eligible)
REACHED(sp_fc_route_eligible)
NOT_REACHED(sp_notify_arm)
REACHED(sp_resv_default_tokens_of)
REACHED(sp_resv_objective_strict_of)
NOT_REACHED(store_conversation_endpoint)
