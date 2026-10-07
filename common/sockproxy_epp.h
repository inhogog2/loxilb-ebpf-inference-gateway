/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Endpoint Picker (EPP) request stage — the C half of the C <-> Go boundary.
 *
 * A fullproxy rule with epp_mode != EPP_MODE_OFF asks a Gateway API
 * Inference Extension endpoint picker where each request goes. The worker
 * thread hands the buffered request to Go (llb_epp_submit, returns at once
 * with a stream id), parks the client fd, and goes on serving other
 * connections. Go runs the ext_proc exchange and, from whichever thread,
 * hands the decision back (proxy_epp_complete): it is copied into a side
 * table keyed by the stream id and the fd's owner worker is woken through
 * the MPSC resume ring, the path the prefill and capacity queues use. The
 * owner worker re-drives the request (pd_resume_parked -> proxy_setup_ep__
 * -> epp_stage), takes the decision out of the table and routes on it.
 *
 * Every request that received a stream id ends with exactly one
 * llb_epp_resp_event of kind EPP_EV_RESP_EOS or EPP_EV_ABORT, whichever
 * way it ends, or the EPP's in-flight count never drops.
 *
 * Interface spec 4.3 of the Phase 1 document; mirrored by
 * pkg/loxinet/ai_epp_dp.go.
 */
#ifndef __SOCKPROXY_EPP_H__
#define __SOCKPROXY_EPP_H__

#include <stdint.h>
#include <stddef.h>

#define EPP_MAX_CANDS 4
#define EPP_CAND_LEN  64

/* epp_result.status */
enum epp_res_status {
  EPP_RES_OK        = 0,  /* cands[] (possibly none) + mutations apply */
  EPP_RES_IMMEDIATE = 1,  /* the EPP answered the client: imm_* go back as is */
  EPP_RES_ERROR     = 2,  /* deadline, gRPC error, NOT_SERVING: epp_mode decides */
};

/* llb_epp_resp_event.kind */
enum epp_resp_event {
  EPP_EV_RESP_HEADERS = 1,  /* backend response headers + status + served ip:port */
  EPP_EV_RESP_EOS     = 2,  /* the response ended normally */
  EPP_EV_ABORT        = 3,  /* client or backend went away; nothing more comes */
};

/* The decision, as Go hands it over. The buffers belong to the caller for
 * the duration of proxy_epp_complete only; C copies what it keeps. */
struct epp_result {
  int      status;                 /* enum epp_res_status */
  int      ncands;                 /* 0..EPP_MAX_CANDS */
  char     cands[EPP_MAX_CANDS][EPP_CAND_LEN];  /* "ip:port", in the EPP's order */
  int      imm_code;               /* status == EPP_RES_IMMEDIATE: HTTP code */
  const char *imm_body;  int imm_body_len;
  const char *hdr_set;   int hdr_set_len;   /* "k: v\r\n" repeated; for an
                                              immediate answer: its headers */
  const char *hdr_del;   int hdr_del_len;   /* "k\r\n" repeated */
  const char *new_body;  int new_body_len;  /* 0 = the body is unchanged */
};

/* C -> Go, exported by pkg/loxinet/ai_epp_dp.go (weak stubs in
 * sockproxy_ai_gw_stub.c for C-only links). Called on a worker thread;
 * returns at once. Go copies the buffers before returning and never
 * writes them (cgo exports cannot spell const, as every llb_* export).
 * Returns the stream id (> 0) when accepted, 0 when refused (no such rule,
 * queue full): the caller applies the rule's failure mode right away. */
extern uint64_t llb_epp_submit(uint32_t svc_id, void *ns, int fd, uint64_t gen,
                               char *req_hdrs, int req_hdrs_len,
                               char *body, int body_len,
                               char *subset, int subset_len);

/* C -> Go, exported by pkg/loxinet/ai_epp_dp.go. The response phase of a
 * request that received a stream id. Must not block: Go queues the work. */
extern void llb_epp_resp_event(uint64_t sid, int kind, int http_status,
                               char *resp_hdrs, int resp_hdrs_len,
                               char *served, int served_len);

/* Go -> C, from any thread. Stores the decision for (fd, gen, sid) and wakes
 * the fd's owner worker. 0 = stored and the wake queued; -1 = bad argument;
 * -2 = the fd is no longer the registration the submit saw (dropped);
 * -3 = stored but the worker could not be woken (the reaper collects it). */
int proxy_epp_complete(void *ns, int fd, uint64_t gen, uint64_t sid,
                       const struct epp_result *r);

/* The side table (sockproxy_epp.c). */
typedef struct epp_pending epp_pending_t;
/* Take the decision stored for sid out of the table. NULL when none is
 * there yet; an entry whose fd/gen do not match is dropped and NULL
 * returned. The caller owns the result until epp_pending_free. */
epp_pending_t *epp_pending_take(uint64_t sid, int fd, uint64_t gen);
const struct epp_result *epp_pending_result(const epp_pending_t *p);
void epp_pending_free(epp_pending_t *p);
/* Drop and free the entry for sid, if any (the request went away). */
void epp_pending_drop(uint64_t sid);
int  epp_pending_count(void);
/* Free entries older than max_age_ns (orphans whose request died between
 * the completion and the resume). Returns how many were freed. */
int  epp_pending_reap(uint64_t max_age_ns);

/* Monotonic nanoseconds. */
uint64_t epp_now_ns(void);

/* A 4xx/5xx answered by the proxy on behalf of the EPP stage, or the EPP's
 * own immediate response, written to the client with Connection: close and
 * lb_err_body_sent set so the selection error path closes silently. */
struct proxy_fd_ent;
void epp_send_error(struct proxy_fd_ent *pfe, int status, const char *code,
                    const char *detail);
void epp_send_immediate(struct proxy_fd_ent *pfe, const struct epp_result *r);

/* The EPP bookkeeping of a connection ends: report an abort for a stream
 * that never reached its end-of-stream report and drop any decision still
 * waiting. Called when the request slot is reused and when the client fd
 * is released. */
void epp_request_end(struct proxy_fd_ent *pfe);

#endif /* __SOCKPROXY_EPP_H__ */
