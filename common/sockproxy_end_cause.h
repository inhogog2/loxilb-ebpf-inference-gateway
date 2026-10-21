/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause)
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_end_cause.h — why an answer ended before its client had all of it.
 *
 * A request whose answer began and was cut is aborted, not completed: the
 * client did not receive a complete response. So is a request that ended
 * before any answer, the client leaving, the rule's listener going away or,
 * off P/D, the backend leg ending (its record carries status 0: no status was
 * sent;
 * sockproxy_teardown_settle.h says which requests are owed it). Its request record (llb_ai_record_request) names the end in
 * error_code; "" is an answer that ended whole, or a request a status already
 * accounts for. Each code has one cause:
 *
 *   client   the client left (a reset, a hangup, a failed write) or stopped
 *            reading. Traffic, not an error.
 *   engine   the backend leg ended under the answer.
 *   gateway  the gateway cut it: a policy cap, a silent engine the reaper
 *            ended, the rule's listener closed.
 *
 * The gateway (ai_metrics.go) maps each code to outcome="aborted" with its
 * cause, and anything it does not know to completed; the two tables are held
 * in lockstep by scripts/check-source-invariants.sh. The graceful-[DONE]
 * sweep is not here: its client got a clean end (the lifecycle record and
 * pd_terminator_synthesized carry the truncation).
 *
 * Pure header: integers in, strings out.
 */
#ifndef __SOCKPROXY_END_CAUSE_H__
#define __SOCKPROXY_END_CAUSE_H__

enum sp_end_cause {
  SP_END_NONE = 0,        /* ended whole, or unknown yet */
  SP_END_CLIENT_GONE,     /* the client left with the answer open */
  SP_END_CLIENT_STALL,    /* the client stopped reading ([SSE_STALL]) */
  SP_END_BACKEND_DIED,    /* the leg the answer came on (or was to come on) ended under it */
  SP_END_DURATION_CAP,    /* [SSE_CAP]: the stream's duration cap */
  SP_END_STREAM_TIMEOUT,  /* ERR-01: the decode engine went silent */
  SP_END_IDLE_TIMEOUT,    /* the idle reaper */
  SP_END_LISTENER_CLOSED, /* the rule's listener went away (answer open, or none yet) */
  SP_END_CLIENT_NO_ANSWER, /* the client left a request before any answer */
  SP_END_CAUSES
};

typedef struct sp_end_code {
  const char *code;       /* the request record's error_code */
  const char *cause;      /* client, engine or gateway */
} sp_end_code_t;

static const sp_end_code_t sp_end_codes[SP_END_CAUSES] = {
  [SP_END_NONE]            = { "", "" },
  [SP_END_CLIENT_GONE]     = { "client_abort", "client" },
  [SP_END_CLIENT_STALL]    = { "client_stall", "client" },
  [SP_END_BACKEND_DIED]    = { "backend_died", "engine" },
  [SP_END_DURATION_CAP]    = { "max_stream_duration_exceeded", "gateway" },
  [SP_END_STREAM_TIMEOUT]  = { "pd_decode_stream_timeout", "gateway" },
  [SP_END_IDLE_TIMEOUT]    = { "pd_idle_timeout", "gateway" },
  [SP_END_LISTENER_CLOSED] = { "listener_closed", "gateway" },
  [SP_END_CLIENT_NO_ANSWER] = { "client_abort_before_answer", "client" },
};

static inline const char *
sp_end_code(int end)
{
  return (end > SP_END_NONE && end < SP_END_CAUSES) ? sp_end_codes[end].code : "";
}

/* The end a connection's teardown records for its last request: the cause
 * already recorded when the answer ended (a reaper's cut, a stall, the leg
 * dying under it), else, for an answer still open (HTTP/1.1: the client's
 * response framer is inside it), the client leaving, or the gateway when the
 * whole listener is going. A request the teardown rule owes before any
 * answer (no status, `no_answer`: a P/D request in its prefill or before the
 * decode leg's first byte, or any whole request on a rule that is not P/D) is
 * the client leaving before it, or the gateway when the whole listener is
 * going (on a P/D rule the lifecycle's aborted/gateway, 10, pairs with it). An
 * answer that ended whole, or a request a status accounts for, has none. */
static inline int
sp_end_cause_at_teardown(int recorded, int listener, int answer_open,
                         int no_answer)
{
  if (recorded > SP_END_NONE && recorded < SP_END_CAUSES) {
    return recorded;
  }
  if (answer_open) {
    return listener ? SP_END_LISTENER_CLOSED : SP_END_CLIENT_GONE;
  }
  if (no_answer) {
    return listener ? SP_END_LISTENER_CLOSED : SP_END_CLIENT_NO_ANSWER;
  }
  return SP_END_NONE;
}

/* The ends a request is recorded by before any answer, status 0: the client
 * leaving, the rule's listener going away, or the leg the answer was to come
 * on ending (off P/D; a P/D leg that ends before an answer is answered by the
 * gateway with its status). */
static inline int
sp_end_recorded_before_answer(int end)
{
  return end == SP_END_CLIENT_NO_ANSWER || end == SP_END_LISTENER_CLOSED ||
         end == SP_END_BACKEND_DIED;
}

/* The client left, at whatever stage: the P/D lifecycle's aborted (9). A
 * stalled client is recorded by its reaper, not at the teardown. */
static inline int
sp_end_client_left(int end)
{
  return end == SP_END_CLIENT_GONE || end == SP_END_CLIENT_NO_ANSWER;
}

#endif /* __SOCKPROXY_END_CAUSE_H__ */
