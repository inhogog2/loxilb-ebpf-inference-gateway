/* A response the client has begun to receive takes no new status line.
 *
 * The gateway writes whole responses of its own: refusals, outages, the
 * reapers' timeouts. Written after a backend's answer has begun, such a
 * status line lands inside that answer's body. What starts an answer is the
 * response framer's view of the bytes relayed to the client: from the first
 * byte of a status line to the last byte of the message. An answer that has
 * begun is ended in-band when it is a stream (an SSE error event naming the
 * code the status line carried) and by the close otherwise. */
#ifndef SOCKPROXY_ANSWER_H
#define SOCKPROXY_ANSWER_H
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* A buffer that is a whole response, as opposed to bytes inside one. */
static inline int sp_answer_is_status_line(const void *buf, size_t len)
{
  return len >= 5 && memcmp(buf, "HTTP/", 5) == 0;
}

/* The framer is inside a message from its first status-line byte
 * (on_message_begin, so a status line split across reads counts) to its
 * last byte (on_message_complete). A framer that could not frame what it was
 * given counts as inside: the bytes it relays may be the middle of an answer.
 * Only a message framed to its end clears that. */
static inline void sp_answer_msg_begin(_Atomic uint8_t *in_msg)
{
  atomic_store_explicit(in_msg, 1, memory_order_relaxed);
}
static inline void sp_answer_msg_done(_Atomic uint8_t *in_msg)
{
  atomic_store_explicit(in_msg, 0, memory_order_relaxed);
}
static inline void sp_answer_framing_lost(_Atomic uint8_t *in_msg)
{
  atomic_store_explicit(in_msg, 1, memory_order_relaxed);
}

/* The code a gateway answer names ({"error":"<code>"...}), copied into out;
 * "gateway_error" when the buffer names none. */
static inline void sp_answer_error_code(const char *buf, size_t len,
                                        char *out, size_t cap)
{
  static const char key[] = "\"error\":\"";
  const size_t klen = sizeof(key) - 1;
  size_t i, j;

  if (cap == 0)
    return;
  for (i = 0; i + klen <= len; i++) {
    if (memcmp(buf + i, key, klen) != 0)
      continue;
    for (j = 0; i + klen + j < len && j + 1 < cap; j++) {
      char ch = buf[i + klen + j];
      if (ch == '"')
        break;
      if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_'))
        goto none;
      out[j] = ch;
    }
    if (j > 0 && i + klen + j < len && buf[i + klen + j] == '"') {
      out[j] = '\0';
      return;
    }
    break;
  }
none:
  snprintf(out, cap, "gateway_error");
}

/* The in-band end of a stream: an SSE error event, sent as the last chunk and
 * the terminator when the answer is chunked. Returns the length written into
 * out, 0 when it does not fit. */
static inline size_t sp_answer_sse_end(const char *code, int chunked,
                                       char *out, size_t cap)
{
  char ev[128];
  int n = snprintf(ev, sizeof(ev), "data: {\"error\":\"%s\"}\n\n", code);
  int m;

  if (n <= 0 || n >= (int)sizeof(ev))
    return 0;
  m = chunked ? snprintf(out, cap, "%x\r\n%s\r\n0\r\n\r\n", n, ev)
              : snprintf(out, cap, "%s", ev);
  return (m > 0 && (size_t)m < cap) ? (size_t)m : 0;
}
#endif
