/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * A client-supplied engine priority does not leave an AI-gateway rule: the
 * tenant band decides the order, and an engine that reorders by its own
 * priority field (vLLM reads the X-Vllm-Priority header first, then the
 * body's top-level `priority`; SGLang reads the body field) would let a
 * sheddable tenant outrank a critical one once admitted. The header is
 * stripped; the body key is renamed in place, at the same length, to a key
 * no engine reads. It is renamed, not set to 0: 0 is vLLM's default but
 * not SGLang's, which ranks an ABSENT priority lowest, so a written 0 would
 * grant a rank the client never had. Renamed, every engine sees exactly
 * what it sees for a request that never carried the field (an engine that
 * refuses unknown fields refused `priority` already).
 *
 * The names are for every includer; the HTTP/1.1 head strip below is
 * compiled for an includer that brought sockproxy_l7hdr_guard.h and
 * sockproxy_h1_hdr.h first (the H1 path and its unit test; the H2 path
 * drops the header from its name-value list, sockproxy_ai_security.c).
 */
#ifndef __SOCKPROXY_NATIVE_PRIO_H__
#define __SOCKPROXY_NATIVE_PRIO_H__

#include <stdint.h>
#include <string.h>

#define SP_NATIVE_PRIO_HDR       "X-Vllm-Priority"
#define SP_NATIVE_PRIO_BODY_KEY  "priority"
#define SP_NATIVE_PRIO_RENAMED   "_gw_prio"   /* the body key's length, 8 */

#ifdef __SOCKPROXY_H1_HDR_H__
/*
 * Strip every X-Vllm-Priority line from the request head in [buf, *len).
 * Returns 1 when at least one was removed (*len shrunk), 0 when the head
 * carried none (the buffer untouched), -1 with the head left as it was when
 * its terminator is not in the buffer.
 */
static inline int
sp_native_prio_strip_head(uint8_t *buf, size_t *len)
{
  size_t cur = *len;

  if (cur < 4 || !memmem(buf, cur, "\r\n\r\n", 4))
    return -1;
  if (!l7h1_strip_header(buf, &cur, SP_NATIVE_PRIO_HDR))
    return -1;
  if (cur == *len)
    return 0;
  *len = cur;
  return 1;
}
#endif /* __SOCKPROXY_H1_HDR_H__ */

#endif /* __SOCKPROXY_NATIVE_PRIO_H__ */
