/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __SOCKPROXY_PD_RECEIPT_H__
#define __SOCKPROXY_PD_RECEIPT_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

/* The P/D request-id receipt, ___prefill_addr_<ep>___decode_addr_<ep>_<uuid>,
 * is stamped once at admission (generate_vllm_request_id) and names the two
 * endpoints selected then. Two later events change an endpoint of the request:
 * the prefill retry (sockproxy_pd_vllm.c, pd_retry_prefill) and the connect-time
 * decode fallback (pd_connect_decode). Each re-renders its half here, in the
 * request about to be written and in the gateway's own copies, so that every
 * consumer of the receipt (the id the decode engine echoes to the client, the
 * completion/audit records, receipt_probe on the GPU harness) names the
 * endpoint that served. Header-only so the standalone request-id unit test
 * can include it without the proxy's build. */

enum pd_receipt_half {
  PD_RECEIPT_PREFILL = 0,   /* the <ep> after ___prefill_addr_ */
  PD_RECEIPT_DECODE  = 1    /* the <ep> after ___decode_addr_, before _<uuid> */
};

/* Rewrite one half of the receipt in place. buf/len describe either a full
 * HTTP request (the search is bounded to its header block) or a bare id (no
 * CRLF: the whole buffer is the search range, as for the pfe's own copies).
 * Returns 0 when the half was rewritten, 1 when it already named n_addr (not
 * a byte changed), -1 when there is no receipt or the result would not fit
 * cap (the buffer is untouched in both of those cases). The prefill half ends
 * at ___decode_addr_; the decode half ends at the last '_' before the end of
 * the id's line, the one that introduces the uuid tail. */
static inline int
pd_receipt_rewrite(uint8_t *buf, size_t *len, size_t cap, int half,
                   const char *n_addr)
{
  uint8_t *he = memmem(buf, *len, "\r\n\r\n", 4);
  size_t hdr_len = he ? (size_t)(he + 4 - buf) : *len;
  char *hdr_end = (char *)buf + hdr_len;
  char *tag = hdr_len ? memmem(buf, hdr_len, "___prefill_addr_", 16) : NULL;
  char *p_start = tag ? tag + 16 : NULL;
  char *d_tag = p_start ? memmem(p_start, (size_t)(hdr_end - p_start),
                                 "___decode_addr_", 15) : NULL;
  char *a_start, *a_end;
  if (!p_start || !d_tag || !n_addr) return -1;

  if (half == PD_RECEIPT_PREFILL) {
    a_start = p_start;
    a_end = d_tag;
  } else {
    char *line_end, *p;
    a_start = d_tag + 15;
    line_end = memmem(a_start, (size_t)(hdr_end - a_start), "\r\n", 2);
    if (!line_end) line_end = hdr_end;
    a_end = NULL;
    for (p = line_end; p > a_start; ) {
      p--;
      if (*p == '_') { a_end = p; break; }
    }
    if (!a_end) return -1;
  }

  int n_len = (int)strlen(n_addr);
  int o_len = (int)(a_end - a_start);
  int shift = n_len - o_len;
  if (n_len <= 0) return -1;
  if (shift == 0 && memcmp(a_start, n_addr, (size_t)n_len) == 0) return 1;
  if (*len + (size_t)(shift > 0 ? shift : 0) > cap) return -1;
  if (shift != 0) {
    memmove(a_end + shift, a_end, *len - (size_t)(a_end - (char *)buf));
    *len = (size_t)((ssize_t)*len + shift);
  }
  memcpy(a_start, n_addr, (size_t)n_len);
  return 0;
}

/* The same for a NUL-terminated copy of the id held in a fixed buffer of
 * `cap` bytes (pfe->vllm_request_id, pfe->resp_request_id). An empty string
 * has no receipt and returns -1. */
static inline int
pd_receipt_rewrite_str(char *id, size_t cap, int half, const char *n_addr)
{
  size_t len = strnlen(id, cap);
  int rc;
  if (len == 0 || len >= cap) return -1;
  rc = pd_receipt_rewrite((uint8_t *)id, &len, cap - 1, half, n_addr);
  if (rc == 0) id[len] = '\0';
  return rc;
}

#endif /* __SOCKPROXY_PD_RECEIPT_H__ */
