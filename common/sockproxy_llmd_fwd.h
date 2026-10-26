/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * The objective and the fairness identity that leave the gateway for the
 * backend when a rule runs with fc_llmd_headers on. The includer provides
 * log_error and, before this file, sockproxy_l7hdr_guard.h and
 * sockproxy_h1_hdr.h; the proxy and the unit test run the same code.
 */
#ifndef __SOCKPROXY_LLMD_FWD_H__
#define __SOCKPROXY_LLMD_FWD_H__

#include "sockproxy_llmd.h"

/*
 * A client's copy of the objective and of the fairness identity (the new and
 * the deprecated names) is removed from the request head in [buf, *len),
 * whatever the request is; with `write` the resolved values are written in
 * their place, but not on a chunked request (an insertion needs room, and
 * the bytes after the head must not move on one). `objective` is the class
 * the admission gate resolved; `fairness` is the authenticated tenant, and a
 * request without one gets none. Returns 0, or -1 with the head left as it
 * was when its terminator is not in the buffer.
 */
static inline int
sp_llmd_rewrite_head(uint8_t *buf, size_t *len, size_t bufsize,
                     const char *objective, const char *fairness, int write)
{
  static const char *const names[] = {
    SP_LLMD_OBJECTIVE_HDR, SP_LLMD_OBJECTIVE_OLD,
    SP_LLMD_FAIRNESS_HDR, SP_LLMD_FAIRNESS_OLD,
  };
  size_t cur = *len;
  uint8_t *copy_end;

  if (cur < 4 || !memmem(buf, cur, "\r\n\r\n", 4))
    return -1;
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    copy_end = l7h1_strip_header(buf, &cur, names[i]);
    if (!copy_end)
      return -1;
  }
  if (write) {
    size_t scan = cur < 2048 ? cur : 2048;

    if (!memmem(buf, scan, "Transfer-Encoding: chunked", 26) &&
        !memmem(buf, scan, "transfer-encoding: chunked", 26)) {
      if (objective && objective[0])
        (void)l7h1_splice_header(buf, &cur, bufsize, SP_LLMD_OBJECTIVE_HDR,
                                 objective);
      if (fairness && fairness[0])
        (void)l7h1_splice_header(buf, &cur, bufsize, SP_LLMD_FAIRNESS_HDR,
                                 fairness);
    }
  }
  *len = cur;
  return 0;
}

#endif /* __SOCKPROXY_LLMD_FWD_H__ */
