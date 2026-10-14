/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * Edits of an HTTP/1.1 request header block in place: strip a header, strip
 * a family of headers, splice one line in.
 *
 * Each of them takes [msg, *len) and treats everything before the first
 * blank line as the header block. None can tell a header block from other
 * bytes that happen to hold a blank line, so the caller must hand them a
 * buffer that BEGINS with a request's header block and nothing else
 * (sockproxy_creq_block.h is how the relay path knows).
 *
 * Kept in a header so the unit test runs the same code under a sanitizer.
 * The includer provides log_error and, before this file,
 * sockproxy_l7hdr_guard.h.
 */
#ifndef __SOCKPROXY_H1_HDR_H__
#define __SOCKPROXY_H1_HDR_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#ifndef L7_HDR_NAME_MAX
#define L7_HDR_NAME_MAX 64
#endif
#ifndef L7_HDR_VALUE_MAX
#define L7_HDR_VALUE_MAX 256
#endif

/* Strip EVERY occurrence of header `name` (case-insensitive) from the request
 * header block in [msg, *len). Returns the (possibly shrunk) header terminator,
 * or NULL if the \r\n\r\n terminator is lost. Bounded to the header block only. */
static __attribute__((unused)) uint8_t *
l7h1_strip_header(uint8_t *msg, size_t *len, const char *name)
{
  uint8_t *headers_end = memmem(msg, *len, "\r\n\r\n", 4);
  size_t name_len = strlen(name);
  if (!headers_end || name_len == 0)
    return headers_end;

  /* Walk header lines from the first CRLF after the request-line. */
  uint8_t *line = memmem(msg, (size_t)(headers_end - msg), "\r\n", 2);
  while (line && line < headers_end) {
    uint8_t *hdr = line + 2;                 /* start of the next header line */
    if (hdr >= headers_end)
      break;
    /* Match "<name>:" case-insensitively at the start of this header line. */
    if ((size_t)(headers_end - hdr) > name_len &&
        strncasecmp((const char *)hdr, name, name_len) == 0 &&
        hdr[name_len] == ':') {
      uint8_t *line_end = memmem(hdr, (size_t)(*len - (size_t)(hdr - msg)),
                                 "\r\n", 2);
      if (!line_end)
        break;
      line_end += 2;                         /* include the trailing CRLF */
      size_t remove_len = (size_t)(line_end - hdr);
      memmove(hdr, line_end, *len - (size_t)(line_end - msg));
      *len -= remove_len;
      headers_end = memmem(msg, *len, "\r\n\r\n", 4);
      if (!headers_end)
        return NULL;
      /* Re-scan from the same `line` (hdr now holds the following header). */
      continue;
    }
    line = memmem(hdr, (size_t)(headers_end - hdr), "\r\n", 2);
  }
  return headers_end;
}

/* Strip every header whose name starts with prefix (case-insensitive) from
 * the header block in [msg, *len): a whole family a client must not be able
 * to send upstream, whatever its members are called. Same contract as
 * l7h1_strip_header: the header terminator, or NULL if it was lost. */
static __attribute__((unused)) uint8_t *
l7h1_strip_header_prefix(uint8_t *msg, size_t *len, const char *prefix)
{
  uint8_t *headers_end = memmem(msg, *len, "\r\n\r\n", 4);
  size_t plen = strlen(prefix);
  if (!headers_end || plen == 0)
    return headers_end;

  uint8_t *line = memmem(msg, (size_t)(headers_end - msg), "\r\n", 2);
  while (line && line < headers_end) {
    uint8_t *hdr = line + 2;
    if (hdr >= headers_end)
      break;
    if ((size_t)(headers_end - hdr) > plen &&
        strncasecmp((const char *)hdr, prefix, plen) == 0) {
      uint8_t *line_end = memmem(hdr, (size_t)(*len - (size_t)(hdr - msg)),
                                 "\r\n", 2);
      if (!line_end)
        break;
      line_end += 2;
      size_t remove_len = (size_t)(line_end - hdr);
      memmove(hdr, line_end, *len - (size_t)(line_end - msg));
      *len -= remove_len;
      headers_end = memmem(msg, *len, "\r\n\r\n", 4);
      if (!headers_end)
        return NULL;
      continue;
    }
    line = memmem(hdr, (size_t)(headers_end - hdr), "\r\n", 2);
  }
  return headers_end;
}

/* Splice one "<name>: <value>\r\n" line before the final \r\n\r\n. */
static __attribute__((unused)) int
l7h1_splice_header(uint8_t *msg, size_t *len, size_t bufsize,
                   const char *name, const char *value)
{
  char inject_buf[L7_HDR_NAME_MAX + L7_HDR_VALUE_MAX + 8];

  /*
   * A field carrying CR or LF would not stay one header line: everything
   * after the break becomes a header line of the receiver's own. Refuse the
   * splice. Nothing untrusted is logged -- the name is exactly the string
   * under suspicion, and writing it into a log is the same mistake one layer
   * down.
   */
  if (l7_hdr_pair_unsafe(name, value)) {
    log_error("l7h1_splice_header: refused a header field carrying a line "
              "break or an empty name (name_len=%zu value_len=%zu)",
              name ? strlen(name) : (size_t)0,
              value ? strlen(value) : (size_t)0);
    return -1;
  }

  int n = snprintf(inject_buf, sizeof(inject_buf), "%s: %s\r\n", name, value);
  if (n <= 0 || (size_t)n >= sizeof(inject_buf))
    return -1;
  size_t inject_len = (size_t)n;

  uint8_t *headers_end = memmem(msg, *len, "\r\n\r\n", 4);
  if (!headers_end)
    return -1;
  if (*len + inject_len >= bufsize)
    return -1;

  uint8_t *insert_point = headers_end + 2;   /* after last header CRLF */
  size_t tail_len = *len - (size_t)(insert_point - msg);
  memmove(insert_point + inject_len, insert_point, tail_len);
  memcpy(insert_point, inject_buf, inject_len);
  *len += inject_len;
  return 0;
}

#endif /* __SOCKPROXY_H1_HDR_H__ */
