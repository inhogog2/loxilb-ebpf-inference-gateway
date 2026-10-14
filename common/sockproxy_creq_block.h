/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * Where a client read stands in its HTTP/1.1 request.
 *
 * The relay path hands the gateway one socket read at a time. Whether such a
 * read is a request's header block cannot be told from its bytes: a body may
 * carry a blank line, and the last chunk of a chunked body is one. So the
 * question is answered by the request framer, which has seen every byte of
 * the connection in order, and kept here per connection:
 *
 *   creq_block_read_begin()  before a read is fed to the framer
 *   creq_block_msg_begin()   the framer saw a request's first byte
 *   creq_block_hdrs_done()   the framer saw the end of a header block
 *   creq_block_msg_done()    the framer saw a request's last byte
 *   creq_block_read_end()    after the read was fed; ok = the framer took it
 *
 * After read_end, hdr_block is 1 only when the read began at a request's
 * first byte and that request's header block ends inside it. A read that
 * began inside a request (the rest of a header block, body bytes), and a
 * read the framer refused, read 0. A caller that rewrites header lines acts
 * on a read only when hdr_block is 1, and then on the read's first header
 * block only: that is once per request and never on body bytes.
 *
 * Header-only and free of gateway types so the unit test drives it with the
 * real framer.
 */
#ifndef __SOCKPROXY_CREQ_BLOCK_H__
#define __SOCKPROXY_CREQ_BLOCK_H__

#include <stdint.h>

typedef struct creq_block {
  uint8_t open;       /* a request's first byte has been framed and its last has not */
  uint8_t at_start;   /* the read being framed began between two requests */
  uint8_t rd_hdrs;    /* the first request begun in this read ended its header block in it */
  uint8_t rd_msgs;    /* requests begun in this read */
  uint8_t hdr_block;  /* the answer for the read last framed */
} creq_block_t;

static inline void
creq_block_reset(creq_block_t *b)
{
  b->open = 0;
  b->at_start = 0;
  b->rd_hdrs = 0;
  b->rd_msgs = 0;
  b->hdr_block = 0;
}

static inline void
creq_block_read_begin(creq_block_t *b)
{
  b->at_start = !b->open;
  b->rd_hdrs = 0;
  b->rd_msgs = 0;
  b->hdr_block = 0;
}

static inline void
creq_block_msg_begin(creq_block_t *b)
{
  b->open = 1;
  if (b->rd_msgs < UINT8_MAX)
    b->rd_msgs++;
}

static inline void
creq_block_hdrs_done(creq_block_t *b)
{
  /* Only the header block that opens the read counts: a second request in
   * the same read has its header block somewhere after the first one's
   * body, where no caller looks. */
  if (b->at_start && b->rd_msgs == 1)
    b->rd_hdrs = 1;
}

static inline void
creq_block_msg_done(creq_block_t *b)
{
  b->open = 0;
}

static inline void
creq_block_read_end(creq_block_t *b, int ok)
{
  if (!ok) {
    /* Not a request the framer can follow: nothing in it is a header block,
     * and the framer starts over on the next read. */
    creq_block_reset(b);
    return;
  }
  b->hdr_block = (uint8_t)(b->at_start && b->rd_hdrs);
}

#endif /* __SOCKPROXY_CREQ_BLOCK_H__ */
