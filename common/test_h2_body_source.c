/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_body_source.c - a request body forwarded to an HTTP/2 backend
 * outlives the client stream that carried it, and is never lost.
 *
 * A backend reads a request body on its own schedule (flow control), so the
 * client stream can be reset and freed before the body has gone. The body
 * source used to point into the client stream's buffer: the backend then
 * read freed memory. It now carries its own copy, owned by the stream
 * mapping. And the mapping is taken BEFORE the request is submitted: taken
 * after it, an allocation failure left nghttp2 holding a source that nothing
 * would ever free.
 *
 * This drives the REAL proxy_h2_forward_to_backend over the shared HTTP/2
 * fixture (test_h2_fixture.h): a real gateway session for the client, a real
 * backend session to a fake backend that holds the stream window at 0, so
 * the request body waits at the gateway. The gateway code is built with
 * ASan: a read of the freed buffer aborts, a leaked source fails the leak
 * check at exit.
 *
 * Build: make test_h2body (ASan + UBSan, the gateway object included).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "test_h2_fixture.h"

static const char body[] = "{\"model\":\"m1\",\"messages\":[]}";
#define BODY_LEN (sizeof(body) - 1)

int
main(void)
{
  proxy_epval_t *pool;
  proxy_h2_stream_t *st;
  stream_mapping_t *m;
  h2_data_source_t *src;
  int32_t s1, s3, s5;
  int streams;

  h2fx_init();
  pool = h2fx_pool("all.example", 1);
  h2fx_lpm = pool;
  h2fx_be_window = 0;      /* the backend takes headers, no body, until it says */

  /* A first request opens the backend connection, and the backend's
   * settings (stream window 0) reach the gateway. */
  s1 = h2fx_submit("m1", NULL, 0);
  CHECK(h2fx_gw_read() == 0, "the first request is read and forwarded");
  CHECK(h2fx_connect_calls == 1 && h2fx_be[0].streams == 1 && h2fx_be[0].end_stream,
        "the backend got it (connects %d, streams %d)", h2fx_connect_calls,
        h2fx_be[0].streams);
  CHECK(h2fx_be_send(0) == 0, "the backend's settings reach the gateway");
  (void)s1;

  /* A request with a body: the headers go, the body waits for the window. */
  s3 = h2fx_submit("m1", (const uint8_t *)body, BODY_LEN);
  CHECK(h2fx_gw_read() == 0, "the request with a body is read and forwarded");
  CHECK(h2fx_connect_calls == 1 && h2fx_be[0].streams == 2 && h2fx_be[0].body_len == 0 &&
        !h2fx_be[0].end_stream,
        "on the same connection, headers only (streams %d, body %zu)",
        h2fx_be[0].streams, h2fx_be[0].body_len);
  st = h2fx_stream(s3);
  m = h2fx_mapping(0, s3);
  CHECK(st && m && m->data_source, "the stream is mapped with a body source");
  if (!st || !m || !m->data_source)
    return h2fx_result();
  src = m->data_source;
  CHECK(src->len == BODY_LEN && src->data != st->data_buf,
        "the source carries its own copy of the body, not the stream's buffer");

  /* The client gives up on it: the stream and its buffer are freed. */
  assert(nghttp2_submit_rst_stream(h2fx_cl, NGHTTP2_FLAG_NONE, s3, NGHTTP2_CANCEL) == 0);
  h2fx_to_gateway();
  CHECK(h2fx_stream(s3) == NULL, "the client's reset freed the stream and its buffer");

  /* The backend opens the window: the gateway reads the source now. */
  assert(nghttp2_submit_window_update(h2fx_be[0].srv, NGHTTP2_FLAG_NONE,
                                      h2fx_be[0].stream, 65535) == 0);
  CHECK(h2fx_be_send(0) == 0, "the window reaches the gateway");
  CHECK(h2fx_be[0].body_len == BODY_LEN && !memcmp(h2fx_be[0].body, body, BODY_LEN) &&
        h2fx_be[0].end_stream,
        "the backend got the whole body after the client stream was gone (%zu bytes)",
        h2fx_be[0].body_len);

  /* The mapping cannot be allocated: the request is not submitted, and
   * nothing is left for nghttp2 to hold. */
  streams = h2fx_be[0].streams;
  s5 = h2fx_submit("m1", (const uint8_t *)body, BODY_LEN);
  h2fx_fail_calloc_size = sizeof(stream_mapping_t);
  CHECK(h2fx_gw_read() == 0, "the request whose mapping fails is read");
  CHECK(h2fx_calloc_failed == 1, "the mapping's allocation was the one that failed");
  CHECK(h2fx_mapping(0, s5) == NULL, "no mapping for it");
  CHECK(h2fx_be[0].streams == streams,
        "and no request reached the backend (streams %d)", h2fx_be[0].streams);
  assert(nghttp2_submit_rst_stream(h2fx_cl, NGHTTP2_FLAG_NONE, s5, NGHTTP2_CANCEL) == 0);
  h2fx_to_gateway();

  /* Teardown, so the leak check reads only the code under test: a source
   * nghttp2 was left holding is reported here. */
  h2fx_fini();
  return h2fx_result();
}
