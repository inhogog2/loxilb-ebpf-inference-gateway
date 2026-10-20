/* A started answer takes no new status line: the framer's view of "started"
 * under real HTTP_RESPONSE framing, cut at every byte, and the pieces the
 * guard writes in its place (sockproxy_answer.h). */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include "llhttp.h"
#include "sockproxy_answer.h"

typedef struct { _Atomic uint8_t in_msg; int completed; } track;
static int begin(llhttp_t *p) { sp_answer_msg_begin(&((track *)p->data)->in_msg); return 0; }
static int done(llhttp_t *p)
{
  track *t = p->data;
  sp_answer_msg_done(&t->in_msg);
  t->completed++;
  return 0;
}
static int inside(track *t) { return atomic_load(&t->in_msg); }

static void framer(llhttp_t *p, llhttp_settings_t *s, track *t)
{
  llhttp_settings_init(s);
  s->on_message_begin = begin;
  s->on_message_complete = done;
  llhttp_init(p, HTTP_RESPONSE, s);
  p->data = t;
}

int main(void)
{
  /* Started from the first status-line byte to the last byte of the message,
   * at every cut: a status line split across reads is already an answer. */
  {
    const char r[] = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n"
                     "f\r\ndata: {\"a\":1}\n\n\r\n0\r\n\r\n";
    size_t n = sizeof(r) - 1;
    for (size_t cut = 1; cut < n; cut++) {
      track t = {0}; llhttp_t p; llhttp_settings_t s;
      framer(&p, &s, &t);
      assert(!inside(&t));
      assert(llhttp_execute(&p, r, cut) == HPE_OK);
      assert(inside(&t) && t.completed == 0);
      assert(llhttp_execute(&p, r + cut, n - cut) == HPE_OK);
      assert(!inside(&t) && t.completed == 1);
    }
  }
  /* An interim response is a message of its own: after the 100 the final
   * answer has not started, and its first byte starts it. */
  {
    const char c[] = "HTTP/1.1 100 Continue\r\n\r\n";
    const char f[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    track t = {0}; llhttp_t p; llhttp_settings_t s;
    framer(&p, &s, &t);
    assert(llhttp_execute(&p, c, sizeof(c) - 1) == HPE_OK);
    assert(!inside(&t) && t.completed == 1);
    assert(llhttp_execute(&p, f, 1) == HPE_OK);
    assert(inside(&t));
    assert(llhttp_execute(&p, f + 1, sizeof(f) - 2) == HPE_OK);
    assert(!inside(&t) && t.completed == 2);
  }
  /* A framer that loses the framing counts as inside (what it relays may be
   * the middle of an answer) until a message is framed to its end. */
  {
    const char bad[] = "\x01garbage that is not a status line\r\n";
    const char next[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    track t = {0}; llhttp_t p; llhttp_settings_t s;
    framer(&p, &s, &t);
    assert(llhttp_execute(&p, bad, sizeof(bad) - 1) != HPE_OK);
    llhttp_init(&p, HTTP_RESPONSE, &s); p.data = &t;
    sp_answer_framing_lost(&t.in_msg);
    assert(inside(&t));
    assert(llhttp_execute(&p, next, sizeof(next) - 1) == HPE_OK);
    assert(!inside(&t));
  }

  /* What a whole response is. */
  assert(sp_answer_is_status_line("HTTP/1.1 504 Gateway Timeout\r\n", 30));
  assert(!sp_answer_is_status_line("data: [DONE]\n\n", 14));
  assert(!sp_answer_is_status_line("HTTP", 4));

  /* The code the status line carried, and none invented. */
  {
    char code[64];
    const char t1[] = "HTTP/1.1 502 Bad Gateway\r\n\r\n{\"error\":\"pd_decode_stream_timeout\"}";
    const char t2[] = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
    const char t3[] = "HTTP/1.1 403 Forbidden\r\n\r\n{\"error\":\"Request blocked by LlamaFirewall\"}";
    const char t4[] = "HTTP/1.1 504 x\r\n\r\n{\"error\":\"unterminated";
    sp_answer_error_code(t1, sizeof(t1) - 1, code, sizeof(code));
    assert(!strcmp(code, "pd_decode_stream_timeout"));
    sp_answer_error_code(t2, sizeof(t2) - 1, code, sizeof(code));
    assert(!strcmp(code, "gateway_error"));
    sp_answer_error_code(t3, sizeof(t3) - 1, code, sizeof(code));
    assert(!strcmp(code, "gateway_error"));
    sp_answer_error_code(t4, sizeof(t4) - 1, code, sizeof(code));
    assert(!strcmp(code, "gateway_error"));
    char small[8];
    sp_answer_error_code(t1, sizeof(t1) - 1, small, sizeof(small));
    assert(!strcmp(small, "gateway"));
  }

  /* The in-band end: an SSE error event, chunk-framed with the terminator on
   * a chunked answer, and decodable by the framer that relayed it. */
  {
    char out[192];
    size_t n = sp_answer_sse_end("pd_idle_timeout", 0, out, sizeof(out));
    assert(n == strlen("data: {\"error\":\"pd_idle_timeout\"}\n\n"));
    assert(!memcmp(out, "data: {\"error\":\"pd_idle_timeout\"}\n\n", n));
    n = sp_answer_sse_end("pd_idle_timeout", 1, out, sizeof(out));
    {
      char size_line[16];
      int sl = snprintf(size_line, sizeof(size_line), "%zx\r\n",
                        strlen("data: {\"error\":\"pd_idle_timeout\"}\n\n"));
      assert(n > 0 && !memcmp(out, size_line, (size_t)sl));
    }
    assert(!memcmp(out + n - 7, "\r\n0\r\n\r\n", 7));
    assert(!memmem(out, n, "HTTP/", 5));
    {
      const char head[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
      track t = {0}; llhttp_t p; llhttp_settings_t s;
      framer(&p, &s, &t);
      assert(llhttp_execute(&p, head, sizeof(head) - 1) == HPE_OK);
      assert(llhttp_execute(&p, out, n) == HPE_OK);
      assert(t.completed == 1 && !inside(&t));
    }
    assert(sp_answer_sse_end("pd_idle_timeout", 1, out, 16) == 0);
  }

  puts("answer tracking: started from the first status-line byte at every cut, interim and lost framing; "
       "the in-band end decodes as the answer's last chunk PASS");
  return 0;
}
