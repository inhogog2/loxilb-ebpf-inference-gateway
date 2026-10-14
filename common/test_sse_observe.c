/* Real HTTP_RESPONSE framing, split at every byte and across HTTP chunks. */
#include <assert.h>
#include <stdio.h>
#include "llhttp.h"
#include "sockproxy_sse_observe.h"
typedef struct { sp_sse_observer_t sse; char body[1024]; size_t len; int ended; } observation;
static int field(llhttp_t *p, const char *at, size_t n) { observation *o=p->data; sp_sse_field(&o->sse,at,n); return 0; }
static int value(llhttp_t *p, const char *at, size_t n) { observation *o=p->data; sp_sse_value(&o->sse,at,n); return 0; }
static int value_done(llhttp_t *p) { observation *o=p->data; sp_sse_header_done(&o->sse); return 0; }
static int message_done(llhttp_t *p) { observation *o=p->data; o->ended++; sp_sse_message_done(&o->sse); return 0; }
static int body(llhttp_t *p, const char *at, size_t n) {
  observation *o=p->data; assert(o->len+n<sizeof(o->body));
  memcpy(o->body+o->len,at,n); o->len+=n; sp_sse_body(&o->sse,at,n); return 0;
}
int main(void) {
  const char response[] = "HTTP/1.1 200 OK\r\nCoNtEnT-TyPe: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n"
    "8\r\ndata: [D\r\n6\r\nONE]\n\n\r\n0\r\n\r\n";
  for(size_t split=1;split<sizeof(response)-1;split++) {
    observation o={0}; llhttp_t p; llhttp_settings_t s;
    llhttp_settings_init(&s); s.on_header_field=field; s.on_header_value=value;
    s.on_header_value_complete=value_done; s.on_body=body;
    llhttp_init(&p,HTTP_RESPONSE,&s); p.data=&o;
    assert(llhttp_execute(&p,response,split)==HPE_OK);
    assert(llhttp_execute(&p,response+split,sizeof(response)-1-split)==HPE_OK);
    if (!o.sse.is_sse || !o.sse.done)
      fprintf(stderr,"split=%zu sse=%u done=%u field=%s value=%s body=%.*s\n",split,o.sse.is_sse,o.sse.done,o.sse.field,o.sse.value,(int)o.len,o.body);
    assert(o.sse.is_sse && o.sse.done);
    assert(o.len==14 && !memcmp(o.body,"data: [DONE]\n\n",14));
  }
  sp_sse_observer_t o={0}; sp_sse_field(&o,"Content-Type",12);
  sp_sse_value(&o,"text/event-streaming",20); sp_sse_header_done(&o); assert(!o.is_sse);
  o.is_sse=1; sp_sse_body(&o,"data: [D",8);
  sp_sse_body(&o,"ONE]\n\nabcdefghijklmnopqrstuvwxyz0123456789",40); assert(o.done);
  /* A stream that ends by its framing, with no [DONE] event: not done while
   * a byte of the response is still to come, done at its last byte, at every
   * cut. */
  {
    const char nodone[] = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
      "f\r\ndata: {\"a\":1}\n\n\r\n0\r\n\r\n";
    size_t n = sizeof(nodone)-1;
    for(size_t split=1;split<n;split++) {
      observation o={0}; llhttp_t p; llhttp_settings_t s;
      llhttp_settings_init(&s); s.on_header_field=field; s.on_header_value=value;
      s.on_header_value_complete=value_done; s.on_body=body; s.on_message_complete=message_done;
      llhttp_init(&p,HTTP_RESPONSE,&s); p.data=&o;
      assert(llhttp_execute(&p,nodone,split)==HPE_OK);
      assert(!o.sse.done && !o.ended);
      assert(llhttp_execute(&p,nodone+split,n-split)==HPE_OK);
      assert(o.ended==1 && o.sse.is_sse && o.sse.done);
    }
  }
  /* A stream that is its [DONE] event and nothing else, by Content-Length. */
  {
    const char only[] = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 14\r\n\r\ndata: [DONE]\n\n";
    observation o={0}; llhttp_t p; llhttp_settings_t s;
    llhttp_settings_init(&s); s.on_header_field=field; s.on_header_value=value;
    s.on_header_value_complete=value_done; s.on_body=body; s.on_message_complete=message_done;
    llhttp_init(&p,HTTP_RESPONSE,&s); p.data=&o;
    assert(llhttp_execute(&p,only,sizeof(only)-1)==HPE_OK);
    assert(o.ended==1 && o.sse.is_sse && o.sse.done && o.len==14);
  }
  /* An answer that is not a stream is not ended as one. */
  {
    const char json[] = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    observation o={0}; llhttp_t p; llhttp_settings_t s;
    llhttp_settings_init(&s); s.on_header_field=field; s.on_header_value=value;
    s.on_header_value_complete=value_done; s.on_body=body; s.on_message_complete=message_done;
    llhttp_init(&p,HTTP_RESPONSE,&s); p.data=&o;
    assert(llhttp_execute(&p,json,sizeof(json)-1)==HPE_OK);
    assert(o.ended==1 && !o.sse.is_sse && !o.sse.done);
  }
  puts("SSE dechunked observer: PASS"); return 0;
}
