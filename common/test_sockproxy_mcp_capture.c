/* Copyright (c) 2026 LoxiLB Authors; SPDX-License-Identifier: BSD-3-Clause */
/* Portable capture/framing model, not a Gateway integration test.
 * clang -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined
 *   -Wno-unused-parameter test_sockproxy_mcp_capture.c llhttp.c httpapi.c
 *   http.c -o test_mcp_capture */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llhttp.h"
static int fail_realloc;
static void *capture_realloc(void *p, size_t n) {
  if (fail_realloc) return NULL;
  return realloc(p,n);
}
#define realloc capture_realloc
#include "sockproxy_mcp_capture.h"
#undef realloc
#define META "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}"
struct model {
  struct sp_mcp_capture *capture;
  unsigned completed, refused, delivered, alive, header_active;
  int validation_status, bad_pause_api, allow_trailers;
};
static unsigned checks;
static int begun(llhttp_t *p) {
  struct model *m=p->data;
  sp_mcp_capture_reset(m->capture);m->header_active=0;return 0;
}
static int field(llhttp_t *p,const char *at,size_t n) {
  struct model *m=p->data;
  /* Match the Gateway's explicit MCP trailer admission rule. Trailers
   * arrive after the canonical header block; none may alter its authority. */
  if((p->flags & F_TRAILING) && !m->allow_trailers){
    m->validation_status=400;m->refused++;return -1;
  }
  if(!m->header_active){sp_mcp_header_begin(&m->capture->req);m->header_active=1;}
  sp_mcp_header_name(&m->capture->req,at,n);return 0;
}
static int value(llhttp_t *p,const char *at,size_t n) {
  struct model *m=p->data;sp_mcp_header_value(&m->capture->req,at,n);return 0;
}
static int value_done(llhttp_t *p) {
  struct model *m=p->data;sp_mcp_header_end(&m->capture->req);m->header_active=0;return 0;
}
static int body(llhttp_t *p,const char *at,size_t n) {
  struct model *m=p->data;return sp_mcp_capture_body(m->capture,at,n) ? -1 : 0;
}
static int complete(llhttp_t *p) {
  struct model *m=p->data;
  m->completed++;
  m->validation_status=sp_mcp_validate(&m->capture->req,llhttp_method_name(p->method),m->capture->body,m->capture->len);
  if(m->validation_status){m->refused++;return -1;}
  /* Match the parent's original pause API use, retaining the model object
   * until llhttp_execute returns. A parser callback never owns its free. */
  if(m->bad_pause_api){llhttp_pause(p);return 0;}
  return HPE_PAUSED;
}
static void init(llhttp_t *p,llhttp_settings_t *s,struct model *m) {
  memset(m,0,sizeof(*m));m->alive=1;m->capture=calloc(1,sizeof(*m->capture));assert(m->capture);
  llhttp_settings_init(s);s->on_message_begin=begun;s->on_header_field=field;
  s->on_header_value=value;s->on_header_value_complete=value_done;s->on_body=body;s->on_message_complete=complete;
  llhttp_init(p,HTTP_REQUEST,s);p->data=m;
}
static void retire(struct model *m) {
  assert(m->alive);sp_mcp_capture_free(m->capture);m->capture=NULL;m->alive=0;
}
int main(void) {
  struct sp_mcp_media media={0};
  sp_mcp_media_header(&media,"Content-Type",12,"Application/JSON; charset=utf-8",31);
  sp_mcp_media_header(&media,"Accept",6,"application/json, text/event-stream",35);
  assert(sp_mcp_media_valid(&media));checks++;
  memset(&media,0,sizeof(media));
  sp_mcp_media_header(&media,"Content-Type",12,"application/json",16);
  sp_mcp_media_header(&media,"Accept",6,"application/json",16);
  assert(!sp_mcp_media_valid(&media));checks++;
  sp_mcp_media_header(&media,"Accept",6,"text/event-stream",17);
  assert(sp_mcp_media_valid(&media));checks++;
  sp_mcp_media_header(&media,"Content-Type",12,"application/json",16);
  assert(!sp_mcp_media_valid(&media));checks++;
  memset(&media,0,sizeof(media));
  sp_mcp_media_header(&media,"Content-Type",12,"application/jsonx",17);
  sp_mcp_media_header(&media,"Accept",6,"application/json, text/event-stream",35);
  assert(!sp_mcp_media_valid(&media));checks++;
  /* Invalid suffixes, parameters, qvalues and lists cannot silently turn
   * unsupported response media into an accepted routing request. */
  const char *ct_bad[]={"application/json garbage","application/json\r\n",
    "application/json, text/plain","application/json;","application/json; charset",
    "application/json; charset=","application/json; charset=\"unterminated",
    "application/json; charset=\"a\"tail","application/json; charset=\"a\\",
    "application/json; charset=\"a\001b\"","application/json; charset=a b",
    "application /json","application/ json","*/json","application/*","*/*",""};
  for(size_t i=0;i<sizeof(ct_bad)/sizeof(ct_bad[0]);i++){
    memset(&media,0,sizeof(media));
    sp_mcp_media_header(&media,"content-type",12,ct_bad[i],strlen(ct_bad[i]));
    sp_mcp_media_header(&media,"accept",6,"application/json,text/event-stream",34);
    assert(media.error==400 && !sp_mcp_media_valid(&media));checks++;
  }
  const char *accept_bad[]={"application/json garbage,text/event-stream",
    "application/json;q=0,text/event-stream", "application/json,text/event-stream;q=0",
    "application/json;q=0.000,text/event-stream;q=1", "application/json;q=1.001,text/event-stream",
    "application/json;q=.5,text/event-stream", "application/json;q=00,text/event-stream",
    "application/json;q=-1,text/event-stream", "application/json;q=2,text/event-stream",
    "application/json;q=0.0001,text/event-stream", "application/json;q=0.1.2,text/event-stream",
    "application/json;q=\"1\",text/event-stream", "application/json;q=1;q=1,text/event-stream",
    "application/json;q=true,text/event-stream", "application/json;q=,text/event-stream",
    "application/json;,text/event-stream", "application/json;x=\"bad,text/event-stream",
    "application/json,text/event-stream,", ",application/json,text/event-stream",
    "application/json,,text/event-stream", "application/json,text/event-stream x",
    "*/*", "application/*,text/event-stream", "application/json,text/*", "*/json,text/event-stream", ""};
  for(size_t i=0;i<sizeof(accept_bad)/sizeof(accept_bad[0]);i++){
    memset(&media,0,sizeof(media));
    sp_mcp_media_header(&media,"content-type",12,"application/json",16);
    sp_mcp_media_header(&media,"accept",6,accept_bad[i],strlen(accept_bad[i]));
    assert(!sp_mcp_media_valid(&media));checks++;
  }
  const char *accept_good[]={"application/json;q=1,text/event-stream;q=0.001",
    "application/json;q=1.,text/event-stream;q=0.1", "application/json;Q=0.123,text/event-stream;q=1.000",
    " APPLICATION/JSON \t; q = 0.5 , text/event-stream ; q=1 ",
    "application/json;note=\"a,b;c\",text/event-stream",
    "application/json;note=\"a\\\"b,c\",text/event-stream",
    "application/json;note=\"\",text/event-stream",
    "application/json;q=0,application/json;q=1,text/event-stream",
    "*/*;q=0,application/json,text/event-stream",
    "application/json,text/event-stream,other/type;note=\"x,y\""};
  for(size_t i=0;i<sizeof(accept_good)/sizeof(accept_good[0]);i++){
    memset(&media,0,sizeof(media));
    sp_mcp_media_header(&media,"content-type",12," application/json \t; charset = \"utf-8\" ",39);
    sp_mcp_media_header(&media,"accept",6,accept_good[i],strlen(accept_good[i]));
    assert(sp_mcp_media_valid(&media));checks++;
  }
  const char *sample="application/json;note=\"a,b;c\";q=1,text/event-stream;q=0.5";
  size_t sample_len=strlen(sample);char media_copy[128];
  for(size_t i=0;i<sample_len;i++)for(unsigned b=0;b<256;b++){
    memcpy(media_copy,sample,sample_len);media_copy[i]=(char)b;
    memset(&media,0,sizeof(media));
    sp_mcp_media_header(&media,"accept",6,media_copy,sample_len);checks++;
  }
  struct sp_mcp_capture *c=calloc(1,sizeof(*c));assert(c);
  assert(sp_mcp_capture_body(NULL,"x",1)==400);checks++;
  assert(sp_mcp_capture_body(c,NULL,1)==400);checks++;
  assert(sp_mcp_capture_body(c,NULL,0)==0 && c->len==0 && c->body==NULL);checks++;
  assert(sp_mcp_capture_body(c,"abc",3)==0 && c->len==3 && !memcmp(c->body,"abc",3));checks++;
  char *saved=c->body;size_t savedcap=c->cap;
  fail_realloc=1;
  assert(sp_mcp_capture_body(c,"x",savedcap)==503 && c->body==saved && c->len==3 && c->cap==savedcap);checks++;
  fail_realloc=0;sp_mcp_capture_reset(c);assert(!c->body && !c->len && !c->cap);checks++;
  char *huge=malloc(SP_MCP_PROXY_BODY_MAX);assert(huge);memset(huge,'x',SP_MCP_PROXY_BODY_MAX);
  assert(sp_mcp_capture_body(c,huge,SP_MCP_PROXY_BODY_MAX)==0);checks++;
  saved=c->body;
  assert(sp_mcp_capture_body(c,"x",1)==413 && c->body==saved && c->len==SP_MCP_PROXY_BODY_MAX);checks++;
  sp_mcp_capture_reset(c);assert(sp_mcp_capture_body(c,huge,SP_MCP_PROXY_BODY_MAX+1)==413 && !c->body);checks++;
  free(huge);sp_mcp_capture_free(c);sp_mcp_capture_free(NULL);
  const char *json="{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META "}}";
  char wire[2048],chunked[2048],pipeline[4096];
  int wn=snprintf(wire,sizeof(wire),"POST /mcp HTTP/1.1\r\nHost: example\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: echo\r\nContent-Length: %zu\r\n\r\n%s",strlen(json),json);assert(wn>0);
  int cn=snprintf(chunked,sizeof(chunked),"POST /mcp HTTP/1.1\r\nHost: example\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: echo\r\nTransfer-Encoding: chunked\r\n\r\n%zx\r\n%s\r\n0\r\n\r\n",strlen(json),json);assert(cn>0);
  const char *msgs[]={wire,chunked};const size_t lens[]={(size_t)wn,(size_t)cn};
  for(unsigned x=0;x<2;x++)for(size_t split=0;split<=lens[x];split++){
    struct model m;llhttp_t parser;llhttp_settings_t settings;init(&parser,&settings,&m);
    enum llhttp_errno e=llhttp_execute(&parser,msgs[x],split);
    if(split<lens[x]){assert(e==HPE_OK);e=llhttp_execute(&parser,msgs[x]+split,lens[x]-split);}
    if(e!=HPE_PAUSED){fprintf(stderr,"pause API model returned %s (split=%zu, complete=%u)\n",llhttp_errno_name(e),split,m.completed);}
    assert(m.completed==1 && m.validation_status==0 && m.alive && m.capture->len==strlen(json));
    assert(!memcmp(m.capture->body,json,strlen(json)));
    /* This assertion captures the integration's assumption explicitly. */
    assert(e==HPE_PAUSED);
    assert(llhttp_get_error_pos(&parser)==msgs[x]+lens[x]);
    llhttp_resume(&parser);checks++;retire(&m);
  }
  /* Every nonempty trailer block is refused before message-complete,
   * including routing/security fields and an unrelated extension field. */
  const char *trailers[]={"Mcp-Method: tools/list\r\n", "Mcp-Name: attacker\r\n",
    "Authorization: Bearer attacker\r\n", "Content-Type: text/plain\r\n",
    "X-Unrelated: benign\r\n"};
  char trailer_wire[2048];
  for(size_t ti=0;ti<sizeof(trailers)/sizeof(trailers[0]);ti++){
    assert(cn>=2);memcpy(trailer_wire,chunked,(size_t)cn-2);
    int tn=snprintf(trailer_wire+cn-2,sizeof(trailer_wire)-(size_t)cn+2,"%s\r\n",trailers[ti]);
    assert(tn>0);size_t len=(size_t)cn-2+(size_t)tn;
    for(size_t split=0;split<=len;split++){
      struct model tm;llhttp_t tp;llhttp_settings_t ts;init(&tp,&ts,&tm);
      enum llhttp_errno te=llhttp_execute(&tp,trailer_wire,split);
      if(te==HPE_OK && split<len)te=llhttp_execute(&tp,trailer_wire+split,len-split);
      assert(te!=HPE_OK && te!=HPE_PAUSED);
      assert(tm.refused==1 && tm.validation_status==400 && !tm.completed && !tm.delivered && tm.alive);
      checks++;retire(&tm);
    }
  }
  /* The permissive pre-fix model accepts an unrelated trailer; this proves
   * llhttp invokes ordinary field callbacks for trailer authority too. */
  struct model permissive;llhttp_t pp;llhttp_settings_t ps;init(&pp,&ps,&permissive);
  permissive.allow_trailers=1;
  enum llhttp_errno pe=llhttp_execute(&pp,trailer_wire,strlen(trailer_wire));
  assert(pe==HPE_PAUSED && permissive.completed==1 && !permissive.refused);checks++;retire(&permissive);
  snprintf(pipeline,sizeof(pipeline),"%s%s",wire,wire);
  struct model m;llhttp_t parser;llhttp_settings_t settings;init(&parser,&settings,&m);
  /* Reproduce the broken manual-pause callback: execute traverses both
   * requests and returns OK, invalidating the admission boundary. */
  m.bad_pause_api=1;
  enum llhttp_errno e=llhttp_execute(&parser,pipeline,strlen(pipeline));
  assert(e==HPE_OK && m.completed==2);checks++;retire(&m);
  init(&parser,&settings,&m);
  e=llhttp_execute(&parser,pipeline,strlen(pipeline));
  assert(e==HPE_PAUSED && m.completed==1 && llhttp_get_error_pos(&parser)==pipeline+wn);checks++;
  assert(llhttp_get_error_pos(&parser)!=pipeline+strlen(pipeline));m.refused++;
  assert(!m.delivered && m.alive);checks++;retire(&m);
  init(&parser,&settings,&m);
  const char *empty="POST /mcp HTTP/1.1\r\nHost: example\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/list\r\nContent-Length: 0\r\n\r\n";
  e=llhttp_execute(&parser,empty,strlen(empty));assert(e!=HPE_OK && m.validation_status==400 && m.refused==1 && m.alive);checks++;retire(&m);
  printf("PASS %u portable MCP capture/framing model checks (not Gateway integration)\n",checks);return 0;
}
