#!/usr/bin/env python3
"""Compile the actual H2/H1 response callbacks with llhttp and relay mocks.

This is a parser/adapter regression test, not a live Gateway qualification.
Callbacks are extracted from current production source; a syntax marker change
fails explicitly rather than silently running a stale copy.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
source = (ROOT / "sockproxy_h2.c").read_text()
start = source.index("static int h2_h1_hop(")
end = source.index("static backend_h2_session_t *h2_h1_session_new", start)
callbacks = source[start:end]
PREFIX = r'''
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include "llhttp.h"
#include "sockproxy_mcp_capture.h"
#define NGHTTP2_NV_FLAG_NONE 0
#define NGHTTP2_HEADERS 1
#define NGHTTP2_DATA 0
#define NGHTTP2_FLAG_END_STREAM 1
#define NGHTTP2_NO_ERROR 0
#define H2_SESSION_HIGH_WATER (50U*1024U*1024U)
typedef struct {uint8_t *name,*value;size_t namelen,valuelen;uint8_t flags;} nghttp2_nv;
typedef struct {struct {int type,stream_id,flags;} hd;} nghttp2_frame;
typedef struct {int metric_response_status;} proxy_h2_stream_t;
typedef struct {size_t total_response_buffer_size;proxy_h2_stream_t stream;} proxy_h2_session_t;
typedef struct {nghttp2_nv *response_headers;size_t response_headers_count;int client_stream_id;} stream_mapping_t;
typedef struct {
 proxy_h2_session_t *client_session;stream_mapping_t *stream_map;
 int bridge_cancelled,bridge_done,bridge_value_started,backend_fd;
 char bridge_field[128],bridge_value[16384];
 size_t bridge_field_len,bridge_value_len,bridge_header_bytes;
 llhttp_t parser;llhttp_settings_t settings;
 char body[4096];size_t body_len;int statuses[10],nstatus,completed;
} backend_h2_session_t;
static unsigned checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);abort();}} while(0)
static proxy_h2_stream_t *find_stream(proxy_h2_session_t *s,int id) {(void)id;return &s->stream;}
static void clear_headers(stream_mapping_t *m) {
 for(size_t i=0;i<m->response_headers_count;i++){free(m->response_headers[i].name);free(m->response_headers[i].value);}
 free(m->response_headers);m->response_headers=NULL;m->response_headers_count=0;
}
static int proxy_h2_inject_resp_headers(stream_mapping_t *m,const nghttp2_nv *nv,int n) {
 CHECK(n==1);size_t i=m->response_headers_count++;
 m->response_headers=realloc(m->response_headers,m->response_headers_count*sizeof(*nv));CHECK(m->response_headers);
 m->response_headers[i]=*nv;
 m->response_headers[i].name=malloc(nv->namelen+1);m->response_headers[i].value=malloc(nv->valuelen+1);
 CHECK(m->response_headers[i].name&&m->response_headers[i].value);
 memcpy(m->response_headers[i].name,nv->name,nv->namelen);m->response_headers[i].name[nv->namelen]=0;
 memcpy(m->response_headers[i].value,nv->value,nv->valuelen);m->response_headers[i].value[nv->valuelen]=0;
 return 1;
}
static int proxy_h2_backend_on_frame_recv_callback(void *sess,const nghttp2_frame *f,void *arg) {
 (void)sess;backend_h2_session_t *bs=arg;stream_mapping_t *m=bs->stream_map;
 if(f->hd.type==NGHTTP2_HEADERS){
  CHECK(m->response_headers_count);CHECK(!strcmp((char*)m->response_headers[0].name,":status"));
  CHECK(bs->nstatus<10);bs->statuses[bs->nstatus++]=atoi((char*)m->response_headers[0].value);
  for(size_t i=1;i<m->response_headers_count;i++) {
   CHECK(m->response_headers[i].name[0]!=':');
   CHECK(strcmp((char*)m->response_headers[i].name,"connection"));
   CHECK(strcmp((char*)m->response_headers[i].name,"transfer-encoding"));
   CHECK(strcmp((char*)m->response_headers[i].name,"x-remove"));
  }
  clear_headers(m);
 }else {CHECK(f->hd.flags==NGHTTP2_FLAG_END_STREAM);bs->completed++;}
 return 0;
}
static int proxy_h2_backend_on_data_chunk_recv_callback(void *sess,int flags,int id,const uint8_t *data,size_t len,void *arg) {
 (void)sess;(void)flags;(void)id;backend_h2_session_t *bs=arg;
 CHECK(len<=sizeof(bs->body)-bs->body_len);memcpy(bs->body+bs->body_len,data,len);bs->body_len+=len;return 0;
}
static int proxy_h2_backend_on_stream_close_callback(void *sess,int id,int code,void *arg) {
 (void)sess;(void)id;(void)code;(void)arg;return 0;
}
'''
SUFFIX = r'''
static void init(backend_h2_session_t *bs,proxy_h2_session_t *cs,stream_mapping_t *m) {
 memset(bs,0,sizeof(*bs));memset(cs,0,sizeof(*cs));memset(m,0,sizeof(*m));
 bs->client_session=cs;bs->stream_map=m;bs->backend_fd=-1;
 llhttp_settings_init(&bs->settings);
 bs->settings.on_message_begin=h2_h1_begin;bs->settings.on_header_field=h2_h1_field;
 bs->settings.on_header_value=h2_h1_value;bs->settings.on_header_value_complete=h2_h1_value_done;
 bs->settings.on_headers_complete=h2_h1_headers_done;bs->settings.on_body=h2_h1_body;
 bs->settings.on_message_complete=h2_h1_complete;
 llhttp_init(&bs->parser,HTTP_RESPONSE,&bs->settings);bs->parser.data=bs;
}
static void split_case(const char *raw,int valid,int eof,const char *body,int statuses) {
 size_t n=strlen(raw);
 for(size_t cut=0;cut<=n;cut++) {
  backend_h2_session_t bs;proxy_h2_session_t cs;stream_mapping_t m;init(&bs,&cs,&m);
  llhttp_errno_t err=llhttp_execute(&bs.parser,raw,cut);
  if(err==HPE_OK)err=llhttp_execute(&bs.parser,raw+cut,n-cut);
  if(err==HPE_OK&&eof)err=llhttp_finish(&bs.parser);
  if(valid){CHECK(err==HPE_PAUSED);CHECK(bs.bridge_done);CHECK(bs.completed==1);CHECK(bs.nstatus==statuses);
   CHECK(bs.body_len==strlen(body));CHECK(!memcmp(bs.body,body,bs.body_len));
  }else{CHECK(err!=HPE_OK&&err!=HPE_PAUSED);CHECK(!bs.bridge_done);CHECK(!bs.completed);}
  clear_headers(&m);
 }
}
int main(void){
 split_case("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",1,0,"{}",1);
 split_case("HTTP/1.1 200 OK\r\nConnection: x-remove, close\r\nX-Remove: secret\r\nContent-Length: 0\r\n\r\n",1,0,"",1);
 split_case("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",1,0,"{}",2);
 split_case("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na\nb\r\n2\r\ncd\r\n0\r\n\r\n",1,0,"a\nbcd",1);
 split_case("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}",1,1,"{}",1);
 split_case("HTTP/1.1 204 No Content\r\n\r\n",1,0,"",1);
 split_case("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",0,1,"",0);
 split_case("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",0,1,"",0);
 split_case("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: no\r\n\r\n",0,1,"",0);
 split_case("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",0,1,"",0);
 split_case("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",0,1,"",0);
 split_case("HTTP/1.1 101 Switching Protocols\r\n\r\n",0,1,"",0);
 split_case("HTTP/1.1 999 Bad\r\nContent-Length: 0\r\n\r\n",0,1,"",0);
 backend_h2_session_t bs;proxy_h2_session_t cs;stream_mapping_t m;init(&bs,&cs,&m);
 const char *first="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n";
 CHECK(llhttp_execute(&bs.parser,first,strlen(first))==HPE_OK);CHECK(bs.body_len==3&&!bs.completed);
 cs.total_response_buffer_size=H2_SESSION_HIGH_WATER;
 CHECK(llhttp_execute(&bs.parser,"1\r\nx\r\n",6)!=HPE_OK);CHECK(!bs.completed);clear_headers(&m);
 init(&bs,&cs,&m);bs.bridge_cancelled=1;
 CHECK(llhttp_execute(&bs.parser,first,strlen(first))!=HPE_OK);CHECK(!bs.body_len&&!bs.completed);clear_headers(&m);
 init(&bs,&cs,&m);const char *extra="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
 CHECK(llhttp_execute(&bs.parser,extra,strlen(extra))==HPE_PAUSED);
 CHECK(llhttp_get_error_pos(&bs.parser)!=extra+strlen(extra));CHECK(bs.completed==1);clear_headers(&m);
 printf("PASS %u actual bridge callback/parser checks\n",checks);return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="mcp-bridge-") as tmp:
    c = Path(tmp) / "bridge.c"
    exe = Path(tmp) / "bridge"
    c.write_text(PREFIX + callbacks + SUFFIX)
    cmd = [os.environ.get("CC", "clang"), "-std=c11", "-Wall", "-Wextra",
           "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
           "-fno-omit-frame-pointer", "-g", "-I", str(ROOT), str(c),
           str(ROOT / "llhttp.c"), str(ROOT / "httpapi.c"), str(ROOT / "http.c"),
           "-o", str(exe)]
    subprocess.run(cmd, check=True)
    subprocess.run([str(exe)], check=True)
