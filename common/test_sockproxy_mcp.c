/* Copyright (c) 2026 LoxiLB Authors; SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "sockproxy_mcp.h"
#define META "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}"
static struct sp_mcp_request req;
static unsigned checks;
static void header(const char *k, const char *v) { sp_mcp_header(&req,k,strlen(k),v,strlen(v)); }
static void setup(const char *method, const char *name) {
  sp_mcp_reset(&req); header("MCP-Protocol-Version", SP_MCP_VERSION); header("Mcp-Method",method);
  if (name) header("Mcp-Name",name);
}
static void expect(const char *body, int status) {
  int got = sp_mcp_validate(&req,"POST",body,strlen(body));
  if (got != status) { fprintf(stderr,"expected %d got %d: %s\n",status,got,body); abort(); }
  checks++;
}
int main(void) {
  const char *valid = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META "}}";
  setup("tools/call","echo"); expect(valid,0);
  /* Fragmentation boundaries do not erase or overwrite duplicate detection. */
  sp_mcp_reset(&req);
  sp_mcp_header_begin(&req); sp_mcp_header_name(&req,"MCP-Proto",9); sp_mcp_header_name(&req,"col-Version",11);
  sp_mcp_header_value(&req,"2026-",5); sp_mcp_header_value(&req,"07-28",5); sp_mcp_header_end(&req);
  header("mCp-MeThOd","tools/call"); header("mcp-name","echo"); expect(valid,0);
  header("MCP-NAME","echo"); expect(valid,400);
  setup("tools/call","echo"); header("MCP-Protocol-Version",SP_MCP_VERSION); expect(valid,400);
  setup("tools/call","echo"); header("MCP-METHOD","tools/call"); expect(valid,400);
  setup("tools/call","bad"); expect(valid,400);
  setup("tools/call",NULL); expect(valid,400);
  setup("tools/list",NULL); expect(valid,400);
  setup("tools/call","echo"); header("MCP-Session-ID","obsolete"); header("Last-Event-ID","obsolete");
  header("Mcp-Param-unknown","anything"); expect(valid,0);
  assert(sp_mcp_validate(&req,"GET",valid,strlen(valid))==405); checks++;
  assert(sp_mcp_validate(&req,"POST",valid,SP_MCP_BODY_MAX+1)==413); checks++;
  setup("tools/call","echo");
  const char *bad[] = {"", "null", "[]", "{}", "true", "{", "{\"method\":\"tools/call\"}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":null}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":01}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":1.}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":1e}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":tru}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":[1,]}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":{\"a\":1,\"\\u0061\":2}}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":\"\\ud800\"}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":\"\\udc00\"}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META ",\"x\":\"\\q\"}}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"," META "},\"id\":null}"};
  for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) expect(bad[i],400);
  /* Every prefix cut fails closed. */
  for(size_t i=0;i<strlen(valid);i++) { assert(sp_mcp_validate(&req,"POST",valid,i)==400); checks++; }
  char trailing[1024]; snprintf(trailing,sizeof(trailing),"%s garbage",valid); expect(trailing,400);
  snprintf(trailing,sizeof(trailing),"%s {}",valid); expect(trailing,400);
  expect("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"e\\u0063ho\"," META ",\"extra\":[null,true,false,1.2e-3,{\"q\":\"\\ud83d\\ude00\"}]}}",0);
  setup("tools/call","=?base64?ZWNobw==?="); expect(valid,0);
  assert(req.name_len==4 && !memcmp(req.name,"echo",4)); checks++;
  setup("tools/call","=?base64?7ZWc6riA?=");
  expect("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"\\ud55c\\uae00\"," META "}}",0);
  setup("tools/call","=?base64?ZQpj?=");
  expect("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"e\\nc\"," META "}}",0);
  setup("tools/call","=?base64?ZQBj?=");
  expect("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"e\\u0000c\"," META "}}",0);
  setup("tools/call","=?base64?PT9iYXNlNjQ/WlFOaj89?=");
  expect("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"=?base64?ZQNj?=\"," META "}}",0);
  const char *encbad[]={"=?base64?Zg=?=","=?base64?Zh==?=","=?base64?Zm9=?=","=?base64?Z!==?=","=?base64?Zg==Zg==?=","=?base64?wIA=?=","=?base64?7aCA?=","=?base64?9JCAgA==?=","한글"};
  for(size_t i=0;i<sizeof(encbad)/sizeof(encbad[0]);i++){setup("tools/call",encbad[i]);assert(req.error==400);checks++;}
  setup("tools/list",NULL);
  expect("{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"params\":{" META "}}",0);
  header("Mcp-Name","unused"); expect("{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"params\":{" META "}}",400);
  setup("prompts/get","echo"); expect("{\"jsonrpc\":\"2.0\",\"method\":\"prompts/get\",\"params\":{\"name\":\"echo\"," META "}}",0);
  setup("resources/read","file:///a"); expect("{\"jsonrpc\":\"2.0\",\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///a\"," META "}}",0);
  char *huge=malloc(SP_MCP_HEADER_VALUE_MAX+2); assert(huge); memset(huge,'x',SP_MCP_HEADER_VALUE_MAX+1); huge[SP_MCP_HEADER_VALUE_MAX+1]=0;
  setup("tools/call",huge); assert(req.error==413); checks++; free(huge);
  char nested[256]; unsigned k=0;
  for(unsigned i=0;i<SP_MCP_DEPTH_MAX+2;i++)nested[k++]='[';
  nested[k++]='0';for(unsigned i=0;i<SP_MCP_DEPTH_MAX+2;i++)nested[k++]=']';nested[k]=0;
  setup("tools/call","echo");expect(nested,413);
  /* Token limits and long-name boundaries reject rather than truncate. */
  size_t cap = SP_MCP_NAME_MAX + 512;
  char *longbody = malloc(cap), *longname = malloc(SP_MCP_NAME_MAX + 2);
  assert(longbody && longname);
  memset(longname, 'x', SP_MCP_NAME_MAX); longname[SP_MCP_NAME_MAX] = 0;
  setup("tools/call",longname);
  snprintf(longbody,cap,"{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"%s\"," META "}}",longname);
  expect(longbody,0); assert(req.name_len==SP_MCP_NAME_MAX);checks++;
  longname[SP_MCP_NAME_MAX]='x';longname[SP_MCP_NAME_MAX+1]=0;
  setup("tools/call",longname); assert(req.error==413);checks++;
  char *enc = malloc(SP_MCP_HEADER_VALUE_MAX + 1); assert(enc);
  memcpy(enc,"=?base64?",9); size_t eo=9;
  for(size_t i=0;i<SP_MCP_NAME_MAX/3;i++){memcpy(enc+eo,"eHh4",4);eo+=4;}
  memcpy(enc+eo,"eA==?=",6);eo+=6;enc[eo]=0;
  setup("tools/call",enc); assert(req.error==0 && req.name_len==SP_MCP_NAME_MAX);checks++;
  free(enc);free(longname);free(longbody);
  char *many=malloc(SP_MCP_TOKENS_MAX*2+4); assert(many);
  many[0]='['; size_t off=1;
  for(unsigned i=0;i<SP_MCP_TOKENS_MAX;i++){many[off++]='0';many[off++]=',';}
  many[off-1]=']';many[off]=0;
  setup("tools/call","echo");expect(many,413);free(many);
  setup("tools/call","=?base64?" "?=");
  expect("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"\"," META "}}",0);
  setup("tools/call","echo");
  sp_mcp_header(&req,"bad\0name",8,"x",1);assert(req.error==400);checks++;
  setup("tools/call","echo");
  /* Deterministic byte mutations exercise parser memory safety under sanitizers. */
  size_t vl=strlen(valid);char copy[1024];
  for(size_t i=0;i<vl;i++)for(unsigned b=0;b<256;b++){
    memcpy(copy,valid,vl);copy[i]=(char)b;
    (void)sp_mcp_validate(&req,"POST",copy,vl);checks++;
  }
  printf("PASS %u MCP validator checks\n",checks); return 0;
}
