/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "security_ipv6.h"

static unsigned char packet[256];
static void init(unsigned char protocol, unsigned int payload) {
    memset(packet,0,sizeof(packet));packet[0]=0x60;packet[6]=protocol;
    packet[4]=payload>>8;packet[5]=payload;
}
static struct security_ipv6_transport parse(unsigned int length) {
    return security_ipv6_transport(packet,packet+length);
}
int main(void) {
    struct security_ipv6_transport r;
    init(17,8);r=parse(48);assert(r.status==0 && r.protocol==17 && r.offset==40 && !r.fragmented);
    init(60,16);packet[40]=17;r=parse(56);assert(r.status==0 && r.protocol==17 && r.offset==48);
    init(0,24);packet[40]=43;packet[48]=17;r=parse(64);assert(r.status==0 && r.protocol==17 && r.offset==56);
    init(51,20);packet[40]=6;packet[41]=1;r=parse(60);assert(r.status==0 && r.protocol==6 && r.offset==52);
    init(44,16);packet[40]=17;packet[43]=1;r=parse(56);assert(r.status==0 && r.fragmented && r.protocol==17 && r.offset==48);
    packet[43]=8;r=parse(56);assert(r.status==SECURITY_IPV6_NONINITIAL_FRAGMENT && r.fragmented);
    packet[43]=0;r=parse(56);assert(r.status==0 && r.fragmented); /* atomic fragment */
    init(60,16);packet[40]=17;packet[41]=20;r=parse(56);assert(r.status==SECURITY_IPV6_MALFORMED);
    init(60,1);r=parse(48);assert(r.status==SECURITY_IPV6_MALFORMED); /* padding is not payload */
    init(17,8);r=parse(47);assert(r.status==SECURITY_IPV6_MALFORMED);
    init(44,7);r=parse(47);assert(r.status==SECURITY_IPV6_MALFORMED);
    init(60,80);for(int i=0;i<9;i++)packet[40+i*8]=i==8?17:60;
    r=parse(120);assert(r.status==SECURITY_IPV6_TOO_DEEP);
    init(60,72);for(int i=0;i<8;i++)packet[40+i*8]=i==7?17:60;
    r=parse(112);assert(r.status==0 && r.protocol==17 && r.offset==104);
    init(50,8);r=parse(48);assert(r.status==0 && r.protocol==50); /* ESP stays opaque */
    init(44,24);packet[40]=44;packet[48]=17;r=parse(64);
    assert(r.status==SECURITY_IPV6_MALFORMED && r.fragmented); /* duplicate fragment */
    init(44,16);packet[40]=58;packet[43]=8;r=parse(56);
    assert(r.status==SECURITY_IPV6_NONINITIAL_FRAGMENT && r.protocol==58); /* ICMP is not UDP */
    puts("SECURITY_IPV6_HEADER_WALK_PASS");return 0;
}
