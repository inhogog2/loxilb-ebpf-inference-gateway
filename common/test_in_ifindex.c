/*
 * The ingress-interface read (sockproxy_in_ifindex.h), on a real loopback
 * connection: the accepted socket reports the loopback device, the read
 * leaves the socket's IP_PKTINFO option as it found it, a connecting
 * socket and a socket that is not one report a failure and never an index,
 * and the cached form reads once.
 *
 * Needs no privilege and no network beyond loopback.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "sockproxy_in_ifindex.h"

static int listener(struct sockaddr_in *addr)
{
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  socklen_t len = sizeof(*addr);

  assert(fd >= 0);
  memset(addr, 0, sizeof(*addr));
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  assert(bind(fd, (struct sockaddr *)addr, sizeof(*addr)) == 0);
  assert(listen(fd, 4) == 0);
  assert(getsockname(fd, (struct sockaddr *)addr, &len) == 0);
  return fd;
}

static int pktinfo_flag(int fd)
{
  int v = -1;
  socklen_t len = sizeof(v);

  assert(getsockopt(fd, IPPROTO_IP, IP_PKTINFO, &v, &len) == 0);
  return v;
}

/* An accepted loopback connection arrived on the loopback device. */
static void
test_accepted_socket_reports_its_device(void)
{
  struct sockaddr_in addr;
  int lfd = listener(&addr);
  int cfd = socket(AF_INET, SOCK_STREAM, 0);
  int afd, lo = (int)if_nametoindex("lo");
  int32_t idx;

  assert(lo > 0);
  assert(connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
  afd = accept(lfd, NULL, NULL);
  assert(afd >= 0);

  /* The option was off, as on a listener that never asked for it: the read
   * still answers, and puts the option back. */
  assert(pktinfo_flag(afd) == 0);
  idx = sp_in_ifindex_read(afd);
  assert(idx == lo);
  assert(pktinfo_flag(afd) == 0);

  /* Read again after data flowed: the same device. */
  assert(write(cfd, "x", 1) == 1);
  assert(sp_in_ifindex_read(afd) == lo);

  /* A socket that already had the option keeps it. */
  {
    int on = 1;
    assert(setsockopt(afd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == 0);
    assert(sp_in_ifindex_read(afd) == lo);
    assert(pktinfo_flag(afd) == 1);
  }

  /* The connecting side has no ingress device: a failure, never an index. */
  assert(sp_in_ifindex_read(cfd) == SP_IN_IFINDEX_FAILED);
  assert(pktinfo_flag(cfd) == 0);

  close(afd);
  close(cfd);
  close(lfd);
}

/* Not a socket, a closed descriptor, a socket of another family. */
static void
test_bad_descriptors_fail(void)
{
  int p[2], u;

  assert(sp_in_ifindex_read(-1) == SP_IN_IFINDEX_FAILED);
  assert(pipe(p) == 0);
  assert(sp_in_ifindex_read(p[0]) == SP_IN_IFINDEX_FAILED);
  close(p[0]);
  close(p[1]);
  assert(sp_in_ifindex_read(p[0]) == SP_IN_IFINDEX_FAILED);
  u = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(u >= 0);
  assert(sp_in_ifindex_read(u) == SP_IN_IFINDEX_FAILED);
  close(u);
}

/* The control buffer as the kernel hands it back. */
static void
test_cmsg_parse(void)
{
  union {
    char buf[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } c;
  struct msghdr mh;
  struct cmsghdr *cm;
  struct in_pktinfo pi;

  /* Nothing in it. */
  assert(sp_in_ifindex_cmsg(c.buf, 0) == SP_IN_IFINDEX_FAILED);

  /* Another option first, then the packet info. */
  memset(&c, 0, sizeof(c));
  memset(&mh, 0, sizeof(mh));
  mh.msg_control = c.buf;
  mh.msg_controllen = sizeof(c.buf);
  cm = CMSG_FIRSTHDR(&mh);
  cm->cmsg_level = IPPROTO_IP;
  cm->cmsg_type = IP_TTL;
  cm->cmsg_len = CMSG_LEN(sizeof(int));
  cm = CMSG_NXTHDR(&mh, cm);
  assert(cm);
  cm->cmsg_level = IPPROTO_IP;
  cm->cmsg_type = IP_PKTINFO;
  cm->cmsg_len = CMSG_LEN(sizeof(pi));
  memset(&pi, 0, sizeof(pi));
  pi.ipi_ifindex = 42;
  memcpy(CMSG_DATA(cm), &pi, sizeof(pi));
  assert(sp_in_ifindex_cmsg(c.buf, sizeof(c.buf)) == 42);

  /* An index of zero or below is not an interface. */
  pi.ipi_ifindex = 0;
  memcpy(CMSG_DATA(cm), &pi, sizeof(pi));
  assert(sp_in_ifindex_cmsg(c.buf, sizeof(c.buf)) == SP_IN_IFINDEX_FAILED);
  pi.ipi_ifindex = -3;
  memcpy(CMSG_DATA(cm), &pi, sizeof(pi));
  assert(sp_in_ifindex_cmsg(c.buf, sizeof(c.buf)) == SP_IN_IFINDEX_FAILED);

  /* A packet info shorter than the structure is not read, whatever its
   * first bytes say. */
  pi.ipi_ifindex = 42;
  memcpy(CMSG_DATA(cm), &pi, sizeof(pi));
  cm->cmsg_len = CMSG_LEN(sizeof(pi) - 4);
  assert(sp_in_ifindex_cmsg(c.buf, sizeof(c.buf)) == SP_IN_IFINDEX_FAILED);

  /* Only the other option. */
  assert(sp_in_ifindex_cmsg(c.buf, CMSG_SPACE(sizeof(int))) ==
         SP_IN_IFINDEX_FAILED);
}

/* The cached form: nothing while it is not wanted, one read when it is, the
 * result kept whether it is an index or a failure. */
static void
test_cached_reads_once(void)
{
  struct sockaddr_in addr;
  int lfd = listener(&addr);
  int cfd = socket(AF_INET, SOCK_STREAM, 0);
  int afd, lo = (int)if_nametoindex("lo");
  int32_t slot = 0;

  assert(connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
  afd = accept(lfd, NULL, NULL);
  assert(afd >= 0);

  /* Not wanted: no read, the slot stays "not read", the answer is 0. */
  assert(sp_in_ifindex_cached(&slot, afd, 0) == 0 && slot == 0);
  /* Wanted: read and kept. */
  assert(sp_in_ifindex_cached(&slot, afd, 1) == lo && slot == lo);
  /* Kept: a descriptor that can no longer answer is not asked. */
  assert(sp_in_ifindex_cached(&slot, -1, 1) == lo);
  assert(sp_in_ifindex_cached(&slot, -1, 0) == lo);

  /* A failed read is kept as a failure and answered as "not known". */
  slot = 0;
  assert(sp_in_ifindex_cached(&slot, cfd, 1) == 0);
  assert(slot == SP_IN_IFINDEX_FAILED);
  assert(sp_in_ifindex_cached(&slot, afd, 1) == 0);
  assert(slot == SP_IN_IFINDEX_FAILED);

  close(afd);
  close(cfd);
  close(lfd);
}

int
main(void)
{
  test_accepted_socket_reports_its_device();
  test_bad_descriptors_fail();
  test_cmsg_parse();
  test_cached_reads_once();
  puts("PASS: ingress interface of an accepted connection: read, restored, cached once");
  return 0;
}
