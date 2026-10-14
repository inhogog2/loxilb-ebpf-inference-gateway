/*
 * The interface a TCP connection arrived on.
 *
 * The kernel keeps the packet info of the connection's first segment on the
 * accepted socket and hands it back through IP_PKTOPTIONS once IP_PKTINFO
 * is on, also when the option is switched on after accept. The index is of
 * the logical device: the bridge of a tagged VLAN, the VXLAN device, the
 * VTI of an IPsec tunnel. It is fixed for the life of the connection, so a
 * caller reads it once and keeps it.
 *
 * Header-only: a socket in, an index out, no proxy state. The unit test
 * (test_in_ifindex.c) drives it with a loopback connection.
 */
#ifndef __SOCKPROXY_IN_IFINDEX_H__
#define __SOCKPROXY_IN_IFINDEX_H__

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef IP_PKTOPTIONS
#define IP_PKTOPTIONS 9
#endif

/* What a caller caches: 0 is "not read yet", so a failed read is kept as
 * SP_IN_IFINDEX_FAILED and not tried again on every request. */
#define SP_IN_IFINDEX_FAILED (-1)

/*
 * sp_in_ifindex_cmsg - the interface index in a control buffer as
 * IP_PKTOPTIONS returns it. SP_IN_IFINDEX_FAILED when the buffer holds no
 * packet info or the index is not a positive one.
 */
static inline int32_t
sp_in_ifindex_cmsg(void *cbuf, size_t clen)
{
  struct msghdr mh;
  struct cmsghdr *cm;

  memset(&mh, 0, sizeof(mh));
  mh.msg_control = cbuf;
  mh.msg_controllen = clen;
  for (cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
    struct in_pktinfo pi;

    if (cm->cmsg_level != IPPROTO_IP || cm->cmsg_type != IP_PKTINFO)
      continue;
    if (cm->cmsg_len < CMSG_LEN(sizeof(pi)))
      return SP_IN_IFINDEX_FAILED;
    memcpy(&pi, CMSG_DATA(cm), sizeof(pi));
    return pi.ipi_ifindex > 0 ? (int32_t)pi.ipi_ifindex : SP_IN_IFINDEX_FAILED;
  }
  return SP_IN_IFINDEX_FAILED;
}

/*
 * sp_in_ifindex_read - read the ingress interface of an accepted IPv4 TCP
 * socket. Two or three system calls; the socket's IP_PKTINFO option is left
 * as it was found. Returns the index (> 0) or SP_IN_IFINDEX_FAILED.
 */
static inline int32_t
sp_in_ifindex_read(int fd)
{
  /* Room for the packet info and for whatever else the socket's options
   * add; the kernel truncates rather than fails. */
  union {
    char buf[256];
    struct cmsghdr align;
  } c;
  socklen_t clen = sizeof(c.buf);
  int was = 0, on = 1, off = 0, rc;
  socklen_t wlen = sizeof(was);

  if (fd < 0)
    return SP_IN_IFINDEX_FAILED;
  if (getsockopt(fd, IPPROTO_IP, IP_PKTINFO, &was, &wlen) != 0)
    was = 0;
  if (!was && setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) != 0)
    return SP_IN_IFINDEX_FAILED;
  rc = getsockopt(fd, IPPROTO_IP, IP_PKTOPTIONS, c.buf, &clen);
  if (!was)
    (void)setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &off, sizeof(off));
  if (rc != 0)
    return SP_IN_IFINDEX_FAILED;
  return sp_in_ifindex_cmsg(c.buf, (size_t)clen);
}

/*
 * sp_in_ifindex_cached - the index a connection keeps in *slot, read from
 * fd the first time it is asked for while wanted is set. Returns the index,
 * or 0 when it is not known: never read, or the read failed.
 */
static inline int
sp_in_ifindex_cached(int32_t *slot, int fd, int wanted)
{
  if (*slot == 0 && wanted)
    *slot = sp_in_ifindex_read(fd);
  return *slot > 0 ? (int)*slot : 0;
}

#endif /* __SOCKPROXY_IN_IFINDEX_H__ */
