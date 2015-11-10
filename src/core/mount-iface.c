/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Werner Fink

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

/*
 * Find the name of the network interface to which a IP address belongs to.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <assert.h>

#include "log.h"
#include "def.h"
#include "mount-iface.h"

static struct ifaddrs *ifa_list;

_pure_ static unsigned int mask2prefix(const void* ipv6)
{
        unsigned int nippels = 0;
        unsigned int i;

        assert(ipv6);

        for (i = 0; i < sizeof(struct in6_addr); i++) {
                uint8_t byte = ((const uint8_t*)ipv6)[i];
                if (byte == 0xFF) {
                        nippels += sizeof(uint8_t);
                        continue;
                }
                while (byte & 0x80) {
                        nippels++;
                        byte <<= 1;
                }
                break;
        }

        return nippels;
}

static void netmask(unsigned int prefix, const void* in6, void* out6)
{
        unsigned int nippels;
        unsigned int i;

        assert(in6);
        assert(out6);

        for (i = 0; i < sizeof(struct in6_addr); i++) {
                nippels = (prefix < sizeof(uint8_t)) ? prefix : sizeof(uint8_t);
                ((uint8_t*)out6)[i] = ((const uint8_t*)in6)[i] & (0xFF00>>nippels);
                prefix -= nippels;
        }
}

char *host2iface(const char *ip)
{
        const struct ifaddrs *ifa;
        uint32_t ip4 = 0;
        char *ret = NULL;
        struct search {
                union {
                        struct in_addr   addr;
                        struct in6_addr addr6;
                };
                int family;
        } host;
        int r;

        if (!ifa_list && (getifaddrs(&ifa_list) < 0)) {
                log_oom();
                goto err;
        }

        if (strchr(ip, ':')) {
                r = inet_pton(AF_INET6, ip, &host.addr6);
                host.family = AF_INET6;
        } else {
                r = inet_pton(AF_INET, ip, &host.addr);
                host.family = AF_INET;
        }

        if (r < 0) {
                log_error("Failed to convert IP address %s from text to binary: %m", ip);
                goto err;
        }

        for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {

                if (!ifa->ifa_addr)
                        continue;
                if (ifa->ifa_flags & IFF_POINTOPOINT)
                        continue;
                if (!ifa->ifa_addr)
                        continue;
                if (!ifa->ifa_netmask)
                        continue;

                if (ifa->ifa_addr->sa_family == AF_INET) {
                        uint32_t addr, dest, mask;

                        if (host.family != AF_INET)
                                continue;
                        if (!ifa->ifa_broadaddr)
                                continue;

                        if (!ip4)
                                ip4 = (uint32_t)ntohl(host.addr.s_addr);

                        addr = (uint32_t)ntohl(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr);
                        if ((addr & 0xFF000000) == 0x7F000000)            /* IPV4 loopback */
                                continue;

                        mask = (uint32_t)ntohl(((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr.s_addr);
                        dest = (uint32_t)ntohl(((struct sockaddr_in*)ifa->ifa_broadaddr)->sin_addr.s_addr);
                        if ((ip4 & mask) != (dest & mask))
                                continue;

                        ret = ifa->ifa_name;
                        break;        
                } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                        struct in6_addr *addr, *mask, dest, ip6;
                        unsigned int prefix;

                        if (host.family != AF_INET6)
                                continue;

                        addr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
                        mask = &((struct sockaddr_in6*)ifa->ifa_netmask)->sin6_addr;
                        prefix = mask2prefix(mask);

                        netmask(prefix, addr, &dest);
                        netmask(prefix, &host.addr6, &ip6);

                        if (memcmp(&dest, &ip6, sizeof(struct in6_addr)) != 0)
                                continue;

                        ret = ifa->ifa_name;
                        break;
                }
        }
err:
        return ret;
}

void freeroutes(void)
{
        if (ifa_list)
                freeifaddrs(ifa_list);
        ifa_list = NULL;
}
