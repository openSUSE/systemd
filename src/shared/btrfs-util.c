/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <stdlib.h>
#include <sys/vfs.h>
#include <sys/stat.h>

#ifdef HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#include "missing.h"
#include "util.h"
#include "path-util.h"
#include "macro.h"
#include "strv.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "btrfs-util.h"

int btrfs_defrag_fd(int fd) {
        assert(fd >= 0);

        if (ioctl(fd, BTRFS_IOC_DEFRAG, NULL) < 0)
                return -errno;

        return 0;
}

int btrfs_defrag(const char *p) {
        _cleanup_close_ int fd = -1;

        fd = open(p, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return btrfs_defrag_fd(fd);
}
