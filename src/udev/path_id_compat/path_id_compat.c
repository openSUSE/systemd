/*
 * path_id_compat.c: compose persistent device path (compat version)
 *
 * Copyright (C) 2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * Logic based on Hannes Reinecke's shell script.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include "libudev.h"

#define PATH_SIZE       16384
#define SYSFS_PATH      "/sys"

static int path_prepend(char **path, const char *fmt, ...)
{
        va_list va;
        char *old;
        char *pre;
        int err;

        old = *path;

        va_start(va, fmt);
        err = vasprintf(&pre, fmt, va);
        va_end(va);
        if (err < 0)
                return err;

        if (old != NULL) {
                err = asprintf(path, "%s-%s", pre, old);
                if (err < 0)
                        return err;
                free(pre);
        } else {
                *path = pre;
        }

        free(old);
        return 0;
}

static struct udev_device *skip_subsystem(struct udev_device *dev, const char *subsys)
{
        struct udev_device *parent = dev;

        while (parent != NULL) {
                const char *subsystem;

                subsystem = udev_device_get_subsystem(parent);
                if (subsystem == NULL || strcmp(subsystem, subsys) != 0)
                        break;
                dev = parent;
                parent = udev_device_get_parent(parent);
        }
        return dev;
}

static struct udev_device *handle_scsi_default(struct udev_device *parent, char **path)
{
        struct udev_device *hostdev;
        int host, bus, target, lun;
        const char *name;
        char *base;
        char *pos;
        DIR *dir;
        struct dirent *dent;
        int basenum;

        hostdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host");
        if (hostdev == NULL)
                return NULL;

        name = udev_device_get_sysname(parent);
        if (sscanf(name, "%d:%d:%d:%d", &host, &bus, &target, &lun) != 4)
                return NULL;

        /* rebase host offset to get the local relative number */
        basenum = -1;
        base = strdup(udev_device_get_syspath(hostdev));
        if (base == NULL)
                return NULL;
        pos = strrchr(base, '/');
        if (pos == NULL) {
                parent = NULL;
                goto out;
        }
        pos[0] = '\0';
        dir = opendir(base);
        if (dir == NULL) {
                parent = NULL;
                goto out;
        }
        for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
                char *rest;
                int i;

                if (dent->d_name[0] == '.')
                        continue;
                if (dent->d_type != DT_DIR && dent->d_type != DT_LNK)
                        continue;
                if (strncmp(dent->d_name, "host", 4) != 0)
                        continue;
                i = strtoul(&dent->d_name[4], &rest, 10);
                if (rest[0] != '\0')
                        continue;
                if (basenum == -1 || i < basenum)
                        basenum = i;
        }
        closedir(dir);
        if (basenum == -1) {
                parent = NULL;
                goto out;
        }
        host -= basenum;

        path_prepend(path, "scsi-%u:%u:%u:%u", host, bus, target, lun);
out:
        free(base);
        return hostdev;
}

static struct udev_device *handle_ata(struct udev_device *parent, char **path)
{
        struct udev_device *hostdev;
        int host, bus, target, lun;
        const char *name;

        hostdev = udev_device_get_parent_with_subsystem_devtype(parent, "scsi", "scsi_host");
        if (hostdev == NULL)
                return NULL;

        name = udev_device_get_sysname(parent);
        if (sscanf(name, "%d:%d:%d:%d", &host, &bus, &target, &lun) != 4)
                return NULL;

        path_prepend(path, "scsi-%u:%u:%u:%u", host, bus, target, lun);
out:
        return hostdev;
}

static struct udev_device *handle_scsi(struct udev_device *parent, char **path)
{
        const char *devtype;
        const char *name;

        devtype = udev_device_get_devtype(parent);
        if (devtype == NULL || strcmp(devtype, "scsi_device") != 0)
                return parent;

        /* lousy scsi sysfs does not have a "subsystem" for the transport */
        name = udev_device_get_syspath(parent);

        if (strstr(name, "/ata") != NULL) {
                parent = handle_ata(parent, path);
                goto out;
        }

        parent = handle_scsi_default(parent, path);
out:
        return parent;
}

int main(int argc, char **argv)
{
        struct udev *udev;
        struct udev_device *dev;
        struct udev_device *parent;
        char syspath[PATH_SIZE];
        char *path = NULL;
        int rc = 1;

        if (argv[1] == NULL) {
                fprintf(stderr, "No device specified\n");
                rc = 2;
                goto exit2;
        }

        udev = udev_new();
        if (udev == NULL)
                goto exit2;

        snprintf(syspath, PATH_SIZE, "%s%s", SYSFS_PATH, argv[1]);
        dev = udev_device_new_from_syspath(udev, syspath);
        if (dev == NULL) {
                fprintf(stderr, "unable to access '%s'\n", argv[1]);
                rc = 3;
                goto exit1;
        }

        /* walk up the chain of devices and compose path */
        parent = dev;
        while (parent != NULL) {
                const char *subsys;

                subsys = udev_device_get_subsystem(parent);

                if (subsys == NULL) {
                        ;
                } else if (strcmp(subsys, "scsi") == 0) {
                        parent = handle_scsi(parent, &path);
                } else if (strcmp(subsys, "pci") == 0) {
                        path_prepend(&path, "pci-%s", udev_device_get_sysname(parent));
                        parent = skip_subsystem(parent, "pci");
                }

                parent = udev_device_get_parent(parent);
        }

        if (path != NULL) {
                printf("ID_PATH_COMPAT=%s\n", path);
                free(path);
                rc = 0;
        }

        udev_device_unref(dev);

exit1:
        udev_unref(udev);

exit2:
        return rc;
}
