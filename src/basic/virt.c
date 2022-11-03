/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "def.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"
#include "virt.h"

static int detect_vm_cpuid(void) {

        /* CPUID is an x86 specific interface. */
#if defined(__i386__) || defined(__x86_64__)

        static const struct {
                const char *cpuid;
                int id;
        } cpuid_vendor_table[] = {
                { "XenVMMXenVMM", VIRTUALIZATION_XEN       },
                { "KVMKVMKVM",    VIRTUALIZATION_KVM       },
                /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
                { "VMwareVMware", VIRTUALIZATION_VMWARE    },
                /* http://msdn.microsoft.com/en-us/library/ff542428.aspx */
                { "Microsoft Hv", VIRTUALIZATION_MICROSOFT },
        };

        uint32_t eax, ecx;
        bool hypervisor;

        /* http://lwn.net/Articles/301888/ */

#if defined (__i386__)
#define REG_a "eax"
#define REG_b "ebx"
#elif defined (__amd64__)
#define REG_a "rax"
#define REG_b "rbx"
#endif

        /* First detect whether there is a hypervisor */
        eax = 1;
        __asm__ __volatile__ (
                /* ebx/rbx is being used for PIC! */
                "  push %%"REG_b"         \n\t"
                "  cpuid                  \n\t"
                "  pop %%"REG_b"          \n\t"

                : "=a" (eax), "=c" (ecx)
                : "0" (eax)
        );

        hypervisor = !!(ecx & 0x80000000U);

        if (hypervisor) {
                union {
                        uint32_t sig32[3];
                        char text[13];
                } sig = {};
                unsigned j;

                /* There is a hypervisor, see what it is */
                eax = 0x40000000U;
                __asm__ __volatile__ (
                        /* ebx/rbx is being used for PIC! */
                        "  push %%"REG_b"         \n\t"
                        "  cpuid                  \n\t"
                        "  mov %%ebx, %1          \n\t"
                        "  pop %%"REG_b"          \n\t"

                        : "=a" (eax), "=r" (sig.sig32[0]), "=c" (sig.sig32[1]), "=d" (sig.sig32[2])
                        : "0" (eax)
                );

                log_debug("Virtualization found, CPUID=%s", sig.text);

                for (j = 0; j < ELEMENTSOF(cpuid_vendor_table); j ++)
                        if (streq(sig.text, cpuid_vendor_table[j].cpuid))
                                return cpuid_vendor_table[j].id;

                return VIRTUALIZATION_VM_OTHER;
        }
#endif
        log_debug("No virtualization found in CPUID");

        return VIRTUALIZATION_NONE;
}

static int detect_vm_device_tree(void) {
#if defined(__arm__) || defined(__aarch64__) || defined(__powerpc__) || defined(__powerpc64__)
        _cleanup_free_ char *hvtype = NULL;
        int r;

        r = read_one_line_file("/proc/device-tree/hypervisor/compatible", &hvtype);
        if (r == -ENOENT) {
                _cleanup_closedir_ DIR *dir = NULL;
                struct dirent *dent;

                if (access("/proc/device-tree/ibm,partition-name", F_OK) == 0 &&
                    access("/proc/device-tree/hmc-managed?", F_OK) == 0 &&
                    access("/proc/device-tree/chosen/qemu,graphic-width", F_OK) != 0)
                        return VIRTUALIZATION_POWERVM;

                dir = opendir("/proc/device-tree");
                if (!dir) {
                        if (errno == ENOENT) {
                                log_debug_errno(errno, "/proc/device-tree: %m");
                                return VIRTUALIZATION_NONE;
                        }
                        return -errno;
                }

                FOREACH_DIRENT(dent, dir, return -errno)
                        if (strstr(dent->d_name, "fw-cfg")) {
                                log_debug("Virtualization QEMU: \"fw-cfg\" present in /proc/device-tree/%s", dent->d_name);
                                return VIRTUALIZATION_QEMU;
                        }

                log_debug("No virtualization found in /proc/device-tree/*");
                return VIRTUALIZATION_NONE;
        } else if (r < 0)
                return r;

        log_debug("Virtualization %s found in /proc/device-tree/hypervisor/compatible", hvtype);
        if (streq(hvtype, "linux,kvm"))
                return VIRTUALIZATION_KVM;
        else if (strstr(hvtype, "xen"))
                return VIRTUALIZATION_XEN;
        else
                return VIRTUALIZATION_VM_OTHER;
#else
        log_debug("This platform does not support /proc/device-tree");
        return VIRTUALIZATION_NONE;
#endif
}

static int detect_vm_dmi(void) {
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)

        static const char *const dmi_vendors[] = {
                "/sys/class/dmi/id/product_name", /* Test this before sys_vendor to detect KVM over QEMU */
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor",
                "/sys/class/dmi/id/bios_vendor"
        };

        static const struct {
                const char *vendor;
                int id;
        } dmi_vendor_table[] = {
                { "KVM",           VIRTUALIZATION_KVM       },
                { "QEMU",          VIRTUALIZATION_QEMU      },
                /* http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 */
                { "VMware",        VIRTUALIZATION_VMWARE    },
                { "VMW",           VIRTUALIZATION_VMWARE    },
                { "innotek GmbH",  VIRTUALIZATION_ORACLE    },
                { "Xen",           VIRTUALIZATION_XEN       },
                { "Bochs",         VIRTUALIZATION_BOCHS     },
                { "Parallels",     VIRTUALIZATION_PARALLELS },
        };
        unsigned i;
        int r;

        for (i = 0; i < ELEMENTSOF(dmi_vendors); i++) {
                _cleanup_free_ char *s = NULL;
                unsigned j;

                r = read_one_line_file(dmi_vendors[i], &s);
                if (r < 0) {
                        if (r == -ENOENT)
                                continue;

                        return r;
                }



                for (j = 0; j < ELEMENTSOF(dmi_vendor_table); j++)
                        if (startswith(s, dmi_vendor_table[j].vendor)) {
                                log_debug("Virtualization %s found in DMI (%s)", s, dmi_vendors[i]);
                                return dmi_vendor_table[j].id;
                        }
        }
#endif

        log_debug("No virtualization found in DMI");

        return VIRTUALIZATION_NONE;
}

static int detect_vm_xen(void) {
        /* Check for Dom0 will be executed later in detect_vm_xen_dom0
           Thats why we dont check the content of /proc/xen/capabilities here. */
        if (access("/proc/xen/capabilities", F_OK) < 0) {
                log_debug("Virtualization XEN not found, /proc/xen/capabilities does not exist");
                return VIRTUALIZATION_NONE;
        }

        log_debug("Virtualization XEN found (/proc/xen/capabilities exists)");
        return  VIRTUALIZATION_XEN;

}

#define XENFEAT_dom0 11 /* xen/include/public/features.h */
#define PATH_FEATURES "/sys/hypervisor/properties/features"
/* Returns false for domU, or true for dom0 */
static bool detect_vm_xen_dom0(void) {
        _cleanup_free_ char *domcap = NULL;
        char *cap, *i;
        int r;

        r = read_one_line_file(PATH_FEATURES, &domcap);
        if (r == 0) {
                unsigned long features;

                r = sscanf(domcap, "%lx", &features);
                if (r == 1) {
                        r = !!(features & (1U << XENFEAT_dom0));
                        log_debug("Virtualization XEN, found %s with value %08lx, "
                                  "XENFEAT_dom0 (indicating the 'hardware domain') is%s set.",
                                  PATH_FEATURES, features, r ? "" : " not");
                        return r ? true : false;
                }
                log_debug("Virtualization XEN, found %s, unhandled content '%s'",
                          PATH_FEATURES, domcap);
        }

        r = read_one_line_file("/proc/xen/capabilities", &domcap);
        if (r == -ENOENT) {
                log_debug("Virtualization XEN not found, /proc/xen/capabilities does not exist");
                return false;
        }
        if (r < 0)
                return r;

        i = domcap;
        while ((cap = strsep(&i, ",")))
                if (streq(cap, "control_d"))
                        break;
        if (!cap) {
                log_debug("Virtualization XEN DomU found (/proc/xen/capabilites)");
                return false;
        }

        log_debug("Virtualization XEN Dom0 ignored (/proc/xen/capabilities)");
        return true;
}

static int detect_vm_hypervisor(void) {
        _cleanup_free_ char *hvtype = NULL;
        int r;

        r = read_one_line_file("/sys/hypervisor/type", &hvtype);
        if (r == -ENOENT)
                return VIRTUALIZATION_NONE;
        if (r < 0)
                return r;

        log_debug("Virtualization %s found in /sys/hypervisor/type", hvtype);

        if (streq(hvtype, "xen"))
                return VIRTUALIZATION_XEN;
        else
                return VIRTUALIZATION_VM_OTHER;
}

static int detect_vm_uml(void) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* Detect User-Mode Linux by reading /proc/cpuinfo */
        f = fopen("/proc/cpuinfo", "re");
        if (!f) {
                if (errno == ENOENT) {
                        log_debug("/proc/cpuinfo not found, assuming no UML virtualization.");
                        return VIRTUALIZATION_NONE;
                }
                return -errno;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *t;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                t = startswith(line, "vendor_id\t: ");
                if (t) {
                        if (startswith(t, "User Mode Linux")) {
                                log_debug("UML virtualization found in /proc/cpuinfo");
                                return VIRTUALIZATION_UML;
                        }

                        break;
                }
        }

        log_debug("UML virtualization not found in /proc/cpuinfo.");
        return VIRTUALIZATION_NONE;
}

static int detect_vm_zvm(void) {

#if defined(__s390__)
        _cleanup_free_ char *t = NULL;
        int r;

        r = get_proc_field("/proc/sysinfo", "VM00 Control Program", WHITESPACE, &t);
        if (r == -ENOENT)
                return VIRTUALIZATION_NONE;
        if (r < 0)
                return r;

        log_debug("Virtualization %s found in /proc/sysinfo", t);
        if (streq(t, "z/VM"))
                return VIRTUALIZATION_ZVM;
        else
                return VIRTUALIZATION_KVM;
#else
        log_debug("This platform does not support /proc/sysinfo");
        return VIRTUALIZATION_NONE;
#endif
}

/* Returns a short identifier for the various VM implementations */
int detect_vm(void) {
        static thread_local int cached_found = _VIRTUALIZATION_INVALID;
        int r;
        bool other = false;

        if (cached_found >= 0)
                return cached_found;

        r = detect_vm_cpuid();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE) {
                if (r == VIRTUALIZATION_VM_OTHER)
                        other = true;
                else
                        goto finish;
        }

        r = detect_vm_dmi();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE) {
                if (r == VIRTUALIZATION_VM_OTHER)
                        other = true;
                else
                        goto finish;
        }

        /* x86 xen will most likely be detected by cpuid. If not (most likely
         * because we're not an x86 guest), then we should try the xen capabilities
         * file next. If that's not found, then we check for the high-level
         * hypervisor sysfs file:
         *
         * https://bugs.freedesktop.org/show_bug.cgi?id=77271 */

        r = detect_vm_xen();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE) {
                if (r == VIRTUALIZATION_VM_OTHER)
                        other = true;
                else
                        goto finish;
        }

        r = detect_vm_hypervisor();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE) {
                if (r == VIRTUALIZATION_VM_OTHER)
                        other = true;
                else
                        goto finish;
        }

        r = detect_vm_device_tree();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE) {
                if (r == VIRTUALIZATION_VM_OTHER)
                        other = true;
                else
                        goto finish;
        }

        r = detect_vm_uml();
        if (r < 0)
                return r;
        if (r != VIRTUALIZATION_NONE) {
                if (r == VIRTUALIZATION_VM_OTHER)
                        other = true;
                else
                        goto finish;
        }

        r = detect_vm_zvm();
        if (r < 0)
                return r;

finish:
        /* x86 xen Dom0 is detected as XEN in hypervisor and maybe others.
         * In order to detect the Dom0 as not virtualization we need to
         * double-check it */
        if (r == VIRTUALIZATION_XEN && detect_vm_xen_dom0())
                r = VIRTUALIZATION_NONE;
        else if (r == VIRTUALIZATION_NONE && other)
                r = VIRTUALIZATION_VM_OTHER;

        cached_found = r;
        log_debug("Found VM virtualization %s", virtualization_to_string(r));
        return r;
}

int detect_container(void) {

        static const struct {
                const char *value;
                int id;
        } value_table[] = {
                { "lxc",            VIRTUALIZATION_LXC            },
                { "lxc-libvirt",    VIRTUALIZATION_LXC_LIBVIRT    },
                { "systemd-nspawn", VIRTUALIZATION_SYSTEMD_NSPAWN },
                { "docker",         VIRTUALIZATION_DOCKER         },
                { "rkt",            VIRTUALIZATION_RKT            },
        };

        static thread_local int cached_found = _VIRTUALIZATION_INVALID;
        _cleanup_free_ char *m = NULL;
        const char *e = NULL;
        unsigned j;
        int r;

        if (cached_found >= 0)
                return cached_found;

        /* /proc/vz exists in container and outside of the container,
         * /proc/bc only outside of the container. */
        if (access("/proc/vz", F_OK) >= 0 &&
            access("/proc/bc", F_OK) < 0) {
                r = VIRTUALIZATION_OPENVZ;
                goto finish;
        }

        if (getpid() == 1) {
                /* If we are PID 1 we can just check our own
                 * environment variable */

                e = getenv("container");
                if (isempty(e)) {
                        r = VIRTUALIZATION_NONE;
                        goto finish;
                }
        } else {

                /* Otherwise, PID 1 dropped this information into a
                 * file in /run. This is better than accessing
                 * /proc/1/environ, since we don't need CAP_SYS_PTRACE
                 * for that. */

                r = read_one_line_file("/run/systemd/container", &m);
                if (r == -ENOENT) {

                        /* Fallback for cases where PID 1 was not
                         * systemd (for example, cases where
                         * init=/bin/sh is used. */

                        r = getenv_for_pid(1, "container", &m);
                        if (r <= 0) {

                                /* If that didn't work, give up,
                                 * assume no container manager.
                                 *
                                 * Note: This means we still cannot
                                 * detect containers if init=/bin/sh
                                 * is passed but privileges dropped,
                                 * as /proc/1/environ is only readable
                                 * with privileges. */

                                r = VIRTUALIZATION_NONE;
                                goto finish;
                        }
                }
                if (r < 0)
                        return r;

                e = m;
        }

        for (j = 0; j < ELEMENTSOF(value_table); j++)
                if (streq(e, value_table[j].value)) {
                        r = value_table[j].id;
                        goto finish;
                }

        r = VIRTUALIZATION_CONTAINER_OTHER;

finish:
        log_debug("Found container virtualization %s", virtualization_to_string(r));
        cached_found = r;
        return r;
}

int detect_virtualization(void) {
        int r;

        r = detect_container();
        if (r == 0)
                r = detect_vm();

        return r;
}

int running_in_chroot(void) {
        int ret;

        ret = files_same("/proc/1/root", "/");
        if (ret < 0)
                return ret;

        return ret == 0;
}

static const char *const virtualization_table[_VIRTUALIZATION_MAX] = {
        [VIRTUALIZATION_NONE] = "none",
        [VIRTUALIZATION_KVM] = "kvm",
        [VIRTUALIZATION_QEMU] = "qemu",
        [VIRTUALIZATION_BOCHS] = "bochs",
        [VIRTUALIZATION_XEN] = "xen",
        [VIRTUALIZATION_UML] = "uml",
        [VIRTUALIZATION_VMWARE] = "vmware",
        [VIRTUALIZATION_ORACLE] = "oracle",
        [VIRTUALIZATION_MICROSOFT] = "microsoft",
        [VIRTUALIZATION_ZVM] = "zvm",
        [VIRTUALIZATION_PARALLELS] = "parallels",
        [VIRTUALIZATION_POWERVM] = "powervm",
        [VIRTUALIZATION_VM_OTHER] = "vm-other",

        [VIRTUALIZATION_SYSTEMD_NSPAWN] = "systemd-nspawn",
        [VIRTUALIZATION_LXC_LIBVIRT] = "lxc-libvirt",
        [VIRTUALIZATION_LXC] = "lxc",
        [VIRTUALIZATION_OPENVZ] = "openvz",
        [VIRTUALIZATION_DOCKER] = "docker",
        [VIRTUALIZATION_RKT] = "rkt",
        [VIRTUALIZATION_CONTAINER_OTHER] = "container-other",
};

DEFINE_STRING_TABLE_LOOKUP(virtualization, int);
