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

#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#ifdef HAVE_SYSV_COMPAT
# include <linux/tiocl.h>
# include <linux/vt.h>
# include <sys/ioctl.h>
# include <sys/klog.h>
# include <errno.h>
# include "util.h"
#endif

#include "fileio.h"
#include "journald-server.h"
#include "journald-console.h"

static bool prefix_timestamp(void) {

        static int cached_printk_time = -1;

        if (_unlikely_(cached_printk_time < 0)) {
                _cleanup_free_ char *p = NULL;

                cached_printk_time =
                        read_one_line_file("/sys/module/printk/parameters/time", &p) >= 0
                        && parse_boolean(p) > 0;
        }

        return cached_printk_time;
}

#ifdef HAVE_SYSV_COMPAT
void default_tty_path(Server *s)
{
        static const char list[] = "/dev/tty10\0" "/dev/console\0";
        const char *vc;

        if (s->tty_path)
                return;

        NULSTR_FOREACH(vc, list) {
                _cleanup_close_ int fd = -1;

                if (access(vc, F_OK) < 0)
                        continue;

                fd = open_terminal(vc, O_WRONLY|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        continue;

                s->tty_path = strdup(vc);
                break;
        }
}

void klogconsole(Server *s)
{
        _cleanup_free_ char *klogconsole_params = NULL;
        _cleanup_close_ int fd = -1;
        const char *vc = s->tty_path;
        const char *num;
        int tiocl[2];
        int r;

        if (!vc || *vc == 0 || !strneq("/dev/tty", vc, 8))
                return;

        num = vc + strcspn(vc, "0123456789");
        if (safe_atoi(num, &r) < 0)
                return;

        if (access(vc, F_OK) < 0)
                return;

        fd = open_terminal(vc, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return;

        tiocl[0] = TIOCL_SETKMSGREDIRECT;
        tiocl[1] = r;

        if (ioctl(fd, TIOCLINUX, tiocl) < 0)
                return;

        zero(klogconsole_params);
        r = parse_env_file("/etc/sysconfig/boot", NEWLINE,
                           "KLOGCONSOLE_PARAMS", &klogconsole_params,
                           NULL);
        if (r < 0)
                return;
        if (!klogconsole_params || *klogconsole_params == 0)
                return;

        num = klogconsole_params + strcspn(klogconsole_params, "0123456789");
        if (safe_atoi(num, &r) == 0)
                klogctl(8, 0, r);
}
#endif

void server_forward_console(
                Server *s,
                int priority,
                const char *identifier,
                const char *message,
                struct ucred *ucred) {

        struct iovec iovec[5];
        char header_pid[16];
        struct timespec ts;
        char tbuf[4 + DECIMAL_STR_MAX(ts.tv_sec) + DECIMAL_STR_MAX(ts.tv_nsec)-3 + 1];
        int n = 0, fd;
        _cleanup_free_ char *ident_buf = NULL;
        const char *tty;

        assert(s);
        assert(message);

        if (LOG_PRI(priority) > s->max_level_console)
                return;

        /* Do not write security/authorization (private) messages to console */
        if ((priority & LOG_FACMASK) == LOG_AUTHPRIV)
                return;

        /* First: timestamp */
        if (prefix_timestamp()) {
                assert_se(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
                snprintf(tbuf, sizeof(tbuf), "[%5llu.%06llu] ",
                         (unsigned long long) ts.tv_sec,
                         (unsigned long long) ts.tv_nsec / 1000);
                IOVEC_SET_STRING(iovec[n++], tbuf);
        }

        /* Second: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        get_process_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) ucred->pid);
                char_array_0(header_pid);

                if (identifier)
                        IOVEC_SET_STRING(iovec[n++], identifier);

                IOVEC_SET_STRING(iovec[n++], header_pid);
        } else if (identifier) {
                IOVEC_SET_STRING(iovec[n++], identifier);
                IOVEC_SET_STRING(iovec[n++], ": ");
        }

        /* Fourth: message */
        IOVEC_SET_STRING(iovec[n++], message);
        IOVEC_SET_STRING(iovec[n++], "\n");

        tty = s->tty_path ? s->tty_path : "/dev/console";

        fd = open_terminal(tty, O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                log_debug("Failed to open %s for logging: %m", tty);
#ifdef HAVE_SYSV_COMPAT
                if (fd != -ENOENT && fd != -ENODEV)
                        return;
                if (tty != s->tty_path)
                        return;
                if (!streq("/dev/console", tty)) {
                        if (s->tty_path)
                                free(s->tty_path);
                        s->tty_path = NULL;
                        tty = "/dev/console";
                        fd = open_terminal(tty, O_WRONLY|O_NOCTTY|O_CLOEXEC);
                        if (fd < 0)
                                return;
                }
#else
                return;
#endif
        }

        if (writev(fd, iovec, n) < 0)
                log_debug("Failed to write to %s for logging: %m", tty);

        close_nointr_nofail(fd);
}
