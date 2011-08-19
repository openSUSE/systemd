/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Kay Sievers

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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/tiocl.h>
#include <linux/kd.h>
#include <linux/vt.h>

#include "util.h"
#include "log.h"
#include "macro.h"
#include "virt.h"
#include "fileio.h"
#include "strv.h"

static bool is_vconsole(int fd) {
        unsigned char data[1];

        data[0] = TIOCL_GETFGCONSOLE;
        return ioctl(fd, TIOCLINUX, data) >= 0;
}

static int disable_utf8(int fd) {
        int r = 0, k;

        if (ioctl(fd, KDSKBMODE, K_XLATE) < 0)
                r = -errno;

        if (loop_write(fd, "\033%@", 3, false) < 0)
                r = -errno;

        k = write_string_file("/sys/module/vt/parameters/default_utf8", "0");
        if (k < 0)
                r = k;

        if (r < 0)
                log_warning("Failed to disable UTF-8: %s", strerror(-r));

        return r;
}

static int enable_utf8(int fd) {
        int r = 0, k;
        long current = 0;

        if (ioctl(fd, KDGKBMODE, &current) < 0 || current == K_XLATE) {
                /*
                 * Change the current keyboard to unicode, unless it
                 * is currently in raw or off mode anyway. We
                 * shouldn't interfere with X11's processing of the
                 * key events.
                 *
                 * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
                 *
                 */

                if (ioctl(fd, KDSKBMODE, K_UNICODE) < 0)
                        r = -errno;
        }

        if (loop_write(fd, "\033%G", 3, false) < 0)
                r = -errno;

        k = write_string_file("/sys/module/vt/parameters/default_utf8", "1");
        if (k < 0)
                r = k;

        if (r < 0)
                log_warning("Failed to enable UTF-8: %s", strerror(-r));

        return r;
}

static int keymap_load(const char *vc, const char *map, const char *map_toggle, bool utf8, bool disable_capslock, pid_t *_pid) {
        const char *args[9];
        int i = 0;
        pid_t pid;

        if (isempty(map)) {
                /* An empty map means kernel map */
                *_pid = 0;
                return 0;
        }

        args[i++] = KBD_LOADKEYS;
        args[i++] = "-q";
        args[i++] = "-C";
        args[i++] = vc;
        if (utf8)
                args[i++] = "-u";
        args[i++] = map;
        if (map_toggle)
                args[i++] = map_toggle;
        if (disable_capslock)
                args[i++] = "disable.capslock";
        args[i++] = NULL;

        pid = fork();
        if (pid < 0) {
                log_error("Failed to fork: %m");
                return -errno;
        } else if (pid == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        *_pid = pid;
        return 0;
}

static int font_load(const char *vc, const char *font, const char *map, const char *unimap, pid_t *_pid) {
        const char *args[9];
        int i = 0;
        pid_t pid;

        if (isempty(font)) {
                /* An empty font means kernel font */
                *_pid = 0;
                return 0;
        }

        args[i++] = KBD_SETFONT;
        args[i++] = "-C";
        args[i++] = vc;
        args[i++] = font;
        if (map) {
                args[i++] = "-m";
                args[i++] = map;
        }
        if (unimap) {
                args[i++] = "-u";
                args[i++] = unimap;
        }
        args[i++] = NULL;

        pid = fork();
        if (pid < 0) {
                log_error("Failed to fork: %m");
                return -errno;
        } else if (pid == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        *_pid = pid;
        return 0;
}

/*
 * A newly allocated VT uses the font from the active VT. Here
 * we update all possibly already allocated VTs with the configured
 * font. It also allows to restart systemd-vconsole-setup.service,
 * to apply a new font to all VTs.
 */
static void font_copy_to_all_vcs(int fd) {
        struct vt_stat vcs = {};
        int i, r;

        /* get active, and 16 bit mask of used VT numbers */
        r = ioctl(fd, VT_GETSTATE, &vcs);
        if (r < 0)
                return;

        for (i = 1; i <= 15; i++) {
                char vcname[16];
                _cleanup_close_ int vcfd = -1;
                struct console_font_op cfo = {};

                if (i == vcs.v_active)
                        continue;

                /* skip non-allocated ttys */
                snprintf(vcname, sizeof(vcname), "/dev/vcs%i", i);
                if (access(vcname, F_OK) < 0)
                        continue;

                snprintf(vcname, sizeof(vcname), "/dev/tty%i", i);
                vcfd = open_terminal(vcname, O_RDWR|O_CLOEXEC);
                if (vcfd < 0)
                        continue;

                /* copy font from active VT, where the font was uploaded to */
                cfo.op = KD_FONT_OP_COPY;
                cfo.height = vcs.v_active-1; /* tty1 == index 0 */
                ioctl(vcfd, KDFONTOP, &cfo);
        }
}

#ifdef HAVE_SYSV_COMPAT
static int load_compose_table(const char *vc, const char *compose_table, pid_t *_pid) {
        const char *args[1024];
        int i = 0, j = 0;
        pid_t pid;
        char **strv_compose_table = NULL;
        char *to_free[1024];

        if (isempty(compose_table)) {
                /* An empty map means no compose table*/
                *_pid = 0;
                return 0;
        }

        args[i++] = KBD_LOADKEYS;
        args[i++] = "-q";
        args[i++] = "-C";
        args[i++] = vc;

        strv_compose_table = strv_split(compose_table, WHITESPACE);
        if (strv_compose_table) {
                bool compose_loaded = false;
                bool compose_clear = false;
                char **name;
                char *arg;

                STRV_FOREACH (name, strv_compose_table) {
                        if (streq(*name,"-c") || streq(*name,"clear")) {
                                compose_clear = true;
                                continue;
                        }
                        if (!compose_loaded) {
                                if (compose_clear)
                                        args[i++] = "-c";
                        }
                        asprintf(&arg, "compose.%s",*name);
                        compose_loaded = true;
                        args[i++] = to_free[j++] = arg;

                }
                strv_free(strv_compose_table);
        }
        args[i++] = NULL;

        if ((pid = fork()) < 0) {
                log_error("Failed to fork: %m");
                return -errno;
        } else if (pid == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        *_pid = pid;

        for (i=0 ; i < j ; i++)
                free (to_free[i]);

        return 0;
}
#endif

static int set_kbd_rate(const char *vc, const char *kbd_rate, const char *kbd_delay, pid_t *_pid) {
        const char *args[7];
        int i = 0;
        pid_t pid;

        if (isempty(kbd_rate) && isempty(kbd_delay)) {
                *_pid = 0;
                return 0;
        }

        args[i++] = "/bin/kbdrate";
        if (!isempty(kbd_rate)) {
                args[i++] = "-r";
                args[i++] = kbd_rate;
        }
        if (!isempty(kbd_delay)) {
                args[i++] = "-d";
                args[i++] = kbd_delay;
        }
        args[i++] = "-s";
        args[i++] = NULL;

        if ((pid = fork()) < 0) {
                log_error("Failed to fork: %m");
                return -errno;
        } else if (pid == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        *_pid = pid;
        return 0;
}

int main(int argc, char **argv) {
        const char *vc;
        char *vc_keymap = NULL;
        char *vc_keymap_toggle = NULL;
        char *vc_font = NULL;
        char *vc_font_map = NULL;
        char *vc_font_unimap = NULL;
#ifdef HAVE_SYSV_COMPAT
        char *vc_kbd_delay = NULL;
        char *vc_kbd_rate = NULL;
        char *vc_kbd_disable_caps_lock = NULL;
        char *vc_compose_table = NULL;
        pid_t kbd_rate_pid = 0, compose_table_pid = 0;
#endif
        int fd = -1;
        bool utf8;
        bool disable_capslock = false;
        pid_t font_pid = 0, keymap_pid = 0;
        bool font_copy = false;
        int r = EXIT_FAILURE;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argv[1])
                vc = argv[1];
        else {
                vc = "/dev/tty0";
                font_copy = true;
        }

        fd = open_terminal(vc, O_RDWR|O_CLOEXEC);
        if (fd < 0) {
                log_error("Failed to open %s: %m", vc);
                goto finish;
        }

        if (!is_vconsole(fd)) {
                log_error("Device %s is not a virtual console.", vc);
                goto finish;
        }

        utf8 = is_locale_utf8();

#ifdef HAVE_SYSV_COMPAT
        r = parse_env_file("/etc/sysconfig/keyboard", NEWLINE,
                "KEYTABLE", &vc_keymap,
                "KBD_DELAY", &vc_kbd_delay,
                "KBD_RATE", &vc_kbd_rate,
                "KBD_DISABLE_CAPS_LOCK", &vc_kbd_disable_caps_lock,
                "COMPOSETABLE", &vc_compose_table,
                NULL);
        if (r < 0 && r != -ENOENT)
            log_warning("Failed to read /etc/sysconfig/keyboard: %s", strerror(-r));

        r = parse_env_file("/etc/sysconfig/console", NEWLINE,
                "CONSOLE_FONT", &vc_font,
                "CONSOLE_SCREENMAP", &vc_font_map,
                "CONSOLE_UNICODEMAP", &vc_font_unimap,
                NULL);
        if (r < 0 && r != -ENOENT)
            log_warning("Failed to read /etc/sysconfig/console: %s", strerror(-r));

        disable_capslock = vc_kbd_disable_caps_lock && strcasecmp(vc_kbd_disable_caps_lock, "YES") == 0;
#endif

        r = parse_env_file("/etc/vconsole.conf", NEWLINE,
                           "KEYMAP", &vc_keymap,
                           "KEYMAP_TOGGLE", &vc_keymap_toggle,
                           "FONT", &vc_font,
                           "FONT_MAP", &vc_font_map,
                           "FONT_UNIMAP", &vc_font_unimap,
                           NULL);

        if (r < 0 && r != -ENOENT)
                log_warning("Failed to read /etc/vconsole.conf: %s", strerror(-r));

        /* Let the kernel command line override /etc/vconsole.conf */
        if (detect_container(NULL) <= 0) {
                r = parse_env_file("/proc/cmdline", WHITESPACE,
                                   "vconsole.keymap", &vc_keymap,
                                   "vconsole.keymap.toggle", &vc_keymap_toggle,
                                   "vconsole.font", &vc_font,
                                   "vconsole.font.map", &vc_font_map,
                                   "vconsole.font.unimap", &vc_font_unimap,
                                   NULL);

                if (r < 0 && r != -ENOENT)
                        log_warning("Failed to read /proc/cmdline: %s", strerror(-r));
        }

        if (utf8)
                enable_utf8(fd);
        else
                disable_utf8(fd);

        r = EXIT_FAILURE;

        if (keymap_load(vc, vc_keymap, vc_keymap_toggle, utf8, disable_capslock, &keymap_pid) >= 0 &&
#ifdef HAVE_SYSV_COMPAT
            load_compose_table(vc, vc_compose_table, &compose_table_pid) >= 0 &&
            set_kbd_rate(vc, vc_kbd_rate, vc_kbd_delay, &kbd_rate_pid) >= 0 &&
#endif
            font_load(vc, vc_font, vc_font_map, vc_font_unimap, &font_pid) >= 0)
                r = EXIT_SUCCESS;

finish:
        if (keymap_pid > 0)
                wait_for_terminate_and_warn(KBD_LOADKEYS, keymap_pid);

#ifdef HAVE_SYSV_COMPAT
        if (compose_table_pid > 0)
                wait_for_terminate_and_warn(KBD_LOADKEYS, compose_table_pid);

        if (kbd_rate_pid > 0)
                wait_for_terminate_and_warn("/bin/kbdrate", kbd_rate_pid);
#endif

        if (font_pid > 0) {
                wait_for_terminate_and_warn(KBD_SETFONT, font_pid);
                if (font_copy)
                        font_copy_to_all_vcs(fd);
        }

        free(vc_keymap);
        free(vc_font);
        free(vc_font_map);
        free(vc_font_unimap);
#ifdef HAVE_SYSV_COMPAT
        free(vc_kbd_delay);
        free(vc_kbd_rate);
        free(vc_kbd_disable_caps_lock);
        free(vc_compose_table);
#endif

        if (fd >= 0)
                close_nointr_nofail(fd);

        return r;
}
