/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Thomas H.P. Andersen
  Copyright 2010 Lennart Poettering
  Copyright 2011 Michal Schmidt

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
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "install.h"
#include "log.h"
#include "mkdir.h"
#include "path-lookup.h"
#include "path-util.h"
#include "set.h"
#include "special.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "util.h"

typedef enum RunlevelType {
        RUNLEVEL_SYSINIT,
        RUNLEVEL_UP,
        RUNLEVEL_DOWN
} RunlevelType;

static const struct {
        const char *path;
        const char *target;
        const RunlevelType type;
} rcnd_table[] = {
        /* SUSE style boot.d */
        { "boot.d", SPECIAL_SYSINIT_TARGET,   RUNLEVEL_SYSINIT },

        /* Standard SysV runlevels for start-up */
        { "rc1.d",  SPECIAL_RESCUE_TARGET,     RUNLEVEL_UP },
        { "rc2.d",  SPECIAL_MULTI_USER_TARGET, RUNLEVEL_UP },
        { "rc3.d",  SPECIAL_MULTI_USER_TARGET, RUNLEVEL_UP },
        { "rc4.d",  SPECIAL_MULTI_USER_TARGET, RUNLEVEL_UP },
        { "rc5.d",  SPECIAL_GRAPHICAL_TARGET,  RUNLEVEL_UP },

        /* Standard SysV runlevels for shutdown */
        { "rc0.d",  SPECIAL_POWEROFF_TARGET,  RUNLEVEL_DOWN },
        { "rc6.d",  SPECIAL_REBOOT_TARGET,    RUNLEVEL_DOWN }

        /* Note that the order here matters, as we read the
           directories in this order, and we want to make sure that
           sysv_start_priority is known when we first load the
           unit. And that value we only know from S links. Hence
           UP must be read before DOWN */
};

const char *arg_dest = "/tmp";

typedef struct SysvStub {
        char *name;
        char *path;
        char *description;
        int sysv_start_priority;
        char *pid_file;
        char **before;
        char **after;
        char **wants;
        char **wanted_by;
        char **conflicts;
        bool has_lsb;
        bool reload;
        bool loaded;
        bool early;
} SysvStub;

static void free_sysvstub(SysvStub *s) {
        if (!s)
                return;

        free(s->name);
        free(s->path);
        free(s->description);
        free(s->pid_file);
        strv_free(s->before);
        strv_free(s->after);
        strv_free(s->wants);
        strv_free(s->wanted_by);
        strv_free(s->conflicts);
        free(s);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SysvStub*, free_sysvstub);

static void free_sysvstub_hashmapp(Hashmap **h) {
        SysvStub *stub;

        while ((stub = hashmap_steal_first(*h)))
                free_sysvstub(stub);

        hashmap_free(*h);
}

static int add_symlink(const char *service, const char *where) {
        const char *from, *to;
        int r;

        assert(service);
        assert(where);

        from = strjoina(arg_dest, "/", service);
        to = strjoina(arg_dest, "/", where, ".wants/", service);

        mkdir_parents_label(to, 0755);

        r = symlink(from, to);
        if (r < 0) {
                if (errno == EEXIST)
                        return 0;

                return -errno;
        }

        return 1;
}

static int add_alias(const char *service, const char *alias) {
        const char *link;
        int r;

        assert(service);
        assert(alias);

        link = strjoina(arg_dest, "/", alias);

        r = symlink(service, link);
        if (r < 0) {
                if (errno == EEXIST)
                        return 0;

                return -errno;
        }

        return 1;
}

static int generate_unit_file(SysvStub *s) {
        _cleanup_free_ char *before = NULL, *after = NULL, *wants = NULL, *conflicts = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *unit;
        char **p;
        int r;

        assert(s);

        if (!s->loaded)
                return 0;

        unit = strjoina(arg_dest, "/", s->name);

        before = strv_join(s->before, " ");
        after = strv_join(s->after, " ");
        wants = strv_join(s->wants, " ");
        conflicts = strv_join(s->conflicts, " ");

        if (!before || !after || !wants || !conflicts)
                return log_oom();

        /* We might already have a symlink with the same name from a Provides:,
         * or from backup files like /etc/init.d/foo.bak. Real scripts always win,
         * so remove an existing link */
        if (is_symlink(unit) > 0) {
                log_warning("Overwriting existing symlink %s with real service.", unit);
                (void) unlink(unit);
        }

        f = fopen(unit, "wxe");
        if (!f)
                return log_error_errno(errno, "Failed to create unit file %s: %m", unit);

        fprintf(f,
                "# Automatically generated by systemd-sysv-generator\n\n"
                "[Unit]\n"
                "Documentation=man:systemd-sysv-generator(8)\n"
                "SourcePath=%s\n",
                s->path);

        if (s->description)
                fprintf(f, "Description=%s\n", s->description);

        if (s->early)
                fprintf(f, "DefaultDependencies=no\n");

        if (!isempty(before))
                fprintf(f, "Before=%s\n", before);
        if (!isempty(after))
                fprintf(f, "After=%s\n", after);
        if (!isempty(wants))
                fprintf(f, "Wants=%s\n", wants);
        if (!isempty(conflicts))
                fprintf(f, "Conflicts=%s\n", conflicts);

        fprintf(f,
                "\n[Service]\n"
                "Type=forking\n"
                "Restart=no\n"
                "TimeoutSec=5min\n"
                "IgnoreSIGPIPE=no\n"
                "KillMode=process\n"
                "GuessMainPID=no\n"
                "RemainAfterExit=%s\n",
                yes_no(!s->pid_file));

        if (s->pid_file)
                fprintf(f, "PIDFile=%s\n", s->pid_file);

        fprintf(f,
                "ExecStart=%s start\n"
                "ExecStop=%s stop\n",
                s->path, s->path);

        if (s->reload)
                fprintf(f, "ExecReload=%s reload\n", s->path);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit %s: %m", unit);

        STRV_FOREACH(p, s->wanted_by) {
                r = add_symlink(s->name, *p);
                if (r < 0)
                        log_warning_errno(r, "Failed to create 'Wants' symlink to %s, ignoring: %m", *p);
        }

        return 1;
}

static bool usage_contains_reload(const char *line) {
        return (strcasestr(line, "{reload|") ||
                strcasestr(line, "{reload}") ||
                strcasestr(line, "{reload\"") ||
                strcasestr(line, "|reload|") ||
                strcasestr(line, "|reload}") ||
                strcasestr(line, "|reload\""));
}

static char *sysv_translate_name(const char *name) {
        _cleanup_free_ char *c = NULL;
        char *res;

        if (startswith(name, "boot."))
                /* Drop SuSE-style boot. prefix */
                name += 5;

        c = strdup(name);
        if (!c)
                return NULL;

        res = endswith(c, ".sh");
        if (res)
                *res = 0;

        if (unit_name_mangle(c, UNIT_NAME_NOGLOB, &res) < 0)
                return NULL;

        return res;
}

static int sysv_translate_facility(const char *name, const char *filename, char **ret) {

        /* We silently ignore the $ prefix here. According to the LSB
         * spec it simply indicates whether something is a
         * standardized name or a distribution-specific one. Since we
         * just follow what already exists and do not introduce new
         * uses or names we don't care who introduced a new name. */

        static const char * const table[] = {
                /* LSB defined facilities */
                "local_fs",             NULL,
                "network",              SPECIAL_NETWORK_ONLINE_TARGET,
                "named",                SPECIAL_NSS_LOOKUP_TARGET,
                "portmap",              SPECIAL_RPCBIND_TARGET,
                "remote_fs",            SPECIAL_REMOTE_FS_TARGET,
                "syslog",               NULL,
                "time",                 SPECIAL_TIME_SYNC_TARGET,
                "all",                  SPECIAL_DEFAULT_TARGET,
        };

        char *filename_no_sh, *e, *m;
        const char *n;
        unsigned i;
        int r;

        assert(name);
        assert(filename);
        assert(ret);

        n = *name == '+' ? ++name   : name;
        n = *name == '$' ? name + 1 : name;

        for (i = 0; i < ELEMENTSOF(table); i += 2) {
                if (!streq(table[i], n))
                        continue;

                if (!table[i+1])
                        return 0;

                m = strdup(table[i+1]);
                if (!m)
                        return log_oom();

                *ret = m;
                return 1;
        }

        /* If we don't know this name, fallback heuristics to figure
         * out whether something is a target or a service alias. */

        /* Facilities starting with $ are most likely targets */
        if (*name == '$')  {
                r = unit_name_build(n, NULL, ".target", ret);
                if (r < 0)
                        return log_error_errno(r, "Failed to build name for '%s': %m", name);

                return r;
        }

        /* Strip "boot." prefix from file name for comparison (Suse specific) */
        e = startswith(filename, "boot.");
        if (e)
                filename += 5;

        /* Strip ".sh" suffix from file name for comparison */
        filename_no_sh = strdupa(filename);
        e = endswith(filename_no_sh, ".sh");
        if (e) {
                *e = '\0';
                filename = filename_no_sh;
        }

        /* Names equaling the file name of the services are redundant */
        if (streq_ptr(n, filename))
                return 0;

        /* Everything else we assume to be normal service names */
        m = sysv_translate_name(n);
        if (!m)
                return log_oom();

        *ret = m;
        return 1;
}

static int handle_provides(SysvStub *s, unsigned line, const char *full_text, const char *text) {
        int r;

        assert(s);
        assert(full_text);
        assert(text);

        for (;;) {
                _cleanup_free_ char *word = NULL, *m = NULL;

                r = extract_first_word(&text, &word, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse word from provides string: %m");
                if (r == 0)
                        break;

                r = sysv_translate_facility(word, basename(s->path), &m);
                if (r <= 0) /* continue on error */
                        continue;

                switch (unit_name_to_type(m)) {

                case UNIT_SERVICE:
                        log_debug("Adding Provides: alias '%s' for '%s'", m, s->name);
                        r = add_alias(s->name, m);
                        if (r < 0)
                                log_warning_errno(r, "[%s:%u] Failed to add LSB Provides name %s, ignoring: %m", s->path, line, m);
                        break;

                case UNIT_TARGET:

                        /* NB: SysV targets which are provided by a
                         * service are pulled in by the services, as
                         * an indication that the generic service is
                         * now available. This is strictly one-way.
                         * The targets do NOT pull in SysV services! */

                        r = strv_extend(&s->before, m);
                        if (r < 0)
                                return log_oom();

                        r = strv_extend(&s->wants, m);
                        if (r < 0)
                                return log_oom();

                        if (streq(m, SPECIAL_NETWORK_ONLINE_TARGET)) {
                                r = strv_extend(&s->before, SPECIAL_NETWORK_TARGET);
                                if (r < 0)
                                        return log_oom();
                        }

                        break;

                case _UNIT_TYPE_INVALID:
                        log_warning("Unit name '%s' is invalid", m);
                        break;

                default:
                        log_warning("Unknown unit type for unit '%s'", m);
                }
        }

        return 0;
}

static int handle_dependencies(SysvStub *s, unsigned line, const char *full_text, const char *text) {
        int r;

        assert(s);
        assert(full_text);
        assert(text);

        for (;;) {
                _cleanup_free_ char *word = NULL, *m = NULL;
                bool is_before, is_wanted;

                r = extract_first_word(&text, &word, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse word from provides string: %m");
                if (r == 0)
                        break;

                r = sysv_translate_facility(word, basename(s->path), &m);
                if (r <= 0) /* continue on error */
                        continue;

                is_before = startswith_no_case(full_text, "X-Start-Before:");
                is_wanted = startswith_no_case(full_text, "Required-Start:");

                if (streq(m, SPECIAL_NETWORK_ONLINE_TARGET) && !is_before) {
                        /* the network-online target is special, as it needs to be actively pulled in */
                        r = strv_extend(&s->after, m);
                        if (r < 0)
                                return log_oom();

                        r = strv_extend(&s->wants, m);
                } else {
                        r = strv_extend(is_before ? &s->before : &s->after, m);

                        if (is_wanted)
                                r = strv_extend(&s->wants, m);
                }

                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int load_sysv(SysvStub *s) {
        _cleanup_fclose_ FILE *f;
        unsigned line = 0;
        int r;
        enum {
                NORMAL,
                DESCRIPTION,
                LSB,
                LSB_DESCRIPTION,
                USAGE_CONTINUATION
        } state = NORMAL;
        _cleanup_free_ char *short_description = NULL, *long_description = NULL, *chkconfig_description = NULL;
        char *description;
        bool supports_reload = false;
        char l[LINE_MAX];

        assert(s);

        f = fopen(s->path, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", s->path);
        }

        log_debug("Loading SysV script %s", s->path);

        FOREACH_LINE(l, f, goto fail) {
                char *t;

                line++;

                t = strstrip(l);
                if (*t != '#') {
                        /* Try to figure out whether this init script supports
                         * the reload operation. This heuristic looks for
                         * "Usage" lines which include the reload option. */
                        if ( state == USAGE_CONTINUATION ||
                            (state == NORMAL && strcasestr(t, "usage"))) {
                                if (usage_contains_reload(t)) {
                                        supports_reload = true;
                                        state = NORMAL;
                                } else if (t[strlen(t)-1] == '\\')
                                        state = USAGE_CONTINUATION;
                                else
                                        state = NORMAL;
                        }

                        continue;
                }

                if (state == NORMAL && streq(t, "### BEGIN INIT INFO")) {
                        state = LSB;
                        s->has_lsb = true;
                        continue;
                }

                if ((state == LSB_DESCRIPTION || state == LSB) && streq(t, "### END INIT INFO")) {
                        state = NORMAL;
                        continue;
                }

                t++;
                t += strspn(t, WHITESPACE);

                if (state == NORMAL) {

                        /* Try to parse Red Hat style description */

                        if (startswith_no_case(t, "description:")) {

                                size_t k;
                                const char *j;

                                k = strlen(t);
                                if (k > 0 && t[k-1] == '\\') {
                                        state = DESCRIPTION;
                                        t[k-1] = 0;
                                }

                                j = strstrip(t+12);
                                if (isempty(j))
                                        j = NULL;

                                r = free_and_strdup(&chkconfig_description, j);
                                if (r < 0)
                                        return log_oom();

                        } else if (startswith_no_case(t, "pidfile:")) {
                                const char *fn;

                                state = NORMAL;

                                fn = strstrip(t+8);
                                if (!path_is_absolute(fn)) {
                                        log_error("[%s:%u] PID file not absolute. Ignoring.", s->path, line);
                                        continue;
                                }

                                r = free_and_strdup(&s->pid_file, fn);
                                if (r < 0)
                                        return log_oom();
                        }

                } else if (state == DESCRIPTION) {

                        /* Try to parse Red Hat style description
                         * continuation */

                        size_t k;
                        char *j;

                        k = strlen(t);
                        if (k > 0 && t[k-1] == '\\')
                                t[k-1] = 0;
                        else
                                state = NORMAL;

                        j = strstrip(t);
                        if (!isempty(j)) {
                                char *d = NULL;

                                if (chkconfig_description)
                                        d = strjoin(chkconfig_description, " ", j, NULL);
                                else
                                        d = strdup(j);
                                if (!d)
                                        return log_oom();

                                free(chkconfig_description);
                                chkconfig_description = d;
                        }

                } else if (state == LSB || state == LSB_DESCRIPTION) {

                        if (startswith_no_case(t, "Provides:")) {
                                state = LSB;

                                r = handle_provides(s, line, t, t + 9);
                                if (r < 0)
                                        return r;

                        } else if (startswith_no_case(t, "Required-Start:") ||
                                   startswith_no_case(t, "Should-Start:") ||
                                   startswith_no_case(t, "X-Start-Before:") ||
                                   startswith_no_case(t, "X-Start-After:")) {

                                state = LSB;

                                r = handle_dependencies(s, line, t, strchr(t, ':') + 1);
                                if (r < 0)
                                        return r;

                        } else if (startswith_no_case(t, "Description:")) {
                                const char *j;

                                state = LSB_DESCRIPTION;

                                j = strstrip(t+12);
                                if (isempty(j))
                                        j = NULL;

                                r = free_and_strdup(&long_description, j);
                                if (r < 0)
                                        return log_oom();

                        } else if (startswith_no_case(t, "Short-Description:")) {
                                const char *j;

                                state = LSB;

                                j = strstrip(t+18);
                                if (isempty(j))
                                        j = NULL;

                                r = free_and_strdup(&short_description, j);
                                if (r < 0)
                                        return log_oom();

                        } else if (state == LSB_DESCRIPTION) {

                                if (startswith(l, "#\t") || startswith(l, "#  ")) {
                                        const char *j;

                                        j = strstrip(t);
                                        if (!isempty(j)) {
                                                char *d = NULL;

                                                if (long_description)
                                                        d = strjoin(long_description, " ", t, NULL);
                                                else
                                                        d = strdup(j);
                                                if (!d)
                                                        return log_oom();

                                                free(long_description);
                                                long_description = d;
                                        }

                                } else
                                        state = LSB;
                        }
                }
        }

        s->reload = supports_reload;

        /* We use the long description only if
         * no short description is set. */

        if (short_description)
                description = short_description;
        else if (chkconfig_description)
                description = chkconfig_description;
        else if (long_description)
                description = long_description;
        else
                description = NULL;

        if (description) {
                char *d;

                d = strappend(s->has_lsb ? "LSB: " : "SYSV: ", description);
                if (!d)
                        return log_oom();

                s->description = d;
        }

        s->loaded = true;
        return 0;

fail:
        return log_error_errno(errno, "Failed to read configuration file '%s': %m", s->path);
}

static int fix_order(SysvStub *s, Hashmap *all_services) {
        SysvStub *other;
        Iterator j;
        int r;

        assert(s);

        if (!s->loaded)
                return 0;

        if (s->sysv_start_priority < 0)
                return 0;

        HASHMAP_FOREACH(other, all_services, j) {
                if (s == other)
                        continue;

                if (!other->loaded)
                        continue;

                if (other->sysv_start_priority < 0)
                        continue;

                if (s->early != other->early)
                        continue;

                /* If both units have modern headers we don't care
                 * about the priorities */
                if (s->has_lsb && other->has_lsb)
                        continue;

                if (other->sysv_start_priority < s->sysv_start_priority) {
                        r = strv_extend(&s->after, other->name);
                        if (r < 0)
                                return log_oom();

                } else if (other->sysv_start_priority > s->sysv_start_priority) {
                        r = strv_extend(&s->before, other->name);
                        if (r < 0)
                                return log_oom();
                } else
                        continue;

                /* FIXME: Maybe we should compare the name here lexicographically? */
        }

        return 0;
}

static int enumerate_sysv(const LookupPaths *lp, Hashmap *all_services) {
        char **path;
        int r;

        assert(lp);
        assert(all_services);

        STRV_FOREACH(path, lp->sysvinit_path) {
                _cleanup_closedir_ DIR *d = NULL;
                struct dirent *de;

                d = opendir(*path);
                if (!d) {
                        if (errno != ENOENT)
                                log_warning_errno(errno, "Opening %s failed, ignoring: %m", *path);
                        continue;
                }

                FOREACH_DIRENT(de, d, log_error_errno(errno, "Failed to enumerate directory %s, ignoring: %m", *path)) {
                        _cleanup_free_ char *fpath = NULL, *name = NULL;
                        _cleanup_(free_sysvstubp) SysvStub *service = NULL;
                        struct stat st;

                        if (fstatat(dirfd(d), de->d_name, &st, 0) < 0) {
                                log_warning_errno(errno, "stat() failed on %s/%s, ignoring: %m", *path, de->d_name);
                                continue;
                        }

                        if (!(st.st_mode & S_IXUSR))
                                continue;

                        if (!S_ISREG(st.st_mode))
                                continue;

                        name = sysv_translate_name(de->d_name);
                        if (!name)
                                return log_oom();

                        if (hashmap_contains(all_services, name))
                                continue;

                        r = unit_file_lookup_state(UNIT_FILE_SYSTEM, NULL, lp, name, NULL);
                        if (r < 0 && r != -ENOENT) {
                                log_debug_errno(r, "Failed to detect whether %s exists, skipping: %m", name);
                                continue;
                        } else if (r >= 0) {
                                log_debug("Native unit for %s already exists, skipping.", name);
                                continue;
                        }

                        fpath = strjoin(*path, "/", de->d_name, NULL);
                        if (!fpath)
                                return log_oom();

                        service = new0(SysvStub, 1);
                        if (!service)
                                return log_oom();

                        service->sysv_start_priority = -1;
                        service->name = name;
                        service->path = fpath;
                        name = fpath = NULL;

                        r = hashmap_put(all_services, service->name, service);
                        if (r < 0)
                                return log_oom();

                        service = NULL;
                }
        }

        return 0;
}

static int set_dependencies_from_rcnd(const LookupPaths *lp, Hashmap *all_services) {
        Set *runlevel_services[ELEMENTSOF(rcnd_table)] = {};
        _cleanup_set_free_ Set *shutdown_services = NULL;
        SysvStub *service;
        unsigned i;
        Iterator j;
        char **p;
        int r;

        assert(lp);

        STRV_FOREACH(p, lp->sysvrcnd_path) {
                for (i = 0; i < ELEMENTSOF(rcnd_table); i ++) {

                        _cleanup_closedir_ DIR *d = NULL;
                        _cleanup_free_ char *path = NULL;
                        struct dirent *de;

                        path = strjoin(*p, "/", rcnd_table[i].path, NULL);
                        if (!path) {
                                r = log_oom();
                                goto finish;
                        }

                        d = opendir(path);
                        if (!d) {
                                if (errno != ENOENT)
                                        log_warning_errno(errno, "Opening %s failed, ignoring: %m", path);

                                continue;
                        }

                        FOREACH_DIRENT(de, d, log_error_errno(errno, "Failed to enumerate directory %s, ignoring: %m", path)) {
                                _cleanup_free_ char *name = NULL, *fpath = NULL;
                                int a, b;

                                if (de->d_name[0] != 'S' && de->d_name[0] != 'K')
                                        continue;

                                if (strlen(de->d_name) < 4)
                                        continue;

                                a = undecchar(de->d_name[1]);
                                b = undecchar(de->d_name[2]);

                                if (a < 0 || b < 0)
                                        continue;

                                fpath = strjoin(*p, "/", de->d_name, NULL);
                                if (!fpath) {
                                        r = log_oom();
                                        goto finish;
                                }

                                name = sysv_translate_name(de->d_name + 3);
                                if (!name) {
                                        r = log_oom();
                                        goto finish;
                                }

                                service = hashmap_get(all_services, name);
                                if (!service){
                                        log_debug("Ignoring %s symlink in %s, not generating %s.", de->d_name, rcnd_table[i].path, name);
                                        continue;
                                }

                                service->early = IN_SET(rcnd_table[i].type, RUNLEVEL_SYSINIT);

                                if (de->d_name[0] == 'S')  {

                                        if (IN_SET(rcnd_table[i].type, RUNLEVEL_UP, RUNLEVEL_SYSINIT))
                                                service->sysv_start_priority = MAX(a*10 + b, service->sysv_start_priority);

                                        r = set_ensure_allocated(&runlevel_services[i], NULL);
                                        if (r < 0) {
                                                log_oom();
                                                goto finish;
                                        }

                                        r = set_put(runlevel_services[i], service);
                                        if (r < 0) {
                                                log_oom();
                                                goto finish;
                                        }

                                } else if (de->d_name[0] == 'K' &&
                                           IN_SET(rcnd_table[i].type, RUNLEVEL_DOWN, RUNLEVEL_SYSINIT)) {

                                        /* Early boot services want to be stopped lately
                                         * unless user explicitly asked to stop it with
                                         * the default shutdown.target */

                                        r = set_ensure_allocated(&shutdown_services, NULL);
                                        if (r < 0) {
                                                log_oom();
                                                goto finish;
                                        }

                                        r = set_put(shutdown_services, service);
                                        if (r < 0) {
                                                log_oom();
                                                goto finish;
                                        }
                                }
                        }
                }
        }


        for (i = 0; i < ELEMENTSOF(rcnd_table); i ++)
                SET_FOREACH(service, runlevel_services[i], j) {
                        r = strv_extend(&service->before, rcnd_table[i].target);
                        if (r < 0) {
                                log_oom();
                                goto finish;
                        }
                        r = strv_extend(&service->wanted_by, rcnd_table[i].target);
                        if (r < 0) {
                                log_oom();
                                goto finish;
                        }
                }

        SET_FOREACH(service, shutdown_services, j) {
                r = strv_extend(&service->before, SPECIAL_SHUTDOWN_TARGET);
                if (r < 0) {
                        log_oom();
                        goto finish;
                }
                r = strv_extend(&service->conflicts, SPECIAL_SHUTDOWN_TARGET);
                if (r < 0) {
                        log_oom();
                        goto finish;
                }
        }

        r = 0;

finish:
        for (i = 0; i < ELEMENTSOF(rcnd_table); i++)
                set_free(runlevel_services[i]);

        return r;
}

int main(int argc, char *argv[]) {
        _cleanup_(free_sysvstub_hashmapp) Hashmap *all_services = NULL;
        _cleanup_lookup_paths_free_ LookupPaths lp = {};
        SysvStub *service;
        Iterator j;
        int r;

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
                arg_dest = argv[3];

        log_set_target(LOG_TARGET_SAFE);
        log_parse_environment();
        log_open();

        umask(0022);

        r = lookup_paths_init(&lp, MANAGER_SYSTEM, true, NULL, NULL, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to find lookup paths: %m");
                goto finish;
        }

        all_services = hashmap_new(&string_hash_ops);
        if (!all_services) {
                r = log_oom();
                goto finish;
        }

        r = enumerate_sysv(&lp, all_services);
        if (r < 0)
                goto finish;

        r = set_dependencies_from_rcnd(&lp, all_services);
        if (r < 0)
                goto finish;

        HASHMAP_FOREACH(service, all_services, j)
                (void) load_sysv(service);

        HASHMAP_FOREACH(service, all_services, j) {
                (void) fix_order(service, all_services);
                (void) generate_unit_file(service);
        }

        r = 0;

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
